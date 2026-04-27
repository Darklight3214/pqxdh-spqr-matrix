use std::hint::black_box;
use std::time::Instant;
use vodozemac::olm::{Account, SessionConfig, OlmMessage};
use oqs::kem::{Kem, Algorithm};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use crate::stats::BenchResult;
use crate::output;

/// Metric #8: End-to-End Latency — X3DH+DR vs PQXDH+SPQR through Conduit server
///
/// Measures real-world E2E latency including:
/// - Encrypt (local) → HTTP PUT to Conduit → /sync poll → receive event
/// Supports N users, tests all unique pairs (or configurable subset).
///
/// For X3DH+DR: standard OLM encrypt + send + receive
/// For PQXDH+SPQR: encrypt_pq (combined DH+SPQR keys) + send + receive + decrypt
pub fn run(
    conduit_url: &str,
    users: &[(String, String)],   // Vec of (username, password)
    max_pairs: usize,             // 0 = all pairs
    iterations: usize,
    warmup: usize,
) -> serde_json::Value {
    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .pool_max_idle_per_host(4)
        .tcp_nodelay(true)
        .build()
        .expect("HTTP client creation failed");

    let device_suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    // ── Login all users ──
    println!("  [e2e] Logging in {} users...", users.len());
    let mut logged_in: Vec<(String, String, String)> = Vec::new(); // (uid, token, username)

    for (i, (user, pass)) in users.iter().enumerate() {
        let did = format!("BENCH_{}_{}", i, device_suffix);
        match matrix_login(&http, conduit_url, user, pass, &did) {
            Ok((tok, uid)) => {
                println!("  [e2e] Logged in: {} ({})", uid, did);
                logged_in.push((uid, tok, user.clone()));
            }
            Err(e) => {
                println!("  [warn] Login failed for {}: {}", user, e);
            }
        }
    }

    if logged_in.len() < 2 {
        println!("  [error] Need at least 2 logged-in users for E2E. Got {}.", logged_in.len());
        return serde_json::json!({"error": "insufficient users logged in"});
    }

    // ── Generate all unique pairs ──
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    for i in 0..logged_in.len() {
        for j in (i + 1)..logged_in.len() {
            pairs.push((i, j));
        }
    }
    let num_pairs = if max_pairs > 0 && max_pairs < pairs.len() {
        pairs.truncate(max_pairs);
        max_pairs
    } else {
        pairs.len()
    };

    println!("  [e2e] Testing {} user pairs ({} total possible)",
             num_pairs, logged_in.len() * (logged_in.len() - 1) / 2);

    let mut all_classical_samples: Vec<f64> = Vec::new();
    let mut all_pq_samples: Vec<f64> = Vec::new();
    let mut pair_results = Vec::new();

    for (pair_idx, &(ai, bi)) in pairs.iter().enumerate() {
        let (ref _a_uid, ref a_tok, ref a_name) = logged_in[ai];
        let (ref b_uid, ref b_tok, ref b_name) = logged_in[bi];

        println!("  [e2e] Pair {}/{}: {} ↔ {}", pair_idx + 1, num_pairs, a_name, b_name);

        // ── X3DH+DR for this pair ──
        let c_samples = bench_pair_classical(
            &http, conduit_url, a_tok, b_tok, b_uid,
            iterations, warmup,
        );

        // ── PQXDH+SPQR for this pair ──
        let p_samples = bench_pair_pqxdh(
            &http, conduit_url, a_tok, b_tok, b_uid,
            iterations, warmup,
        );

        let cr = BenchResult::new(
            &format!("X3DH+DR {}↔{}", a_name, b_name), "ns", c_samples.clone()
        );
        let pr = BenchResult::new(
            &format!("PQXDH+SPQR {}↔{}", a_name, b_name), "ns", p_samples.clone()
        );

        if !c_samples.is_empty() && !p_samples.is_empty() {
            output::print_comparison_table(
                &format!("E2E Pair: {} ↔ {} (X3DH+DR vs PQXDH+SPQR)", a_name, b_name), &cr, &pr
            );
        }

        all_classical_samples.extend_from_slice(&c_samples);
        all_pq_samples.extend_from_slice(&p_samples);

        pair_results.push(serde_json::json!({
            "pair": format!("{}↔{}", a_name, b_name),
            "x3dh_dr": { "summary": cr.summary(), "count": c_samples.len() },
            "pqxdh_spqr": { "summary": pr.summary(), "count": p_samples.len() },
        }));
    }

    // ── Aggregate results across all pairs ──
    let cr_all = BenchResult::new("X3DH+DR (all pairs)", "ns", all_classical_samples);
    let pr_all = BenchResult::new("PQXDH+SPQR (all pairs)", "ns", all_pq_samples);

    if !cr_all.samples.is_empty() && !pr_all.samples.is_empty() {
        output::print_comparison_table("E2E Aggregate: X3DH+DR vs PQXDH+SPQR", &cr_all, &pr_all);

        let cs = cr_all.summary();
        let ps = pr_all.summary();
        println!("\n  E2E Aggregate Throughput:");
        println!("    X3DH+DR:    {:.1} msgs/sec (at mean latency)", ops_sec(cs.mean));
        println!("    PQXDH+SPQR: {:.1} msgs/sec (at mean latency)", ops_sec(ps.mean));
        println!("    Users:      {}", logged_in.len());
        println!("    Pairs:      {}", num_pairs);
    }

    // Cleanup: logout all
    for (_, tok, _) in &logged_in {
        let _ = http.post(format!("{}/_matrix/client/v3/logout", conduit_url))
            .bearer_auth(tok).json(&serde_json::json!({})).send();
    }

    serde_json::json!({
        "aggregate": {
            "x3dh_dr": { "summary": cr_all.summary(), "count": cr_all.samples.len() },
            "pqxdh_spqr": { "summary": pr_all.summary(), "count": pr_all.samples.len() },
        },
        "pairs": pair_results,
        "config": {
            "num_users": logged_in.len(),
            "num_pairs": num_pairs,
            "iterations_per_pair": iterations,
        },
    })
}

fn ops_sec(mean_ns: f64) -> f64 {
    if mean_ns > 0.0 { 1_000_000_000.0 / mean_ns } else { 0.0 }
}

/// Benchmark X3DH+DR E2E for one user pair.
///
/// Encrypt → HTTP PUT to Conduit → /sync poll → receive → decrypt
fn bench_pair_classical(
    http: &reqwest::blocking::Client, conduit_url: &str,
    sender_tok: &str, receiver_tok: &str, receiver_uid: &str,
    iterations: usize, warmup: usize,
) -> Vec<f64> {
    let sender_acct = Account::new();
    let mut receiver_acct = Account::new();
    receiver_acct.generate_one_time_keys(1);
    let otk = *receiver_acct.one_time_keys().values().next().expect("No OTK");
    receiver_acct.mark_keys_as_published();

    let mut sender_session = sender_acct.create_outbound_session(
        SessionConfig::version_2(),
        receiver_acct.curve25519_key(),
        otk,
    );

    // Establish receiver session
    let first_msg = sender_session.encrypt("e2e_init");
    let mut receiver_session = if let OlmMessage::PreKey(ref pkm) = first_msg {
        receiver_acct.create_inbound_session(sender_acct.curve25519_key(), pkm)
            .expect("Inbound session failed").session
    } else {
        panic!("Expected PreKeyMessage");
    };

    // Create room
    let room_id = match create_bench_room(http, conduit_url, sender_tok, receiver_uid) {
        Ok(r) => r,
        Err(e) => { println!("    [error] {}", e); return vec![]; }
    };
    let _ = http.post(format!("{}/_matrix/client/v3/join/{}", conduit_url, room_id))
        .bearer_auth(receiver_tok).json(&serde_json::json!({})).send();
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Initial sync
    let init_sync: serde_json::Value = http
        .get(format!("{}/_matrix/client/v3/sync?timeout=1000", conduit_url))
        .bearer_auth(receiver_tok).send().unwrap().json().unwrap_or_default();
    let mut since = init_sync["next_batch"].as_str().map(|s| s.to_string());

    let sender_key_b64 = sender_acct.curve25519_key().to_base64();
    let mut samples = Vec::with_capacity(iterations);

    for i in 0..(warmup + iterations) {
        let plaintext = format!("bench_c_{}", i);
        let t0 = Instant::now();

        // Encrypt
        let olm_msg = black_box(sender_session.encrypt(&plaintext));
        let (msg_type, ct_bytes) = match &olm_msg {
            OlmMessage::PreKey(m) => (0u8, m.to_bytes()),
            OlmMessage::Normal(m) => (1u8, m.to_bytes()),
        };

        // Send via Conduit
        let txn = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let _ = http.put(format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.encrypted/{}",
            conduit_url, room_id, txn
        ))
        .bearer_auth(sender_tok)
        .json(&serde_json::json!({
            "algorithm": "m.olm.v1.curve25519-aes-sha2",
            "sender_key": sender_key_b64,
            "ciphertext": B64.encode(&ct_bytes),
            "type": msg_type,
        }))
        .send();

        // Receive via /sync and decrypt
        let mut received = false;
        for _ in 0..5 {
            let mut url = format!("{}/_matrix/client/v3/sync?timeout=2000", conduit_url);
            if let Some(ref s) = since {
                url.push_str(&format!("&since={}", s));
            }
            let r: serde_json::Value = match http.get(&url).bearer_auth(receiver_tok).send() {
                Ok(resp) => resp.json().unwrap_or_default(),
                Err(_) => continue,
            };
            since = r["next_batch"].as_str().map(|s| s.to_string());
            if let Some(rooms) = r["rooms"]["join"].as_object() {
                if let Some(rd) = rooms.get(&room_id) {
                    if let Some(evts) = rd["timeline"]["events"].as_array() {
                        for evt in evts {
                            if let Some(ct_b64) = evt["content"]["ciphertext"].as_str() {
                                if let Ok(ct_raw) = B64.decode(ct_b64) {
                                    let msg_t = evt["content"]["type"].as_u64().unwrap_or(1) as u8;
                                    let recv_msg = if msg_t == 0 {
                                        OlmMessage::from_parts(0, &ct_raw).ok()
                                    } else {
                                        OlmMessage::from_parts(1, &ct_raw).ok()
                                    };
                                    if let Some(msg) = recv_msg {
                                        let _ = black_box(receiver_session.decrypt(&msg));
                                    }
                                }
                                received = true;
                            }
                        }
                        if received { break; }
                    }
                }
            }
        }

        let elapsed = t0.elapsed();
        if i >= warmup && received {
            samples.push(elapsed.as_nanos() as f64);
        }
    }

    samples
}

/// Benchmark PQXDH+SPQR E2E for one user pair.
///
/// encrypt_pq → HTTP PUT with SPQR metadata → /sync poll → receive → decrypt_pq
fn bench_pair_pqxdh(
    http: &reqwest::blocking::Client, conduit_url: &str,
    sender_tok: &str, receiver_tok: &str, receiver_uid: &str,
    iterations: usize, warmup: usize,
) -> Vec<f64> {
    let sender_acct = Account::new();
    let mut receiver_acct = Account::new();
    let (rcv_spk, _sig) = receiver_acct.generate_signed_prekey();
    receiver_acct.generate_one_time_keys(1);
    let otk = *receiver_acct.one_time_keys().values().next().expect("No OTK");
    receiver_acct.mark_keys_as_published();

    let kem = Kem::new(Algorithm::MlKem768).expect("ML-KEM-768 unavailable");
    let (kem_pk, kem_sk) = kem.keypair().expect("KEM keygen failed");

    let (mut sender_session, kem_ct) = sender_acct.create_outbound_session_pqxdh(
        SessionConfig::version_2(),
        receiver_acct.curve25519_key(),
        rcv_spk,
        Some(otk),
        kem_pk.as_ref(),
    );

    let first_msg = sender_session.encrypt("e2e_pq_init");
    let mut receiver_session = if let OlmMessage::PreKey(ref pkm) = first_msg {
        receiver_acct.create_inbound_session_pqxdh(
            sender_acct.curve25519_key(), pkm, &kem_ct, kem_sk.as_ref(),
        ).expect("PQXDH inbound failed").session
    } else {
        panic!("Expected PreKeyMessage");
    };

    let room_id = match create_bench_room(http, conduit_url, sender_tok, receiver_uid) {
        Ok(r) => r,
        Err(e) => { println!("    [error] {}", e); return vec![]; }
    };
    let _ = http.post(format!("{}/_matrix/client/v3/join/{}", conduit_url, room_id))
        .bearer_auth(receiver_tok).json(&serde_json::json!({})).send();
    std::thread::sleep(std::time::Duration::from_millis(300));

    let init_sync: serde_json::Value = http
        .get(format!("{}/_matrix/client/v3/sync?timeout=1000", conduit_url))
        .bearer_auth(receiver_tok).send().unwrap().json().unwrap_or_default();
    let mut since = init_sync["next_batch"].as_str().map(|s| s.to_string());

    let sender_key_b64 = sender_acct.curve25519_key().to_base64();
    let mut samples = Vec::with_capacity(iterations);

    for i in 0..(warmup + iterations) {
        let plaintext = format!("bench_p_{}", i);
        let t0 = Instant::now();

        // Encrypt via SPQR Triple Ratchet
        let wire = black_box(sender_session.encrypt_pq(&plaintext));
        let (msg_type, ct_bytes) = match &wire.message {
            OlmMessage::PreKey(m) => (0u8, m.to_bytes()),
            OlmMessage::Normal(m) => (1u8, m.to_bytes()),
        };

        let mut payload = serde_json::json!({
            "algorithm": "m.olm.pqxdh.v1",
            "sender_key": sender_key_b64,
            "ciphertext": B64.encode(&ct_bytes),
            "type": msg_type,
        });
        // Include SPQR metadata
        if let Some(ref meta) = wire.spqr_meta {
            payload["spqr_epoch"] = serde_json::json!(meta.epoch);
            payload["spqr_index"] = serde_json::json!(meta.index);
        }
        // Include Braid messages
        if !wire.braid_msgs.is_empty() {
            payload["braid_msgs"] = serde_json::json!(wire.braid_msgs);
        }

        let txn = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let _ = http.put(format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.encrypted/{}",
            conduit_url, room_id, txn
        ))
        .bearer_auth(sender_tok)
        .json(&payload)
        .send();

        // Receive via /sync and decrypt_pq
        let mut received = false;
        for _ in 0..5 {
            let mut url = format!("{}/_matrix/client/v3/sync?timeout=2000", conduit_url);
            if let Some(ref s) = since {
                url.push_str(&format!("&since={}", s));
            }
            let r: serde_json::Value = match http.get(&url).bearer_auth(receiver_tok).send() {
                Ok(resp) => resp.json().unwrap_or_default(),
                Err(_) => continue,
            };
            since = r["next_batch"].as_str().map(|s| s.to_string());
            if let Some(rooms) = r["rooms"]["join"].as_object() {
                if let Some(rd) = rooms.get(&room_id) {
                    if let Some(evts) = rd["timeline"]["events"].as_array() {
                        for evt in evts {
                            if let Some(ct_b64) = evt["content"]["ciphertext"].as_str() {
                                if let Ok(ct_raw) = B64.decode(ct_b64) {
                                    let msg_t = evt["content"]["type"].as_u64().unwrap_or(1) as u8;
                                    let recv_msg = if msg_t == 0 {
                                        OlmMessage::from_parts(0, &ct_raw).ok()
                                    } else {
                                        OlmMessage::from_parts(1, &ct_raw).ok()
                                    };
                                    if let Some(msg) = recv_msg {
                                        // Reconstruct SPQR metadata from event
                                        let spqr_meta = if evt["content"]["spqr_epoch"].is_u64() {
                                            Some(vodozemac::olm::SpqrMessageMeta {
                                                epoch: evt["content"]["spqr_epoch"].as_u64().unwrap_or(0),
                                                index: evt["content"]["spqr_index"].as_u64().unwrap_or(0) as u32,
                                            })
                                        } else {
                                            None
                                        };
                                        // Reconstruct braid messages from event
                                        let braid_msgs: Vec<vodozemac::olm::BraidMessage> =
                                            serde_json::from_value(
                                                evt["content"]["braid_msgs"].clone()
                                            ).unwrap_or_default();

                                        let _ = black_box(
                                            receiver_session.decrypt_pq(
                                                &msg,
                                                spqr_meta.as_ref(),
                                                &braid_msgs,
                                            )
                                        );
                                    }
                                }
                                received = true;
                            }
                        }
                        if received { break; }
                    }
                }
            }
        }

        let elapsed = t0.elapsed();
        if i >= warmup && received {
            samples.push(elapsed.as_nanos() as f64);
        }
    }

    samples
}

fn matrix_login(
    http: &reqwest::blocking::Client, url: &str,
    user: &str, pass: &str, device_id: &str,
) -> Result<(String, String), String> {
    let r: serde_json::Value = http
        .post(format!("{}/_matrix/client/v3/login", url))
        .json(&serde_json::json!({
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": user},
            "password": pass,
            "device_id": device_id
        }))
        .send().map_err(|e| format!("Connection failed: {e}"))?
        .json().map_err(|e| format!("Bad response: {e}"))?;

    if let Some(err) = r.get("errcode") {
        return Err(format!("Login failed: {}", err));
    }

    Ok((
        r["access_token"].as_str().unwrap_or("").into(),
        r["user_id"].as_str().unwrap_or("").into(),
    ))
}

fn create_bench_room(
    http: &reqwest::blocking::Client, url: &str,
    tok: &str, invite: &str,
) -> Result<String, String> {
    let r: serde_json::Value = http
        .post(format!("{}/_matrix/client/v3/createRoom", url))
        .bearer_auth(tok)
        .json(&serde_json::json!({
            "preset": "private_chat",
            "invite": [invite],
            "name": "pq-olm-bench",
        }))
        .send().map_err(|e| format!("Room creation failed: {e}"))?
        .json().map_err(|e| format!("Bad response: {e}"))?;

    r["room_id"].as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No room_id in response".to_string())
}
