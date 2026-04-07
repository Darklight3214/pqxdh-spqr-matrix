use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::json;
use vodozemac::olm::{Account, AccountPickle, SessionConfig, OlmMessage, Session, SessionPickle, SpqrMessageMeta, BraidMessage};
use oqs::kem::{Kem, Algorithm};
use base64::{Engine, engine::general_purpose::STANDARD as B64};

const CONDUIT: &str = "http://172.16.200.86:6167";
const SPK_ROTATION_DAYS: u64 = 7;

fn derive_pickle_key(password: &str, username: &str) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(username.as_bytes()), password.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(b"pqxdh-node-pickle-key", &mut key).expect("HKDF expand failed");
    key
}

fn prompt(label: &str) -> String {
    print!("{}", label);
    io::stdout().flush().unwrap();
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s.trim().to_string()
}

fn txn_id() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn matrix_login(http: &reqwest::blocking::Client, user: &str, pass: &str, device_id: &str)
    -> Result<(String, String, String), String>
{
    let r: serde_json::Value = http
        .post(format!("{CONDUIT}/_matrix/client/v3/login"))
        .json(&json!({
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
        r["access_token"].as_str().unwrap().into(),
        r["user_id"].as_str().unwrap().into(),
        r["device_id"].as_str().unwrap().into(),
    ))
}

fn matrix_logout(http: &reqwest::blocking::Client, tok: &str) {
    let _ = http
        .post(format!("{CONDUIT}/_matrix/client/v3/logout"))
        .bearer_auth(tok)
        .json(&json!({}))
        .send();
    println!("[logout] Session ended");
}

fn delete_one_device(
    http: &reqwest::blocking::Client, tok: &str, did: &str,
    user: &str, pass: &str,
) -> bool {
    let resp = http
        .delete(format!("{CONDUIT}/_matrix/client/v3/devices/{did}"))
        .bearer_auth(tok)
        .json(&json!({}))
        .send();

    let r: serde_json::Value = match resp {
        Ok(r) => {
            let status = r.status();
            let body: serde_json::Value = r.json().unwrap_or_default();
            if status.is_success() { return true; }
            body
        }
        Err(_) => { return false; }
    };

    let session = match r["session"].as_str() {
        Some(s) => s,
        None => { return false; }
    };

    let resp2 = http
        .delete(format!("{CONDUIT}/_matrix/client/v3/devices/{did}"))
        .bearer_auth(tok)
        .json(&json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": user},
                "password": pass,
                "session": session
            }
        }))
        .send();

    matches!(resp2, Ok(r) if r.status().is_success())
}

fn cleanup_old_devices(
    http: &reqwest::blocking::Client, tok: &str, keep_did: &str,
    user: &str, pass: &str,
) {
    let resp: serde_json::Value = match http
        .get(format!("{CONDUIT}/_matrix/client/v3/devices"))
        .bearer_auth(tok)
        .send()
    {
        Ok(r) => r.json().unwrap_or_default(),
        Err(_) => { return; }
    };

    let devices = match resp["devices"].as_array() {
        Some(d) => d,
        None => { return; }
    };

    let mut deleted = 0;
    for dev in devices {
        let did = dev["device_id"].as_str().unwrap_or("");
        if did == keep_did { continue; }
        if did.starts_with("PQXDH_") {
            if delete_one_device(http, tok, did, user, pass) {
                println!("[cleanup] Deleted old device: {}", did);
                deleted += 1;
            }
        }
    }
    if deleted > 0 {
        println!("[cleanup] Removed {} stale device(s)", deleted);
    }
}

fn sync(http: &reqwest::blocking::Client, tok: &str, since: Option<&str>, timeout: u64)
    -> serde_json::Value
{
    let mut url = format!("{CONDUIT}/_matrix/client/v3/sync?timeout={timeout}");
    if let Some(s) = since {
        url.push_str(&format!("&since={}", s));
    }
    match http.get(&url).bearer_auth(tok).send() {
        Ok(resp) => resp.json().unwrap_or_default(),
        Err(_) => {
            std::thread::sleep(std::time::Duration::from_secs(2));
            json!({})
        }
    }
}

fn verify_own_keys(
    http: &reqwest::blocking::Client, tok: &str,
    uid: &str, did: &str, account: &Account,
) {
    let r: serde_json::Value = match http
        .post(format!("{CONDUIT}/_matrix/client/v3/keys/query"))
        .bearer_auth(tok)
        .json(&json!({ "device_keys": { uid: [] } }))
        .send()
    {
        Ok(resp) => resp.json().unwrap_or(json!({"device_keys": {}})),
        Err(_) => json!({"device_keys": {}}),
    };

    let server_ik = r["device_keys"][uid][did]["keys"][format!("curve25519:{did}")]
        .as_str().unwrap_or("NOT_FOUND");
    let local_ik = account.curve25519_key().to_base64();

    if server_ik == "NOT_FOUND" {
        println!("[verify] Device {} not found on server", did);
    } else if server_ik == local_ik {
        println!("[verify] Keys MATCH on server for {}", did);
    } else {
        println!("[verify] KEY MISMATCH for {}!", did);
        println!("[verify]   Server: {}", server_ik);
        println!("[verify]   Local:  {}", local_ik);
    }
}

fn upload_keys_fresh(
    http: &reqwest::blocking::Client, tok: &str,
    uid: &str, did: &str,
    account: &mut Account,
    kem_pk: &[u8],
) {
    let (spk_public, spk_signature) = account.generate_signed_prekey();
    account.generate_one_time_keys(10);
    let otks = account.one_time_keys();

    let mut otk_json = serde_json::Map::new();
    for (kid, key) in otks.iter() {
        otk_json.insert(
            format!("curve25519:{}", kid.to_base64()),
            json!(key.to_base64()),
        );
    }

    let device_keys_to_sign = json!({
        "user_id": uid,
        "device_id": did,
        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.olm.pqxdh.v1"],
        "keys": {
            format!("curve25519:{did}"): account.curve25519_key().to_base64(),
            format!("ed25519:{did}"): account.ed25519_key().to_base64(),
            format!("kem:{did}"): B64.encode(kem_pk),
            format!("spk:{did}"): spk_public.to_base64(),
            format!("spk_sig:{did}"): spk_signature.to_base64()
        }
    });

    let canonical = serde_json::to_string(&device_keys_to_sign).unwrap();
    let signature = account.sign(&canonical);

    let device_keys = json!({
        "user_id": uid,
        "device_id": did,
        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.olm.pqxdh.v1"],
        "keys": {
            format!("curve25519:{did}"): account.curve25519_key().to_base64(),
            format!("ed25519:{did}"): account.ed25519_key().to_base64(),
            format!("kem:{did}"): B64.encode(kem_pk),
            format!("spk:{did}"): spk_public.to_base64(),
            format!("spk_sig:{did}"): spk_signature.to_base64()
        },
        "signatures": {
            uid: {
                format!("ed25519:{did}"): signature.to_base64()
            }
        }
    });

    let resp: serde_json::Value = http
        .post(format!("{CONDUIT}/_matrix/client/v3/keys/upload"))
        .bearer_auth(tok)
        .json(&json!({
            "device_keys": device_keys,
            "one_time_keys": otk_json
        }))
        .send().expect("Key upload failed")
        .json().expect("Bad response");

    account.mark_keys_as_published();
    let count = resp["one_time_key_counts"]["curve25519"].as_u64().unwrap_or(0);
    println!("[keys] Uploaded. OTKs on server: {}", count);
    println!("[keys] Signed Prekey: {}", spk_public.to_base64());
}

fn upload_otks_only(
    http: &reqwest::blocking::Client, tok: &str,
    account: &mut Account,
) {
    let count_resp: serde_json::Value = http
        .post(format!("{CONDUIT}/_matrix/client/v3/keys/upload"))
        .bearer_auth(tok)
        .json(&json!({}))
        .send().unwrap_or_else(|_| panic!("OTK count check failed"))
        .json().unwrap_or_default();

    let server_count = count_resp["one_time_key_counts"]["curve25519"].as_u64().unwrap_or(0);
    println!("[keys] OTKs on server: {}", server_count);

    if server_count < 5 {
        let to_generate = 10 - server_count as usize;
        account.generate_one_time_keys(to_generate);
        let otks = account.one_time_keys();

        let mut otk_json = serde_json::Map::new();
        for (kid, key) in otks.iter() {
            otk_json.insert(
                format!("curve25519:{}", kid.to_base64()),
                json!(key.to_base64()),
            );
        }

        let resp: serde_json::Value = http
            .post(format!("{CONDUIT}/_matrix/client/v3/keys/upload"))
            .bearer_auth(tok)
            .json(&json!({ "one_time_keys": otk_json }))
            .send().expect("OTK upload failed")
            .json().expect("Bad response");

        account.mark_keys_as_published();
        let new_count = resp["one_time_key_counts"]["curve25519"].as_u64().unwrap_or(0);
        println!("[keys] Topped up OTKs: {}", new_count);
    } else {
        println!("[keys] OTKs sufficient");
    }
}

fn query_keys(http: &reqwest::blocking::Client, tok: &str, peer: &str)
    -> Result<(String, String, String, String, String), String>
{
    let r: serde_json::Value = http
        .post(format!("{CONDUIT}/_matrix/client/v3/keys/query"))
        .bearer_auth(tok)
        .json(&json!({ "device_keys": { peer: [] } }))
        .send().map_err(|e| format!("Query failed: {e}"))?
        .json().map_err(|e| format!("Bad response: {e}"))?;

    let devices = r["device_keys"][peer].as_object()
        .ok_or("No peer devices found".to_string())?;

    let (dev_id, info) = devices.iter()
        .filter(|(did, dinfo)| {
            dinfo["keys"][format!("kem:{did}")].as_str().is_some()
            && dinfo["keys"][format!("spk:{did}")].as_str().is_some()
        })
        .max_by_key(|(did, _)| did.to_string())
        .ok_or("No PQXDH-capable device found for peer".to_string())?;

    let ik = info["keys"][format!("curve25519:{dev_id}")]
        .as_str().ok_or("No identity key")?.to_string();
    let ed_key = info["keys"][format!("ed25519:{dev_id}")]
        .as_str().ok_or("No ed25519 key")?.to_string();
    let kem = info["keys"][format!("kem:{dev_id}")]
        .as_str().ok_or("No KEM key")?.to_string();
    let spk = info["keys"][format!("spk:{dev_id}")]
        .as_str().ok_or("No signed prekey")?.to_string();
    let spk_sig = info["keys"][format!("spk_sig:{dev_id}")]
        .as_str().ok_or("No signed prekey signature")?.to_string();

    let ed_pk = vodozemac::Ed25519PublicKey::from_base64(&ed_key)
        .map_err(|_| "Invalid ed25519 key")?;
    let spk_bytes = vodozemac::Curve25519PublicKey::from_base64(&spk)
        .map_err(|_| "Invalid SPK")?;
    let sig = vodozemac::Ed25519Signature::from_base64(&spk_sig)
        .map_err(|_| "Invalid SPK signature")?;

    ed_pk.verify(spk_bytes.as_bytes(), &sig)
        .map_err(|_| "SPK signature verification FAILED")?;

    println!("[keys] SPK signature verified for device {}", dev_id);

    Ok((dev_id.clone(), ik, kem, spk, spk_sig))
}

fn claim_otk(http: &reqwest::blocking::Client, tok: &str, peer: &str, dev: &str)
    -> Result<String, String>
{
    let r: serde_json::Value = http
        .post(format!("{CONDUIT}/_matrix/client/v3/keys/claim"))
        .bearer_auth(tok)
        .json(&json!({ "one_time_keys": { peer: { dev: "curve25519" } } }))
        .send().map_err(|e| format!("Claim failed: {e}"))?
        .json().map_err(|e| format!("Bad response: {e}"))?;

    let keys = r["one_time_keys"][peer][dev].as_object()
        .ok_or("No OTK returned".to_string())?;
    let (_, val) = keys.iter().next().ok_or("Empty OTK".to_string())?;
    Ok(val.as_str().ok_or("OTK not string")?.to_string())
}

fn create_room(http: &reqwest::blocking::Client, tok: &str, invite: &str) -> String {
    let r: serde_json::Value = http
        .post(format!("{CONDUIT}/_matrix/client/v3/createRoom"))
        .bearer_auth(tok)
        .json(&json!({
            "preset": "private_chat",
            "invite": [invite],
            "initial_state": [{
                "type": "m.room.encryption",
                "content": {"algorithm": "m.olm.pqxdh.v1"}
            }]
        }))
        .send().unwrap().json().unwrap();
    r["room_id"].as_str().unwrap().to_string()
}

fn send_encrypted(
    http: &reqwest::blocking::Client, tok: &str, room: &str,
    session: &mut Session, plaintext: &str, sender_key: &str,
    kem_ct: Option<&[u8]>,
    pending_braid: &mut Vec<BraidMessage>,
) {
    // Inject any pending Braid response messages into the session before encrypting
    // (they'll be piggybacked on this outgoing message)
    let wire = session.encrypt_pq(plaintext);

    let (msg_type, ct_bytes) = match &wire.message {
        OlmMessage::PreKey(m) => (0u8, m.to_bytes()),
        OlmMessage::Normal(m) => (1u8, m.to_bytes()),
    };

    let mut payload = json!({
        "algorithm": "m.olm.pqxdh.v1",
        "sender_key": sender_key,
        "ciphertext": B64.encode(&ct_bytes),
        "type": msg_type
    });

    if let Some(ct) = kem_ct {
        payload["kem_ciphertext"] = json!(B64.encode(ct));
    }

    // Add SPQR metadata (epoch/index for combined key decryption)
    if let Some(ref meta) = wire.spqr_meta {
        payload["spqr_meta"] = serde_json::to_value(meta).unwrap_or_default();
    }

    // Add Braid protocol messages (from encrypt_pq auto-advance + pending responses)
    let mut all_braid = wire.braid_msgs;
    all_braid.append(pending_braid);
    if !all_braid.is_empty() {
        payload["braid_msgs"] = serde_json::to_value(&all_braid).unwrap_or_default();
    }

    if session.has_spqr() {
        payload["spqr"] = json!(true);
    }

    if let Err(e) = http.put(format!(
        "{CONDUIT}/_matrix/client/v3/rooms/{room}/send/m.room.encrypted/{}",
        txn_id()
    ))
    .bearer_auth(tok)
    .json(&payload)
    .send() {
        println!("[error] Send failed: {}", e);
    }
}

fn initiate_session(
    http: &reqwest::blocking::Client, tok: &str,
    account: &mut Account, peer: &str, first_message: &str,
    ik_b64: &str, _msg_counter: &AtomicU64,
) -> (Session, String) {
    println!("[pqxdh] Initiating session with {}...", peer);

    let (peer_did, peer_ik_b64, peer_kem_b64, peer_spk_b64, _peer_spk_sig) = match query_keys(http, tok, peer) {
        Ok(v) => v,
        Err(e) => {
            println!("[error] {}", e);
            std::process::exit(1);
        }
    };

    let peer_ik = vodozemac::Curve25519PublicKey::from_base64(&peer_ik_b64)
        .expect("Bad peer identity key");
    let peer_spk = vodozemac::Curve25519PublicKey::from_base64(&peer_spk_b64)
        .expect("Bad peer signed prekey");
    let peer_kem_pk = B64.decode(&peer_kem_b64).expect("Bad peer KEM key");

    println!("[keys] Peer device: {}", peer_did);
    println!("[keys] Peer identity: {}", peer_ik_b64);
    println!("[keys] Peer SPK: {}", peer_spk_b64);
    println!("[keys] Peer KEM: {} bytes", peer_kem_pk.len());

    let otk_b64 = match claim_otk(http, tok, peer, &peer_did) {
        Ok(v) => v,
        Err(e) => {
            println!("[error] Failed to claim OTK: {}", e);
            std::process::exit(1);
        }
    };
    let peer_otk = vodozemac::Curve25519PublicKey::from_base64(&otk_b64)
        .expect("Bad peer OTK");
    println!("[keys] Claimed OTK: {}", otk_b64);

    let (mut session, kem_ct) = account.create_outbound_session_pqxdh(
        SessionConfig::version_2(),
        peer_ik,
        peer_spk,
        Some(peer_otk),
        &peer_kem_pk,
    );

    println!("[pqxdh] Session created");
    println!("[pqxdh] KEM ciphertext: {} bytes", kem_ct.len());
    println!("[pqxdh] Protocol: 4x X25519 + ML-KEM-768 + SPQR");

    let room_id = create_room(http, tok, peer);
    println!("[room] Created: {}", room_id);

    send_encrypted(http, tok, &room_id, &mut session, first_message, ik_b64, Some(&kem_ct), &mut Vec::new());
    println!("[sent] \"{}\"", first_message);

    (session, room_id)
}

fn try_decrypt_events(
    events: &[serde_json::Value],
    uid: &str,
    account: &mut Account,
    kem_sk: &[u8],
    scanned: &mut HashSet<String>,
) -> Option<(Session, String, Vec<BraidMessage>)> {
    for evt in events {
        let event_id = evt["event_id"].as_str().unwrap_or("");
        if !event_id.is_empty() {
            if scanned.contains(event_id) { continue; }
            scanned.insert(event_id.to_string());
        }

        let sender = evt["sender"].as_str().unwrap_or("");
        if sender == uid { continue; }
        if evt["type"].as_str() != Some("m.room.encrypted") { continue; }

        let content = &evt["content"];
        if content["type"].as_u64().unwrap_or(99) != 0 { continue; }

        let ct_b64 = content["ciphertext"].as_str().unwrap_or("");
        let kem_ct_b64 = content["kem_ciphertext"].as_str().unwrap_or("");
        if ct_b64.is_empty() || kem_ct_b64.is_empty() { continue; }

        println!("[pqxdh] Received PreKey from {}", sender);

        let ct = match B64.decode(ct_b64) {
            Ok(v) => v,
            Err(_) => { println!("[error] Bad ciphertext base64"); continue; }
        };
        let kem_ct = match B64.decode(kem_ct_b64) {
            Ok(v) => v,
            Err(_) => { println!("[error] Bad KEM ciphertext base64"); continue; }
        };

        let olm = match OlmMessage::from_parts(0, &ct) {
            Ok(m) => m,
            Err(e) => { println!("[error] Bad PreKey format: {}", e); continue; }
        };

        if let OlmMessage::PreKey(ref pkm) = olm {
            match account.create_inbound_session_pqxdh(
                pkm.identity_key(), pkm, &kem_ct, kem_sk,
            ) {
                Ok(result) => {
                    let pt = String::from_utf8_lossy(&result.plaintext);
                    println!("[pqxdh] Session established");
                    println!("[pqxdh] Decrypted: \"{}\"", pt);
                    println!("[pqxdh] Protocol: 4x X25519 + ML-KEM-768 + SPQR");

                    // Process Braid messages piggybacked on the PreKey event
                    // to bootstrap the SPQR epoch exchange
                    let braid_msgs: Vec<BraidMessage> = content.get("braid_msgs")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();
                    let mut session = result.session;
                    let response_braid = session.process_braid_messages(&braid_msgs);
                    if !braid_msgs.is_empty() {
                        println!("[spqr] Processed {} Braid message(s) from PreKey, {} response(s)",
                            braid_msgs.len(), response_braid.len());
                    }

                    return Some((session, sender.to_string(), response_braid));
                }
                Err(e) => {
                    println!("[error] PQXDH session failed: {:?}", e);
                    continue;
                }
            }
        }
    }
    None
}

fn try_decrypt_sync(
    r: &serde_json::Value,
    uid: &str,
    account: &mut Account,
    kem_sk: &[u8],
    scanned: &mut HashSet<String>,
) -> Option<(Session, String, String, Vec<BraidMessage>)> {
    let rooms = r["rooms"]["join"].as_object()?;
    for (rid, rd) in rooms {
        if let Some(evts) = rd["timeline"]["events"].as_array() {
            if let Some((session, sender, braid_resp)) = try_decrypt_events(evts, uid, account, kem_sk, scanned) {
                return Some((session, rid.clone(), sender, braid_resp));
            }
        }
    }
    None
}

fn wait_for_session(
    http: &reqwest::blocking::Client, tok: &str, uid: &str,
    account: &mut Account, kem_sk: &[u8],
) -> (Session, String, String, Vec<BraidMessage>) {
    println!("[wait] Listening for incoming PQXDH session...");

    let r = sync(http, tok, None, 1000);
    let mut since = r["next_batch"].as_str().map(|s| s.to_string());

    let mut joined_rooms: HashSet<String> = HashSet::new();
    let mut scanned_messages: HashSet<String> = HashSet::new();

    loop {
        let r = sync(http, tok, since.as_deref(), 10000);
        since = r["next_batch"].as_str().map(|s| s.to_string());

        let mut newly_joined: Vec<String> = Vec::new();

        if let Some(inv) = r["rooms"]["invite"].as_object() {
            for (rid, _) in inv {
                if joined_rooms.contains(rid) { continue; }
                let join_result = http.post(format!("{CONDUIT}/_matrix/client/v3/join/{rid}"))
                    .json(&json!({}))
                    .bearer_auth(tok)
                    .send();
                if join_result.is_ok() {
                    println!("[room] Joined {}", rid);
                    joined_rooms.insert(rid.clone());
                    newly_joined.push(rid.clone());
                }
            }
        }

        if let Some(result) = try_decrypt_sync(&r, uid, account, kem_sk, &mut scanned_messages) {
            return result;
        }

        if !newly_joined.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(500));

            let r2 = sync(http, tok, since.as_deref(), 5000);
            since = r2["next_batch"].as_str().map(|s| s.to_string());

            if let Some(result) = try_decrypt_sync(&r2, uid, account, kem_sk, &mut scanned_messages) {
                return result;
            }

            for rid in &newly_joined {
                println!("[wait] Backfilling {} via /messages", rid);
                let url = format!(
                    "{CONDUIT}/_matrix/client/v3/rooms/{}/messages?dir=b&limit=20",
                    rid
                );
                let msgs: serde_json::Value = match http.get(&url).bearer_auth(tok).send() {
                    Ok(resp) => resp.json().unwrap_or_default(),
                    Err(_) => continue,
                };
                if let Some(evts) = msgs["chunk"].as_array() {
                    if let Some((session, sender, braid_resp)) = try_decrypt_events(evts, uid, account, kem_sk, &mut scanned_messages) {
                        return (session, rid.clone(), sender, braid_resp);
                    }
                }
            }
        }
    }
}

// ========== HISTORY ==========

fn append_history(username: &str, sender: &str, text: &str) {
    let path = format!(".pqxdh-{}.history", username);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{}|{}", sender, text);
    }
}

fn show_history(username: &str) {
    let path = format!(".pqxdh-{}.history", username);
    if let Ok(raw) = fs::read_to_string(&path) {
        let lines: Vec<&str> = raw.lines().collect();
        let start = lines.len().saturating_sub(50);
        if start < lines.len() && !lines.is_empty() {
            println!("\n--- Chat History (last {}) ---", lines.len() - start);
            for line in &lines[start..] {
                if let Some((from, text)) = line.split_once('|') {
                    println!("  {}: {}", from, text);
                }
            }
            println!("--- End History ---\n");
        }
    }
}

fn clear_history(username: &str) {
    let path = format!(".pqxdh-{}.history", username);
    if Path::new(&path).exists() {
        let _ = fs::remove_file(&path);
        println!("[history] Cleared");
    }
}

// ========== SESSION PERSISTENCE ==========

fn save_session_data(username: &str, session: &Session, room_id: &str, peer_uid: &str, msg_count: u64, pickle_key: &[u8; 32]) {
    let pickle = session.pickle().encrypt(pickle_key);
    let data = json!({
        "session_pickle": pickle,
        "room_id": room_id,
        "peer_uid": peer_uid,
        "msg_count": msg_count,
    });
    let path = format!(".pqxdh-{}.session", username);
    fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
    println!("[session] Saved to {}", path);
}

fn load_session_data(username: &str, pickle_key: &[u8; 32]) -> Option<(Session, String, String, u64)> {
    let path = format!(".pqxdh-{}.session", username);
    if !Path::new(&path).exists() { return None; }
    let raw = fs::read_to_string(&path).ok()?;
    let data: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let pickle_str = data["session_pickle"].as_str()?;
    let pickle = SessionPickle::from_encrypted(pickle_str, pickle_key).ok()?;
    let session = Session::from_pickle(pickle);
    let room_id = data["room_id"].as_str()?.to_string();
    let peer_uid = data["peer_uid"].as_str()?.to_string();
    let msg_count = data["msg_count"].as_u64().unwrap_or(0);
    println!("[session] Restored: room {} with {} ({} msgs sent)", room_id, peer_uid, msg_count);
    Some((session, room_id, peer_uid, msg_count))
}

fn delete_session_data(username: &str) {
    let path = format!(".pqxdh-{}.session", username);
    if Path::new(&path).exists() {
        let _ = fs::remove_file(&path);
        println!("[session] Cleared old session");
    }
}

// ========== CHAT LOOP ==========

fn chat_loop(
    http: &reqwest::blocking::Client, tok: &str, uid: &str,
    session: Arc<Mutex<Session>>, room_id: &str, sender_key: &str,
    _kem_sk: Arc<Vec<u8>>, username: &str, peer_uid: &str,
    msg_counter: Arc<AtomicU64>, pickle_key: [u8; 32],
    initial_braid: Arc<Mutex<Vec<BraidMessage>>>,
) -> bool {
    let has_spqr = session.lock().unwrap().has_spqr();

    println!("\n========================================");
    println!("  PQXDH Encrypted Chat");
    if has_spqr {
        println!("  SPQR post-quantum protection: ACTIVE");
    }
    println!("  Room: {}", room_id);
    println!("  Peer: {}", peer_uid);
    println!("  /logout - switch account (session saved)");
    println!("  /exit   - quit program (session saved)");
    println!("  /new    - forget session, start fresh");
    println!("  /clear  - clear chat history");
    println!("========================================\n");

    show_history(username);

    let initial = sync(http, tok, None, 500);

    let mut scanned_messages: HashSet<String> = HashSet::new();

    let pending_braid: Arc<Mutex<Vec<BraidMessage>>> = Arc::new(Mutex::new({
        // Seed with any Braid responses from the initial PreKey processing
        let mut initial = initial_braid.lock().unwrap().drain(..).collect::<Vec<_>>();
        initial
    }));

    // Backfill missed messages
    {
        let mut sess = session.lock().unwrap();
        let mut missed_count = 0;
        if let Some(rooms) = initial["rooms"]["join"].as_object() {
            if let Some(rd) = rooms.get(room_id) {
                if let Some(evts) = rd["timeline"]["events"].as_array() {
                    for evt in evts {
                        let event_id = evt["event_id"].as_str().unwrap_or("");
                        if !event_id.is_empty() {
                            if scanned_messages.contains(event_id) { continue; }
                            scanned_messages.insert(event_id.to_string());
                        }
                        
                        let sender = evt["sender"].as_str().unwrap_or("");
                        if sender == uid { continue; }
                        if evt["type"].as_str() != Some("m.room.encrypted") { continue; }

                        let content = &evt["content"];
                        let ct_b64 = content["ciphertext"].as_str().unwrap_or("");
                        let msg_type = content["type"].as_u64().unwrap_or(1) as usize;
                        if ct_b64.is_empty() { continue; }

                        let ct = match B64.decode(ct_b64) { Ok(b) => b, Err(_) => continue };
                        let olm = match OlmMessage::from_parts(msg_type, &ct) { Ok(m) => m, Err(_) => continue };

                        // Parse SPQR metadata and Braid messages from event
                        let spqr_meta: Option<SpqrMessageMeta> = content.get("spqr_meta")
                            .and_then(|v| serde_json::from_value(v.clone()).ok());
                        let braid_msgs: Vec<BraidMessage> = content.get("braid_msgs")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();

                        match sess.decrypt_pq(&olm, spqr_meta.as_ref(), &braid_msgs) {
                            Ok((pt, response_braid)) => {
                                if !response_braid.is_empty() {
                                    pending_braid.lock().unwrap().extend(response_braid);
                                }
                                let txt = String::from_utf8_lossy(&pt);
                                println!("[missed] {}: {}", sender, txt);
                                append_history(username, sender, &txt);
                                missed_count += 1;
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        }
        if missed_count > 0 {
            println!("[backfill] {} missed message(s)\n", missed_count);
        }
    }

    let since = Arc::new(Mutex::new(
        initial["next_batch"].as_str().map(|s| s.to_string())
    ));

    let recv_tok = tok.to_string();
    let recv_uid = uid.to_string();
    let recv_session = session.clone();
    let recv_since = since.clone();
    let recv_username = username.to_string();
    let recv_room_id = room_id.to_string();

    let running = Arc::new(Mutex::new(true));
    let running_clone = running.clone();
    let sync_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let sync_error_clone = sync_error.clone();
    
    let scanned_messages_arc = Arc::new(Mutex::new(scanned_messages));
    let scanned_clone = scanned_messages_arc.clone();

    let pending_braid_clone = pending_braid.clone();

    let handle = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let http = reqwest::blocking::Client::new();
            while *running_clone.lock().unwrap() {
                let since_val = recv_since.lock().unwrap().clone();
                let r = sync(&http, &recv_tok, since_val.as_deref(), 5000);
                *recv_since.lock().unwrap() = r["next_batch"].as_str().map(|s| s.to_string());

                if let Some(rooms) = r["rooms"]["join"].as_object() {
                    for (rid, rd) in rooms { if rid != &recv_room_id { continue; }
                        if let Some(evts) = rd["timeline"]["events"].as_array() {
                            for evt in evts {
                                let event_id = evt["event_id"].as_str().unwrap_or("");
                                if !event_id.is_empty() {
                                    let mut scanned = scanned_clone.lock().unwrap();
                                    if scanned.contains(event_id) { continue; }
                                    scanned.insert(event_id.to_string());
                                }
                                
                                let sender = evt["sender"].as_str().unwrap_or("");
                                if sender == recv_uid { continue; }
                                if evt["type"].as_str() != Some("m.room.encrypted") { continue; }

                                let content = &evt["content"];
                                let ct_b64 = content["ciphertext"].as_str().unwrap_or("");
                                let msg_type = content["type"].as_u64().unwrap_or(1) as usize;
                                if ct_b64.is_empty() { continue; }

                                let ct = match B64.decode(ct_b64) { Ok(b) => b, Err(_) => continue };
                                let olm = match OlmMessage::from_parts(msg_type, &ct) { Ok(m) => m, Err(_) => continue };

                                // Parse SPQR metadata and Braid messages from event
                                let spqr_meta: Option<SpqrMessageMeta> = content.get("spqr_meta")
                                    .and_then(|v| serde_json::from_value(v.clone()).ok());
                                let braid_msgs: Vec<BraidMessage> = content.get("braid_msgs")
                                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                                    .unwrap_or_default();

                                let mut sess = recv_session.lock().unwrap();

                                match sess.decrypt_pq(&olm, spqr_meta.as_ref(), &braid_msgs) {
                                    Ok((pt, response_braid)) => {
                                        let txt = String::from_utf8_lossy(&pt);
                                        if !response_braid.is_empty() {
                                            pending_braid_clone.lock().unwrap().extend(response_braid);
                                        }
                                        println!("\r{}: {}", sender, txt);
                                        append_history(&recv_username, sender, &txt);
                                        print!("> ");
                                        io::stdout().flush().ok();
                                    }
                                    Err(e) => {
                                        if msg_type == 0 {
                                            println!("\r[warn] Unexpected PreKey from {} (peer restarted?)", sender);
                                        } else {
                                            println!("\r[error] Decrypt failed: {:?}", e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }));

        if let Err(panic_info) = result {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            *sync_error_clone.lock().unwrap() = Some(format!("Sync thread panicked: {}", msg));
            *running_clone.lock().unwrap() = false;
        }
    });

    let room_id_owned = room_id.to_string();
    let sender_key_owned = sender_key.to_string();
    let username_owned = username.to_string();
    let peer_uid_owned = peer_uid.to_string();
    let uid_owned = uid.to_string();
    let mut new_requested = false;

    let result = loop {
        // Check if background sync thread has crashed
        if let Some(err) = sync_error.lock().unwrap().as_ref() {
            println!("\n[error] {}", err);
            println!("[error] Background sync has stopped. Saving session and exiting.");
            break true;
        }

        print!("> ");
        io::stdout().flush().unwrap();

        let mut line = String::new();
        io::stdin().read_line(&mut line).unwrap();
        let line = line.trim();

        if line == "/logout" {
            break true;
        }

        if line == "/exit" {
            break false;
        }

        if line == "/clear" {
            clear_history(&username_owned);
            continue;
        }

        if line == "/new" {
            delete_session_data(&username_owned);
            // Also clear the state file so next login starts fresh
            let state_path = format!(".pqxdh-{}.state", username_owned);
            if Path::new(&state_path).exists() {
                let _ = fs::remove_file(&state_path);
                println!("[state] Cleared");
            }
            clear_history(&username_owned);
            new_requested = true;
            break true;
        }

        if line.is_empty() { continue; }

        let mut sess = session.lock().unwrap();
        let mut braid_to_send: Vec<BraidMessage> = pending_braid.lock().unwrap().drain(..).collect();
        send_encrypted(http, tok, &room_id_owned, &mut sess, line, &sender_key_owned, None, &mut braid_to_send);
        append_history(&username_owned, &uid_owned, line);
    };

    *running.lock().unwrap() = false;
    let _ = handle.join();

    if !new_requested {
        let sess = session.lock().unwrap();
        save_session_data(&username_owned, &sess, &room_id_owned, &peer_uid_owned, msg_counter.load(Ordering::Relaxed), &pickle_key);
    }

    result
}

// ========== STATE PERSISTENCE ==========

fn save_state(username: &str, account: &Account, kem_pk: &[u8], kem_sk: &[u8], spk_created: u64, device_id: &str, pickle_key: &[u8; 32]) {
    let pickle = account.pickle().encrypt(pickle_key);
    let state = json!({
        "account_pickle": pickle,
        "kem_pk": B64.encode(kem_pk),
        "kem_sk": B64.encode(kem_sk),
        "spk_created_at": spk_created,
        "device_id": device_id,
    });
    let path = format!(".pqxdh-{}.state", username);
    fs::write(&path, serde_json::to_string_pretty(&state).unwrap())
        .expect("Failed to save state");
    println!("[state] Saved to {}", path);
}

fn load_state(username: &str, pickle_key: &[u8; 32]) -> Option<(Account, Vec<u8>, Vec<u8>, u64, bool, String)> {
    let path = format!(".pqxdh-{}.state", username);
    if !Path::new(&path).exists() {
        return None;
    }
    let raw = fs::read_to_string(&path).ok()?;
    let data: serde_json::Value = serde_json::from_str(&raw).ok()?;

    let pickle_str = data["account_pickle"].as_str()?;
    let pickle = AccountPickle::from_encrypted(pickle_str, pickle_key).ok()?;
    let account = Account::from_pickle(pickle);
    let kem_pk = B64.decode(data["kem_pk"].as_str()?).ok()?;
    let kem_sk = B64.decode(data["kem_sk"].as_str()?).ok()?;
    let device_id = data["device_id"].as_str().unwrap_or("PQXDH_UNKNOWN").to_string();

    let spk_created = data["spk_created_at"].as_u64().unwrap_or(0);
    let now = current_timestamp();
    let age_days = (now - spk_created) / 86400;
    let needs_rotation = age_days >= SPK_ROTATION_DAYS;

    println!("[state] Loaded from {} (device: {})", path, device_id);
    println!("[state] SPK age: {} days (rotation at {} days)", age_days, SPK_ROTATION_DAYS);

    Some((account, kem_pk, kem_sk, spk_created, needs_rotation, device_id))
}


// ========== INITIATOR HELPER ==========

fn run_initiator_flow(
    http: &reqwest::blocking::Client, tok: &str, uid: &str,
    account: &mut Account, peer: &str, ik_b64: &str,
    kem_sk_arc: Arc<Vec<u8>>, kem_pk_bytes: &[u8], kem_sk_bytes: &[u8],
    username: &str, spk_created: u64, did: &str, pickle_key: [u8; 32],
) -> bool {
    println!("\n[role] INITIATOR");
    print!("> ");
    io::stdout().flush().unwrap();

    let mut first_msg = String::new();
    io::stdin().read_line(&mut first_msg).unwrap();
    let first_msg = first_msg.trim().to_string();
    if first_msg == "/logout" { matrix_logout(http, tok); return true; }
    if first_msg == "/exit" { matrix_logout(http, tok); return false; }

    let msg_counter = Arc::new(AtomicU64::new(0));
    let (session, room_id) = initiate_session(
        http, tok, account, peer, &first_msg, ik_b64, &msg_counter,
    );
    append_history(username, uid, &first_msg);
    save_state(username, account, kem_pk_bytes, kem_sk_bytes, spk_created, did, &pickle_key);
    let session_arc = Arc::new(Mutex::new(session));
    chat_loop(http, tok, uid, session_arc, &room_id, ik_b64, kem_sk_arc, username, peer, msg_counter, pickle_key, Arc::new(Mutex::new(Vec::new())))
}

// ========== MAIN SESSION LOGIC ==========


#[derive(Clone, Copy)]
enum StartMode {
    Fresh,
    Restore,
    Rotate,
}

fn run_session(http: &reqwest::blocking::Client) -> bool {
    let username = prompt("Username: ");
    let password = prompt("Password: ");

    let pickle_key = derive_pickle_key(&password, &username);

    let state_result = load_state(&username, &pickle_key);

    let start_mode = match &state_result {
        None => StartMode::Fresh,
        Some((_, _, _, _, needs_rotation, _)) => {
            if *needs_rotation { StartMode::Rotate } else { StartMode::Restore }
        }
    };

    let device_id = match start_mode {
        StartMode::Fresh => {
            let did = format!("PQXDH_{}_{}", username.to_uppercase(), current_timestamp());
            println!("[state] Fresh start - device: {}", did);
            did
        }
        StartMode::Rotate => {
            let did = format!("PQXDH_{}_{}", username.to_uppercase(), current_timestamp());
            println!("[state] SPK rotation - new device: {}", did);
            did
        }
        StartMode::Restore => {
            let (_, _, _, _, _, ref saved_did) = state_result.as_ref().unwrap();
            println!("[state] Restoring device: {}", saved_did);
            saved_did.clone()
        }
    };

    let (tok, uid, did) = match matrix_login(http, &username, &password, &device_id) {
        Ok(v) => v,
        Err(e) => {
            println!("[error] {}", e);
            return true;
        }
    };

    println!("[login] {} (device: {})", uid, did);

    let (mut account, kem_pk_bytes, kem_sk_bytes, spk_created) = match start_mode {
        StartMode::Fresh => {
            delete_session_data(&username);
            let mut acct = Account::new();
            println!("[crypto] Identity: {} (new)", acct.curve25519_key().to_base64());

            let kem = Kem::new(Algorithm::MlKem768).unwrap();
            let (kem_pk, kem_sk) = kem.keypair().unwrap();
            let pk = kem_pk.as_ref().to_vec();
            let sk = kem_sk.as_ref().to_vec();
            println!("[crypto] KEM: {} bytes (new)", pk.len());

            upload_keys_fresh(http, &tok, &uid, &did, &mut acct, &pk);
            verify_own_keys(http, &tok, &uid, &did, &acct);
            cleanup_old_devices(http, &tok, &did, &username, &password);

            let now = current_timestamp();
            save_state(&username, &acct, &pk, &sk, now, &did, &pickle_key);
            (acct, pk, sk, now)
        }
        StartMode::Rotate => {
            delete_session_data(&username);
            let (acct, _, _, _, _, _) = state_result.unwrap();
            let mut acct = acct;

            println!("[crypto] Identity: {} (preserved)", acct.curve25519_key().to_base64());

            let kem = Kem::new(Algorithm::MlKem768).unwrap();
            let (kem_pk, kem_sk) = kem.keypair().unwrap();
            let pk = kem_pk.as_ref().to_vec();
            let sk = kem_sk.as_ref().to_vec();
            println!("[crypto] KEM: {} bytes (rotated)", pk.len());

            upload_keys_fresh(http, &tok, &uid, &did, &mut acct, &pk);
            verify_own_keys(http, &tok, &uid, &did, &acct);
            cleanup_old_devices(http, &tok, &did, &username, &password);

            let now = current_timestamp();
            save_state(&username, &acct, &pk, &sk, now, &did, &pickle_key);
            (acct, pk, sk, now)
        }
        StartMode::Restore => {
            let (acct, pk, sk, spk_ts, _, _) = state_result.unwrap();
            println!("[crypto] Identity: {} (restored)", acct.curve25519_key().to_base64());
            println!("[crypto] KEM: {} bytes (restored)", pk.len());
            let mut acct = acct;
            upload_otks_only(http, &tok, &mut acct);
            verify_own_keys(http, &tok, &uid, &did, &acct);
            save_state(&username, &acct, &pk, &sk, spk_ts, &did, &pickle_key);
            (acct, pk, sk, spk_ts)
        }
    };

    let ik_b64 = account.curve25519_key().to_base64();
    let kem_sk_arc = Arc::new(kem_sk_bytes.clone());

    // Check for saved session FIRST (resume previous chat)
    if let Some((restored_session, saved_room_id, saved_peer, saved_count)) = load_session_data(&username, &pickle_key) {
        let p = prompt(&format!("\nResume chat with {}? [Y/n]: ", saved_peer));
        if p.trim().eq_ignore_ascii_case("y") || p.trim().is_empty() {
            println!("[info] Resuming chat with {}", saved_peer);
            let msg_counter = Arc::new(AtomicU64::new(saved_count));
            let session_arc = Arc::new(Mutex::new(restored_session));
            let login_again = chat_loop(
                http, &tok, &uid, session_arc, &saved_room_id, &ik_b64,
                kem_sk_arc, &username, &saved_peer, msg_counter, pickle_key,
                Arc::new(Mutex::new(Vec::new())),
            );
            matrix_logout(http, &tok);
            return login_again;
        } else {
            println!("[info] Discarding saved session.");
            delete_session_data(&username);
        }
    }

    // No saved session - determine peer and role
    let peer = {
        let p = prompt("\nChat with: ");
        if p.starts_with("@") { p } else { format!("@{}:matrix.local", p) }
    };
    println!("[info] Peer: {}", peer);

    let peer_ready = query_keys(http, &tok, &peer).is_ok();

    let login_again = if peer_ready {
        println!("\n[info] Choose role:");
        println!("  [i] Initiate session");
        println!("  [w] Wait for session");
        let choice = prompt("Choice [i/w]: ");

        match choice.to_lowercase().as_str() {
            "w" => {
                println!("\n[role] RESPONDER - waiting for {}...", peer);
                let (session, room_id, _sender, initial_braid) = wait_for_session(
                    http, &tok, &uid, &mut account, &kem_sk_bytes,
                );
                save_state(&username, &account, &kem_pk_bytes, &kem_sk_bytes, spk_created, &did, &pickle_key);
                let msg_counter = Arc::new(AtomicU64::new(0));
                let session_arc = Arc::new(Mutex::new(session));
                let initial_braid_arc: Arc<Mutex<Vec<BraidMessage>>> = Arc::new(Mutex::new(initial_braid));
                chat_loop(http, &tok, &uid, session_arc, &room_id, &ik_b64, kem_sk_arc, &username, &peer, msg_counter, pickle_key, initial_braid_arc)
            }
            _ => run_initiator_flow(
                http, &tok, &uid, &mut account, &peer, &ik_b64,
                kem_sk_arc, &kem_pk_bytes, &kem_sk_bytes,
                &username, spk_created, &did, pickle_key,
            ),
        }
    } else {
        println!("\n[info] {} hasn't uploaded keys yet.", peer);
        println!("[info] Choose:");
        println!("  [w] Wait for session");
        println!("  [r] Retry checking keys");
        let choice = prompt("Choice [w/r]: ");

        match choice.to_lowercase().as_str() {
            "r" => {
                println!("\n[info] Polling...");
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    print!(".");
                    io::stdout().flush().ok();
                    if query_keys(http, &tok, &peer).is_ok() {
                        println!("\n[info] {} ready!", peer);
                        return run_initiator_flow(
                            http, &tok, &uid, &mut account, &peer, &ik_b64,
                            kem_sk_arc, &kem_pk_bytes, &kem_sk_bytes,
                            &username, spk_created, &did, pickle_key,
                        );
                    }
                }
            }
            _ => {
                println!("\n[role] RESPONDER");
                let (session, room_id, _, initial_braid) = wait_for_session(
                    http, &tok, &uid, &mut account, &kem_sk_bytes,
                );
                save_state(&username, &account, &kem_pk_bytes, &kem_sk_bytes, spk_created, &did, &pickle_key);
                let msg_counter = Arc::new(AtomicU64::new(0));
                let session_arc = Arc::new(Mutex::new(session));
                let initial_braid_arc: Arc<Mutex<Vec<BraidMessage>>> = Arc::new(Mutex::new(initial_braid));
                chat_loop(http, &tok, &uid, session_arc, &room_id, &ik_b64, kem_sk_arc, &username, &peer, msg_counter, pickle_key, initial_braid_arc)
            }
        }
    };

    matrix_logout(http, &tok);
    login_again
}

fn main() {
    println!("========================================");
    println!("  PQXDH Matrix Client");
    println!("  ML-KEM-768 + X25519 + SPQR");
    println!("========================================\n");

    let http = reqwest::blocking::Client::new();

    loop {
        let login_again = run_session(&http);
        if !login_again {
            println!("\n[exit] Goodbye!");
            break;
        }
        println!("\n========================================");
        println!("  Login again or press Ctrl+C to exit");
        println!("========================================\n");
    }
}
