use std::hint::black_box;
use std::time::Instant;
use crate::helpers;
use crate::stats::BenchResult;
use crate::output;

/// Metric #11: Megolm Group Encryption — Outbound encrypt + Inbound decrypt
///
/// Tests group message encryption at varying plaintext sizes and group sizes
/// (simulated via multiple InboundGroupSession recipients decrypting the same
/// ciphertext).
pub fn run(iterations: usize, warmup: usize) -> serde_json::Value {
    let msg_sizes: Vec<usize> = vec![64, 256, 1024];
    let group_sizes: Vec<usize> = vec![2, 10, 50];
    let mut result_map = serde_json::Map::new();

    // ── Per-message encrypt/decrypt at varying plaintext sizes ──
    for &size in &msg_sizes {
        let plaintext = helpers::make_plaintext(size);

        let mut encrypt_samples = Vec::with_capacity(iterations);
        let mut decrypt_samples = Vec::with_capacity(iterations);
        {
            let (mut outbound, mut inbound) = helpers::create_megolm_session_pair();
            for i in 0..(warmup + iterations) {
                let t0 = Instant::now();
                let ct = black_box(outbound.encrypt(&plaintext));
                let enc_time = t0.elapsed();

                let t1 = Instant::now();
                let _ = black_box(inbound.decrypt(&ct).unwrap());
                let dec_time = t1.elapsed();

                if i >= warmup {
                    encrypt_samples.push(enc_time.as_nanos() as f64);
                    decrypt_samples.push(dec_time.as_nanos() as f64);
                }
            }
        }

        let enc = BenchResult::new("Megolm Encrypt", "ns", encrypt_samples);
        let dec = BenchResult::new("Megolm Decrypt", "ns", decrypt_samples);
        output::print_comparison_table(
            &format!("Megolm ({} B plaintext)", size), &enc, &dec
        );

        result_map.insert(format!("{}B", size), serde_json::json!({
            "encrypt": { "summary": enc.summary(), "samples": enc.samples },
            "decrypt": { "summary": dec.summary(), "samples": dec.samples },
        }));
    }

    // ── Key distribution overhead per group size ──
    // Simulates the cost of encrypting the session key for N recipients
    // using individual Olm sessions (how real Matrix key distribution works).
    println!("\n  Key Distribution Cost (Olm-wrapped session key for N members):");
    let mut dist_results = Vec::new();

    for &n in &group_sizes {
        let (outbound, _inbound) = helpers::create_megolm_session_pair();
        let session_key_bytes = outbound.session_key().to_bytes();

        // Create N classical OLM sessions and encrypt the session key to each
        let mut key_dist_samples = Vec::with_capacity(iterations.min(100));
        for _ in 0..iterations.min(100) {
            let t0 = Instant::now();
            for _ in 0..n {
                let (_, _, mut alice_sess, _bob_sess) = helpers::create_classical_session_pair();
                let _ = black_box(alice_sess.encrypt(&session_key_bytes));
            }
            let elapsed = t0.elapsed();
            key_dist_samples.push(elapsed.as_nanos() as f64);
        }

        let kr = BenchResult::new(&format!("{} members", n), "ns", key_dist_samples);
        output::print_single_table(
            &format!("Key distribution to {} members", n), &kr
        );

        let s = kr.summary();
        println!("    → {:.2} ms mean for {} members ({:.2} ms/member)",
            s.mean / 1_000_000.0, n, s.mean / 1_000_000.0 / n as f64);

        dist_results.push(serde_json::json!({
            "group_size": n,
            "summary": s,
            "samples": kr.samples,
        }));
    }

    result_map.insert("key_distribution".into(), serde_json::json!(dist_results));
    serde_json::Value::Object(result_map)
}
