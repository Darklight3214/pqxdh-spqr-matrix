use std::hint::black_box;
use std::time::Instant;
use crate::helpers;
use crate::stats::BenchResult;
use crate::output;

/// Metric #5: Per-message Encrypt/Decrypt Time — X3DH+DR vs PQXDH+SPQR
///
/// Measures the per-message cost of encryption and decryption at varying
/// plaintext sizes. For PQXDH+SPQR, uses the real Triple Ratchet path
/// (encrypt_pq/decrypt_pq) which combines DH and SPQR keys.
pub fn run(iterations: usize, warmup: usize) -> serde_json::Value {
    let msg_sizes: Vec<usize> = vec![64, 256, 1024];
    let mut result_map = serde_json::Map::new();

    for &size in &msg_sizes {
        let plaintext = helpers::make_plaintext(size);

        // ── X3DH + Double Ratchet encrypt/decrypt ──
        let mut classical_enc = Vec::with_capacity(iterations);
        let mut classical_dec = Vec::with_capacity(iterations);
        {
            let (_, _, mut alice_sess, mut bob_sess) = helpers::create_classical_session_pair();
            for i in 0..(warmup + iterations) {
                let t0 = Instant::now();
                let msg = black_box(alice_sess.encrypt(&plaintext));
                let enc_time = t0.elapsed();

                let t1 = Instant::now();
                let _ = black_box(bob_sess.decrypt(&msg).unwrap());
                let dec_time = t1.elapsed();

                if i >= warmup {
                    classical_enc.push(enc_time.as_nanos() as f64);
                    classical_dec.push(dec_time.as_nanos() as f64);
                }
            }
        }

        // ── PQXDH + SPQR Triple Ratchet encrypt/decrypt ──
        let mut pq_enc = Vec::with_capacity(iterations);
        let mut pq_dec = Vec::with_capacity(iterations);
        {
            let (_, _, mut alice_sess, mut bob_sess, _pk, _sk) =
                helpers::create_pqxdh_session_pair();
            let mut pending_braid: Vec<vodozemac::olm::BraidMessage> = Vec::new();
            for i in 0..(warmup + iterations) {
                let t0 = Instant::now();
                let wire = black_box(alice_sess.encrypt_pq(&plaintext));
                let enc_time = t0.elapsed();

                let mut braid_in = wire.braid_msgs;
                braid_in.extend(pending_braid.drain(..));

                let t1 = Instant::now();
                match bob_sess.decrypt_pq(
                    &wire.message,
                    wire.spqr_meta.as_ref(),
                    &braid_in,
                ) {
                    Ok((_, resp_braid)) => {
                        pending_braid.extend(resp_braid);
                    }
                    Err(_) => {
                        let _ = bob_sess.decrypt(&wire.message);
                    }
                }
                let dec_time = t1.elapsed();

                if i >= warmup {
                    pq_enc.push(enc_time.as_nanos() as f64);
                    pq_dec.push(dec_time.as_nanos() as f64);
                }
            }
        }

        let ce = BenchResult::new("X3DH+DR Encrypt", "ns", classical_enc);
        let pe = BenchResult::new("PQXDH+SPQR Encrypt", "ns", pq_enc);
        output::print_comparison_table(
            &format!("Encrypt ({} B): X3DH+DR vs PQXDH+SPQR", size), &ce, &pe
        );

        let cd = BenchResult::new("X3DH+DR Decrypt", "ns", classical_dec);
        let pd = BenchResult::new("PQXDH+SPQR Decrypt", "ns", pq_dec);
        output::print_comparison_table(
            &format!("Decrypt ({} B): X3DH+DR vs PQXDH+SPQR", size), &cd, &pd
        );

        result_map.insert(format!("{}B", size), serde_json::json!({
            "encrypt": {
                "classical": { "summary": ce.summary(), "samples": ce.samples },
                "pq": { "summary": pe.summary(), "samples": pe.samples },
            },
            "decrypt": {
                "classical": { "summary": cd.summary(), "samples": cd.samples },
                "pq": { "summary": pd.summary(), "samples": pd.samples },
            },
        }));
    }

    serde_json::Value::Object(result_map)
}
