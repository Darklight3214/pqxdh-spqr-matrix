use std::hint::black_box;
use std::time::Instant;
use crate::helpers;
use crate::stats::BenchResult;
use crate::output;

/// Metric #5: Per-message Encrypt/Decrypt Time
pub fn run(iterations: usize, warmup: usize) -> serde_json::Value {
    let msg_sizes: Vec<usize> = vec![64, 256, 1024];
    let mut result_map = serde_json::Map::new();

    for &size in &msg_sizes {
        let plaintext = helpers::make_plaintext(size);

        // ── Classical encrypt ──
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

        // ── PQ encrypt_pq ──
        let mut pq_enc = Vec::with_capacity(iterations);
        let mut pq_dec = Vec::with_capacity(iterations);
        {
            let (_, _, mut alice_sess, mut bob_sess, _pk, sk) =
                helpers::create_pqxdh_session_pair();
            for i in 0..(warmup + iterations) {
                let t0 = Instant::now();
                let (msg, spqr_ct) = black_box(alice_sess.encrypt_pq(&plaintext));
                let enc_time = t0.elapsed();

                let t1 = Instant::now();
                let _ = black_box(
                    bob_sess.decrypt_pq(&msg, spqr_ct.as_deref(), Some(&sk)).unwrap()
                );
                let dec_time = t1.elapsed();

                if i >= warmup {
                    pq_enc.push(enc_time.as_nanos() as f64);
                    pq_dec.push(dec_time.as_nanos() as f64);
                }
            }
        }

        let ce = BenchResult::new("Classical Encrypt", "ns", classical_enc);
        let pe = BenchResult::new("PQ Encrypt", "ns", pq_enc);
        output::print_comparison_table(
            &format!("Encrypt ({} B plaintext)", size), &ce, &pe
        );

        let cd = BenchResult::new("Classical Decrypt", "ns", classical_dec);
        let pd = BenchResult::new("PQ Decrypt", "ns", pq_dec);
        output::print_comparison_table(
            &format!("Decrypt ({} B plaintext)", size), &cd, &pd
        );

        result_map.insert(format!("{}B", size), serde_json::json!({
            "encrypt": {
                "classical": { "summary": ce.summary() },
                "pq": { "summary": pe.summary() },
            },
            "decrypt": {
                "classical": { "summary": cd.summary() },
                "pq": { "summary": pd.summary() },
            },
        }));
    }

    serde_json::Value::Object(result_map)
}
