use std::hint::black_box;
use std::time::Instant;
use crate::helpers;
use crate::stats::BenchResult;
use crate::output;

/// Metric #2: Ratchet Step Time — measures DH ratchet advance cost
/// by alternating message direction. Since SPQR encrypt_pq is a stub,
/// both paths should be nearly identical; this documents the architecture.
pub fn run(iterations: usize, warmup: usize) -> serde_json::Value {
    // ── Classical: alternate messages to trigger ratchet advances ──
    let mut classical_samples = Vec::with_capacity(iterations);
    {
        let (_, _, mut alice_sess, mut bob_sess) = helpers::create_classical_session_pair();
        for i in 0..(warmup + iterations) {
            // Alice → Bob (triggers bob's ratchet advance)
            let t0 = Instant::now();
            let msg_ab = black_box(alice_sess.encrypt("ratchet_bench"));
            let _ = black_box(bob_sess.decrypt(&msg_ab).unwrap());
            // Bob → Alice (triggers alice's ratchet advance)
            let msg_ba = black_box(bob_sess.encrypt("ratchet_back"));
            let _ = black_box(alice_sess.decrypt(&msg_ba).unwrap());
            let elapsed = t0.elapsed();

            if i >= warmup {
                classical_samples.push(elapsed.as_nanos() as f64);
            }
        }
    }

    // ── PQ (SPQR stub): same pattern via encrypt_pq / decrypt_pq ──
    let mut pq_samples = Vec::with_capacity(iterations);
    {
        let (_, _, mut alice_sess, mut bob_sess, _pk, sk) =
            helpers::create_pqxdh_session_pair();
        for i in 0..(warmup + iterations) {
            let t0 = Instant::now();
            let (msg_ab, spqr_ct_ab) = black_box(alice_sess.encrypt_pq("ratchet_bench"));
            let _ = black_box(bob_sess.decrypt_pq(&msg_ab, spqr_ct_ab.as_deref(), Some(&sk)).unwrap());
            let (msg_ba, spqr_ct_ba) = black_box(bob_sess.encrypt_pq("ratchet_back"));
            let _ = black_box(alice_sess.decrypt_pq(&msg_ba, spqr_ct_ba.as_deref(), Some(&sk)).unwrap());
            let elapsed = t0.elapsed();

            if i >= warmup {
                pq_samples.push(elapsed.as_nanos() as f64);
            }
        }
    }

    let cr = BenchResult::new("Classical DR", "ns", classical_samples);
    let pr = BenchResult::new("SPQR Ratchet", "ns", pq_samples);
    output::print_comparison_table("Ratchet Step (2 direction changes)", &cr, &pr);

    serde_json::json!({
        "classical": { "summary": cr.summary(), "samples_count": cr.samples.len() },
        "pq": { "summary": pr.summary(), "samples_count": pr.samples.len() },
    })
}
