use std::hint::black_box;
use std::time::Instant;
use crate::helpers;
use crate::stats::BenchResult;
use crate::output;

/// Metric #13: Multi-Session Scaling — Throughput with N concurrent sessions
///
/// Creates N independent session pairs and measures aggregate encrypt+decrypt
/// throughput, testing how well the crypto scales under multi-session load.
/// This ports the concurrent-session concept from the Python `matrix-client`
/// tests into the Rust benchmarking suite against the real vodozemac library.
pub fn run(iterations: usize, warmup: usize) -> serde_json::Value {
    let session_counts: Vec<usize> = vec![1, 10, 50, 100];
    let plaintext = helpers::make_plaintext(256);
    let mut result_map = serde_json::Map::new();

    for &n_sessions in &session_counts {
        println!("\n  Testing {} concurrent session(s)...", n_sessions);

        // ── Classical sessions ──
        let mut classical_pairs: Vec<_> = (0..n_sessions)
            .map(|_| {
                let (_, _, a, b) = helpers::create_classical_session_pair();
                (a, b)
            })
            .collect();

        let mut classical_samples = Vec::with_capacity(iterations);
        for i in 0..(warmup + iterations) {
            let t0 = Instant::now();
            // Round-robin across sessions
            for (alice, bob) in classical_pairs.iter_mut() {
                let msg = black_box(alice.encrypt(&plaintext));
                let _ = black_box(bob.decrypt(&msg).unwrap());
            }
            let elapsed = t0.elapsed();
            if i >= warmup {
                classical_samples.push(elapsed.as_nanos() as f64);
            }
        }

        // ── PQXDH sessions ──
        let mut pq_pairs: Vec<_> = (0..n_sessions)
            .map(|_| {
                let (_, _, a, b, _pk, _sk) = helpers::create_pqxdh_session_pair();
                let pending: Vec<vodozemac::olm::BraidMessage> = Vec::new();
                (a, b, pending)
            })
            .collect();

        let mut pq_samples = Vec::with_capacity(iterations);
        for i in 0..(warmup + iterations) {
            let t0 = Instant::now();
            for (alice, bob, pending) in pq_pairs.iter_mut() {
                let wire = black_box(alice.encrypt_pq(&plaintext));
                let mut braid_in = wire.braid_msgs;
                braid_in.extend(pending.drain(..));
                match bob.decrypt_pq(
                    &wire.message,
                    wire.spqr_meta.as_ref(),
                    &braid_in,
                ) {
                    Ok((_, resp_braid)) => {
                        pending.extend(resp_braid);
                    }
                    Err(_) => {
                        let _ = bob.decrypt(&wire.message);
                    }
                }
            }
            let elapsed = t0.elapsed();
            if i >= warmup {
                pq_samples.push(elapsed.as_nanos() as f64);
            }
        }

        let cr = BenchResult::new(
            &format!("Classical ×{}", n_sessions), "ns", classical_samples,
        );
        let pr = BenchResult::new(
            &format!("PQ ×{}", n_sessions), "ns", pq_samples,
        );
        output::print_comparison_table(
            &format!("Scaling: {} sessions (total round-trip per iteration)", n_sessions),
            &cr, &pr,
        );

        let cs = cr.summary();
        let ps = pr.summary();

        // Per-message throughput
        let c_msgs_sec = if cs.mean > 0.0 {
            (n_sessions as f64 * 1_000_000_000.0) / cs.mean
        } else { 0.0 };
        let p_msgs_sec = if ps.mean > 0.0 {
            (n_sessions as f64 * 1_000_000_000.0) / ps.mean
        } else { 0.0 };

        println!("    Classical: {:.0} msgs/sec ({} sessions)", c_msgs_sec, n_sessions);
        println!("    PQ-OLM:    {:.0} msgs/sec ({} sessions)", p_msgs_sec, n_sessions);

        result_map.insert(format!("{}sessions", n_sessions), serde_json::json!({
            "session_count": n_sessions,
            "classical": {
                "summary": cs,
                "msgs_per_sec": c_msgs_sec,
                "samples": cr.samples,
            },
            "pq": {
                "summary": ps,
                "msgs_per_sec": p_msgs_sec,
                "samples": pr.samples,
            },
        }));
    }

    serde_json::Value::Object(result_map)
}
