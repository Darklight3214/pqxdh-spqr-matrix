use std::hint::black_box;
use std::time::Instant;
use crate::helpers;
use crate::stats::BenchResult;
use crate::output;

/// Metric #2: Ratchet Step Time — SPQR Triple Ratchet vs Classical Double Ratchet
///
/// Measures the cost of alternating message direction which triggers ratchet
/// advances. For classical, this is the DH Double Ratchet key derivation.
/// For PQXDH+SPQR, this includes the ML-KEM Braid state machine and combined
/// key derivation (DR key ⊕ SPQR epoch key via HKDF).
pub fn run(iterations: usize, warmup: usize) -> serde_json::Value {
    // ── Classical Double Ratchet: alternate messages to trigger ratchet advances ──
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

    // ── PQXDH + SPQR Triple Ratchet: same pattern via encrypt_pq / decrypt_pq ──
    // Uses the real SPQR API which combines DH ratchet key with SPQR epoch key
    // through HKDF(salt=spqr_key, ikm=dr_key, info="SPQR_COMBINE").
    // When SPQR is initialized, encrypt_pq produces combined keys; when not yet
    // initialized, it falls back to standard DH-only encryption.
    let mut pq_samples = Vec::with_capacity(iterations);
    {
        let (_, _, mut alice_sess, mut bob_sess, _pk, _sk) =
            helpers::create_pqxdh_session_pair();

        // Accumulated Braid response messages to forward on next call
        let mut alice_pending_braid: Vec<vodozemac::olm::BraidMessage> = Vec::new();
        let mut bob_pending_braid: Vec<vodozemac::olm::BraidMessage> = Vec::new();

        for i in 0..(warmup + iterations) {
            let t0 = Instant::now();

            // Alice → Bob via SPQR Triple Ratchet
            let wire_ab = black_box(alice_sess.encrypt_pq("ratchet_bench"));
            // Combine Alice's outgoing braid msgs with any pending from Bob
            let mut braid_for_bob = wire_ab.braid_msgs;
            braid_for_bob.extend(alice_pending_braid.drain(..));

            let decrypt_result_ab = bob_sess.decrypt_pq(
                &wire_ab.message,
                wire_ab.spqr_meta.as_ref(),
                &braid_for_bob,
            );
            match decrypt_result_ab {
                Ok((_, resp_braid)) => {
                    // Bob's response braid msgs go to Alice on next round
                    bob_pending_braid.extend(resp_braid);
                }
                Err(_) => {
                    // Fallback: try standard decrypt if SPQR key not ready
                    let _ = bob_sess.decrypt(&wire_ab.message);
                }
            }

            // Bob → Alice via SPQR Triple Ratchet
            let wire_ba = black_box(bob_sess.encrypt_pq("ratchet_back"));
            let mut braid_for_alice = wire_ba.braid_msgs;
            braid_for_alice.extend(bob_pending_braid.drain(..));

            let decrypt_result_ba = alice_sess.decrypt_pq(
                &wire_ba.message,
                wire_ba.spqr_meta.as_ref(),
                &braid_for_alice,
            );
            match decrypt_result_ba {
                Ok((_, resp_braid)) => {
                    alice_pending_braid.extend(resp_braid);
                }
                Err(_) => {
                    let _ = alice_sess.decrypt(&wire_ba.message);
                }
            }

            let elapsed = t0.elapsed();

            if i >= warmup {
                pq_samples.push(elapsed.as_nanos() as f64);
            }
        }
    }

    let cr = BenchResult::new("X3DH + Double Ratchet", "ns", classical_samples);
    let pr = BenchResult::new("PQXDH + SPQR Triple Ratchet", "ns", pq_samples);
    output::print_comparison_table("Ratchet Step (2 direction changes)", &cr, &pr);

    serde_json::json!({
        "classical": { "summary": cr.summary(), "samples": cr.samples },
        "pq": { "summary": pr.summary(), "samples": pr.samples },
    })
}
