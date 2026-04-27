use std::hint::black_box;
use std::time::Instant;
use vodozemac::olm::{Account, SessionConfig, OlmMessage};
use oqs::kem::{Kem, Algorithm};
use crate::stats::BenchResult;
use crate::output;

/// Metric #1: Handshake Time — X3DH+DR vs PQXDH+SPQR session establishment
///
/// Measures the complete session establishment cost including key generation,
/// key agreement, and initial PreKeyMessage exchange.
/// - X3DH: 3× X25519 DH computations
/// - PQXDH: 4× X25519 DH + ML-KEM-768 encapsulate/decapsulate
pub fn run(iterations: usize, warmup: usize) -> serde_json::Value {
    // ── X3DH + Double Ratchet ──
    let mut classical_initiator = Vec::with_capacity(iterations);
    let mut classical_responder = Vec::with_capacity(iterations);
    let mut classical_roundtrip = Vec::with_capacity(iterations);

    for i in 0..(warmup + iterations) {
        let alice = Account::new();
        let mut bob = Account::new();
        bob.generate_one_time_keys(1);
        let otk = *bob.one_time_keys().values().next().unwrap();

        // Initiator timing
        let t0 = Instant::now();
        let mut alice_session = black_box(alice.create_outbound_session(
            SessionConfig::version_2(),
            bob.curve25519_key(),
            otk,
        ));
        let t_init = t0.elapsed();

        // Produce PreKeyMessage
        let msg = alice_session.encrypt("handshake_bench");

        // Responder timing
        let t1 = Instant::now();
        if let OlmMessage::PreKey(ref pkm) = msg {
            let _result = black_box(bob.create_inbound_session(
                alice.curve25519_key(),
                pkm,
            ).unwrap());
        }
        let t_resp = t1.elapsed();

        if i >= warmup {
            classical_initiator.push(t_init.as_nanos() as f64);
            classical_responder.push(t_resp.as_nanos() as f64);
            classical_roundtrip.push((t_init + t_resp).as_nanos() as f64);
        }
    }

    // ── PQXDH + SPQR Triple Ratchet ──
    let mut pq_initiator = Vec::with_capacity(iterations);
    let mut pq_responder = Vec::with_capacity(iterations);
    let mut pq_roundtrip = Vec::with_capacity(iterations);

    for i in 0..(warmup + iterations) {
        let alice = Account::new();
        let mut bob = Account::new();
        let (bob_spk, _sig) = bob.generate_signed_prekey();
        bob.generate_one_time_keys(1);
        let otk = *bob.one_time_keys().values().next().unwrap();

        let kem = Kem::new(Algorithm::MlKem768).unwrap();
        let (kem_pk, kem_sk) = kem.keypair().unwrap();
        let pk_bytes = kem_pk.as_ref().to_vec();
        let sk_bytes = kem_sk.as_ref().to_vec();

        // Initiator timing (includes KEM encapsulation)
        let t0 = Instant::now();
        let (mut alice_session, kem_ct) = black_box(alice.create_outbound_session_pqxdh(
            SessionConfig::version_2(),
            bob.curve25519_key(),
            bob_spk,
            Some(otk),
            &pk_bytes,
        ));
        let t_init = t0.elapsed();

        let msg = alice_session.encrypt("handshake_bench");

        // Responder timing (includes KEM decapsulation)
        let t1 = Instant::now();
        if let OlmMessage::PreKey(ref pkm) = msg {
            let _result = black_box(bob.create_inbound_session_pqxdh(
                alice.curve25519_key(),
                pkm,
                &kem_ct,
                &sk_bytes,
            ).unwrap());
        }
        let t_resp = t1.elapsed();

        if i >= warmup {
            pq_initiator.push(t_init.as_nanos() as f64);
            pq_responder.push(t_resp.as_nanos() as f64);
            pq_roundtrip.push((t_init + t_resp).as_nanos() as f64);
        }
    }

    // Print results
    let cr = BenchResult::new("X3DH+DR Roundtrip", "ns", classical_roundtrip.clone());
    let pr = BenchResult::new("PQXDH+SPQR Roundtrip", "ns", pq_roundtrip.clone());
    output::print_comparison_table("Handshake Roundtrip: X3DH+DR vs PQXDH+SPQR", &cr, &pr);

    let ci = BenchResult::new("X3DH+DR Initiator", "ns", classical_initiator.clone());
    let pi = BenchResult::new("PQXDH+SPQR Initiator", "ns", pq_initiator.clone());
    output::print_comparison_table("Handshake Initiator Only", &ci, &pi);

    let cre = BenchResult::new("X3DH+DR Responder", "ns", classical_responder.clone());
    let pre = BenchResult::new("PQXDH+SPQR Responder", "ns", pq_responder.clone());
    output::print_comparison_table("Handshake Responder Only", &cre, &pre);

    serde_json::json!({
        "roundtrip": {
            "classical": { "summary": cr.summary(), "samples_count": cr.samples.len() },
            "pq": { "summary": pr.summary(), "samples_count": pr.samples.len() },
        },
        "initiator": {
            "classical": { "summary": ci.summary(), "samples_count": ci.samples.len() },
            "pq": { "summary": pi.summary(), "samples_count": pi.samples.len() },
        },
        "responder": {
            "classical": { "summary": cre.summary(), "samples_count": cre.samples.len() },
            "pq": { "summary": pre.summary(), "samples_count": pre.samples.len() },
        },
    })
}
