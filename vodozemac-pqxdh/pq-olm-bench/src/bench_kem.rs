use std::hint::black_box;
use std::time::Instant;
use oqs::kem::{Kem, Algorithm};
use x25519_dalek::{EphemeralSecret, PublicKey};
use rand::rngs::OsRng;
use crate::stats::BenchResult;
use crate::output;

/// Metric #7: KEM Primitive Times — X25519 DH (used by X3DH+DR) vs ML-KEM-768 (used by PQXDH+SPQR)
///
/// Isolates the raw cryptographic primitive costs to show exactly where
/// the PQXDH+SPQR overhead originates.
pub fn run(iterations: usize, warmup: usize) -> serde_json::Value {
    // ═══════════════════════════════════════════
    //  ML-KEM-768 Keygen (PQXDH+SPQR primitive)
    // ═══════════════════════════════════════════
    let mut kem_keygen_samples = Vec::with_capacity(iterations);
    {
        let kem = Kem::new(Algorithm::MlKem768).expect("ML-KEM-768 unavailable");
        for i in 0..(warmup + iterations) {
            let t0 = Instant::now();
            let (_pk, _sk) = black_box(kem.keypair().expect("KEM keygen failed"));
            let elapsed = t0.elapsed();
            if i >= warmup {
                kem_keygen_samples.push(elapsed.as_nanos() as f64);
            }
        }
    }

    // ═══════════════════════════════════════════
    //  ML-KEM-768 Encapsulate (PQXDH+SPQR primitive)
    // ═══════════════════════════════════════════
    let mut kem_encaps_samples = Vec::with_capacity(iterations);
    {
        let kem = Kem::new(Algorithm::MlKem768).expect("ML-KEM-768 unavailable");
        let (pk, _sk) = kem.keypair().expect("KEM keygen failed");
        for i in 0..(warmup + iterations) {
            let t0 = Instant::now();
            let (_ct, _ss) = black_box(kem.encapsulate(&pk).expect("KEM encaps failed"));
            let elapsed = t0.elapsed();
            if i >= warmup {
                kem_encaps_samples.push(elapsed.as_nanos() as f64);
            }
        }
    }

    // ═══════════════════════════════════════════
    //  ML-KEM-768 Decapsulate (PQXDH+SPQR primitive)
    // ═══════════════════════════════════════════
    let mut kem_decaps_samples = Vec::with_capacity(iterations);
    {
        let kem = Kem::new(Algorithm::MlKem768).expect("ML-KEM-768 unavailable");
        let (pk, sk) = kem.keypair().expect("KEM keygen failed");
        // Pre-generate ciphertexts for each iteration to isolate decaps timing
        let mut cts: Vec<Vec<u8>> = Vec::with_capacity(warmup + iterations);
        for _ in 0..(warmup + iterations) {
            let (ct, _ss) = kem.encapsulate(&pk).expect("KEM encaps failed");
            cts.push(ct.into_vec());
        }
        for i in 0..(warmup + iterations) {
            let ct_ref = kem.ciphertext_from_bytes(&cts[i]).expect("Bad CT");
            let t0 = Instant::now();
            let _ss = black_box(kem.decapsulate(&sk, &ct_ref).expect("KEM decaps failed"));
            let elapsed = t0.elapsed();
            if i >= warmup {
                kem_decaps_samples.push(elapsed.as_nanos() as f64);
            }
        }
    }

    // ═══════════════════════════════════════════
    //  X25519 Key Generation (X3DH+DR primitive)
    // ═══════════════════════════════════════════
    let mut x25519_keygen_samples = Vec::with_capacity(iterations);
    for i in 0..(warmup + iterations) {
        let t0 = Instant::now();
        let secret = black_box(EphemeralSecret::random_from_rng(OsRng));
        let _public = black_box(PublicKey::from(&secret));
        let elapsed = t0.elapsed();
        if i >= warmup {
            x25519_keygen_samples.push(elapsed.as_nanos() as f64);
        }
    }

    // ═══════════════════════════════════════════
    //  X25519 Diffie-Hellman Exchange (X3DH+DR primitive)
    // ═══════════════════════════════════════════
    let mut x25519_dh_samples = Vec::with_capacity(iterations);
    {
        // Pre-generate peer public keys to isolate DH timing
        let mut peer_pubs: Vec<PublicKey> = Vec::with_capacity(warmup + iterations);
        for _ in 0..(warmup + iterations) {
            let s = EphemeralSecret::random_from_rng(OsRng);
            peer_pubs.push(PublicKey::from(&s));
        }
        for i in 0..(warmup + iterations) {
            let my_secret = EphemeralSecret::random_from_rng(OsRng);
            let t0 = Instant::now();
            let _shared = black_box(my_secret.diffie_hellman(&peer_pubs[i]));
            let elapsed = t0.elapsed();
            if i >= warmup {
                x25519_dh_samples.push(elapsed.as_nanos() as f64);
            }
        }
    }

    // ═══════════════════════════════════════════
    //  Results
    // ═══════════════════════════════════════════
    let kem_keygen = BenchResult::new("ML-KEM-768 Keygen (PQXDH+SPQR)", "ns", kem_keygen_samples);
    let kem_encaps = BenchResult::new("ML-KEM-768 Encaps (PQXDH+SPQR)", "ns", kem_encaps_samples);
    let kem_decaps = BenchResult::new("ML-KEM-768 Decaps (PQXDH+SPQR)", "ns", kem_decaps_samples);
    let x_keygen = BenchResult::new("X25519 Keygen (X3DH+DR)", "ns", x25519_keygen_samples);
    let x_dh = BenchResult::new("X25519 DH (X3DH+DR)", "ns", x25519_dh_samples);

    // Print comparison tables
    output::print_comparison_table("Key Generation: X3DH+DR vs PQXDH+SPQR", &x_keygen, &kem_keygen);
    output::print_comparison_table("Key Exchange: X25519 DH vs ML-KEM-768 Encaps", &x_dh, &kem_encaps);
    output::print_single_table("ML-KEM-768 Decapsulation (PQXDH+SPQR only)", &kem_decaps);

    // Throughput: ops/sec at mean latency
    let kem_kg_s = kem_keygen.summary();
    let kem_en_s = kem_encaps.summary();
    let kem_de_s = kem_decaps.summary();
    let x_kg_s = x_keygen.summary();
    let x_dh_s = x_dh.summary();

    let ops_sec = |mean_ns: f64| -> f64 {
        if mean_ns > 0.0 { 1_000_000_000.0 / mean_ns } else { 0.0 }
    };

    println!("\n  Throughput (ops/sec at mean latency):");
    println!("    X25519 Keygen (X3DH+DR)       : {:.0} ops/sec", ops_sec(x_kg_s.mean));
    println!("    X25519 DH (X3DH+DR)           : {:.0} ops/sec", ops_sec(x_dh_s.mean));
    println!("    ML-KEM-768 Keygen (PQXDH+SPQR): {:.0} ops/sec", ops_sec(kem_kg_s.mean));
    println!("    ML-KEM-768 Encaps (PQXDH+SPQR): {:.0} ops/sec", ops_sec(kem_en_s.mean));
    println!("    ML-KEM-768 Decaps (PQXDH+SPQR): {:.0} ops/sec", ops_sec(kem_de_s.mean));

    serde_json::json!({
        "keygen": {
            "x3dh_dr": { "summary": x_kg_s, "ops_per_sec": ops_sec(x_kg_s.mean) },
            "pqxdh_spqr": { "summary": kem_kg_s, "ops_per_sec": ops_sec(kem_kg_s.mean) },
        },
        "exchange": {
            "x3dh_dr_dh": { "summary": x_dh_s, "ops_per_sec": ops_sec(x_dh_s.mean) },
            "pqxdh_spqr_encaps": { "summary": kem_en_s, "ops_per_sec": ops_sec(kem_en_s.mean) },
            "pqxdh_spqr_decaps": { "summary": kem_de_s, "ops_per_sec": ops_sec(kem_de_s.mean) },
        },
    })
}
