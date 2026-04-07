use vodozemac::olm::Account;
use oqs::kem::{Kem, Algorithm};
use crate::output;

/// Metric #6: Key & Bundle Sizes — all cryptographic artifact sizes
pub fn run() -> serde_json::Value {
    let mut account = Account::new();
    let (_spk, _spk_sig) = account.generate_signed_prekey();
    account.generate_one_time_keys(1);
    let _otk = *account.one_time_keys().values().next().unwrap();

    let kem = Kem::new(Algorithm::MlKem768).unwrap();
    let (kem_pk, kem_sk) = kem.keypair().unwrap();
    let (kem_ct, _kem_ss) = kem.encapsulate(&kem_pk).unwrap();

    let kem_pk_str = format!("{} B", kem_pk.as_ref().len());
    let kem_sk_str = format!("{} B", kem_sk.as_ref().len());
    let kem_ct_str = format!("{} B", kem_ct.as_ref().len());

    let rows: Vec<(&str, &str, &str)> = vec![
        ("Identity Key (Curve25519)", "32 B", "32 B"),
        ("Signing Key (Ed25519)", "32 B", "32 B"),
        ("Signed Prekey (Curve25519)", "—", "32 B"),
        ("SPK Signature (Ed25519)", "—", "64 B"),
        ("One-Time Key (Curve25519)", "32 B", "32 B"),
        ("KEM Public Key (ML-KEM-768)", "—", &kem_pk_str),
        ("KEM Secret Key (ML-KEM-768)", "—", &kem_sk_str),
        ("KEM Ciphertext (ML-KEM-768)", "—", &kem_ct_str),
        ("KEM Shared Secret", "—", "32 B"),
    ];

    output::print_kv_table("Key & Artifact Sizes", &rows);

    // Bundle size comparison
    let classical_bundle = 32 + 32 + 32; // ik + signing + otk
    let pq_bundle = 32 + 32 + 32 + 64 + 32 + kem_pk.as_ref().len(); // + spk + sig + kem_pk
    let pq_prekey_msg_extra = kem_ct.as_ref().len(); // KEM CT sent with first message

    println!("\n  Prekey Bundle Upload Sizes:");
    println!("    Classical : {} B", classical_bundle);
    println!("    PQ-OLM    : {} B  (+{} B, {:.1}x)",
        pq_bundle,
        pq_bundle - classical_bundle,
        pq_bundle as f64 / classical_bundle as f64,
    );
    println!("    PQ PreKey message extra: +{} B (KEM ciphertext)", pq_prekey_msg_extra);

    serde_json::json!({
        "keys": {
            "identity_key_bytes": 32,
            "signing_key_bytes": 32,
            "signed_prekey_bytes": 32,
            "spk_signature_bytes": 64,
            "otk_bytes": 32,
            "kem_pk_bytes": kem_pk.as_ref().len(),
            "kem_sk_bytes": kem_sk.as_ref().len(),
            "kem_ct_bytes": kem_ct.as_ref().len(),
            "kem_ss_bytes": 32,
        },
        "bundles": {
            "classical_bundle_bytes": classical_bundle,
            "pq_bundle_bytes": pq_bundle,
            "overhead_bytes": pq_bundle - classical_bundle,
            "overhead_factor": pq_bundle as f64 / classical_bundle as f64,
            "prekey_msg_extra_bytes": pq_prekey_msg_extra,
        },
    })
}
