use crate::output;

/// Metric #4: Security Level — X3DH+DR vs PQXDH+SPQR comparison table
///
/// Documents the security properties achieved by each protocol stack,
/// showing what the PQ upgrade gains in exchange for its overhead costs.
pub fn run() -> serde_json::Value {
    let rows: Vec<(&str, &str, &str)> = vec![
        ("Key Agreement",        "X3DH (3× X25519)",                 "PQXDH (4× X25519 + ML-KEM-768)"),
        ("Ratchet",              "Double Ratchet (X25519 DH)",       "SPQR Triple Ratchet (DR + ML-KEM-768 Braid)"),
        ("AEAD",                 "AES-256-CBC + HMAC-SHA-256",       "AES-256-CBC + HMAC-SHA-256"),
        ("Classical Security",   "128-bit",                          "128-bit"),
        ("Quantum Security",     "NONE",                             "NIST Level 3 (ML-KEM-768)"),
        ("Forward Secrecy",      "Yes (per DH ratchet step)",        "Yes (per DH ratchet step + PQ epoch)"),
        ("Post-Compromise Sec.", "Yes (DH ratchet)",                 "Yes (DH ratchet + PQ Braid ratchet)"),
        ("KEM Standard",         "—",                                "FIPS 203 (ML-KEM-768)"),
        ("Hybrid Approach",      "—",                                "X25519 ∥ ML-KEM-768 (combined keys)"),
        ("PQ Harvest-Now Attack","Vulnerable",                       "Protected"),
    ];

    output::print_kv_table("Security Properties: X3DH+DR vs PQXDH+SPQR", &rows);

    let json_rows: Vec<serde_json::Value> = rows
        .iter()
        .map(|(prop, classical, pq)| {
            serde_json::json!({
                "property": prop,
                "x3dh_dr": classical,
                "pqxdh_spqr": pq,
            })
        })
        .collect();

    serde_json::json!({
        "properties": json_rows,
    })
}
