use crate::output;

/// Metric #4: Security Level — documentation-only comparison table
pub fn run() -> serde_json::Value {
    let rows: Vec<(&str, &str, &str)> = vec![
        ("Key Agreement", "X3DH (3× X25519)", "PQXDH (4× X25519 + ML-KEM-768)"),
        ("Ratchet", "Double Ratchet (X25519)", "SPQR (DR + ML-KEM-768 every 50th)"),
        ("AEAD", "AES-256-CBC + HMAC-SHA-256", "AES-256-CBC + HMAC-SHA-256"),
        ("Classical Security", "128-bit", "128-bit"),
        ("Quantum Security", "NONE", "NIST Level 3 (ML-KEM-768)"),
        ("Forward Secrecy", "Yes (per direction change)", "Yes (per direction change)"),
        ("Post-Compromise Security", "Yes (DH ratchet)", "Yes (DH + PQ ratchet)"),
        ("KEM Standard", "—", "FIPS 203 (ML-KEM-768)"),
        ("Hybrid Approach", "—", "X25519 ∥ ML-KEM-768"),
        ("PQ Harvest-Now Attack", "Vulnerable", "Protected"),
    ];

    output::print_kv_table("Security Properties Comparison", &rows);

    let json_rows: Vec<serde_json::Value> = rows
        .iter()
        .map(|(prop, classical, pq)| {
            serde_json::json!({
                "property": prop,
                "classical": classical,
                "pq_olm": pq,
            })
        })
        .collect();

    serde_json::json!({
        "properties": json_rows,
    })
}
