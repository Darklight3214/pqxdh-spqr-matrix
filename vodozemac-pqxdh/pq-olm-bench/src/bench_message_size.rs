use crate::helpers;

use comfy_table::{Table, Cell, Attribute, ContentArrangement};

/// Metric #3: Message Size on Wire — X3DH+DR vs PQXDH+SPQR ciphertext overhead
///
/// Compares the ciphertext size at various plaintext lengths, showing how
/// much additional wire data the PQ upgrade introduces per message.
pub fn run() -> serde_json::Value {
    let sizes: Vec<usize> = vec![0, 16, 64, 256, 1024, 4096];

    let mut rows = Vec::new();

    println!();
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Plaintext").add_attribute(Attribute::Bold),
        Cell::new("X3DH+DR CT").add_attribute(Attribute::Bold),
        Cell::new("PQXDH+SPQR CT").add_attribute(Attribute::Bold),
        Cell::new("X3DH+DR Overhead").add_attribute(Attribute::Bold),
        Cell::new("PQXDH+SPQR Overhead").add_attribute(Attribute::Bold),
        Cell::new("PQ Extra").add_attribute(Attribute::Bold),
    ]);

    for &pt_size in &sizes {
        let plaintext = helpers::make_plaintext(pt_size);

        // X3DH + Double Ratchet
        let (_, _, mut alice_c, _bob_c) = helpers::create_classical_session_pair();
        let msg_c = alice_c.encrypt(&plaintext);
        let ct_c_bytes = helpers::olm_message_bytes(&msg_c);
        let ct_c_len = ct_c_bytes.len();

        // PQXDH + SPQR Triple Ratchet
        let (_, _, mut alice_p, _bob_p, _pk, _sk) = helpers::create_pqxdh_session_pair();
        let wire = alice_p.encrypt_pq(&plaintext);
        let ct_p_bytes = helpers::olm_message_bytes(&wire.message);
        let ct_p_len = ct_p_bytes.len();
        // Braid messages carry KEM ciphertexts
        let braid_extra: usize = wire.braid_msgs.iter()
            .map(|bm| serde_json::to_vec(bm).unwrap_or_default().len())
            .sum();
        let spqr_meta_extra = if wire.spqr_meta.is_some() { 16 } else { 0 };

        let overhead_c = ct_c_len as i64 - pt_size as i64;
        let overhead_p = ct_p_len as i64 - pt_size as i64;
        let pq_extra = ct_p_len as i64 - ct_c_len as i64 + braid_extra as i64 + spqr_meta_extra;

        table.add_row(vec![
            Cell::new(format!("{} B", pt_size)),
            Cell::new(format!("{} B", ct_c_len)),
            Cell::new(format!("{} B", ct_p_len)),
            Cell::new(format!("+{} B", overhead_c)),
            Cell::new(format!("+{} B", overhead_p)),
            Cell::new(format!("+{} B", pq_extra)),
        ]);

        rows.push(serde_json::json!({
            "plaintext_bytes": pt_size,
            "classical_ct_bytes": ct_c_len,
            "pq_ct_bytes": ct_p_len,
            "classical_overhead": overhead_c,
            "pq_overhead": overhead_p,
            "pq_extra_vs_classical": pq_extra,
            "braid_extra_bytes": braid_extra,
            "spqr_meta_extra": spqr_meta_extra,
        }));
    }

    println!("  Message Size: X3DH+DR vs PQXDH+SPQR");
    println!("{table}");

    serde_json::json!({
        "sizes": rows,
        "note": "CT includes OlmMessage framing. 'PQ Extra' = additional bytes vs classical including Braid messages and SPQR metadata."
    })
}
