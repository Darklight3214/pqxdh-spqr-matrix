use crate::helpers;

use comfy_table::{Table, Cell, Attribute, ContentArrangement};

/// Metric #3: Message Size on Wire — ciphertext overhead at various plaintext sizes
pub fn run() -> serde_json::Value {
    let sizes: Vec<usize> = vec![0, 16, 64, 256, 1024, 4096];

    let mut rows = Vec::new();

    println!();
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Plaintext").add_attribute(Attribute::Bold),
        Cell::new("Classical CT").add_attribute(Attribute::Bold),
        Cell::new("PQ CT").add_attribute(Attribute::Bold),
        Cell::new("Classical Overhead").add_attribute(Attribute::Bold),
        Cell::new("PQ Overhead").add_attribute(Attribute::Bold),
        Cell::new("PQ Extra").add_attribute(Attribute::Bold),
    ]);

    for &pt_size in &sizes {
        let plaintext = helpers::make_plaintext(pt_size);

        // Classical
        let (_, _, mut alice_c, _bob_c) = helpers::create_classical_session_pair();
        let msg_c = alice_c.encrypt(&plaintext);
        let ct_c_bytes = helpers::olm_message_bytes(&msg_c);
        let ct_c_len = ct_c_bytes.len();

        // PQXDH
        let (_, _, mut alice_p, _bob_p, _pk, _sk) = helpers::create_pqxdh_session_pair();
        let (msg_p, spqr_ct) = alice_p.encrypt_pq(&plaintext);
        let ct_p_bytes = helpers::olm_message_bytes(&msg_p);
        let ct_p_len = ct_p_bytes.len();
        let spqr_extra = spqr_ct.as_ref().map_or(0, |c| c.len());

        let overhead_c = ct_c_len as i64 - pt_size as i64;
        let overhead_p = ct_p_len as i64 - pt_size as i64;
        let pq_extra = ct_p_len as i64 - ct_c_len as i64 + spqr_extra as i64;

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
            "spqr_kem_ct_bytes": spqr_extra,
        }));
    }

    println!("  Message Size on Wire");
    println!("{table}");

    serde_json::json!({
        "sizes": rows,
        "note": "CT includes OlmMessage framing. 'PQ Extra' = additional bytes vs classical. SPQR KEM CT appears every 50th msg (currently stubbed to None)."
    })
}
