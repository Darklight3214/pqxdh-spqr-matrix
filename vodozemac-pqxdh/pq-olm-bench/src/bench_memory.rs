use crate::helpers;
use crate::stats::format_bytes;
use comfy_table::{Table, Cell, Attribute, ContentArrangement};

/// Metric #12: Memory Footprint — Session state sizes (pickled)
///
/// Measures serialized sizes of accounts, sessions, and Megolm group sessions
/// to understand memory overhead of PQ vs classical for mobile/embedded targets.
pub fn run() -> serde_json::Value {
    // ── Classical Account ──
    let (alice_c, bob_c, alice_sess_c, bob_sess_c) = helpers::create_classical_session_pair();

    let alice_c_pickle = serde_json::to_vec(&alice_c.pickle()).unwrap();
    let bob_c_pickle = serde_json::to_vec(&bob_c.pickle()).unwrap();
    let alice_sess_c_pickle = serde_json::to_vec(&alice_sess_c.pickle()).unwrap();
    let bob_sess_c_pickle = serde_json::to_vec(&bob_sess_c.pickle()).unwrap();

    // ── PQXDH Account ──
    let (alice_p, bob_p, alice_sess_p, bob_sess_p, _pk, _sk) = helpers::create_pqxdh_session_pair();

    let alice_p_pickle = serde_json::to_vec(&alice_p.pickle()).unwrap();
    let bob_p_pickle = serde_json::to_vec(&bob_p.pickle()).unwrap();
    let alice_sess_p_pickle = serde_json::to_vec(&alice_sess_p.pickle()).unwrap();
    let bob_sess_p_pickle = serde_json::to_vec(&bob_sess_p.pickle()).unwrap();

    // ── Megolm Group Sessions ──
    let (outbound, inbound) = helpers::create_megolm_session_pair();
    let outbound_pickle = serde_json::to_vec(&outbound.pickle()).unwrap();
    let inbound_pickle = serde_json::to_vec(&inbound.pickle()).unwrap();

    // ── After N messages ──
    let n_msgs = 100;
    let (_, _, mut a_sess_c2, mut b_sess_c2) = helpers::create_classical_session_pair();
    for _ in 0..n_msgs {
        let msg = a_sess_c2.encrypt("test");
        let _ = b_sess_c2.decrypt(&msg).unwrap();
    }
    let sess_c_after_n = serde_json::to_vec(&a_sess_c2.pickle()).unwrap();

    let (_, _, mut a_sess_p2, mut b_sess_p2, _pk2, _sk2) = helpers::create_pqxdh_session_pair();
    let mut pending_braid: Vec<vodozemac::olm::BraidMessage> = Vec::new();
    for _ in 0..n_msgs {
        let wire = a_sess_p2.encrypt_pq("test");
        let mut braid_in = wire.braid_msgs;
        braid_in.extend(pending_braid.drain(..));
        match b_sess_p2.decrypt_pq(
            &wire.message,
            wire.spqr_meta.as_ref(),
            &braid_in,
        ) {
            Ok((_, resp)) => pending_braid.extend(resp),
            Err(_) => { let _ = b_sess_p2.decrypt(&wire.message); }
        }
    }
    let sess_p_after_n = serde_json::to_vec(&a_sess_p2.pickle()).unwrap();

    // Print table
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Component").add_attribute(Attribute::Bold),
        Cell::new("Classical").add_attribute(Attribute::Bold),
        Cell::new("PQ-OLM").add_attribute(Attribute::Bold),
        Cell::new("Δ").add_attribute(Attribute::Bold),
    ]);

    let row = |label: &str, c: usize, p: usize| {
        vec![
            Cell::new(label),
            Cell::new(format_bytes(c as f64)),
            Cell::new(format_bytes(p as f64)),
            Cell::new(format!("+{} ({}x)", format_bytes((p as i64 - c as i64).max(0) as f64),
                if c > 0 { format!("{:.1}", p as f64 / c as f64) } else { "∞".into() })),
        ]
    };

    table.add_row(row("Account (Alice)", alice_c_pickle.len(), alice_p_pickle.len()));
    table.add_row(row("Account (Bob)", bob_c_pickle.len(), bob_p_pickle.len()));
    table.add_row(row("Session (Alice, fresh)", alice_sess_c_pickle.len(), alice_sess_p_pickle.len()));
    table.add_row(row("Session (Bob, fresh)", bob_sess_c_pickle.len(), bob_sess_p_pickle.len()));
    table.add_row(row(
        &format!("Session (after {} msgs)", n_msgs),
        sess_c_after_n.len(), sess_p_after_n.len()
    ));

    // Megolm (no classical equivalent — same for both)
    table.add_row(vec![
        Cell::new("Megolm Outbound"),
        Cell::new(format_bytes(outbound_pickle.len() as f64)),
        Cell::new("(same)"),
        Cell::new("—"),
    ]);
    table.add_row(vec![
        Cell::new("Megolm Inbound"),
        Cell::new(format_bytes(inbound_pickle.len() as f64)),
        Cell::new("(same)"),
        Cell::new("—"),
    ]);

    println!("\n  Memory Footprint (Pickled State Sizes)");
    println!("{table}");

    serde_json::json!({
        "classical": {
            "account_alice_bytes": alice_c_pickle.len(),
            "account_bob_bytes": bob_c_pickle.len(),
            "session_alice_fresh_bytes": alice_sess_c_pickle.len(),
            "session_bob_fresh_bytes": bob_sess_c_pickle.len(),
            "session_after_n_msgs_bytes": sess_c_after_n.len(),
        },
        "pq": {
            "account_alice_bytes": alice_p_pickle.len(),
            "account_bob_bytes": bob_p_pickle.len(),
            "session_alice_fresh_bytes": alice_sess_p_pickle.len(),
            "session_bob_fresh_bytes": bob_sess_p_pickle.len(),
            "session_after_n_msgs_bytes": sess_p_after_n.len(),
        },
        "megolm": {
            "outbound_bytes": outbound_pickle.len(),
            "inbound_bytes": inbound_pickle.len(),
        },
        "n_msgs_for_growth": n_msgs,
    })
}
