use crate::helpers;
use crate::stats::format_bytes;

use comfy_table::{Table, Cell, Attribute, ContentArrangement};

/// Metric #9: Bandwidth Consumption — Total data for conversations, monthly projection
///
/// Calculates wire-level byte costs for conversations of varying length,
/// accounting for PreKey overhead on first message, normal message overhead,
/// and SPQR KEM ciphertext overhead (via Braid messages).
///
/// Compares X3DH+DR vs PQXDH+SPQR total data consumption per conversation
/// and projects monthly bandwidth at configurable message rates.
pub fn run() -> serde_json::Value {
    let conversation_lengths: &[usize] = &[1, 10, 50, 100, 500, 1000];
    let plaintext_size = 256; // Average message size in bytes
    let plaintext = helpers::make_plaintext(plaintext_size);

    // KEM ciphertext size (1088 bytes for ML-KEM-768)
    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768).expect("ML-KEM-768 unavailable");
    let (pk, _sk) = kem.keypair().expect("KEM keygen failed");
    let (ct, _ss) = kem.encapsulate(&pk).expect("KEM encaps failed");
    let kem_ct_size = ct.as_ref().len(); // 1088 bytes
    let kem_pk_size = pk.as_ref().len(); // 1184 bytes

    let mut json_rows = Vec::new();

    println!();
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Msgs").add_attribute(Attribute::Bold),
        Cell::new("X3DH+DR (B)").add_attribute(Attribute::Bold),
        Cell::new("PQXDH+SPQR (B)").add_attribute(Attribute::Bold),
        Cell::new("Δ Bytes").add_attribute(Attribute::Bold),
        Cell::new("Overhead %").add_attribute(Attribute::Bold),
        Cell::new("SPQR Braid Msgs").add_attribute(Attribute::Bold),
    ]);

    for &n in conversation_lengths {
        // ── Classical X3DH + Double Ratchet ──
        let (_, _, mut c_alice, _c_bob) = helpers::create_classical_session_pair();
        let mut classical_total: usize = 0;

        for _ in 0..n {
            let msg = c_alice.encrypt(&plaintext);
            let ct_bytes = helpers::olm_message_bytes(&msg);
            classical_total += ct_bytes.len();
            // Measure actual JSON envelope overhead
            let envelope_size = serde_json::to_vec(&serde_json::json!({
                "algorithm": "m.olm.v1.curve25519-aes-sha2",
                "sender_key": "base64_placeholder_32bytes_aaaaaaa",
                "ciphertext": "placeholder",
                "type": 1,
            })).unwrap().len();
            classical_total += envelope_size;
        }

        // ── PQXDH + SPQR Triple Ratchet ──
        let (_, _, mut p_alice, _p_bob, _pk, _sk) = helpers::create_pqxdh_session_pair();
        let mut pq_total: usize = 0;
        let mut braid_msg_count: usize = 0;

        // First message includes KEM ciphertext for PQXDH handshake
        pq_total += kem_ct_size; // Initial PQXDH KEM CT

        for _ in 0..n {
            let wire = p_alice.encrypt_pq(&plaintext);
            let ct_bytes = helpers::olm_message_bytes(&wire.message);
            pq_total += ct_bytes.len();

            // Count Braid messages (each carries KEM ciphertexts)
            for bm in &wire.braid_msgs {
                let braid_bytes = serde_json::to_vec(bm).unwrap_or_default();
                pq_total += braid_bytes.len();
                braid_msg_count += 1;
            }

            // SPQR metadata overhead
            if wire.spqr_meta.is_some() {
                pq_total += 16; // epoch (u64) + index (u32) + framing
            }

            // Measure actual JSON envelope overhead
            let envelope_size = serde_json::to_vec(&serde_json::json!({
                "algorithm": "m.olm.pqxdh.v1",
                "sender_key": "base64_placeholder_32bytes_aaaaaaa",
                "ciphertext": "placeholder",
                "type": 1,
                "spqr_epoch": 0u64,
                "spqr_index": 0u32,
            })).unwrap().len();
            pq_total += envelope_size;
        }

        let delta = pq_total as i64 - classical_total as i64;
        let overhead_pct = if classical_total > 0 {
            (delta as f64 / classical_total as f64) * 100.0
        } else {
            0.0
        };

        table.add_row(vec![
            Cell::new(n.to_string()),
            Cell::new(format_bytes(classical_total as f64)),
            Cell::new(format_bytes(pq_total as f64)),
            Cell::new(format!("+{}", format_bytes(delta.max(0) as f64))),
            Cell::new(format!("{:.1}%", overhead_pct)),
            Cell::new(format!("{}", braid_msg_count)),
        ]);

        json_rows.push(serde_json::json!({
            "message_count": n,
            "classical_bytes": classical_total,
            "pq_bytes": pq_total,
            "delta_bytes": delta,
            "overhead_pct": overhead_pct,
            "braid_msg_count": braid_msg_count,
        }));
    }

    println!("  Bandwidth: X3DH+DR vs PQXDH+SPQR ({} B plaintext/msg)", plaintext_size);
    println!("{table}");

    // ═══════════════════════════════════════════
    //  Monthly Projections
    // ═══════════════════════════════════════════
    let daily_rates: &[usize] = &[100, 500, 1000, 5000, 10000];

    println!();
    let mut monthly_table = Table::new();
    monthly_table.set_content_arrangement(ContentArrangement::Dynamic);
    monthly_table.set_header(vec![
        Cell::new("Msgs/Day").add_attribute(Attribute::Bold),
        Cell::new("X3DH+DR/Month").add_attribute(Attribute::Bold),
        Cell::new("PQXDH+SPQR/Month").add_attribute(Attribute::Bold),
        Cell::new("Extra/Month").add_attribute(Attribute::Bold),
    ]);

    let mut json_monthly = Vec::new();

    // Use average bytes-per-message from measured data
    let (_, _, mut c_test, _) = helpers::create_classical_session_pair();
    let c_msg = c_test.encrypt(&plaintext);
    let c_avg_bytes = helpers::olm_message_bytes(&c_msg).len() + 100; // + envelope

    let (_, _, mut p_test, _, _, _) = helpers::create_pqxdh_session_pair();
    let p_wire = p_test.encrypt_pq(&plaintext);
    let mut p_avg_bytes = helpers::olm_message_bytes(&p_wire.message).len() + 120;
    // Amortized SPQR overhead
    let pq_per_msg_extra = kem_ct_size as f64 / 100.0  // Amortized session setup
        + (kem_ct_size as f64 / 50.0); // SPQR Braid every ~50th message
    p_avg_bytes += pq_per_msg_extra as usize;

    for &daily in daily_rates {
        let monthly = daily * 30;
        let c_monthly_bytes = monthly * c_avg_bytes;
        let p_monthly_bytes = monthly * p_avg_bytes;
        let extra = p_monthly_bytes as i64 - c_monthly_bytes as i64;

        monthly_table.add_row(vec![
            Cell::new(format!("{}", daily)),
            Cell::new(format_bytes(c_monthly_bytes as f64)),
            Cell::new(format_bytes(p_monthly_bytes as f64)),
            Cell::new(format!("+{}", format_bytes(extra.max(0) as f64))),
        ]);

        json_monthly.push(serde_json::json!({
            "msgs_per_day": daily,
            "classical_monthly_bytes": c_monthly_bytes,
            "pq_monthly_bytes": p_monthly_bytes,
            "extra_monthly_bytes": extra,
        }));
    }

    println!("  Monthly Bandwidth Projection (per user)");
    println!("{monthly_table}");

    // Key upload size comparison
    println!("\n  Prekey Bundle Upload Sizes:");
    println!("    X3DH+DR   : ~96 B (IK + OTK + signing key)");
    println!("    PQXDH+SPQR: ~{} B (+ SPK 32B + sig 64B + KEM PK {} B)",
        96 + 32 + 64 + kem_pk_size, kem_pk_size);
    println!("    Upload overhead: +{} B ({:.1}x)",
        32 + 64 + kem_pk_size,
        (96 + 32 + 64 + kem_pk_size) as f64 / 96.0);

    serde_json::json!({
        "per_conversation": json_rows,
        "monthly_projection": json_monthly,
        "config": {
            "plaintext_size": plaintext_size,
            "kem_ct_size": kem_ct_size,
            "kem_pk_size": kem_pk_size,
        },
    })
}
