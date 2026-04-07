use crate::helpers;
#[allow(unused_imports)]
use crate::output;
use comfy_table::{Table, Cell, Attribute, ContentArrangement};

/// Metric #9: Bandwidth Consumption — Total data for conversations, monthly projection
///
/// Calculates wire-level byte costs for conversations of varying length,
/// accounting for PreKey overhead on first message, normal message overhead,
/// and SPQR KEM ciphertext overhead (every 50th message — currently stubbed).
///
/// Projects monthly bandwidth at configurable message rates, relevant for
/// 10Gb/s infrastructure planning.
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
        Cell::new("Classical (B)").add_attribute(Attribute::Bold),
        Cell::new("PQ-OLM (B)").add_attribute(Attribute::Bold),
        Cell::new("Δ Bytes").add_attribute(Attribute::Bold),
        Cell::new("Overhead %").add_attribute(Attribute::Bold),
        Cell::new("SPQR KEM CTs").add_attribute(Attribute::Bold),
    ]);

    for &n in conversation_lengths {
        // ── Classical: 1 PreKey + (n-1) Normal ──
        let (_, _, mut c_alice, _c_bob) = helpers::create_classical_session_pair();
        let mut classical_total: usize = 0;

        for _ in 0..n {
            let msg = c_alice.encrypt(&plaintext);
            let ct_bytes = helpers::olm_message_bytes(&msg);
            classical_total += ct_bytes.len();
            // Add JSON framing overhead estimate (algorithm, sender_key, type fields)
            classical_total += 120; // ~120 bytes JSON envelope
        }

        // ── PQ-OLM: 1 PreKey + (n-1) Normal + SPQR KEM CTs ──
        let (_, _, mut p_alice, _p_bob, _pk, _sk) = helpers::create_pqxdh_session_pair();
        let mut pq_total: usize = 0;
        let mut spqr_kem_count: usize = 0;

        // First message includes KEM ciphertext for PQXDH handshake
        pq_total += kem_ct_size; // Initial PQXDH KEM CT

        for _ in 0..n {
            let (msg, spqr_ct) = p_alice.encrypt_pq(&plaintext);
            let ct_bytes = helpers::olm_message_bytes(&msg);
            pq_total += ct_bytes.len();
            pq_total += 140; // ~140 bytes JSON envelope (has kem fields)

            if let Some(ref sct) = spqr_ct {
                pq_total += sct.len();
                spqr_kem_count += 1;
            }

            // Account for the SPQR overhead that WOULD exist if not stubbed:
            // Every 50th message sends a 1088-byte KEM ciphertext
            // We track the "would-be" count for projection purposes
        }

        // Projected SPQR KEM count (even though stubbed)
        let projected_spqr_count = if n >= 50 { n / 50 } else { 0 };
        let projected_spqr_bytes = projected_spqr_count * kem_ct_size;

        let delta = pq_total as i64 - classical_total as i64;
        let overhead_pct = if classical_total > 0 {
            (delta as f64 / classical_total as f64) * 100.0
        } else {
            0.0
        };

        table.add_row(vec![
            Cell::new(n.to_string()),
            Cell::new(format_bytes(classical_total)),
            Cell::new(format_bytes(pq_total)),
            Cell::new(format!("+{}", format_bytes(delta as usize))),
            Cell::new(format!("{:.1}%", overhead_pct)),
            Cell::new(format!("{} (actual) / {} (projected)",
                spqr_kem_count, projected_spqr_count)),
        ]);

        json_rows.push(serde_json::json!({
            "message_count": n,
            "classical_bytes": classical_total,
            "pq_bytes": pq_total,
            "delta_bytes": delta,
            "overhead_pct": overhead_pct,
            "spqr_kem_actual": spqr_kem_count,
            "spqr_kem_projected": projected_spqr_count,
            "projected_spqr_extra_bytes": projected_spqr_bytes,
        }));
    }

    println!("  Bandwidth per Conversation ({} B plaintext/msg)", plaintext_size);
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
        Cell::new("Classical/Month").add_attribute(Attribute::Bold),
        Cell::new("PQ-OLM/Month").add_attribute(Attribute::Bold),
        Cell::new("Extra/Month").add_attribute(Attribute::Bold),
        Cell::new("10Gb/s Util %").add_attribute(Attribute::Bold),
    ]);

    let mut json_monthly = Vec::new();

    // Use average bytes-per-message from the 100-message benchmark
    let (_, _, mut c_test, _) = helpers::create_classical_session_pair();
    let c_msg = c_test.encrypt(&plaintext);
    let c_avg_bytes = helpers::olm_message_bytes(&c_msg).len() + 120;

    let (_, _, mut p_test, _, _, _) = helpers::create_pqxdh_session_pair();
    let (p_msg, _) = p_test.encrypt_pq(&plaintext);
    let p_avg_bytes = helpers::olm_message_bytes(&p_msg).len() + 140;

    // Add amortized PQXDH overhead: KEM CT per session + SPQR KEM CT every 50
    let pq_per_msg_extra = kem_ct_size as f64 / 100.0 // Amortized session setup over ~100 msgs
        + (kem_ct_size as f64 / 50.0); // SPQR every 50th message (projected)

    for &daily in daily_rates {
        let monthly = daily * 30;
        let c_monthly_bytes = monthly * c_avg_bytes;
        let p_monthly_bytes = monthly * p_avg_bytes + (monthly as f64 * pq_per_msg_extra) as usize;
        let extra = p_monthly_bytes as i64 - c_monthly_bytes as i64;

        // 10Gb/s = 1.25 GB/s = ~3.24 PB/month
        let ten_gbps_monthly = 1_250_000_000.0 * 3600.0 * 24.0 * 30.0;
        let util_pct = (p_monthly_bytes as f64 / ten_gbps_monthly) * 100.0;

        monthly_table.add_row(vec![
            Cell::new(format!("{}", daily)),
            Cell::new(format_bytes_large(c_monthly_bytes)),
            Cell::new(format_bytes_large(p_monthly_bytes)),
            Cell::new(format!("+{}", format_bytes_large(extra as usize))),
            Cell::new(format!("{:.6}%", util_pct)),
        ]);

        json_monthly.push(serde_json::json!({
            "msgs_per_day": daily,
            "classical_monthly_bytes": c_monthly_bytes,
            "pq_monthly_bytes": p_monthly_bytes,
            "extra_monthly_bytes": extra,
            "ten_gbps_utilization_pct": util_pct,
        }));
    }

    println!("  Monthly Bandwidth Projection (per user)");
    println!("{monthly_table}");

    // Key upload size comparison
    println!("\n  One-Time Key Upload Overhead:");
    println!("    Classical bundle: ~96 B (IK + OTK + signing key)");
    println!("    PQ-OLM bundle:   ~{} B (+ SPK 32B + sig 64B + KEM PK {} B)",
        96 + 32 + 64 + kem_pk_size, kem_pk_size);
    println!("    Upload overhead:  +{} B ({:.1}x)",
        32 + 64 + kem_pk_size,
        (96 + 32 + 64 + kem_pk_size) as f64 / 96.0);

    serde_json::json!({
        "per_conversation": json_rows,
        "monthly_projection": json_monthly,
        "config": {
            "plaintext_size": plaintext_size,
            "kem_ct_size": kem_ct_size,
            "kem_pk_size": kem_pk_size,
            "spqr_interval": 50,
            "spqr_stubbed": true,
        },
    })
}

fn format_bytes(b: usize) -> String {
    if b < 1024 {
        format!("{} B", b)
    } else if b < 1024 * 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{:.2} MB", b as f64 / (1024.0 * 1024.0))
    }
}

fn format_bytes_large(b: usize) -> String {
    if b < 1024 {
        format!("{} B", b)
    } else if b < 1024 * 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else if b < 1024 * 1024 * 1024 {
        format!("{:.2} MB", b as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", b as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
