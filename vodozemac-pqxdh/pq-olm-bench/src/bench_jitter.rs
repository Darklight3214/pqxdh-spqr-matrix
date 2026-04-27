use std::hint::black_box;
use std::time::Instant;
use crate::helpers;
use crate::stats::BenchResult;
use crate::output;

/// Metric #10: Latency Jitter — X3DH+DR vs PQXDH+SPQR distribution analysis
///
/// Production-grade jitter analysis:
/// - Large sample collection for statistical significance
/// - IQR-based outlier detection
/// - Bimodality coefficient (BC) using skewness and kurtosis
/// - Tail latency analysis (P99, P99.9)
/// - Jitter budget calculation for real-time requirements
pub fn run(iterations: usize, warmup: usize) -> serde_json::Value {
    let plaintext = helpers::make_plaintext(256);

    // ═══════════════════════════════════════════
    //  X3DH + Double Ratchet: collect large sample set
    // ═══════════════════════════════════════════
    let mut classical_samples = Vec::with_capacity(iterations);
    {
        let (_, _, mut alice_sess, mut bob_sess) = helpers::create_classical_session_pair();
        for i in 0..(warmup + iterations) {
            let t0 = Instant::now();
            let msg = black_box(alice_sess.encrypt(&plaintext));
            let _ = black_box(bob_sess.decrypt(&msg).unwrap());
            let elapsed = t0.elapsed();
            if i >= warmup {
                classical_samples.push(elapsed.as_nanos() as f64);
            }
        }
    }

    // ═══════════════════════════════════════════
    //  PQXDH + SPQR Triple Ratchet: collect large sample set
    // ═══════════════════════════════════════════
    let mut pq_samples = Vec::with_capacity(iterations);
    {
        let (_, _, mut alice_sess, mut bob_sess, _pk, _sk) =
            helpers::create_pqxdh_session_pair();
        let mut pending_braid: Vec<vodozemac::olm::BraidMessage> = Vec::new();
        for i in 0..(warmup + iterations) {
            let t0 = Instant::now();
            let wire = black_box(alice_sess.encrypt_pq(&plaintext));
            let mut braid_in = wire.braid_msgs;
            braid_in.extend(pending_braid.drain(..));
            match bob_sess.decrypt_pq(
                &wire.message,
                wire.spqr_meta.as_ref(),
                &braid_in,
            ) {
                Ok((_, resp_braid)) => {
                    pending_braid.extend(resp_braid);
                }
                Err(_) => {
                    let _ = bob_sess.decrypt(&wire.message);
                }
            }
            let elapsed = t0.elapsed();
            if i >= warmup {
                pq_samples.push(elapsed.as_nanos() as f64);
            }
        }
    }

    // ═══════════════════════════════════════════
    //  Statistical analysis
    // ═══════════════════════════════════════════
    let cr = BenchResult::new("X3DH+DR Encrypt+Decrypt", "ns", classical_samples.clone());
    let pr = BenchResult::new("PQXDH+SPQR Encrypt+Decrypt", "ns", pq_samples.clone());

    output::print_comparison_table("Latency Jitter (256B): X3DH+DR vs PQXDH+SPQR", &cr, &pr);

    // Detailed jitter analysis
    let c_jitter = analyze_jitter(&classical_samples);
    let p_jitter = analyze_jitter(&pq_samples);

    // Print jitter-specific analysis
    println!("\n  Jitter Analysis: X3DH+DR vs PQXDH+SPQR");
    println!("  ┌─────────────────────────┬────────────────┬────────────────┐");
    println!("  │ Metric                  │ X3DH+DR        │ PQXDH+SPQR     │");
    println!("  ├─────────────────────────┼────────────────┼────────────────┤");
    println!("  │ CV (Coeff. of Var.)     │ {:<14.4} │ {:<14.4} │",
        c_jitter.cv, p_jitter.cv);
    println!("  │ IQR                     │ {:<14.1} │ {:<14.1} │",
        c_jitter.iqr, p_jitter.iqr);
    println!("  │ P99/P50 Ratio           │ {:<14.2} │ {:<14.2} │",
        c_jitter.p99_p50_ratio, p_jitter.p99_p50_ratio);
    println!("  │ P99.9 (ns)              │ {:<14.1} │ {:<14.1} │",
        c_jitter.p999, p_jitter.p999);
    println!("  │ Bimodality Coeff.       │ {:<14.4} │ {:<14.4} │",
        c_jitter.bimodality_coefficient, p_jitter.bimodality_coefficient);
    println!("  │ Bimodal?                │ {:<14} │ {:<14} │",
        if c_jitter.is_bimodal { "YES" } else { "NO" },
        if p_jitter.is_bimodal { "YES" } else { "NO" });
    println!("  │ Outliers (IQR method)   │ {:<14} │ {:<14} │",
        c_jitter.outlier_count, p_jitter.outlier_count);
    println!("  │ Outlier %               │ {:<14.2} │ {:<14.2} │",
        c_jitter.outlier_pct, p_jitter.outlier_pct);
    println!("  │ Jitter (max-min)        │ {:<14.1} │ {:<14.1} │",
        c_jitter.jitter_range, p_jitter.jitter_range);
    println!("  │ Jitter (P95-P5)         │ {:<14.1} │ {:<14.1} │",
        c_jitter.jitter_p95_p5, p_jitter.jitter_p95_p5);
    println!("  └─────────────────────────┴────────────────┴────────────────┘");

    // Stability assessment
    println!("\n  Stability Assessment:");
    let c_stable = c_jitter.cv < 0.1 && !c_jitter.is_bimodal;
    let p_stable = p_jitter.cv < 0.1 && !p_jitter.is_bimodal;
    println!("    X3DH+DR:    {} (CV={:.4}, bimodal={})",
        if c_stable { "STABLE" } else { "VARIABLE" },
        c_jitter.cv, c_jitter.is_bimodal);
    println!("    PQXDH+SPQR: {} (CV={:.4}, bimodal={})",
        if p_stable { "STABLE" } else { "VARIABLE" },
        p_jitter.cv, p_jitter.is_bimodal);

    // Histogram buckets for distribution shape
    let c_hist = histogram(&classical_samples, 10);
    let p_hist = histogram(&pq_samples, 10);

    println!("\n  X3DH+DR Latency Distribution:");
    print_histogram(&c_hist);
    println!("\n  PQXDH+SPQR Latency Distribution:");
    print_histogram(&p_hist);

    serde_json::json!({
        "x3dh_dr": {
            "summary": cr.summary(),
            "samples": cr.samples,
            "jitter": {
                "cv": c_jitter.cv,
                "iqr": c_jitter.iqr,
                "p99_p50_ratio": c_jitter.p99_p50_ratio,
                "p999": c_jitter.p999,
                "bimodality_coefficient": c_jitter.bimodality_coefficient,
                "is_bimodal": c_jitter.is_bimodal,
                "outlier_count": c_jitter.outlier_count,
                "outlier_pct": c_jitter.outlier_pct,
                "jitter_range": c_jitter.jitter_range,
                "jitter_p95_p5": c_jitter.jitter_p95_p5,
            },
            "histogram": c_hist,
        },
        "pqxdh_spqr": {
            "summary": pr.summary(),
            "samples": pr.samples,
            "jitter": {
                "cv": p_jitter.cv,
                "iqr": p_jitter.iqr,
                "p99_p50_ratio": p_jitter.p99_p50_ratio,
                "p999": p_jitter.p999,
                "bimodality_coefficient": p_jitter.bimodality_coefficient,
                "is_bimodal": p_jitter.is_bimodal,
                "outlier_count": p_jitter.outlier_count,
                "outlier_pct": p_jitter.outlier_pct,
                "jitter_range": p_jitter.jitter_range,
                "jitter_p95_p5": p_jitter.jitter_p95_p5,
            },
            "histogram": p_hist,
        },
    })
}

struct JitterAnalysis {
    cv: f64,
    iqr: f64,
    p99_p50_ratio: f64,
    p999: f64,
    bimodality_coefficient: f64,
    is_bimodal: bool,
    outlier_count: usize,
    outlier_pct: f64,
    jitter_range: f64,
    jitter_p95_p5: f64,
}

fn analyze_jitter(samples: &[f64]) -> JitterAnalysis {
    if samples.is_empty() {
        return JitterAnalysis {
            cv: 0.0, iqr: 0.0, p99_p50_ratio: 0.0, p999: 0.0,
            bimodality_coefficient: 0.0, is_bimodal: false,
            outlier_count: 0, outlier_pct: 0.0,
            jitter_range: 0.0, jitter_p95_p5: 0.0,
        };
    }

    let n = samples.len() as f64;
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let mean: f64 = sorted.iter().sum::<f64>() / n;
    let variance: f64 = sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let std_dev = variance.sqrt();
    let cv = if mean > 0.0 { std_dev / mean } else { 0.0 };

    // Percentiles
    let p = |pct: f64| -> f64 {
        let idx = (pct / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    };

    let p5 = p(5.0);
    let p25 = p(25.0);
    let p50 = p(50.0);
    let p75 = p(75.0);
    let p95 = p(95.0);
    let p99 = p(99.0);
    let p999 = p(99.9);

    let iqr = p75 - p25;
    let p99_p50_ratio = if p50 > 0.0 { p99 / p50 } else { 0.0 };

    // IQR-based outlier detection (1.5 × IQR)
    let lower_fence = p25 - 1.5 * iqr;
    let upper_fence = p75 + 1.5 * iqr;
    let outlier_count = sorted.iter()
        .filter(|&&x| x < lower_fence || x > upper_fence)
        .count();
    let outlier_pct = (outlier_count as f64 / n) * 100.0;

    // Bimodality coefficient: BC = (skewness² + 1) / (kurtosis + 3 × (n-1)²/((n-2)×(n-3)))
    let skewness = if std_dev > 0.0 {
        sorted.iter().map(|x| ((x - mean) / std_dev).powi(3)).sum::<f64>() / n
    } else {
        0.0
    };
    let kurtosis = if std_dev > 0.0 {
        sorted.iter().map(|x| ((x - mean) / std_dev).powi(4)).sum::<f64>() / n - 3.0
    } else {
        0.0
    };

    let n_val = samples.len() as f64;
    let bc = if n_val > 3.0 {
        let numerator = skewness.powi(2) + 1.0;
        let excess_kurtosis_adj = kurtosis + 3.0 * (n_val - 1.0).powi(2)
            / ((n_val - 2.0) * (n_val - 3.0));
        if excess_kurtosis_adj > 0.0 {
            numerator / excess_kurtosis_adj
        } else {
            0.0
        }
    } else {
        0.0
    };

    let is_bimodal = bc > 0.555;

    JitterAnalysis {
        cv,
        iqr,
        p99_p50_ratio,
        p999,
        bimodality_coefficient: bc,
        is_bimodal,
        outlier_count,
        outlier_pct,
        jitter_range: sorted.last().unwrap_or(&0.0) - sorted.first().unwrap_or(&0.0),
        jitter_p95_p5: p95 - p5,
    }
}

fn histogram(samples: &[f64], buckets: usize) -> Vec<serde_json::Value> {
    if samples.is_empty() || buckets == 0 {
        return vec![];
    }

    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    // Use P5 to P95 range to avoid outlier-dominated buckets
    let p5_idx = (0.05 * (sorted.len() as f64 - 1.0)).round() as usize;
    let p95_idx = (0.95 * (sorted.len() as f64 - 1.0)).round() as usize;
    let min = sorted[p5_idx];
    let max = sorted[p95_idx];

    if (max - min).abs() < f64::EPSILON {
        return vec![serde_json::json!({"range": format!("{:.0}", min), "count": samples.len()})];
    }

    let width = (max - min) / buckets as f64;
    let mut counts = vec![0usize; buckets];

    for &v in samples {
        if v < min { counts[0] += 1; continue; }
        if v >= max { counts[buckets - 1] += 1; continue; }
        let idx = ((v - min) / width) as usize;
        counts[idx.min(buckets - 1)] += 1;
    }

    counts.iter().enumerate().map(|(i, &c)| {
        let lo = min + i as f64 * width;
        let hi = lo + width;
        serde_json::json!({
            "range_ns": format!("{:.0}-{:.0}", lo, hi),
            "count": c,
            "pct": (c as f64 / samples.len() as f64) * 100.0,
        })
    }).collect()
}

fn print_histogram(buckets: &[serde_json::Value]) {
    let max_count = buckets.iter()
        .filter_map(|b| b["count"].as_u64())
        .max()
        .unwrap_or(1) as f64;

    for bucket in buckets {
        let range = bucket["range_ns"].as_str().unwrap_or("?");
        let count = bucket["count"].as_u64().unwrap_or(0);
        let pct = bucket["pct"].as_f64().unwrap_or(0.0);
        let bar_len = ((count as f64 / max_count) * 30.0) as usize;
        let bar: String = "█".repeat(bar_len);
        println!("    {:>20} │ {:>5} ({:>5.1}%) {}", range, count, pct, bar);
    }
}
