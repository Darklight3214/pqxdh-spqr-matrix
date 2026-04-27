use std::path::Path;
use comfy_table::{Table, Cell, Attribute, ContentArrangement};
use crate::stats::{BenchResult, format_duration_ns};

/// Print a side-by-side comparison table to the terminal.
pub fn print_comparison_table(
    title: &str,
    classical: &BenchResult,
    pq: &BenchResult,
) {
    let cs = classical.summary();
    let ps = pq.summary();

    let fmt = |v: f64, unit: &str| -> String {
        if unit == "ns" { format_duration_ns(v) }
        else { format!("{:.2} {}", v, unit) }
    };

    let overhead_factor = if cs.mean > 0.0 { ps.mean / cs.mean } else { 0.0 };

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Statistic").add_attribute(Attribute::Bold),
        Cell::new(&format!("Classical ({})", classical.label)).add_attribute(Attribute::Bold),
        Cell::new(&format!("PQ ({})", pq.label)).add_attribute(Attribute::Bold),
        Cell::new("Overhead").add_attribute(Attribute::Bold),
    ]);

    let u = &classical.unit;
    let rows: Vec<(&str, f64, f64)> = vec![
        ("Min", cs.min, ps.min),
        ("Max", cs.max, ps.max),
        ("Mean", cs.mean, ps.mean),
        ("Median", cs.median, ps.median),
        ("Std Dev", cs.std_dev, ps.std_dev),
        ("P50", cs.p50, ps.p50),
        ("P95", cs.p95, ps.p95),
        ("P99", cs.p99, ps.p99),
    ];

    for (label, cv, pv) in &rows {
        let ov = if *cv > 0.0 { format!("{:.2}x", pv / cv) } else { "—".into() };
        table.add_row(vec![
            Cell::new(label),
            Cell::new(fmt(*cv, u)),
            Cell::new(fmt(*pv, u)),
            Cell::new(ov),
        ]);
    }

    // 95% CI row
    let c_ci = format!("[{}, {}]", fmt(cs.ci_95.0, u), fmt(cs.ci_95.1, u));
    let p_ci = format!("[{}, {}]", fmt(ps.ci_95.0, u), fmt(ps.ci_95.1, u));
    table.add_row(vec![
        Cell::new("95% CI"),
        Cell::new(c_ci),
        Cell::new(p_ci),
        Cell::new("—"),
    ]);

    table.add_row(vec![
        Cell::new("Samples"),
        Cell::new(cs.count.to_string()),
        Cell::new(ps.count.to_string()),
        Cell::new(format!("{:.2}x (mean)", overhead_factor)),
    ]);

    println!("\n  {}", title);
    println!("{table}");
}

/// Print a single-result table.
pub fn print_single_table(title: &str, result: &BenchResult) {
    let s = result.summary();

    let fmt = |v: f64| -> String {
        if result.unit == "ns" { format_duration_ns(v) }
        else { format!("{:.2} {}", v, result.unit) }
    };

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Statistic").add_attribute(Attribute::Bold),
        Cell::new(&result.label).add_attribute(Attribute::Bold),
    ]);

    table.add_row(vec!["Min", &fmt(s.min)]);
    table.add_row(vec!["Max", &fmt(s.max)]);
    table.add_row(vec!["Mean", &fmt(s.mean)]);
    table.add_row(vec!["Median", &fmt(s.median)]);
    table.add_row(vec!["Std Dev", &fmt(s.std_dev)]);
    table.add_row(vec!["P95", &fmt(s.p95)]);
    table.add_row(vec!["P99", &fmt(s.p99)]);
    let ci_str = format!("[{}, {}]", fmt(s.ci_95.0), fmt(s.ci_95.1));
    table.add_row(vec!["95% CI", &ci_str]);
    table.add_row(vec!["Samples", &s.count.to_string()]);

    println!("\n  {}", title);
    println!("{table}");
}

/// Print a static key-value table (for sizes, security properties, etc.)
pub fn print_kv_table(title: &str, rows: &[(&str, &str, &str)]) {
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Property").add_attribute(Attribute::Bold),
        Cell::new("Classical").add_attribute(Attribute::Bold),
        Cell::new("PQ-OLM").add_attribute(Attribute::Bold),
    ]);
    for (prop, classical, pq) in rows {
        table.add_row(vec![*prop, *classical, *pq]);
    }
    println!("\n  {}", title);
    println!("{table}");
}

/// Write a metric result to CSV
pub fn write_metric_csv(out_dir: &Path, name: &str, result: &serde_json::Value) {
    let csv_path = out_dir.join(format!("{}.csv", name));
    if let Some(obj) = result.as_object() {
        let mut wtr = match csv::Writer::from_path(&csv_path) {
            Ok(w) => w,
            Err(_) => return,
        };
        for (key, val) in obj {
            if let Some(summary) = val.get("summary") {
                let _ = wtr.write_record(&["metric", "label", "stat", "value"]);
                if let Some(sm) = summary.as_object() {
                    for (sk, sv) in sm {
                        let _ = wtr.write_record(&[name, key, sk, &sv.to_string()]);
                    }
                }
            }
        }
        let _ = wtr.flush();
    }
}

/// Write a full report text file with ALL raw sample data + summary statistics.
///
/// Format:
///   - Header with metric name, timestamp, iterations
///   - Raw samples section: one timing per line (nanoseconds)
///   - Summary statistics section: mean, median, CI, etc.
///   - Comparison if two datasets provided
pub fn write_full_report(
    out_dir: &Path,
    metric_name: &str,
    datasets: &[(&BenchResult, &str)],  // (result, label) pairs
) {
    use std::io::Write;
    let path = out_dir.join(format!("{}_full.txt", metric_name));
    let mut f = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(_) => return,
    };

    let ts = {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        format!("unix_epoch+{}s", d.as_secs())
    };

    let _ = writeln!(f, "═══════════════════════════════════════════════════════════════");
    let _ = writeln!(f, "  {} — Full Benchmark Report", metric_name);
    let _ = writeln!(f, "  Generated: {}", ts);
    let _ = writeln!(f, "═══════════════════════════════════════════════════════════════");

    for (result, label) in datasets {
        let s = result.summary();
        let _ = writeln!(f, "");
        let _ = writeln!(f, "───────────────────────────────────────────────────────────────");
        let _ = writeln!(f, "  {} — {} (unit: {})", label, result.label, result.unit);
        let _ = writeln!(f, "───────────────────────────────────────────────────────────────");
        let _ = writeln!(f, "");
        let _ = writeln!(f, "  RAW SAMPLES ({} values, unit: {}):", result.samples.len(), result.unit);
        let _ = writeln!(f, "  ────────────────────────────────");

        // Write all raw samples, 10 per line for readability
        for (i, chunk) in result.samples.chunks(10).enumerate() {
            let vals: Vec<String> = chunk.iter().map(|v| format!("{:.0}", v)).collect();
            let _ = writeln!(f, "  [{:>5}-{:>5}] {}", i * 10, i * 10 + chunk.len() - 1, vals.join(", "));
        }

        let _ = writeln!(f, "");
        let _ = writeln!(f, "  SUMMARY STATISTICS:");
        let _ = writeln!(f, "  ──────────────────");
        let _ = writeln!(f, "  Count          : {}", s.count);
        let _ = writeln!(f, "  Mean           : {} ({:.2} ns)", format_duration_ns(s.mean), s.mean);
        let _ = writeln!(f, "  Median         : {} ({:.2} ns)", format_duration_ns(s.median), s.median);
        let _ = writeln!(f, "  Std Dev        : {} ({:.2} ns)", format_duration_ns(s.std_dev), s.std_dev);
        let _ = writeln!(f, "  CV             : {:.4}", s.cv);
        let _ = writeln!(f, "  Min            : {} ({:.2} ns)", format_duration_ns(s.min), s.min);
        let _ = writeln!(f, "  Max            : {} ({:.2} ns)", format_duration_ns(s.max), s.max);
        let _ = writeln!(f, "  P5             : {} ({:.2} ns)", format_duration_ns(s.p5), s.p5);
        let _ = writeln!(f, "  P25            : {} ({:.2} ns)", format_duration_ns(s.p25), s.p25);
        let _ = writeln!(f, "  P50            : {} ({:.2} ns)", format_duration_ns(s.p50), s.p50);
        let _ = writeln!(f, "  P75            : {} ({:.2} ns)", format_duration_ns(s.p75), s.p75);
        let _ = writeln!(f, "  P95            : {} ({:.2} ns)", format_duration_ns(s.p95), s.p95);
        let _ = writeln!(f, "  P99            : {} ({:.2} ns)", format_duration_ns(s.p99), s.p99);
        let _ = writeln!(f, "  95% CI         : [{}, {}]",
            format_duration_ns(s.ci_95.0), format_duration_ns(s.ci_95.1));
        let _ = writeln!(f, "  Ops/sec        : {:.1}", s.ops_per_sec);
    }

    // If we have exactly 2 datasets, print comparison
    if datasets.len() == 2 {
        let (r1, l1) = &datasets[0];
        let (r2, l2) = &datasets[1];
        let s1 = r1.summary();
        let s2 = r2.summary();
        let overhead = if s1.mean > 0.0 { s2.mean / s1.mean } else { 0.0 };

        let _ = writeln!(f, "");
        let _ = writeln!(f, "───────────────────────────────────────────────────────────────");
        let _ = writeln!(f, "  COMPARISON: {} vs {}", l1, l2);
        let _ = writeln!(f, "───────────────────────────────────────────────────────────────");
        let _ = writeln!(f, "  Mean overhead          : {:.2}x", overhead);
        let _ = writeln!(f, "  Mean delta             : {} ({:.2} ns)",
            format_duration_ns(s2.mean - s1.mean), s2.mean - s1.mean);
        let _ = writeln!(f, "  Median overhead        : {:.2}x",
            if s1.median > 0.0 { s2.median / s1.median } else { 0.0 });
        let _ = writeln!(f, "  P99 overhead           : {:.2}x",
            if s1.p99 > 0.0 { s2.p99 / s1.p99 } else { 0.0 });
        let _ = writeln!(f, "  Ops/sec {} : {:.1}", l1, s1.ops_per_sec);
        let _ = writeln!(f, "  Ops/sec {} : {:.1}", l2, s2.ops_per_sec);
        let _ = writeln!(f, "  Throughput ratio       : {:.2}x",
            if s2.ops_per_sec > 0.0 { s1.ops_per_sec / s2.ops_per_sec } else { 0.0 });
    }

    let _ = writeln!(f, "");
    let _ = writeln!(f, "═══════════════════════════════════════════════════════════════");
    let _ = writeln!(f, "  END OF REPORT");
    let _ = writeln!(f, "═══════════════════════════════════════════════════════════════");
}

