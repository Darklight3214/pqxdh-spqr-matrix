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
    // Extract any BenchResult-like data and write as CSV
    let csv_path = out_dir.join(format!("{}.csv", name));
    if let Some(obj) = result.as_object() {
        let mut wtr = match csv::Writer::from_path(&csv_path) {
            Ok(w) => w,
            Err(_) => return,
        };
        // Write flattened stats
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
