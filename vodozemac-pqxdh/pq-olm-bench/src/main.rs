mod stats;
mod output;
mod helpers;
mod bench_handshake;
mod bench_ratchet;
mod bench_message_size;
mod bench_security;
mod bench_encrypt_decrypt;
mod bench_key_sizes;
mod bench_kem;
mod bench_e2e;
mod bench_bandwidth;
mod bench_jitter;
mod bench_megolm;
mod bench_memory;
mod bench_scaling;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pq-olm-bench", about = "Benchmark suite: Classical OLM vs PQ-OLM (PQXDH + SPQR)")]
struct Cli {
    /// Number of iterations per benchmark
    #[arg(long, default_value = "1000")]
    iterations: usize,

    /// Warmup iterations (not counted)
    #[arg(long, default_value = "200")]
    warmup: usize,

    /// Comma-separated metric numbers (1-13) or "all"
    #[arg(long, default_value = "all")]
    metrics: String,

    /// Conduit server URL for E2E benchmark (metric 8). Optional.
    #[arg(long)]
    conduit_url: Option<String>,

    /// User credentials for E2E benchmark, format: "user1:pass1,user2:pass2,..."
    /// At least 2 users required for E2E. If not specified, defaults to alice:alice123,bob:bob123
    #[arg(long, default_value = "alice:alice123,bob:bob123")]
    users: String,

    /// Number of user pairs to test in E2E benchmark.
    /// Each pair creates independent sessions. 0 = all possible pairs.
    #[arg(long, default_value = "0")]
    e2e_pairs: usize,

    /// Number of concurrent sessions per user pair in crypto benchmarks (1-7, 9-13).
    /// Tests scaling behavior under multi-session load.
    #[arg(long, default_value = "1")]
    sessions: usize,

    /// Pin benchmark thread to CPU core 0 for consistent measurements
    #[arg(long, default_value = "true")]
    pin_cpu: bool,

    /// Output directory for CSV/JSON results
    #[arg(long, default_value = "./results")]
    output_dir: String,
}

/// Parse "user:pass" pairs from the --users CLI argument.
fn parse_users(users_str: &str) -> Vec<(String, String)> {
    users_str
        .split(',')
        .filter_map(|pair| {
            let mut parts = pair.trim().splitn(2, ':');
            let user = parts.next()?.trim().to_string();
            let pass = parts.next()?.trim().to_string();
            if user.is_empty() || pass.is_empty() {
                None
            } else {
                Some((user, pass))
            }
        })
        .collect()
}

/// Collect system info for results metadata
fn system_info() -> serde_json::Value {
    serde_json::json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "rustc": env!("CARGO_PKG_VERSION"),
        "bench_version": "0.2.0",
    })
}

fn main() {
    let cli = Cli::parse();

    // CPU pinning for consistent measurements
    if cli.pin_cpu {
        if let Some(core_ids) = core_affinity::get_core_ids() {
            if let Some(first) = core_ids.first() {
                if core_affinity::set_for_current(*first) {
                    println!("  [cpu] Pinned to core {:?}", first);
                } else {
                    println!("  [cpu] Warning: failed to pin to core 0");
                }
            }
        }
    }

    let metrics: Vec<usize> = if cli.metrics == "all" {
        (1..=13).collect()
    } else {
        cli.metrics
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    };

    let users = parse_users(&cli.users);
    if users.is_empty() {
        eprintln!("Error: no valid user credentials. Use --users 'user1:pass1,user2:pass2'");
        std::process::exit(1);
    }

    let _ = std::fs::create_dir_all(&cli.output_dir);
    let out_dir = PathBuf::from(&cli.output_dir);

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          pq-olm-bench v0.2  —  PQ-OLM Benchmark Suite  ║");
    println!("║       Classical OLM (X3DH) vs PQ-OLM (PQXDH+SPQR)     ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Iterations: {:<6}  Warmup: {:<6}                     ║", cli.iterations, cli.warmup);
    println!("║  Sessions:   {:<6}  Users:  {:<6}                     ║", cli.sessions, users.len());
    println!("║  Metrics:    {:<43}║", cli.metrics);
    println!("║  Output:     {:<43}║", cli.output_dir);
    println!("║  CPU pin:    {:<43}║", if cli.pin_cpu { "yes" } else { "no" });
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    let mut all_results = serde_json::Map::new();
    all_results.insert("_system_info".into(), system_info());

    for metric in &metrics {
        match metric {
            1 => {
                println!("\n━━━ Metric #1: Handshake Time (PQXDH vs X3DH) ━━━");
                let result = bench_handshake::run(cli.iterations, cli.warmup);
                output::write_metric_csv(&out_dir, "01_handshake", &result);
                all_results.insert("01_handshake".into(), result);
            }
            2 => {
                println!("\n━━━ Metric #2: Ratchet Step Time (SPQR vs Classical DR) ━━━");
                let result = bench_ratchet::run(cli.iterations, cli.warmup);
                output::write_metric_csv(&out_dir, "02_ratchet", &result);
                all_results.insert("02_ratchet".into(), result);
            }
            3 => {
                println!("\n━━━ Metric #3: Message Size on Wire ━━━");
                let result = bench_message_size::run();
                output::write_metric_csv(&out_dir, "03_message_size", &result);
                all_results.insert("03_message_size".into(), result);
            }
            4 => {
                println!("\n━━━ Metric #4: Security Level Comparison ━━━");
                let result = bench_security::run();
                all_results.insert("04_security".into(), result);
            }
            5 => {
                println!("\n━━━ Metric #5: Encrypt/Decrypt Time ━━━");
                let result = bench_encrypt_decrypt::run(cli.iterations, cli.warmup);
                output::write_metric_csv(&out_dir, "05_encrypt_decrypt", &result);
                all_results.insert("05_encrypt_decrypt".into(), result);
            }
            6 => {
                println!("\n━━━ Metric #6: Key & Bundle Sizes ━━━");
                let result = bench_key_sizes::run();
                all_results.insert("06_key_sizes".into(), result);
            }
            7 => {
                println!("\n━━━ Metric #7: KEM Primitive Times ━━━");
                let result = bench_kem::run(cli.iterations, cli.warmup);
                output::write_metric_csv(&out_dir, "07_kem_primitives", &result);
                all_results.insert("07_kem_primitives".into(), result);
            }
            8 => {
                println!("\n━━━ Metric #8: End-to-End Latency (via Conduit) ━━━");
                if let Some(ref url) = cli.conduit_url {
                    if users.len() < 2 {
                        println!("  [skip] E2E requires at least 2 users. Got {}.", users.len());
                        all_results.insert("08_e2e_latency".into(),
                            serde_json::json!({"skipped": true, "reason": "need >= 2 users"}));
                    } else {
                        let result = bench_e2e::run(
                            url,
                            &users,
                            cli.e2e_pairs,
                            cli.iterations.min(50),
                            cli.warmup.min(5),
                        );
                        output::write_metric_csv(&out_dir, "08_e2e_latency", &result);
                        all_results.insert("08_e2e_latency".into(), result);
                    }
                } else {
                    println!("  [skip] No --conduit-url provided. Skipping E2E benchmark.");
                    all_results.insert("08_e2e_latency".into(),
                        serde_json::json!({"skipped": true, "reason": "no --conduit-url"}));
                }
            }
            9 => {
                println!("\n━━━ Metric #9: Bandwidth Consumption ━━━");
                let result = bench_bandwidth::run();
                all_results.insert("09_bandwidth".into(), result);
            }
            10 => {
                println!("\n━━━ Metric #10: Latency Jitter ━━━");
                let result = bench_jitter::run(cli.iterations, cli.warmup);
                output::write_metric_csv(&out_dir, "10_jitter", &result);
                all_results.insert("10_jitter".into(), result);
            }
            11 => {
                println!("\n━━━ Metric #11: Megolm Group Encryption ━━━");
                let result = bench_megolm::run(cli.iterations, cli.warmup);
                output::write_metric_csv(&out_dir, "11_megolm", &result);
                all_results.insert("11_megolm".into(), result);
            }
            12 => {
                println!("\n━━━ Metric #12: Memory Footprint ━━━");
                let result = bench_memory::run();
                all_results.insert("12_memory".into(), result);
            }
            13 => {
                println!("\n━━━ Metric #13: Multi-Session Scaling ━━━");
                let result = bench_scaling::run(cli.iterations.min(200), cli.warmup.min(20));
                output::write_metric_csv(&out_dir, "13_scaling", &result);
                all_results.insert("13_scaling".into(), result);
            }
            _ => {
                println!("  [warn] Unknown metric: {}", metric);
            }
        }
    }

    // Write combined JSON (includes all summary stats)
    let json_path = out_dir.join("all_results.json");
    let json_val = serde_json::Value::Object(all_results.clone());
    let json_str = serde_json::to_string_pretty(&json_val).unwrap();
    std::fs::write(&json_path, &json_str).unwrap();
    println!("\n✓ Combined results: {}", json_path.display());

    // Write per-metric full reports with ALL raw sample data
    write_all_raw_reports(&all_results, &out_dir);

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║                   Benchmark Complete                    ║");
    println!("╚══════════════════════════════════════════════════════════╝");
}

/// Extracts raw sample data from each metric's JSON and writes comprehensive
/// text reports with every single timing value plus summary statistics.
fn write_all_raw_reports(results: &serde_json::Map<String, serde_json::Value>, out_dir: &PathBuf) {
    use std::io::Write;
    use crate::stats::format_duration_ns;

    for (metric_name, metric_data) in results {
        if metric_name.starts_with('_') { continue; } // skip _system_info

        let path = out_dir.join(format!("{}_full.txt", metric_name));
        let mut f = match std::fs::File::create(&path) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        let _ = writeln!(f, "═══════════════════════════════════════════════════════════════");
        let _ = writeln!(f, "  {} — Full Benchmark Report", metric_name);
        let _ = writeln!(f, "  Generated: {} (unix epoch + {}s)", 
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs().to_string())
                .unwrap_or_default(),
            ts.as_secs());
        let _ = writeln!(f, "═══════════════════════════════════════════════════════════════");
        let _ = writeln!(f, "");

        // Recursively extract all summary objects from the metric data
        extract_and_write_summaries(&mut f, metric_data, metric_name, 0);

        let _ = writeln!(f, "");
        let _ = writeln!(f, "═══════════════════════════════════════════════════════════════");
        let _ = writeln!(f, "  RAW JSON DATA");
        let _ = writeln!(f, "═══════════════════════════════════════════════════════════════");
        let _ = writeln!(f, "{}", serde_json::to_string_pretty(metric_data).unwrap_or_default());

        let _ = writeln!(f, "");
        let _ = writeln!(f, "═══════════════════════════════════════════════════════════════");
        let _ = writeln!(f, "  END OF REPORT");
        let _ = writeln!(f, "═══════════════════════════════════════════════════════════════");

        println!("  ✓ {}", path.display());
    }
}

/// Recursively walk JSON to find all "summary" objects and print their stats
fn extract_and_write_summaries(
    f: &mut std::fs::File,
    value: &serde_json::Value,
    path: &str,
    depth: usize,
) {
    use std::io::Write;
    use crate::stats::format_duration_ns;

    if let Some(obj) = value.as_object() {
        // Check if this object has a "summary" child
        if let Some(summary) = obj.get("summary") {
            if let Some(sm) = summary.as_object() {
                let indent = "  ".repeat(depth + 1);
                let _ = writeln!(f, "{}───────────────────────────────────────────────────────", indent);
                let _ = writeln!(f, "{}  {}", indent, path);
                let _ = writeln!(f, "{}───────────────────────────────────────────────────────", indent);

                // Print all stats
                let get_f = |key: &str| -> f64 {
                    sm.get(key).and_then(|v| v.as_f64()).unwrap_or(0.0)
                };

                let mean = get_f("mean");
                let median = get_f("median");
                let std_dev = get_f("std_dev");
                let min = get_f("min");
                let max = get_f("max");
                let p5 = get_f("p5");
                let p25 = get_f("p25");
                let p50 = get_f("p50");
                let p75 = get_f("p75");
                let p95 = get_f("p95");
                let p99 = get_f("p99");
                let cv = get_f("cv");
                let ops = get_f("ops_per_sec");

                let ci_lo = sm.get("ci_95")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_f64()).unwrap_or(0.0);
                let ci_hi = sm.get("ci_95")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.get(1))
                    .and_then(|v| v.as_f64()).unwrap_or(0.0);

                let count = sm.get("count").and_then(|v| v.as_u64()).unwrap_or(0);

                let _ = writeln!(f, "{}  Count   : {}", indent, count);
                let _ = writeln!(f, "{}  Mean    : {} ({:.2} ns)", indent, format_duration_ns(mean), mean);
                let _ = writeln!(f, "{}  Median  : {} ({:.2} ns)", indent, format_duration_ns(median), median);
                let _ = writeln!(f, "{}  Std Dev : {} ({:.2} ns)", indent, format_duration_ns(std_dev), std_dev);
                let _ = writeln!(f, "{}  CV      : {:.4}", indent, cv);
                let _ = writeln!(f, "{}  Min     : {} ({:.2} ns)", indent, format_duration_ns(min), min);
                let _ = writeln!(f, "{}  Max     : {} ({:.2} ns)", indent, format_duration_ns(max), max);
                let _ = writeln!(f, "{}  P5      : {}", indent, format_duration_ns(p5));
                let _ = writeln!(f, "{}  P25     : {}", indent, format_duration_ns(p25));
                let _ = writeln!(f, "{}  P50     : {}", indent, format_duration_ns(p50));
                let _ = writeln!(f, "{}  P75     : {}", indent, format_duration_ns(p75));
                let _ = writeln!(f, "{}  P95     : {}", indent, format_duration_ns(p95));
                let _ = writeln!(f, "{}  P99     : {}", indent, format_duration_ns(p99));
                let _ = writeln!(f, "{}  95% CI  : [{}, {}]", indent,
                    format_duration_ns(ci_lo), format_duration_ns(ci_hi));
                let _ = writeln!(f, "{}  Ops/sec : {:.1}", indent, ops);
                let _ = writeln!(f, "");
            }
        }

        // Recurse into child objects
        for (key, child) in obj {
            if key == "summary" { continue; }
            let child_path = format!("{}.{}", path, key);
            extract_and_write_summaries(f, child, &child_path, depth + 1);
        }
    }
}
