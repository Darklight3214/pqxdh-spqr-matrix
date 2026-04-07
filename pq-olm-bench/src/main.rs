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

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pq-olm-bench", about = "Benchmark suite: Classical OLM vs PQ-OLM (PQXDH + SPQR)")]
struct Cli {
    /// Number of iterations per benchmark
    #[arg(long, default_value = "1000")]
    iterations: usize,

    /// Warmup iterations (not counted)
    #[arg(long, default_value = "100")]
    warmup: usize,

    /// Comma-separated metric numbers (1-10) or "all"
    #[arg(long, default_value = "all")]
    metrics: String,

    /// Conduit server URL for E2E benchmark (metric 8). Optional.
    #[arg(long)]
    conduit_url: Option<String>,

    /// User credentials for E2E benchmark, format: "user1:pass1,user2:pass2,..."
    /// At least 2 users required for E2E. If not specified, defaults to alice:alice,bob:bob
    #[arg(long, default_value = "alice:alice123,bob:bob123")]
    users: String,

    /// Number of user pairs to test in E2E benchmark.
    /// Each pair creates independent sessions. 0 = all possible pairs.
    #[arg(long, default_value = "0")]
    e2e_pairs: usize,

    /// Number of concurrent sessions per user pair in crypto benchmarks (1-7, 9-10).
    /// Tests scaling behavior under multi-session load.
    #[arg(long, default_value = "1")]
    sessions: usize,

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

fn main() {
    let cli = Cli::parse();

    let metrics: Vec<usize> = if cli.metrics == "all" {
        (1..=10).collect()
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
    println!("║          pq-olm-bench  —  PQ-OLM Benchmark Suite       ║");
    println!("║       Classical OLM (X3DH) vs PQ-OLM (PQXDH+SPQR)     ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Iterations: {:<6}  Warmup: {:<6}                     ║", cli.iterations, cli.warmup);
    println!("║  Sessions:   {:<6}  Users:  {:<6}                     ║", cli.sessions, users.len());
    println!("║  Metrics:    {:<43}║", cli.metrics);
    println!("║  Output:     {:<43}║", cli.output_dir);
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    let mut all_results = serde_json::Map::new();

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
            _ => {
                println!("  [warn] Unknown metric: {}", metric);
            }
        }
    }

    // Write combined JSON
    let json_path = out_dir.join("all_results.json");
    let json_val = serde_json::Value::Object(all_results);
    let json_str = serde_json::to_string_pretty(&json_val).unwrap();
    std::fs::write(&json_path, &json_str).unwrap();
    println!("\n✓ Combined results: {}", json_path.display());

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║                   Benchmark Complete                    ║");
    println!("╚══════════════════════════════════════════════════════════╝");
}
