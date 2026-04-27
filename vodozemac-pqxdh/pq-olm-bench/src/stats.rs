use serde::Serialize;

/// Holds timing samples (in nanoseconds) and computes statistics.
#[derive(Clone, Serialize)]
pub struct BenchResult {
    pub label: String,
    pub unit: String,
    pub samples: Vec<f64>,
}

#[derive(Clone, Serialize)]
pub struct StatsSummary {
    pub count: usize,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub median: f64,
    pub std_dev: f64,
    pub p5: f64,
    pub p25: f64,
    pub p50: f64,
    pub p75: f64,
    pub p95: f64,
    pub p99: f64,
    pub cv: f64,
    /// 95% confidence interval (lower, upper)
    pub ci_95: (f64, f64),
    /// Throughput: ops/sec at mean latency (only for time-based units)
    pub ops_per_sec: f64,
}

impl BenchResult {
    pub fn new(label: &str, unit: &str, samples: Vec<f64>) -> Self {
        Self {
            label: label.to_string(),
            unit: unit.to_string(),
            samples,
        }
    }

    pub fn summary(&self) -> StatsSummary {
        let n = self.samples.len();
        if n == 0 {
            return StatsSummary {
                count: 0, min: 0.0, max: 0.0, mean: 0.0,
                median: 0.0, std_dev: 0.0,
                p5: 0.0, p25: 0.0, p50: 0.0, p75: 0.0, p95: 0.0, p99: 0.0,
                cv: 0.0, ci_95: (0.0, 0.0), ops_per_sec: 0.0,
            };
        }
        let mut sorted = self.samples.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let min = sorted[0];
        let max = sorted[n - 1];
        let sum: f64 = sorted.iter().sum();
        let mean = sum / n as f64;
        let median = percentile_sorted(&sorted, 50.0);
        let variance: f64 = sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        let std_dev = variance.sqrt();
        let cv = if mean > 0.0 { std_dev / mean } else { 0.0 };

        // 95% CI: mean ± 1.96 * (std_dev / sqrt(n))
        let se = std_dev / (n as f64).sqrt();
        let ci_95 = (mean - 1.96 * se, mean + 1.96 * se);

        // ops/sec for time-based units (ns)
        let ops_per_sec = if self.unit == "ns" && mean > 0.0 {
            1_000_000_000.0 / mean
        } else {
            0.0
        };

        StatsSummary {
            count: n,
            min,
            max,
            mean,
            median,
            std_dev,
            p5: percentile_sorted(&sorted, 5.0),
            p25: percentile_sorted(&sorted, 25.0),
            p50: percentile_sorted(&sorted, 50.0),
            p75: percentile_sorted(&sorted, 75.0),
            p95: percentile_sorted(&sorted, 95.0),
            p99: percentile_sorted(&sorted, 99.0),
            cv,
            ci_95,
            ops_per_sec,
        }
    }
}

fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Format a nanosecond value nicely
pub fn format_duration_ns(ns: f64) -> String {
    if ns < 1_000.0 {
        format!("{:.1} ns", ns)
    } else if ns < 1_000_000.0 {
        format!("{:.2} µs", ns / 1_000.0)
    } else if ns < 1_000_000_000.0 {
        format!("{:.2} ms", ns / 1_000_000.0)
    } else {
        format!("{:.3} s", ns / 1_000_000_000.0)
    }
}

/// Format byte count nicely
pub fn format_bytes(bytes: f64) -> String {
    if bytes < 1024.0 {
        format!("{:.0} B", bytes)
    } else if bytes < 1024.0 * 1024.0 {
        format!("{:.2} KB", bytes / 1024.0)
    } else if bytes < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.2} MB", bytes / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes / (1024.0 * 1024.0 * 1024.0))
    }
}
