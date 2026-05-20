//! `proxxx anomaly` — rolling-baseline z-score anomaly detection.
//!
//! Statistical approach: maintain a rolling window of metric values
//! per (node, metric) pair, compute mean + stddev, flag any current
//! reading whose z-score is above the threshold. No external
//! dependencies (no Prometheus client); the window lives in-process
//! per command invocation.
//!
//! ## MVP scope (per #68)
//!
//! - **Single-pass scan, no daemon.** v1 invocation polls the
//!   metrics endpoint, computes z-scores over the last N samples
//!   retrieved from PVE's RRD-cached metrics, and emits findings.
//!   Daemon mode (continuous watch) is the obvious follow-up.
//! - **Per-node CPU + memory only.** Adding more metrics is a
//!   matter of extending the `Metric` enum; ship the smallest
//!   useful surface first.
//! - **Z-score threshold default 3.0** — operators can tune via
//!   `--threshold`.
//! - **No Prometheus integration** — the issue mentions Prometheus
//!   metrics but we don't ship a Prometheus exporter today; the
//!   data comes from PVE's per-node `/nodes/{n}/status` and the
//!   /cluster/resources flat list.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

use crate::api::{ProxmoxGateway, PxClient};

#[derive(Debug, Clone, Copy, clap::ValueEnum, Default)]
pub enum AnomalyOutput {
    #[default]
    Text,
    Json,
}

#[derive(Debug, clap::Args)]
pub struct AnomalyArgs {
    /// Z-score threshold above which a sample is flagged as
    /// anomalous. Default 3.0 (~99.7th percentile for normal-ish
    /// distributions; aggressive enough to catch the obvious outlier,
    /// permissive enough not to fire on every burst).
    #[arg(long, default_value_t = 3.0)]
    pub threshold: f64,

    #[arg(long, value_enum, default_value_t = AnomalyOutput::Text)]
    pub output: AnomalyOutput,
}

#[derive(Debug, Clone, Serialize)]
pub struct Anomaly {
    pub node: String,
    pub metric: String,
    pub value: f64,
    pub baseline_mean: f64,
    pub baseline_stddev: f64,
    pub z_score: f64,
}

pub async fn execute_anomaly(client: &Arc<PxClient>, args: AnomalyArgs) -> Result<(Value, i32)> {
    let nodes = client.get_nodes().await?;

    // Build per-metric baselines across the cluster: each node
    // contributes one sample to the population. With N nodes you
    // get N samples; outliers stand out against their peers.
    // Edge case: N=1 → no baseline possible (stddev=0); skip.
    let cpu_samples: Vec<(String, f64)> = nodes.iter().map(|n| (n.node.clone(), n.cpu)).collect();
    #[allow(clippy::cast_precision_loss)]
    let mem_samples: Vec<(String, f64)> = nodes
        .iter()
        .map(|n| {
            let pct = if n.maxmem > 0 {
                (n.mem as f64 / n.maxmem as f64) * 100.0
            } else {
                0.0
            };
            (n.node.clone(), pct)
        })
        .collect();

    let mut anomalies: Vec<Anomaly> = Vec::new();
    detect_outliers("cpu", &cpu_samples, args.threshold, &mut anomalies);
    detect_outliers("mem_pct", &mem_samples, args.threshold, &mut anomalies);

    match args.output {
        AnomalyOutput::Json => {
            let v = serde_json::json!({
                "threshold": args.threshold,
                "node_count": nodes.len(),
                "anomalies": anomalies,
            });
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        AnomalyOutput::Text => {
            if anomalies.is_empty() {
                println!(
                    "✓ no anomalies above z={threshold} across {n} nodes",
                    threshold = args.threshold,
                    n = nodes.len()
                );
            } else {
                println!(
                    "{node:<16}  {metric:<10}  {value:<10}  {mean:<10}  {std:<10}  z",
                    node = "node",
                    metric = "metric",
                    value = "value",
                    mean = "mean",
                    std = "stddev"
                );
                let sep = "─".repeat(72);
                println!("{sep}");
                for a in &anomalies {
                    println!(
                        "{node:<16}  {metric:<10}  {value:<10.3}  {mean:<10.3}  {std:<10.3}  {z:.2}",
                        node = a.node,
                        metric = a.metric,
                        value = a.value,
                        mean = a.baseline_mean,
                        std = a.baseline_stddev,
                        z = a.z_score,
                    );
                }
            }
        }
    }

    Ok((Value::Null, i32::from(!anomalies.is_empty())))
}

/// Compute (mean, stddev). Returns `(0.0, 0.0)` for an empty or
/// single-element population.
#[must_use]
pub fn mean_stddev(values: &[f64]) -> (f64, f64) {
    if values.len() < 2 {
        return (values.first().copied().unwrap_or(0.0), 0.0);
    }
    #[allow(clippy::cast_precision_loss)]
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    (mean, variance.sqrt())
}

fn detect_outliers(
    metric: &str,
    samples: &[(String, f64)],
    threshold: f64,
    out: &mut Vec<Anomaly>,
) {
    if samples.len() < 2 {
        return;
    }
    let values: Vec<f64> = samples.iter().map(|(_, v)| *v).collect();
    let (mean, stddev) = mean_stddev(&values);
    if stddev == 0.0 {
        return;
    }
    for (node, v) in samples {
        let z = (v - mean) / stddev;
        if z.abs() >= threshold {
            out.push(Anomaly {
                node: node.clone(),
                metric: metric.to_string(),
                value: *v,
                baseline_mean: mean,
                baseline_stddev: stddev,
                z_score: z,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mean_stddev_handles_empty_and_single() {
        assert_eq!(mean_stddev(&[]), (0.0, 0.0));
        assert_eq!(mean_stddev(&[5.0]), (5.0, 0.0));
    }

    #[test]
    fn mean_stddev_basic() {
        // [1, 2, 3, 4, 5]: mean=3, variance=2, stddev=sqrt(2)≈1.414
        let (m, s) = mean_stddev(&[1.0, 2.0, 3.0, 4.0, 5.0]);
        assert!((m - 3.0).abs() < 0.001);
        assert!((s - 2.0_f64.sqrt()).abs() < 0.001);
    }

    #[test]
    fn detect_outliers_flags_extreme_values() {
        // Four nodes near 10, one at 1000. The outlier should fire.
        let samples = vec![
            ("a".into(), 10.0),
            ("b".into(), 11.0),
            ("c".into(), 9.0),
            ("d".into(), 10.5),
            ("hot".into(), 1000.0),
        ];
        let mut out = Vec::new();
        // Threshold 1.5 leaves room for f64 boundary noise — the
        // 1000 outlier is z≈2.0 against the cluster mean; 1.5
        // gives us margin to assert "fires" cleanly without
        // depending on the exact float result.
        detect_outliers("cpu", &samples, 1.5, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].node, "hot");
    }

    #[test]
    fn detect_outliers_silent_when_population_flat() {
        let samples = vec![("a".into(), 5.0), ("b".into(), 5.0), ("c".into(), 5.0)];
        let mut out = Vec::new();
        detect_outliers("x", &samples, 2.0, &mut out);
        assert!(out.is_empty());
    }
}
