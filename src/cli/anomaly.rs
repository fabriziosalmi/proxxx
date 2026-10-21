//! `proxxx anomaly` — per-node baseline z-score anomaly detection.
//!
//! For each online node, the baseline is that node's own history: the
//! day of RRD samples PVE keeps (`/nodes/{node}/rrddata?timeframe=day`,
//! average). The current reading (`/nodes`) is compared with the mean
//! and standard deviation of that history, and flagged when its z-score
//! reaches the threshold.
//!
//! #356: the previous version compared the nodes with each other in a
//! single snapshot. The largest z-score n values can reach is sqrt(n-1),
//! so the default threshold of 3 could never fire on fewer than 10 nodes
//! (3 nodes: at most 1.41), and an offline node joined the population as
//! cpu 0 / mem 0. A node is now judged against itself, and a node that is
//! offline or has too little history is reported as skipped, not as fine.
//!
//! An anomaly also needs a material change (`--min-cpu-delta`, default 10
//! points; `--min-mem-delta`, default 5 points): on an idle node the
//! history barely moves, and a 2-point CPU blip scored z > 5 on the test
//! cluster. The defaults are a judgement call, not a measurement.
//!
//! Scope: CPU and memory; single pass, no daemon.

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

    /// Smallest CPU change, in percentage points of the node's CPU, that
    /// counts as an anomaly. On an idle node the history barely moves, so
    /// a 2-point blip can score z > 5; this keeps such noise out. A
    /// chosen default, not a measured one.
    #[arg(long, default_value_t = 10.0)]
    pub min_cpu_delta: f64,

    /// Smallest memory change, in percentage points of the node's RAM,
    /// that counts as an anomaly. A chosen default, not a measured one.
    #[arg(long, default_value_t = 5.0)]
    pub min_mem_delta: f64,

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

/// Minimum number of history samples for a baseline.
const MIN_HISTORY: usize = 10;

/// A node that could not be evaluated, and why.
#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub node: String,
    pub reason: String,
}

/// Judge one node's CPU and memory against its own RRD day history,
/// adding to `anomalies` or recording why it could not be judged.
async fn evaluate_node(
    client: &Arc<PxClient>,
    n: &crate::api::types::Node,
    args: &AnomalyArgs,
    anomalies: &mut Vec<Anomaly>,
    skipped: &mut Vec<Skipped>,
) {
    use crate::api::types::{NodeStatus, RrdCf, RrdTimeframe};

    let skip = |reason: String| Skipped {
        node: n.node.clone(),
        reason,
    };
    if !matches!(n.status, NodeStatus::Online) {
        skipped.push(skip("not online".into()));
        return;
    }
    let history = match client
        .get_node_rrddata(&n.node, RrdTimeframe::Day, RrdCf::Average)
        .await
    {
        Ok(h) => h,
        Err(e) => {
            skipped.push(skip(format!("could not read its RRD history: {e:#}")));
            return;
        }
    };
    #[allow(clippy::cast_precision_loss)]
    let current_mem = if n.maxmem > 0 {
        (n.mem as f64 / n.maxmem as f64) * 100.0
    } else {
        f64::NAN
    };
    let cpu_hist: Vec<f64> = history.iter().filter_map(|p| p.cpu).collect();
    let mem_hist: Vec<f64> = history
        .iter()
        .filter_map(|p| {
            let (used, total) = (p.memused.or(p.mem)?, p.memtotal.or(p.maxmem)?);
            (total > 0.0).then(|| used / total * 100.0)
        })
        .collect();
    // `cpu` is a 0..1 fraction, so its floor is scaled from points.
    for (metric, current, hist, min_delta) in [
        ("cpu", n.cpu, &cpu_hist, args.min_cpu_delta / 100.0),
        ("mem_pct", current_mem, &mem_hist, args.min_mem_delta),
    ] {
        match judge(&n.node, metric, current, hist, args.threshold, min_delta) {
            Ok(Some(a)) => anomalies.push(a),
            Ok(None) => {}
            Err(reason) => skipped.push(skip(format!("{metric}: {reason}"))),
        }
    }
}

pub async fn execute_anomaly(client: &Arc<PxClient>, args: AnomalyArgs) -> Result<(Value, i32)> {
    let nodes = client.get_nodes().await?;
    let mut anomalies: Vec<Anomaly> = Vec::new();
    let mut skipped: Vec<Skipped> = Vec::new();

    for n in &nodes {
        evaluate_node(client, n, &args, &mut anomalies, &mut skipped).await;
    }

    match args.output {
        AnomalyOutput::Json => {
            let v = serde_json::json!({
                "threshold": args.threshold,
                "baseline": "per node: RRD day average",
                "node_count": nodes.len(),
                "anomalies": anomalies,
                "skipped": skipped,
            });
            // raw-output: JSON for machines; removing characters would change the data
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        AnomalyOutput::Text => {
            if anomalies.is_empty() && skipped.is_empty() {
                crate::outln!(
                    "✓ no anomalies above z={threshold} across {n} nodes",
                    threshold = args.threshold,
                    n = nodes.len()
                );
            } else if anomalies.is_empty() {
                crate::outln!(
                    "no anomalies above z={} among the nodes checked",
                    args.threshold
                );
            } else {
                crate::outln!(
                    "{node:<16}  {metric:<10}  {value:<10}  {mean:<10}  {std:<10}  z",
                    node = "node",
                    metric = "metric",
                    value = "value",
                    mean = "mean",
                    std = "stddev"
                );
                let sep = "─".repeat(72);
                crate::outln!("{sep}");
                for a in &anomalies {
                    crate::outln!(
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

    if args.output_is_text() {
        for sk in &skipped {
            crate::outln!("? skipped {}: {}", sk.node, sk.reason);
        }
    }
    // Exit 1 on an anomaly, and when a node could not be checked: a
    // skipped node is not a clean result.
    Ok((
        Value::Null,
        i32::from(!anomalies.is_empty() || !skipped.is_empty()),
    ))
}

impl AnomalyArgs {
    const fn output_is_text(&self) -> bool {
        matches!(self.output, AnomalyOutput::Text)
    }
}

/// Compare `current` with the node's own `history`. An anomaly needs both
/// a z-score at or above `threshold` and a change of at least `min_delta`
/// (in the metric's unit) from the mean. `Ok(None)` = not anomalous;
/// `Err` = no usable baseline (too few samples or no current value).
fn judge(
    node: &str,
    metric: &str,
    current: f64,
    history: &[f64],
    threshold: f64,
    min_delta: f64,
) -> std::result::Result<Option<Anomaly>, String> {
    if !current.is_finite() {
        return Err("no current value".into());
    }
    if history.len() < MIN_HISTORY {
        return Err(format!(
            "{} history samples, at least {MIN_HISTORY} needed",
            history.len()
        ));
    }
    let (mean, stddev) = mean_stddev(history);
    let delta = (current - mean).abs();
    if delta < min_delta {
        return Ok(None);
    }
    // A flat history with a material change is as far off as it gets.
    let z = if stddev == 0.0 {
        f64::INFINITY.copysign(current - mean)
    } else {
        (current - mean) / stddev
    };
    Ok((z.abs() >= threshold).then(|| Anomaly {
        node: node.to_string(),
        metric: metric.to_string(),
        value: current,
        baseline_mean: mean,
        baseline_stddev: stddev,
        z_score: z,
    }))
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

    /// #356: a node is judged against its own history, so the default
    /// threshold can fire on any cluster size. The cross-node z-score
    /// could not exceed sqrt(n-1): 1.41 on 3 nodes.
    #[test]
    fn a_reading_far_from_its_own_history_fires_at_the_default_threshold() {
        let history: Vec<f64> = (0..60).map(|i| 0.10 + f64::from(i % 5) * 0.01).collect();
        let a = judge("pve1", "cpu", 0.95, &history, 3.0, 0.10)
            .unwrap()
            .expect("fires");
        assert!(a.z_score > 3.0, "{a:?}");
        assert!(judge("pve1", "cpu", 0.12, &history, 3.0, 0.10)
            .unwrap()
            .is_none());
    }

    /// Measured on an idle test cluster: CPU 0.025 -> 0.048 scored z = 5.08.
    /// Below the minimum change it is not an anomaly.
    #[test]
    fn a_high_z_score_on_a_small_change_is_not_an_anomaly() {
        let history: Vec<f64> = (0..60).map(|i| 0.025 + f64::from(i % 3) * 0.003).collect();
        assert!(judge("pve1", "cpu", 0.048, &history, 3.0, 0.10)
            .unwrap()
            .is_none());
        assert!(judge("pve1", "cpu", 0.048, &history, 3.0, 0.0)
            .unwrap()
            .is_some());
    }

    #[test]
    fn too_little_history_or_no_current_value_is_not_a_clean_result() {
        assert!(judge("n", "cpu", 0.5, &[0.1; 3], 3.0, 0.1).is_err());
        let ten = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert!(judge("n", "mem_pct", f64::NAN, &ten, 3.0, 5.0).is_err());
        // A flat history with a material change fires.
        assert!(judge("n", "cpu", 0.5, &[0.1; 30], 3.0, 0.1)
            .unwrap()
            .is_some());
    }
}
