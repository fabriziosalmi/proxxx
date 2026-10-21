//! `proxxx heatmap` — API latency heatmap (MVP).
//!
//! Per-node API round-trip time as a colored table. Probes
//! `/nodes/{node}/time` on each node sequentially and times the round
//! trip. pveproxy forwards that call to the node itself, so the time is
//! the node's, and a node that is down fails the probe (#353: probing
//! `/version` timed the API node on every row and showed a down node
//! green). Useful for "which node has slowed responses?" diagnosis.
//!
//! ## MVP scope (per #70)
//!
//! - **API RTT only**. Corosync round-trips and per-storage RTT
//!   are valuable but require SSH + node-side probing
//!   (`corosync-cfgtool -s`, `iostat`, NFS stats). Each is one
//!   follow-up PR; the API-RTT probe stands alone today.
//! - **Single snapshot, no TUI**. Full ratatui integration is
//!   tracked as the v2 work. The CLI-table form is shippable now
//!   and renders correctly in any terminal + JSON for tooling.
//! - **No historical retention** — single point in time per call.
//!   Operators wanting a rolling view run the command repeatedly
//!   (e.g. via `watch -n 5 proxxx heatmap`).

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;

use crate::api::{ProxmoxGateway, PxClient};

#[derive(Debug, Clone, Copy, clap::ValueEnum, Default)]
pub enum HeatmapOutput {
    #[default]
    Text,
    Json,
}

#[derive(Debug, clap::Args)]
pub struct HeatmapArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = HeatmapOutput::Text)]
    pub output: HeatmapOutput,
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencySample {
    pub node: String,
    pub endpoint: &'static str,
    /// Round-trip time in milliseconds.
    pub rtt_ms: f64,
    /// Latency bucket: `green` (<50ms), `yellow` (50-200ms), `red`
    /// (>200ms), or `down` when the probe failed (the time is then how
    /// long the failure took, not a latency).
    pub bucket: &'static str,
    /// `Ok` on success, an error string on failure.
    pub status: String,
}

pub async fn execute_heatmap(client: &Arc<PxClient>, args: HeatmapArgs) -> Result<(Value, i32)> {
    let nodes = client.get_nodes().await?;

    let mut samples: Vec<LatencySample> = Vec::with_capacity(nodes.len());
    for n in &nodes {
        let start = Instant::now();
        // `/nodes/{node}/time` is cheap and answered by the node itself
        // (pveproxy proxies it there), so it times that node's path.
        let result = client.get_node_time(&n.node).await;
        let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
        let (status, bucket) = match result {
            Ok(_) => ("Ok".to_string(), bucket_for(rtt_ms)),
            Err(e) => (format!("error: {e:#}"), "down"),
        };
        samples.push(LatencySample {
            node: n.node.clone(),
            endpoint: "/nodes/{node}/time",
            rtt_ms,
            bucket,
            status,
        });
    }
    let any_down = samples.iter().any(|s| s.bucket == "down");

    match args.output {
        HeatmapOutput::Json => {
            // raw-output: JSON for machines; removing characters would change the data
            println!("{}", serde_json::to_string_pretty(&samples)?);
        }
        HeatmapOutput::Text => {
            crate::outln!(
                "{node:<16}  {endpoint:<18}  {rtt:>9}  {bucket:<7}  status",
                node = "node",
                endpoint = "endpoint",
                rtt = "rtt(ms)",
                bucket = "bucket"
            );
            let sep = "─".repeat(70);
            crate::outln!("{sep}");
            for s in &samples {
                crate::outln!(
                    "{node:<16}  {endpoint:<18}  {rtt:>9.1}  {bucket:<7}  {status}",
                    node = s.node,
                    endpoint = s.endpoint,
                    rtt = s.rtt_ms,
                    bucket = s.bucket,
                    status = s.status,
                );
            }
        }
    }
    // Exit 1 when a node could not be probed, as other fan-out commands do.
    Ok((Value::Null, i32::from(any_down)))
}

fn bucket_for(rtt_ms: f64) -> &'static str {
    if rtt_ms < 50.0 {
        "green"
    } else if rtt_ms < 200.0 {
        "yellow"
    } else {
        "red"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_thresholds() {
        assert_eq!(bucket_for(0.0), "green");
        assert_eq!(bucket_for(49.9), "green");
        assert_eq!(bucket_for(50.0), "yellow");
        assert_eq!(bucket_for(199.9), "yellow");
        assert_eq!(bucket_for(200.0), "red");
        assert_eq!(bucket_for(10_000.0), "red");
    }
}
