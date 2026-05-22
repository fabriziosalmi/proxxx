//! Prometheus metrics exporter for Proxmox VE.
//!
//! Scrapes nodes, guests and storage pools from the PVE API on every
//! Prometheus pull, renders the Prometheus text exposition format
//! (text/plain; version=0.0.4) in-process — no external crate needed.
//!
//! Exposed metrics:
//!   `proxxx_node_cpu_usage_ratio{node}`        — 0.0–1.0 CPU utilisation
//!   `proxxx_node_cpu_count{node}`              — logical CPUs
//!   `proxxx_node_memory_used_bytes{node}`
//!   `proxxx_node_memory_total_bytes{node}`
//!   `proxxx_node_disk_used_bytes{node}`
//!   `proxxx_node_disk_total_bytes{node}`
//!   `proxxx_node_uptime_seconds{node}`
//!   `proxxx_node_up{node}`                     — 1=online 0=offline/unknown
//!
//!   `proxxx_guest_cpu_usage_ratio{vmid,name,type,node}`
//!   `proxxx_guest_cpu_count{vmid,name,type,node}`
//!   `proxxx_guest_memory_used_bytes{vmid,name,type,node}`
//!   `proxxx_guest_memory_total_bytes{vmid,name,type,node}`
//!   `proxxx_guest_disk_used_bytes{vmid,name,type,node}`
//!   `proxxx_guest_disk_total_bytes{vmid,name,type,node}`
//!   `proxxx_guest_uptime_seconds{vmid,name,type,node}`
//!   `proxxx_guest_running{vmid,name,type,node}` — 1=running 0=else
//!
//!   `proxxx_storage_used_bytes{node,storage,type}`
//!   `proxxx_storage_total_bytes{node,storage,type}`
//!   `proxxx_storage_avail_bytes{node,storage,type}`
//!   `proxxx_storage_active{node,storage,type}`  — 1=active 0=inactive

use std::sync::Arc;

use anyhow::Result;
use axum::{
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use tracing::info;

use crate::api::{ProxmoxGateway, PxClient};

// ── Text format renderer ───────────────────────────────────────────────

fn escape_label(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

struct MetricWriter {
    buf: String,
}

impl MetricWriter {
    fn new() -> Self {
        Self {
            buf: String::with_capacity(32 * 1024),
        }
    }

    fn help(&mut self, name: &str, help: &str) {
        self.buf.push_str(&format!("# HELP {name} {help}\n"));
        self.buf.push_str(&format!("# TYPE {name} gauge\n"));
    }

    fn gauge(&mut self, name: &str, labels: &[(&str, &str)], value: f64) {
        let label_str = labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{}\"", escape_label(v)))
            .collect::<Vec<_>>()
            .join(",");
        self.buf
            .push_str(&format!("{name}{{{label_str}}} {value}\n"));
    }

    fn finish(self) -> String {
        self.buf
    }
}

// ── Scrape ─────────────────────────────────────────────────────────────

pub async fn scrape(client: &PxClient) -> String {
    let mut w = MetricWriter::new();

    // Fetch the node list once and reuse it for all three scrape sections.
    // `scrape_ok` flips to 0 if ANY fetch fails, surfaced as `proxxx_up` — the
    // Prometheus-idiomatic way to signal a partial scrape without silently
    // dropping counters (a vanished guest gauge looks like a mass power-off).
    let (nodes, mut scrape_ok) = if let Ok(n) = client.get_nodes().await {
        (n, 1.0_f64)
    } else {
        (Vec::new(), 0.0_f64)
    };

    // ── Nodes ─────────────────────────────────────────────────────
    w.help("proxxx_node_up", "1 if node is online");
    w.help("proxxx_node_cpu_usage_ratio", "CPU utilisation 0.0–1.0");
    w.help("proxxx_node_cpu_count", "Logical CPU count");
    w.help("proxxx_node_memory_used_bytes", "RAM used bytes");
    w.help("proxxx_node_memory_total_bytes", "RAM total bytes");
    w.help("proxxx_node_disk_used_bytes", "Root disk used bytes");
    w.help("proxxx_node_disk_total_bytes", "Root disk total bytes");
    w.help("proxxx_node_uptime_seconds", "Node uptime seconds");

    {
        let nodes = &nodes;
        for n in nodes {
            let node = n.node.as_str();
            let up = if n.status == crate::api::types::NodeStatus::Online {
                1.0
            } else {
                0.0
            };
            let l = &[("node", node)];
            w.gauge("proxxx_node_up", l, up);
            w.gauge("proxxx_node_cpu_usage_ratio", l, n.cpu);
            w.gauge("proxxx_node_cpu_count", l, f64::from(n.maxcpu));
            w.gauge("proxxx_node_memory_used_bytes", l, n.mem as f64);
            w.gauge("proxxx_node_memory_total_bytes", l, n.maxmem as f64);
            w.gauge("proxxx_node_disk_used_bytes", l, n.disk as f64);
            w.gauge("proxxx_node_disk_total_bytes", l, n.maxdisk as f64);
            w.gauge("proxxx_node_uptime_seconds", l, n.uptime as f64);
        }
    }

    // ── Guests ────────────────────────────────────────────────────
    w.help("proxxx_guest_running", "1 if guest status is running");
    w.help(
        "proxxx_guest_cpu_usage_ratio",
        "Guest CPU utilisation 0.0–N",
    );
    w.help("proxxx_guest_cpu_count", "vCPU count");
    w.help("proxxx_guest_memory_used_bytes", "Guest RAM used bytes");
    w.help("proxxx_guest_memory_total_bytes", "Guest RAM total bytes");
    w.help("proxxx_guest_disk_used_bytes", "Guest disk used bytes");
    w.help("proxxx_guest_disk_total_bytes", "Guest disk total bytes");
    w.help("proxxx_guest_uptime_seconds", "Guest uptime seconds");

    let all_guests: Vec<crate::api::types::Guest> = if let Ok(g) = client.get_all_guests().await {
        g
    } else {
        scrape_ok = 0.0;
        Vec::new()
    };
    for g in &all_guests {
        let vmid_s = g.vmid.to_string();
        let guest_type = match g.guest_type {
            crate::api::types::GuestType::Qemu => "qemu",
            crate::api::types::GuestType::Lxc => "lxc",
        };
        let running = if g.status == crate::api::types::GuestStatus::Running {
            1.0
        } else {
            0.0
        };
        let l: &[(&str, &str)] = &[
            ("vmid", vmid_s.as_str()),
            ("name", g.name.as_str()),
            ("type", guest_type),
            ("node", g.node.as_str()),
        ];
        w.gauge("proxxx_guest_running", l, running);
        w.gauge("proxxx_guest_cpu_usage_ratio", l, g.cpu);
        w.gauge("proxxx_guest_cpu_count", l, f64::from(g.cpus));
        w.gauge("proxxx_guest_memory_used_bytes", l, g.mem as f64);
        w.gauge("proxxx_guest_memory_total_bytes", l, g.maxmem as f64);
        w.gauge("proxxx_guest_disk_used_bytes", l, g.disk as f64);
        w.gauge("proxxx_guest_disk_total_bytes", l, g.maxdisk as f64);
        w.gauge("proxxx_guest_uptime_seconds", l, g.uptime as f64);
    }

    // ── Storage ───────────────────────────────────────────────────
    // PVE's /cluster/resources gives storage per node; we call
    // get_nodes then per-node storage to keep things simple and avoid
    // duplicate entries from shared pools appearing once per consumer.
    w.help("proxxx_storage_used_bytes", "Storage pool used bytes");
    w.help("proxxx_storage_total_bytes", "Storage pool total bytes");
    w.help("proxxx_storage_avail_bytes", "Storage pool available bytes");
    w.help("proxxx_storage_active", "1 if storage pool is active");

    // Per-node (the `node` label needs it); online-gated, and a failed fetch
    // flips `scrape_ok` rather than silently dropping that node's pools.
    for n in &nodes {
        if !matches!(n.status, crate::api::types::NodeStatus::Online) {
            continue;
        }
        if let Ok(pools) = client.get_storage_pools(&n.node).await {
            for p in &pools {
                let l: &[(&str, &str)] = &[
                    ("node", n.node.as_str()),
                    ("storage", p.storage.as_str()),
                    ("type", p.storage_type.as_str()),
                ];
                w.gauge("proxxx_storage_used_bytes", l, p.used as f64);
                w.gauge("proxxx_storage_total_bytes", l, p.total as f64);
                w.gauge("proxxx_storage_avail_bytes", l, p.avail as f64);
                w.gauge("proxxx_storage_active", l, if p.active { 1.0 } else { 0.0 });
            }
        } else {
            scrape_ok = 0.0;
        }
    }

    // Scrape health — 1 only if every fetch above succeeded.
    w.help(
        "proxxx_up",
        "1 if the scrape gathered all data; 0 if any fetch failed",
    );
    w.gauge("proxxx_up", &[], scrape_ok);

    w.finish()
}

// ── HTTP server ────────────────────────────────────────────────────────

pub async fn run_metrics_server(client: Arc<PxClient>, bind: &str, port: u16) -> Result<()> {
    let addr: std::net::SocketAddr = format!("{bind}:{port}").parse()?;

    let app = Router::new().route(
        "/metrics",
        get(move || {
            let c = Arc::clone(&client);
            async move {
                let body = scrape(&c).await;
                (
                    StatusCode::OK,
                    [(
                        axum::http::header::CONTENT_TYPE,
                        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
                    )],
                    body,
                )
                    .into_response()
            }
        }),
    );

    info!("Prometheus metrics server listening on http://{addr}/metrics");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_label_handles_special_chars() {
        assert_eq!(escape_label(r#"foo"bar"#), r#"foo\"bar"#);
        assert_eq!(escape_label("foo\\bar"), r"foo\\bar");
        assert_eq!(escape_label("foo\nbar"), r"foo\nbar");
        assert_eq!(escape_label("foo\rbar"), r"foo\rbar");
        assert_eq!(escape_label("plain"), "plain");
    }

    #[test]
    fn metric_writer_renders_gauge() {
        let mut w = MetricWriter::new();
        w.help("my_metric", "A test metric");
        w.gauge("my_metric", &[("label", "val")], 42.0);
        let out = w.finish();
        assert!(out.contains("# HELP my_metric A test metric\n"));
        assert!(out.contains("# TYPE my_metric gauge\n"));
        assert!(out.contains("my_metric{label=\"val\"} 42\n"));
    }

    #[test]
    fn metric_writer_multiple_labels() {
        let mut w = MetricWriter::new();
        w.gauge("m", &[("a", "1"), ("b", "2")], 1.0);
        let out = w.finish();
        assert!(out.contains("m{a=\"1\",b=\"2\"} 1\n"));
    }
}
