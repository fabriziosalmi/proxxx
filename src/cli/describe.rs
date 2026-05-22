//! `proxxx describe` — structured cluster digest for LLMs / docs.
//!
//! One command, four output formats, the same data:
//!
//! | Format        | Audience              | Shape                                |
//! | :------------ | :-------------------- | :----------------------------------- |
//! | `text` (default) | Human at a terminal | Sections with sigils, terse columns. |
//! | `md`             | Doc consumer       | GitHub markdown, tables.             |
//! | `json`           | Tooling / `jq`     | Full structured digest.              |
//! | `llm-context`    | LLM agent          | Token-compact, prose+key:value mix.  |
//!
//! Token budget: the `llm-context` format aims for ≲ 4 000 tokens
//! on a 50-node cluster — small enough to paste at the top of an
//! LLM conversation as context. Achieved by:
//!   * One-line summaries per node / guest (no nested tables).
//!   * Counts not enumerations where the count is what matters
//!     (RBAC: "12 users, 7 ACL grants on /vms/*").
//!   * Optional `--include backups|events|rbac` to expand a section.
//!
//! Secrets never appear in any output — neither token IDs nor
//! token secrets reach this code (`PxClient` holds them internally;
//! we only call the read-side gateway methods).

use anyhow::Result;
use clap::ValueEnum;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

use crate::api::{ProxmoxGateway, PxClient};

/// Output format. `LlmContext` is the heading-marker variant
/// designed for paste-into-LLM use; the others are
/// machine-/human-friendly.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum DescribeFormat {
    #[default]
    Text,
    Md,
    Json,
    LlmContext,
}

/// Optional sections to include. Default digest is cluster + nodes
/// + storage + guests + version. The flags below expand it.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum DescribeInclude {
    Events,
    Rbac,
    All,
}

#[derive(Debug, clap::Args)]
pub struct DescribeArgs {
    /// Output format. `llm-context` is the compact-prose variant
    /// designed to paste at the top of an LLM conversation.
    #[arg(long, value_enum, default_value_t = DescribeFormat::Text)]
    pub output: DescribeFormat,

    /// Optional sections to add. Repeatable. `all` is a shortcut
    /// for `events,rbac`.
    #[arg(long, value_enum)]
    pub include: Vec<DescribeInclude>,
}

/// The structured digest. Every field is `pub` so JSON consumers
/// see a stable shape. `Option<…>` covers the cases where the
/// underlying endpoint failed and we degraded gracefully (rather
/// than failing the whole command).
#[derive(Debug, Clone, Serialize)]
pub struct ClusterDigest {
    pub cluster: ClusterInfo,
    pub nodes: Vec<NodeSummary>,
    pub guests: Vec<GuestSummary>,
    pub storages: Vec<StorageSummary>,
    /// Only populated when `--include events` or `--include all`.
    pub recent_failures: Option<Vec<TaskSummary>>,
    /// Only populated when `--include rbac` or `--include all`.
    pub rbac: Option<RbacSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterInfo {
    pub pve_version: String,
    pub node_count: usize,
    pub guest_count: usize,
    pub storage_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeSummary {
    pub node: String,
    pub status: String,
    pub cpu_pct: f64,
    pub mem_used_bytes: u64,
    pub mem_total_bytes: u64,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuestSummary {
    pub vmid: u32,
    pub name: String,
    pub kind: String, // "qemu" | "lxc"
    pub node: String,
    pub status: String,
    pub cores: Option<u32>,
    pub mem_mb: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StorageSummary {
    pub storage: String,
    pub kind: String,
    pub used_bytes: u64,
    pub total_bytes: u64,
    pub shared: bool,
    pub on_nodes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskSummary {
    pub upid: String,
    pub node: String,
    pub kind: String,
    pub id: String,
    pub user: String,
    pub status: String,
    pub start: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RbacSummary {
    pub pool_count: usize,
    pub user_count: usize,
    pub pools: Vec<String>,
}

pub async fn execute_describe(client: &Arc<PxClient>, args: DescribeArgs) -> Result<(Value, i32)> {
    let include_all = args.include.contains(&DescribeInclude::All);
    let include_events = include_all || args.include.contains(&DescribeInclude::Events);
    let include_rbac = include_all || args.include.contains(&DescribeInclude::Rbac);

    let digest = collect(client, include_events, include_rbac).await?;

    match args.output {
        DescribeFormat::Text => print_text(&digest),
        DescribeFormat::Md => print_markdown(&digest),
        DescribeFormat::LlmContext => print_llm_context(&digest),
        DescribeFormat::Json => {
            let s = serde_json::to_string_pretty(&digest)?;
            println!("{s}");
        }
    }
    Ok((Value::Null, 0))
}

async fn collect(
    client: &PxClient,
    include_events: bool,
    include_rbac: bool,
) -> Result<ClusterDigest> {
    let pve_version = match client.get_api_version().await {
        Ok(v) => v.version,
        Err(_) => "(unavailable)".to_string(),
    };

    let nodes_raw = client.get_nodes().await?;
    let nodes: Vec<NodeSummary> = nodes_raw
        .iter()
        .map(|n| NodeSummary {
            node: n.node.clone(),
            status: format!("{:?}", n.status).to_ascii_lowercase(),
            cpu_pct: n.cpu,
            mem_used_bytes: n.mem,
            mem_total_bytes: n.maxmem,
            uptime_secs: n.uptime,
        })
        .collect();

    let mut guests: Vec<GuestSummary> = Vec::new();
    for g in client.get_all_guests().await? {
        guests.push(GuestSummary {
            vmid: g.vmid,
            name: g.name,
            kind: match g.guest_type {
                crate::api::types::GuestType::Qemu => "qemu".into(),
                crate::api::types::GuestType::Lxc => "lxc".into(),
            },
            node: g.node,
            status: format!("{:?}", g.status).to_ascii_lowercase(),
            cores: Some(g.cpus),
            mem_mb: Some(g.maxmem / (1024 * 1024)),
        });
    }

    // Storage: PVE returns one row per (storage, node) pair; we
    // collapse to one row per storage with `on_nodes` carrying the
    // node names the storage is visible on. Shared storages
    // typically appear on every node; we infer `shared` heuristically
    // by counting nodes (a storage on >1 node is effectively shared
    // from the perspective of an operator's mental model).
    let mut storage_map: std::collections::BTreeMap<String, StorageSummary> =
        std::collections::BTreeMap::new();
    for n in &nodes_raw {
        if !matches!(n.status, crate::api::types::NodeStatus::Online) {
            continue;
        }
        for s in client.get_storage_pools(&n.node).await? {
            let entry = storage_map
                .entry(s.storage.clone())
                .or_insert_with(|| StorageSummary {
                    storage: s.storage.clone(),
                    kind: s.storage_type.clone(),
                    used_bytes: s.used,
                    total_bytes: s.total,
                    shared: false, // refined after the loop
                    on_nodes: Vec::new(),
                });
            if !entry.on_nodes.contains(&n.node) {
                entry.on_nodes.push(n.node.clone());
            }
        }
    }
    // A storage visible on >1 node is shared by inference.
    for entry in storage_map.values_mut() {
        entry.shared = entry.on_nodes.len() > 1;
    }
    let storages: Vec<StorageSummary> = storage_map.into_values().collect();

    let recent_failures = if include_events {
        let tasks = client.get_cluster_tasks().await.unwrap_or_default();
        // Filter to failures (status != "OK" and endtime set).
        // Take the 5 most recent.
        let mut failures: Vec<TaskSummary> = tasks
            .into_iter()
            .filter(|t| {
                t.endtime.is_some()
                    && t.status
                        .as_deref()
                        .is_some_and(|s| !s.eq_ignore_ascii_case("OK"))
            })
            .map(|t| TaskSummary {
                upid: t.upid,
                node: t.node,
                kind: t.task_type,
                id: t.id,
                user: t.user,
                status: t.status.unwrap_or_default(),
                start: t.starttime as i64,
            })
            .collect();
        failures.sort_by_key(|f| std::cmp::Reverse(f.start));
        failures.truncate(5);
        Some(failures)
    } else {
        None
    };

    let rbac = if include_rbac {
        let pools = client.list_pools().await.unwrap_or_default();
        let users = client.list_users().await.unwrap_or_default();
        Some(RbacSummary {
            pool_count: pools.len(),
            user_count: users.len(),
            pools: pools.into_iter().map(|p| p.poolid).collect(),
        })
    } else {
        None
    };

    Ok(ClusterDigest {
        cluster: ClusterInfo {
            pve_version,
            node_count: nodes.len(),
            guest_count: guests.len(),
            storage_count: storages.len(),
        },
        nodes,
        guests,
        storages,
        recent_failures,
        rbac,
    })
}

fn format_bytes_gib(n: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let g = (n as f64) / (1024.0 * 1024.0 * 1024.0);
    format!("{g:.1} GiB")
}

fn fmt_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    if d > 0 {
        format!("{d}d{h}h")
    } else {
        format!("{h}h")
    }
}

fn print_text(d: &ClusterDigest) {
    println!("# Cluster ({})", d.cluster.pve_version);
    println!(
        "  {} nodes  /  {} guests  /  {} storages\n",
        d.cluster.node_count, d.cluster.guest_count, d.cluster.storage_count
    );
    println!("## Nodes");
    for n in &d.nodes {
        let mem_used = format_bytes_gib(n.mem_used_bytes);
        let mem_total = format_bytes_gib(n.mem_total_bytes);
        let cpu_pct = (n.cpu_pct * 100.0).clamp(0.0, 100.0);
        println!(
            "  {name:<14} {status:<8}  cpu={cpu_pct:>5.1}%  mem={mem_used} / {mem_total}  up={up}",
            name = n.node,
            status = n.status,
            up = fmt_uptime(n.uptime_secs),
        );
    }
    println!("\n## Guests");
    for g in &d.guests {
        let res = match (g.cores, g.mem_mb) {
            (Some(c), Some(m)) => format!("{c}c/{m}MB"),
            _ => "—".into(),
        };
        println!(
            "  {vmid:<6} {kind:<5} {name:<20} on {node:<10} {status:<8} {res}",
            vmid = g.vmid,
            kind = g.kind,
            name = g.name,
            node = g.node,
            status = g.status,
            res = res,
        );
    }
    println!("\n## Storages");
    for s in &d.storages {
        let shared = if s.shared { "shared" } else { "local" };
        let used_pct = if s.total_bytes > 0 {
            #[allow(clippy::cast_precision_loss)]
            let p = (s.used_bytes as f64 / s.total_bytes as f64) * 100.0;
            format!("{p:>5.1}%")
        } else {
            "  n/a".into()
        };
        println!(
            "  {name:<14} {kind:<10} {used:<5}  on {n} nodes  ({shared})",
            name = s.storage,
            kind = s.kind,
            used = used_pct,
            n = s.on_nodes.len(),
        );
    }
    if let Some(failures) = &d.recent_failures {
        println!("\n## Recent failures ({})", failures.len());
        for t in failures {
            println!(
                "  {start}  {node:<12} {kind:<14} {id:<6}  {user:<18}  {status}",
                start = t.start,
                node = t.node,
                kind = t.kind,
                id = t.id,
                user = t.user,
                status = t.status,
            );
        }
    }
    if let Some(r) = &d.rbac {
        println!("\n## RBAC");
        println!("  {} pools  /  {} users", r.pool_count, r.user_count);
        if !r.pools.is_empty() {
            println!("  Pools: {}", r.pools.join(", "));
        }
    }
}

fn print_markdown(d: &ClusterDigest) {
    println!("# Cluster — PVE {}\n", d.cluster.pve_version);
    println!(
        "**{} nodes** · **{} guests** · **{} storages**\n",
        d.cluster.node_count, d.cluster.guest_count, d.cluster.storage_count
    );
    println!("## Nodes\n");
    println!("| Node | Status | CPU | Memory | Uptime |");
    println!("| :--- | :----- | --: | :----- | :----- |");
    for n in &d.nodes {
        let cpu_pct = (n.cpu_pct * 100.0).clamp(0.0, 100.0);
        println!(
            "| `{}` | {} | {:.1}% | {} / {} | {} |",
            n.node,
            n.status,
            cpu_pct,
            format_bytes_gib(n.mem_used_bytes),
            format_bytes_gib(n.mem_total_bytes),
            fmt_uptime(n.uptime_secs),
        );
    }
    println!("\n## Guests\n");
    println!("| VMID | Kind | Name | Node | Status |");
    println!("| ---: | :--- | :--- | :--- | :----- |");
    for g in &d.guests {
        println!(
            "| {} | {} | {} | `{}` | {} |",
            g.vmid, g.kind, g.name, g.node, g.status
        );
    }
    println!("\n## Storages\n");
    println!("| Storage | Type | Used | Shared | Nodes |");
    println!("| :------ | :--- | ---: | :----- | ----: |");
    for s in &d.storages {
        let used_pct = if s.total_bytes > 0 {
            #[allow(clippy::cast_precision_loss)]
            let p = (s.used_bytes as f64 / s.total_bytes as f64) * 100.0;
            format!("{p:.1}%")
        } else {
            "n/a".into()
        };
        println!(
            "| `{}` | {} | {} | {} | {} |",
            s.storage,
            s.kind,
            used_pct,
            if s.shared { "yes" } else { "no" },
            s.on_nodes.len()
        );
    }
    if let Some(failures) = &d.recent_failures {
        println!("\n## Recent failures ({})\n", failures.len());
        for t in failures {
            println!(
                "- `{}` on `{}` ({}, status: {})",
                t.kind, t.node, t.id, t.status
            );
        }
    }
    if let Some(r) = &d.rbac {
        println!("\n## RBAC\n");
        println!("- {} pools / {} users", r.pool_count, r.user_count);
        if !r.pools.is_empty() {
            println!("- Pools: {}", r.pools.join(", "));
        }
    }
}

/// LLM-context format — compact prose + key:value, designed to
/// paste at the top of a chat. Avoids markdown tables (they cost
/// tokens) in favour of one-line summaries.
fn print_llm_context(d: &ClusterDigest) {
    println!(
        "Proxmox cluster: PVE {}, {} nodes, {} guests, {} storages.",
        d.cluster.pve_version, d.cluster.node_count, d.cluster.guest_count, d.cluster.storage_count
    );
    println!();
    println!("Nodes:");
    for n in &d.nodes {
        let cpu_pct = (n.cpu_pct * 100.0).clamp(0.0, 100.0);
        println!(
            "- {} ({}): cpu {:.1}%, mem {} / {}, up {}",
            n.node,
            n.status,
            cpu_pct,
            format_bytes_gib(n.mem_used_bytes),
            format_bytes_gib(n.mem_total_bytes),
            fmt_uptime(n.uptime_secs),
        );
    }
    println!();
    println!("Guests (vmid kind name@node status):");
    for g in &d.guests {
        println!("- {} {} {}@{} {}", g.vmid, g.kind, g.name, g.node, g.status);
    }
    println!();
    println!("Storages (name kind used%/shared nodes):");
    for s in &d.storages {
        let used_pct = if s.total_bytes > 0 {
            #[allow(clippy::cast_precision_loss)]
            let p = (s.used_bytes as f64 / s.total_bytes as f64) * 100.0;
            format!("{p:.0}%")
        } else {
            "n/a".into()
        };
        let shared = if s.shared { "shared" } else { "local" };
        println!(
            "- {} {} {}/{}  on {} nodes",
            s.storage,
            s.kind,
            used_pct,
            shared,
            s.on_nodes.len()
        );
    }
    if let Some(failures) = &d.recent_failures {
        if !failures.is_empty() {
            println!();
            println!("Recent failures ({}):", failures.len());
            for t in failures {
                println!("- {} on {}: {} (id {})", t.kind, t.node, t.status, t.id);
            }
        }
    }
    if let Some(r) = &d.rbac {
        println!();
        println!(
            "RBAC: {} pools ({}), {} users.",
            r.pool_count,
            r.pools.join(", "),
            r.user_count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_digest() -> ClusterDigest {
        ClusterDigest {
            cluster: ClusterInfo {
                pve_version: "9.1.1".into(),
                node_count: 1,
                guest_count: 1,
                storage_count: 1,
            },
            nodes: vec![NodeSummary {
                node: "pve-1".into(),
                status: "online".into(),
                cpu_pct: 0.05,
                mem_used_bytes: 4 * 1024 * 1024 * 1024,
                mem_total_bytes: 32 * 1024 * 1024 * 1024,
                uptime_secs: 86400 * 2,
            }],
            guests: vec![GuestSummary {
                vmid: 100,
                name: "web".into(),
                kind: "qemu".into(),
                node: "pve-1".into(),
                status: "running".into(),
                cores: Some(4),
                mem_mb: Some(4096),
            }],
            storages: vec![StorageSummary {
                storage: "local".into(),
                kind: "dir".into(),
                used_bytes: 50 * 1024 * 1024 * 1024,
                total_bytes: 100 * 1024 * 1024 * 1024,
                shared: false,
                on_nodes: vec!["pve-1".into()],
            }],
            recent_failures: None,
            rbac: None,
        }
    }

    #[test]
    fn json_serializes_with_stable_top_level_keys() {
        let d = sample_digest();
        let v = serde_json::to_value(&d).unwrap();
        for key in &["cluster", "nodes", "guests", "storages"] {
            assert!(
                v.get(key).is_some(),
                "ClusterDigest missing top-level key `{key}`",
            );
        }
    }

    #[test]
    fn format_bytes_gib_is_iec() {
        assert_eq!(format_bytes_gib(0), "0.0 GiB");
        assert_eq!(format_bytes_gib(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(format_bytes_gib(32_u64 * 1024 * 1024 * 1024), "32.0 GiB");
    }

    #[test]
    fn fmt_uptime_collapses_under_24h() {
        assert_eq!(fmt_uptime(3600), "1h");
        assert_eq!(fmt_uptime(86400), "1d0h");
        assert_eq!(fmt_uptime(86400 * 2 + 3600 * 5), "2d5h");
    }
}
