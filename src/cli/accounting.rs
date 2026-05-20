//! `proxxx accounting report` — current-state resource accounting.
//!
//! Aggregate `/cluster/resources` by pool / user / node / tag and
//! emit per-group totals: guest count, CPU cores, memory GiB, disk
//! GiB. Useful for MSP invoicing snapshots, internal chargeback, and
//! "is this pool really worth its slot?" capacity reviews.
//!
//! ## MVP scope (per #62)
//!
//! - **Current-state only.** Time-window aggregation (CPU-hours over
//!   the last 30 days from RRD) is the obvious follow-up but requires
//!   parsing PVE's RRD files via `/nodes/{n}/rrd` — separate work.
//!   The single-point-in-time report is useful in its own right:
//!   "as of now, pool X is using N cores and M GiB across K guests."
//! - **PBS dedup-aware backup bytes** — explicitly out per the
//!   issue's v1 ladder; that's a PBS API integration that lives in
//!   a follow-up.
//! - **Output**: text (default) or JSON. CSV mentioned in the issue
//!   is trivial to add post-MVP; the JSON shape is the contract.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::api::{ProxmoxGateway, PxClient};

/// Grouping dimension.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum GroupBy {
    /// Resource pool (PVE `/pool/<name>`).
    Pool,
    /// Cluster node.
    Node,
    /// Free-form tag — guests have a CSV `tags` field; each tag
    /// becomes its own row (a guest with `prod,critical` contributes
    /// to two groups).
    Tag,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, Default)]
pub enum AccountingOutput {
    #[default]
    Text,
    Json,
}

#[derive(Debug, clap::Args)]
pub struct AccountingReportArgs {
    /// Dimension to aggregate on. Defaults to `pool` — the most
    /// common chargeback question.
    #[arg(long, value_enum, default_value_t = GroupBy::Pool)]
    pub group_by: GroupBy,

    /// Include guests with no group assignment under a synthetic
    /// `(none)` row. Off by default — operators usually want to
    /// see assigned pools only.
    #[arg(long)]
    pub include_unassigned: bool,

    #[arg(long, value_enum, default_value_t = AccountingOutput::Text)]
    pub output: AccountingOutput,
}

/// One row of the report.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GroupTotals {
    pub group: String,
    pub guest_count: u32,
    pub cpu_cores: u32,
    pub mem_bytes: u64,
    pub disk_bytes: u64,
}

pub async fn execute_accounting(
    client: &Arc<PxClient>,
    args: AccountingReportArgs,
) -> Result<(Value, i32)> {
    // Pull every guest in one shot.
    let nodes = client.get_nodes().await?;
    let mut all_guests: Vec<crate::api::types::Guest> = Vec::new();
    for n in &nodes {
        if let Ok(g) = client.get_guests(&n.node).await {
            all_guests.extend(g);
        }
    }

    // Pool membership is per-guest via `/pools/<id>/members`. For
    // current-state accounting we walk every pool once and build a
    // vmid → poolid map; the alternative (per-guest pool lookup)
    // would be N calls instead of P.
    let mut vmid_to_pool: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    if matches!(args.group_by, GroupBy::Pool) {
        if let Ok(pools) = client.list_pools().await {
            for p in pools {
                if let Ok(details) = client.get_pool(&p.poolid).await {
                    for m in details.members {
                        // PoolMember.vmid is `u32`; `0` denotes a
                        // non-guest entry (storage member). Skip
                        // those — accounting only cares about guests.
                        if m.vmid != 0 {
                            vmid_to_pool.insert(m.vmid, p.poolid.clone());
                        }
                    }
                }
            }
        }
    }

    let mut groups: BTreeMap<String, GroupTotals> = BTreeMap::new();
    for g in &all_guests {
        let group_keys: Vec<String> = match args.group_by {
            GroupBy::Pool => match vmid_to_pool.get(&g.vmid) {
                Some(p) => vec![p.clone()],
                None if args.include_unassigned => vec!["(none)".into()],
                None => continue,
            },
            GroupBy::Node => vec![g.node.clone()],
            GroupBy::Tag => {
                let tags: Vec<String> = g
                    .tags
                    .split([';', ','])
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                if tags.is_empty() {
                    if args.include_unassigned {
                        vec!["(no-tag)".into()]
                    } else {
                        continue;
                    }
                } else {
                    tags
                }
            }
        };
        for key in group_keys {
            let entry = groups.entry(key.clone()).or_insert(GroupTotals {
                group: key,
                ..GroupTotals::default()
            });
            entry.guest_count += 1;
            entry.cpu_cores = entry.cpu_cores.saturating_add(g.cpus);
            entry.mem_bytes = entry.mem_bytes.saturating_add(g.maxmem);
            entry.disk_bytes = entry.disk_bytes.saturating_add(g.maxdisk);
        }
    }

    let rows: Vec<GroupTotals> = groups.into_values().collect();
    match args.output {
        AccountingOutput::Json => {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        AccountingOutput::Text => {
            println!(
                "{group:<24}  {guests:<8}  {cores:<8}  {mem:<12}  disk",
                group = "group",
                guests = "guests",
                cores = "cores",
                mem = "mem"
            );
            let sep = "─".repeat(72);
            println!("{sep}");
            for r in &rows {
                println!(
                    "{group:<24}  {guests:<8}  {cores:<8}  {mem:<12}  {disk}",
                    group = r.group,
                    guests = r.guest_count,
                    cores = r.cpu_cores,
                    mem = fmt_gib(r.mem_bytes),
                    disk = fmt_gib(r.disk_bytes),
                );
            }
        }
    }
    Ok((Value::Null, 0))
}

fn fmt_gib(n: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let g = (n as f64) / (1024.0 * 1024.0 * 1024.0);
    format!("{g:.1} GiB")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_gib_handles_breakpoints() {
        assert_eq!(fmt_gib(0), "0.0 GiB");
        assert_eq!(fmt_gib(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(fmt_gib(8_u64 * 1024 * 1024 * 1024), "8.0 GiB");
    }

    #[test]
    fn group_totals_default_is_zeroed() {
        let t = GroupTotals::default();
        assert_eq!(t.guest_count, 0);
        assert_eq!(t.cpu_cores, 0);
        assert_eq!(t.mem_bytes, 0);
        assert_eq!(t.disk_bytes, 0);
    }
}
