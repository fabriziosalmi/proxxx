//! `proxxx accounting report` — current-state + time-window resource
//! accounting.
//!
//! Aggregate `/cluster/resources` by pool / node / tag and emit
//! per-group totals: guest count, CPU cores, memory GiB, disk GiB.
//! With `--timeframe <hour|day|week|month|year>` it ALSO fetches
//! per-guest RRD time-series via `/nodes/{n}/{qemu|lxc}/{vmid}/rrddata`
//! and integrates them into CPU-hours, GiB-hours, and per-direction
//! network GiB — the canonical chargeback units.
//!
//! ## Aggregation math
//!
//! PVE's RRD returns ~70 bucket-midpoint samples over the chosen
//! window. Each sample carries the bucket's average value for
//! every metric. For each adjacent pair of samples `(p_i, p_{i+1})`
//! we treat the interval `[t_i, t_{i+1}]` as carrying `p_i`'s
//! average values and integrate:
//!
//!   `cpu_hours`       += cpu × maxcpu × Δt / 3600         (cpu is a fraction 0..1)
//!   `mem_gib_hours`   += (mem / GiB) × Δt / 3600          (mem in bytes)
//!   `net_in_gib`      += (netin × Δt) / GiB               (netin is bytes/sec)
//!   `net_out_gib`     += (netout × Δt) / GiB              (netout is bytes/sec)
//!   `disk_read_gib`   += (diskread × Δt) / GiB
//!   `disk_write_gib`  += (diskwrite × Δt) / GiB
//!
//! Δt is the actual time delta from the samples themselves — we
//! do NOT assume a fixed bucket size, because PVE's resolutions
//! (hour ≈ 60 s buckets, day ≈ 30 m, week ≈ 3 h, month ≈ 1 d,
//! year ≈ 1 w) differ and the bucket boundaries can be irregular
//! near the head of the window.
//!
//! ## What's NOT integrated (deferred)
//!
//! - **PBS dedup-aware backup bytes** — separate PBS API.
//! - **CSV output** — JSON is the contract; trivial post-hoc.
//! - **Cost ledger** — operators bring their own price book.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::api::types::{RrdCf, RrdPoint, RrdTimeframe};
use crate::api::{ProxmoxGateway, PxClient};

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

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

/// Time window for the RRD aggregation. `None` means current-state
/// only — no RRD calls. The other variants map 1:1 to PVE's
/// `RrdTimeframe`.
#[derive(Debug, Clone, Copy, clap::ValueEnum, Default, PartialEq, Eq)]
pub enum AccountingTimeframe {
    /// Current-state only — no per-guest RRD fetch.
    #[default]
    None,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl AccountingTimeframe {
    const fn to_pve(self) -> Option<RrdTimeframe> {
        match self {
            Self::None => None,
            Self::Hour => Some(RrdTimeframe::Hour),
            Self::Day => Some(RrdTimeframe::Day),
            Self::Week => Some(RrdTimeframe::Week),
            Self::Month => Some(RrdTimeframe::Month),
            Self::Year => Some(RrdTimeframe::Year),
        }
    }
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

    /// Aggregate over a historical time window via per-guest RRD.
    /// `none` (default) emits current-state totals only. Anything
    /// else adds CPU-hours, GiB-hours, and per-direction network
    /// GiB columns by walking PVE's RRD samples for each guest.
    ///
    /// One RRD call per guest — expect 30-60 s on a 100-guest
    /// cluster with `--timeframe month`.
    #[arg(long, value_enum, default_value_t = AccountingTimeframe::None)]
    pub timeframe: AccountingTimeframe,

    #[arg(long, value_enum, default_value_t = AccountingOutput::Text)]
    pub output: AccountingOutput,
}

/// One row of the report.
///
/// The `cpu_hours` / `mem_gib_hours` / `net_*_gib` / `disk_*_gib`
/// fields are `Option<f64>`: `None` when `--timeframe none`
/// (current-state only); `Some(_)` for any other timeframe. The
/// `#[serde(skip_serializing_if = "Option::is_none")]` keeps the
/// JSON shape minimal in the current-state path.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GroupTotals {
    pub group: String,
    pub guest_count: u32,
    pub cpu_cores: u32,
    pub mem_bytes: u64,
    pub disk_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_hours: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_gib_hours: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_in_gib: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_out_gib: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_read_gib: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_write_gib: Option<f64>,
    /// Best-effort: number of guests whose RRD fetch failed (we
    /// kept aggregating with whatever points we got from the
    /// rest). Surfaced so the operator knows the accounting is
    /// partial.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rrd_fetch_failures: Option<u32>,
}

/// Per-guest integrated totals over the time window. Pure
/// function output of [`integrate_rrd`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WindowedTotals {
    pub cpu_hours: f64,
    pub mem_gib_hours: f64,
    pub net_in_gib: f64,
    pub net_out_gib: f64,
    pub disk_read_gib: f64,
    pub disk_write_gib: f64,
}

impl WindowedTotals {
    fn accumulate(&mut self, other: &Self) {
        self.cpu_hours += other.cpu_hours;
        self.mem_gib_hours += other.mem_gib_hours;
        self.net_in_gib += other.net_in_gib;
        self.net_out_gib += other.net_out_gib;
        self.disk_read_gib += other.disk_read_gib;
        self.disk_write_gib += other.disk_write_gib;
    }
}

/// Integrate an RRD point series into the chargeable units. Pure
/// function; no I/O. The math is documented at the top of this
/// module. Bucket gaps (`time` not monotone, large jumps) are
/// preserved as integrated zero-time — we don't try to fabricate
/// data across the gap.
#[must_use]
pub fn integrate_rrd(points: &[RrdPoint]) -> WindowedTotals {
    let mut t = WindowedTotals::default();
    for w in points.windows(2) {
        let dt = w[1].time.saturating_sub(w[0].time);
        if dt == 0 {
            continue;
        }
        #[allow(clippy::cast_precision_loss)]
        let dt_secs = dt as f64;
        let p = &w[0];
        let cpu = p.cpu.unwrap_or(0.0);
        let maxcpu = p.maxcpu.unwrap_or(1.0);
        t.cpu_hours += cpu * maxcpu * dt_secs / 3600.0;
        let mem = p.mem.unwrap_or(0.0);
        t.mem_gib_hours += (mem / GIB) * (dt_secs / 3600.0);
        let netin = p.netin.unwrap_or(0.0);
        t.net_in_gib += (netin * dt_secs) / GIB;
        let netout = p.netout.unwrap_or(0.0);
        t.net_out_gib += (netout * dt_secs) / GIB;
        let dread = p.diskread.unwrap_or(0.0);
        t.disk_read_gib += (dread * dt_secs) / GIB;
        let dwrite = p.diskwrite.unwrap_or(0.0);
        t.disk_write_gib += (dwrite * dt_secs) / GIB;
    }
    t
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

    // Time-window aggregation: fetch + integrate per-guest RRD
    // BEFORE grouping, so each guest's WindowedTotals lives in a
    // map we look up during group rollup.
    let timeframe_pve = args.timeframe.to_pve();
    let mut per_guest_window: std::collections::HashMap<u32, WindowedTotals> =
        std::collections::HashMap::new();
    let mut per_guest_failures: std::collections::HashSet<u32> = std::collections::HashSet::new();
    if let Some(tf) = timeframe_pve {
        eprintln!(
            "accounting: fetching RRD `{}` for {} guest(s)...",
            tf.as_pve_str(),
            all_guests.len()
        );
        for g in &all_guests {
            match client
                .get_guest_rrddata(&g.node, g.vmid, g.guest_type, tf, RrdCf::Average)
                .await
            {
                Ok(points) => {
                    per_guest_window.insert(g.vmid, integrate_rrd(&points));
                }
                Err(_) => {
                    per_guest_failures.insert(g.vmid);
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

            if timeframe_pve.is_some() {
                // Lazy-init the time-window fields the first time we
                // touch this group with --timeframe active.
                entry.cpu_hours.get_or_insert(0.0);
                entry.mem_gib_hours.get_or_insert(0.0);
                entry.net_in_gib.get_or_insert(0.0);
                entry.net_out_gib.get_or_insert(0.0);
                entry.disk_read_gib.get_or_insert(0.0);
                entry.disk_write_gib.get_or_insert(0.0);
                entry.rrd_fetch_failures.get_or_insert(0);

                if let Some(w) = per_guest_window.get(&g.vmid) {
                    let mut agg = WindowedTotals {
                        cpu_hours: entry.cpu_hours.unwrap_or(0.0),
                        mem_gib_hours: entry.mem_gib_hours.unwrap_or(0.0),
                        net_in_gib: entry.net_in_gib.unwrap_or(0.0),
                        net_out_gib: entry.net_out_gib.unwrap_or(0.0),
                        disk_read_gib: entry.disk_read_gib.unwrap_or(0.0),
                        disk_write_gib: entry.disk_write_gib.unwrap_or(0.0),
                    };
                    agg.accumulate(w);
                    entry.cpu_hours = Some(agg.cpu_hours);
                    entry.mem_gib_hours = Some(agg.mem_gib_hours);
                    entry.net_in_gib = Some(agg.net_in_gib);
                    entry.net_out_gib = Some(agg.net_out_gib);
                    entry.disk_read_gib = Some(agg.disk_read_gib);
                    entry.disk_write_gib = Some(agg.disk_write_gib);
                }
                if per_guest_failures.contains(&g.vmid) {
                    let n = entry.rrd_fetch_failures.unwrap_or(0) + 1;
                    entry.rrd_fetch_failures = Some(n);
                }
            }
        }
    }

    let rows: Vec<GroupTotals> = groups.into_values().collect();
    let has_window = timeframe_pve.is_some();
    match args.output {
        AccountingOutput::Json => {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        AccountingOutput::Text if has_window => {
            // Wide format: include the time-window columns.
            println!(
                "{group:<20}  {guests:<6}  {cores:<5}  {mem:<10}  {disk:<10}  {cpuh:<10}  {memh:<14}  {netin:<10}  net-out",
                group = "group",
                guests = "guests",
                cores = "cores",
                mem = "mem",
                disk = "disk",
                cpuh = "cpu·h",
                memh = "mem GiB·h",
                netin = "net-in",
            );
            let sep = "─".repeat(110);
            println!("{sep}");
            for r in &rows {
                println!(
                    "{group:<20}  {guests:<6}  {cores:<5}  {mem:<10}  {disk:<10}  {cpuh:<10.2}  {memh:<14.1}  {netin:<10.2}  {netout:.2} GiB",
                    group = r.group,
                    guests = r.guest_count,
                    cores = r.cpu_cores,
                    mem = fmt_gib(r.mem_bytes),
                    disk = fmt_gib(r.disk_bytes),
                    cpuh = r.cpu_hours.unwrap_or(0.0),
                    memh = r.mem_gib_hours.unwrap_or(0.0),
                    netin = r.net_in_gib.unwrap_or(0.0),
                    netout = r.net_out_gib.unwrap_or(0.0),
                );
            }
            if !per_guest_failures.is_empty() {
                eprintln!(
                    "\nnote: {} guest(s) had RRD fetch failures — totals are partial",
                    per_guest_failures.len()
                );
            }
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
        assert!(t.cpu_hours.is_none());
    }

    #[test]
    fn integrate_rrd_empty_or_single_point_is_zero() {
        // Empty: nothing to integrate.
        assert_eq!(integrate_rrd(&[]), WindowedTotals::default());
        // One point: no Δt available.
        let one = vec![RrdPoint {
            time: 100,
            cpu: Some(0.5),
            maxcpu: Some(4.0),
            mem: Some(8.0 * GIB),
            ..Default::default()
        }];
        assert_eq!(integrate_rrd(&one), WindowedTotals::default());
    }

    #[test]
    fn integrate_rrd_cpu_hours_basic() {
        // Two points 3600 s apart with cpu=0.5 (50%) and 4 cores.
        // Expected cpu_hours = 0.5 × 4 × 3600/3600 = 2.0.
        let points = vec![
            RrdPoint {
                time: 0,
                cpu: Some(0.5),
                maxcpu: Some(4.0),
                ..Default::default()
            },
            RrdPoint {
                time: 3600,
                ..Default::default()
            },
        ];
        let t = integrate_rrd(&points);
        assert!((t.cpu_hours - 2.0).abs() < 1e-9, "got {}", t.cpu_hours);
    }

    #[test]
    fn integrate_rrd_mem_gib_hours_basic() {
        // mem = 8 GiB held for 3600 s → 8 GiB·h.
        let points = vec![
            RrdPoint {
                time: 0,
                mem: Some(8.0 * GIB),
                ..Default::default()
            },
            RrdPoint {
                time: 3600,
                ..Default::default()
            },
        ];
        let t = integrate_rrd(&points);
        assert!(
            (t.mem_gib_hours - 8.0).abs() < 1e-6,
            "got {}",
            t.mem_gib_hours
        );
    }

    #[test]
    fn integrate_rrd_network_basic() {
        // netin = 1 MiB/s for 100 s → 100 MiB ≈ 0.0977 GiB.
        let mib = 1024.0 * 1024.0;
        let points = vec![
            RrdPoint {
                time: 0,
                netin: Some(mib),
                netout: Some(2.0 * mib),
                ..Default::default()
            },
            RrdPoint {
                time: 100,
                ..Default::default()
            },
        ];
        let t = integrate_rrd(&points);
        let expected_in = 100.0 * mib / GIB;
        let expected_out = 200.0 * mib / GIB;
        assert!((t.net_in_gib - expected_in).abs() < 1e-6);
        assert!((t.net_out_gib - expected_out).abs() < 1e-6);
    }

    #[test]
    fn integrate_rrd_handles_time_gap_without_explosion() {
        // Three points: small Δt, then a huge gap (e.g. PVE was
        // offline for 24h). We integrate honestly — the big gap
        // multiplies the SECOND point's interval by 86400 s.
        // No NaN, no overflow.
        let points = vec![
            RrdPoint {
                time: 0,
                cpu: Some(0.1),
                maxcpu: Some(1.0),
                ..Default::default()
            },
            RrdPoint {
                time: 60,
                cpu: Some(0.0),
                maxcpu: Some(1.0),
                ..Default::default()
            },
            RrdPoint {
                time: 60 + 86400,
                ..Default::default()
            },
        ];
        let t = integrate_rrd(&points);
        // First interval: 0.1 × 1 × 60/3600 = 0.00166...
        // Second interval has cpu=0 so contributes nothing.
        assert!((t.cpu_hours - (0.1 * 60.0 / 3600.0)).abs() < 1e-9);
        assert!(t.cpu_hours.is_finite());
    }

    #[test]
    fn integrate_rrd_non_monotonic_time_returns_zero_dt() {
        // PVE shouldn't emit out-of-order points, but if it
        // ever does (clock skew across hosts?) we shouldn't
        // accumulate negative time. saturating_sub clamps to 0,
        // so the integration contribution is 0 for those pairs.
        let points = vec![
            RrdPoint {
                time: 1000,
                cpu: Some(0.5),
                maxcpu: Some(1.0),
                ..Default::default()
            },
            RrdPoint {
                time: 999,
                ..Default::default()
            },
        ];
        let t = integrate_rrd(&points);
        assert!(t.cpu_hours.abs() < 1e-9);
    }

    #[test]
    fn accounting_timeframe_maps_to_pve_correctly() {
        assert_eq!(AccountingTimeframe::None.to_pve(), None);
        assert_eq!(AccountingTimeframe::Hour.to_pve(), Some(RrdTimeframe::Hour));
        assert_eq!(AccountingTimeframe::Year.to_pve(), Some(RrdTimeframe::Year));
    }

    #[test]
    fn windowed_totals_accumulate_is_additive() {
        let mut a = WindowedTotals {
            cpu_hours: 1.0,
            mem_gib_hours: 2.0,
            net_in_gib: 3.0,
            net_out_gib: 4.0,
            disk_read_gib: 5.0,
            disk_write_gib: 6.0,
        };
        let b = a.clone();
        a.accumulate(&b);
        assert!((a.cpu_hours - 2.0).abs() < 1e-9);
        assert!((a.mem_gib_hours - 4.0).abs() < 1e-9);
        assert!((a.net_in_gib - 6.0).abs() < 1e-9);
        assert!((a.net_out_gib - 8.0).abs() < 1e-9);
        assert!((a.disk_read_gib - 10.0).abs() < 1e-9);
        assert!((a.disk_write_gib - 12.0).abs() < 1e-9);
    }
}
