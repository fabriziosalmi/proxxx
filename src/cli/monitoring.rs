//! Observability surface — metrics (RRD time-series), external metric
//! exporters, alert engine + daemon, PVE 8 notifications, storage
//! health (disks/SMART/LVM/ZFS), HA inspector + failover preview,
//! replication job inspector.

use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Subcommand)]
pub enum AlertsCommand {
    /// One-shot evaluation of all configured rules. Prints events that
    /// would fire as JSON. Does NOT send. Use this in cron pipelines
    /// piped to your own notifier, or for `--dry-run`-style tests.
    Eval,
    /// Long-running daemon: poll cluster state every `--interval` and
    /// dispatch events through the configured channels. Dedup window
    /// per rule. Stop with Ctrl+C.
    Watch {
        /// Polling interval in seconds. Default 30.
        #[arg(long, default_value_t = 30)]
        interval: u64,
    },
    /// Send a synthetic test event to validate channel config end-to-end.
    Test {
        /// Route spec, e.g. `"telegram"`, `"ntfy:topic"`, `"webhook:URL"`.
        #[arg(long)]
        route: String,
        /// Severity for the test event. Default `info`.
        #[arg(long, default_value = "info")]
        severity: String,
    },
}

/// Selectable metric for `proxxx metrics …`. Each variant maps to a
/// `RrdPoint` field via the extractor in `execute_metrics`. Closed
/// enum (clap `ValueEnum`) so users can't typo their way into a silent
/// no-op.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum MetricField {
    /// CPU utilisation (0.0..1.0; multiply by 100 for percentage).
    Cpu,
    /// Memory used (bytes). For node, falls back to `memused` when
    /// `mem` is absent (PVE node responses use the verbose name).
    Mem,
    /// Bytes read from disk in this bucket.
    Diskread,
    /// Bytes written to disk in this bucket.
    Diskwrite,
    /// Bytes received on network.
    Netin,
    /// Bytes sent on network.
    Netout,
    /// Load average (node-only).
    Loadavg,
    /// IO-wait fraction (node-only).
    Iowait,
    /// Capacity used. Storage = `used`; guest = `disk`.
    Used,
    /// Total capacity. Storage = `total`; guest = `maxdisk`.
    Total,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TimeframeCli {
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl From<TimeframeCli> for crate::api::types::RrdTimeframe {
    fn from(t: TimeframeCli) -> Self {
        match t {
            TimeframeCli::Hour => Self::Hour,
            TimeframeCli::Day => Self::Day,
            TimeframeCli::Week => Self::Week,
            TimeframeCli::Month => Self::Month,
            TimeframeCli::Year => Self::Year,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CfCli {
    Average,
    Max,
}

impl From<CfCli> for crate::api::types::RrdCf {
    fn from(c: CfCli) -> Self {
        match c {
            CfCli::Average => Self::Average,
            CfCli::Max => Self::Max,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum MetricsCommand {
    /// Per-VM metrics. Auto-discovers which node owns the VMID unless
    /// `--node` is supplied (faster — skips the cluster-wide scan).
    Vm {
        vmid: u32,
        #[arg(long)]
        node: Option<String>,
        #[arg(long, value_enum, default_value_t = MetricField::Cpu)]
        field: MetricField,
        #[arg(long, value_enum, default_value_t = TimeframeCli::Hour)]
        timeframe: TimeframeCli,
        #[arg(long, value_enum, default_value_t = CfCli::Average)]
        cf: CfCli,
    },
    /// Per-LXC metrics.
    Ct {
        vmid: u32,
        #[arg(long)]
        node: Option<String>,
        #[arg(long, value_enum, default_value_t = MetricField::Cpu)]
        field: MetricField,
        #[arg(long, value_enum, default_value_t = TimeframeCli::Hour)]
        timeframe: TimeframeCli,
        #[arg(long, value_enum, default_value_t = CfCli::Average)]
        cf: CfCli,
    },
    /// Per-node metrics. Adds `loadavg`, `iowait`, root pool usage on
    /// top of the guest fields.
    Node {
        node: String,
        #[arg(long, value_enum, default_value_t = MetricField::Cpu)]
        field: MetricField,
        #[arg(long, value_enum, default_value_t = TimeframeCli::Hour)]
        timeframe: TimeframeCli,
        #[arg(long, value_enum, default_value_t = CfCli::Average)]
        cf: CfCli,
    },
    /// Per-storage capacity metrics (`used` / `total`).
    Storage {
        #[arg(long)]
        node: String,
        #[arg(long)]
        storage: String,
        #[arg(long, value_enum, default_value_t = MetricField::Used)]
        field: MetricField,
        #[arg(long, value_enum, default_value_t = TimeframeCli::Hour)]
        timeframe: TimeframeCli,
        #[arg(long, value_enum, default_value_t = CfCli::Average)]
        cf: CfCli,
    },
    /// Start a Prometheus metrics exporter. Scrapes nodes, guests and
    /// storage from the PVE API on every pull and serves them in
    /// Prometheus text format on GET /metrics. No auth — bind to
    /// localhost and put a reverse proxy or firewall in front for
    /// production deployments.
    Serve {
        /// Bind address (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        /// Listen port (default: 9100)
        #[arg(long, default_value_t = 9100)]
        port: u16,
    },
    /// Pre-rendered PNG graph reference (server-side path) for a guest.
    /// Distinct from `vm`/`ct` which return numeric series — this is
    /// for UI/export pipelines wanting an existing image.
    RrdPng {
        vmid: u32,
        /// `cpu`, `memory`, `netin`, `netout`, `diskread`, `diskwrite`.
        #[arg(long)]
        ds: String,
        #[arg(long, value_enum, default_value_t = TimeframeCli::Hour)]
        timeframe: TimeframeCli,
        #[arg(long, value_enum, default_value_t = CfCli::Average)]
        cf: CfCli,
    },
}

/// External metric exporter CRUD (`/cluster/metrics/server`).
/// Two protocols supported by PVE: `influxdb` and `graphite`. Each
/// has different mandatory + optional fields; less-common knobs go
/// via `--raw KEY=VAL`.
#[derive(Debug, Subcommand)]
pub enum MetricServersCommand {
    List,
    Show {
        id: String,
    },
    /// Create an exporter. PVE routes per-id: POST /cluster/metrics/
    /// server/{id} with `type` + protocol-specific knobs in the body.
    Create {
        /// Exporter id (operator-chosen name).
        #[arg(long)]
        id: String,
        /// `influxdb` | `graphite`.
        #[arg(long, value_name = "TYPE")]
        server_type: String,
        /// Server hostname or IP.
        #[arg(long)]
        server: String,
        /// Server port (e.g. 8086 for `InfluxDB` OSS, 2003 for Graphite).
        #[arg(long)]
        port: u16,
        #[arg(long)]
        comment: Option<String>,
        /// influxdb: `udp` | `http` | `https`.
        #[arg(long)]
        influxdbproto: Option<String>,
        /// graphite: `tcp` | `udp`.
        #[arg(long)]
        proto: Option<String>,
        /// influxdb cloud: org. influxdb OSS: ignored.
        #[arg(long)]
        organization: Option<String>,
        /// influxdb: target bucket / database name.
        #[arg(long)]
        bucket: Option<String>,
        /// graphite: top-level path prefix.
        #[arg(long)]
        path: Option<String>,
        /// influxdb 2.x: bearer token.
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        id: String,
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        disable: Option<bool>,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        id: String,
        #[arg(long)]
        yes: bool,
    },
}

/// PVE 8+ notifications. Three sub-trees, one per resource:
/// `endpoint` (delivery mechanisms), `matcher` (routing rules),
/// `target` (read-only valid-name list).
#[derive(Debug, Subcommand)]
pub enum NotificationsCommand {
    #[command(subcommand)]
    Endpoint(NotificationEndpointCommand),
    #[command(subcommand)]
    Matcher(NotificationMatcherCommand),
    /// List all valid delivery target names (endpoints + groups).
    Targets,
}

#[derive(Debug, Subcommand)]
pub enum NotificationEndpointCommand {
    /// List all configured endpoints across all types.
    List,
    /// Create an endpoint. Type-specific knobs go via `--raw KEY=VAL`
    /// (e.g. for smtp: `--raw server=mail.example.com --raw from=…`;
    /// for gotify: `--raw server=https://gotify.example.com --raw token=…`).
    Create {
        /// Endpoint type: `sendmail` | `smtp` | `gotify` | `webhook`.
        #[arg(long)]
        endpoint_type: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        #[arg(long)]
        endpoint_type: String,
        name: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        disable: Option<bool>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        #[arg(long)]
        endpoint_type: String,
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum NotificationMatcherCommand {
    List,
    /// Create a routing rule. `--target` is repeatable (each one is an
    /// endpoint or group name). Match clauses via `--match-field` /
    /// `--match-severity` (also repeatable).
    Create {
        #[arg(long)]
        name: String,
        /// Repeatable — endpoint/group names to deliver matched events to.
        #[arg(long, required = true)]
        target: Vec<String>,
        /// Repeatable — `field=pattern` clauses (e.g. `type=vzdump`).
        #[arg(long)]
        match_field: Vec<String>,
        /// Repeatable — severity filters (`error`, `warning`, etc.).
        #[arg(long)]
        match_severity: Vec<String>,
        /// `all` (default) | `any`.
        #[arg(long)]
        mode: Option<String>,
        #[arg(long)]
        invert_match: Option<bool>,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        name: String,
        #[arg(long)]
        target: Vec<String>,
        #[arg(long)]
        match_field: Vec<String>,
        #[arg(long)]
        match_severity: Vec<String>,
        #[arg(long)]
        mode: Option<String>,
        #[arg(long)]
        invert_match: Option<bool>,
        #[arg(long)]
        disable: Option<bool>,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum DisksCommand {
    /// Physical disk inventory: model, serial, size, current usage,
    /// SMART verdict. One row per `/dev/sd*` / `/dev/nvme*`.
    List {
        #[arg(long)]
        node: String,
    },
    /// Full SMART output for one disk. Use the `devpath` from
    /// `disks list` (e.g. `/dev/sda`). For NVME the `attributes`
    /// table is empty — the smartctl `text` blob carries the
    /// data instead.
    Smart {
        #[arg(long)]
        node: String,
        /// Block device path, e.g. `/dev/sda` or `/dev/nvme0n1`.
        #[arg(long)]
        disk: String,
    },
    /// LVM volume groups on the node.
    Lvm {
        #[arg(long)]
        node: String,
    },
    /// LVM-thin pools on the node. The `metadata_used / metadata_size`
    /// ratio is the canary — at ~1.0 the thin pool stops accepting
    /// writes and every VM on top of it freezes.
    Lvmthin {
        #[arg(long)]
        node: String,
    },
    /// ZFS pools on the node. Watch `health != "ONLINE"` — anything
    /// else (DEGRADED, FAULTED, REMOVED, UNAVAIL) is operator-actionable.
    Zfs {
        #[arg(long)]
        node: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum HaCommand {
    /// List HA groups (PVE-version-tolerant: hits `/cluster/ha/rules`
    /// on PVE 9, falls back to `/cluster/ha/groups` semantics).
    Groups,
    /// Hit the LITERAL `/cluster/ha/groups` path (PVE 8 only — on
    /// PVE 9 this returns 500 because the path was migrated to
    /// `/cluster/ha/rules`).
    GroupsLegacy,
    /// Create an HA group (PVE 8). Nodes are CSV with optional
    /// `:priority` suffixes, e.g. `pve1:2,pve2:1,pve3`.
    GroupCreate {
        #[arg(long)]
        group: String,
        /// Member nodes, CSV with optional `:N` priorities.
        #[arg(long)]
        nodes: String,
        /// Restrict resources to nodes in the group only (no fallback
        /// to other nodes when all members are down).
        #[arg(long, default_value_t = false)]
        restricted: bool,
        /// Don't auto-fall-back when the preferred node returns.
        #[arg(long, default_value_t = false)]
        nofailback: bool,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Update an HA group's nodes / restricted / nofailback / comment.
    GroupUpdate {
        group: String,
        #[arg(long)]
        nodes: Option<String>,
        #[arg(long)]
        restricted: Option<bool>,
        #[arg(long)]
        nofailback: Option<bool>,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Delete an HA group. Refuses unless `--yes` is passed.
    GroupDelete {
        group: String,
        #[arg(long)]
        yes: bool,
    },
    /// List HA-managed resources (VMs/CTs).
    Resources,
    /// Show the HA manager runtime status (raw CRM internal state).
    Status,
    /// User-facing live HA status — heterogeneous list mixing per-node,
    /// per-service, and master/quorum rows. Higher-level than `status`.
    StatusCurrent,
    /// "What if?" preview: where does each resource land if a node fails?
    Preview {
        /// Node to simulate as failed.
        #[arg(long)]
        node: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ReplicationCommand {
    /// List configured replication jobs (cluster-wide).
    Jobs,
    /// Show runtime status of replication jobs on one node.
    Status {
        #[arg(long)]
        node: String,
    },
}

/// Feature #8 — alerts CLI dispatch.
pub async fn execute_alerts(
    client: &Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    profile: Option<&str>,
    action: AlertsCommand,
) -> Result<(Value, i32)> {
    use crate::alerts::engine::{evaluate, ClusterSnapshot, EngineState};
    use crate::alerts::{parse_route, send_event, AlertEvent, DedupCache, Severity};
    use crate::api::ProxmoxGateway;

    // Build a cluster snapshot once (used by Eval and Watch).
    async fn snapshot(client: &crate::api::PxClient) -> Result<ClusterSnapshot> {
        let nodes = client.get_nodes().await.unwrap_or_default();
        let mut storage = Vec::new();
        let mut replication = Vec::new();
        for n in &nodes {
            if n.status == crate::api::types::NodeStatus::Online {
                if let Ok(s) = client.get_storage_pools(&n.node).await {
                    storage.extend(s);
                }
                if let Ok(r) = client.list_replication_status(&n.node).await {
                    replication.extend(r);
                }
            }
        }
        Ok(ClusterSnapshot {
            nodes,
            storage,
            replication,
        })
    }

    match action {
        AlertsCommand::Eval => {
            let rules = config.alerts.clone().unwrap_or_default();
            if rules.is_empty() {
                return Ok((
                    serde_json::json!({"events": [], "warning": "no [[alerts]] rules configured"}),
                    0,
                ));
            }
            let snap = snapshot(client).await?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let (events, _state) = evaluate(&rules, &snap, EngineState::default(), now);
            Ok((
                serde_json::json!({
                    "evaluated_rules": rules.len(),
                    "events": events,
                }),
                0,
            ))
        }
        AlertsCommand::Watch { interval } => {
            let rules = config.alerts.clone().unwrap_or_default();
            if rules.is_empty() {
                anyhow::bail!("no [[alerts]] rules configured — nothing to watch");
            }
            let http = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let tg = match config.telegram.as_ref() {
                None => None,
                Some(cfg) => Some(crate::hitl::telegram::TelegramGateway::from_config(cfg).await?),
            };

            // Pre-parse routes once — invalid specs are reported then.
            let parsed_routes: Vec<(crate::config::AlertRuleConfig, Vec<crate::alerts::Channel>)> =
                rules
                    .iter()
                    .map(|r| {
                        let chans: Vec<crate::alerts::Channel> = r
                            .route
                            .iter()
                            .filter_map(|s| {
                                let p = parse_route(s);
                                if p.is_none() {
                                    tracing::warn!("rule {}: ignoring unknown route {s:?}", r.name);
                                }
                                p
                            })
                            .collect();
                        (r.clone(), chans)
                    })
                    .collect();

            let mut state = EngineState::default();
            // Cache schema v2 — persist the dedup window across daemon
            // restarts so a routine restart (config reload, kernel
            // update, accidental SIGHUP) does NOT re-fire every active
            // alert. Best-effort: a missing/corrupt cache yields an
            // empty DedupCache rather than failing the daemon.
            let mut dedup = match crate::app::cache::load_alert_dedup(profile) {
                Ok(rows) => {
                    if !rows.is_empty() {
                        tracing::info!(
                            "alert daemon: restored {} dedup entries from cache",
                            rows.len()
                        );
                    }
                    DedupCache::from_entries(rows)
                }
                Err(e) => {
                    tracing::warn!("alert daemon: dedup cache load failed: {e:#} — starting empty");
                    DedupCache::default()
                }
            };
            tracing::info!(
                "alert daemon starting: {} rules, interval {}s",
                rules.len(),
                interval
            );
            // (macro audit) — graceful shutdown on
            // SIGTERM/SIGINT. The select! races the daemon's tick
            // against the signal handler; whichever fires first wins.
            // On SIGTERM systemd waits up to 90 s before SIGKILL —
            // we comfortably exit within milliseconds.
            loop {
                tokio::select! {
                    biased; // signals are higher priority than the next tick
                    () = crate::util::shutdown::wait_for_shutdown_signal() => {
                        tracing::info!("alert daemon: shutdown signal received, exiting cleanly");
                        // Final flush so the dedup window survives the
                        // shutdown — operator restarts the daemon, the
                        // cache is current. Best-effort by design.
                        // Phase 12 audit fix: async wrapper so a contended
                        // SQLite flush at shutdown can't pin the runtime
                        // and delay the systemd 90s SIGKILL window.
                        if let Err(e) = crate::app::cache::save_alert_dedup_async(
                            profile.map(str::to_owned),
                            dedup.entries(),
                        )
                        .await
                        {
                            tracing::warn!(
                                "alert daemon: dedup cache flush at shutdown failed: {e:#}"
                            );
                        }
                        return Ok((
                            serde_json::json!({ "status": "shutdown" }),
                            0,
                        ));
                    }
                    snap_res = snapshot(client) => {
                        let snap = match snap_res {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(
                                    "snapshot fetch failed: {e:#} — retrying next tick"
                                );
                                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                                continue;
                            }
                        };
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let (events, new_state) = evaluate(&rules, &snap, state, now);
                        state = new_state;

                        for ev in &events {
                            let Some((rule, channels)) =
                                parsed_routes.iter().find(|(r, _)| r.name == ev.rule)
                            else {
                                continue;
                            };
                            if !dedup.allow(&ev.rule, &ev.target, rule.dedup_secs, now) {
                                continue;
                            }
                            for ch in channels {
                                if let Err(e) = send_event(ch, ev, &http, tg.as_ref()).await {
                                    tracing::warn!("alert {} → {ch:?} failed: {e:#}", ev.rule);
                                }
                            }
                        }

                        dedup.evict_older_than(86_400, now);
                        // Persist after each tick so a crash within
                        // `sleep` window costs at most one tick of
                        // dedup state. Best-effort — a transient I/O
                        // error must not kill the daemon.
                        // Phase 12 audit fix: async wrapper — see the
                        // shutdown branch above for rationale.
                        if let Err(e) = crate::app::cache::save_alert_dedup_async(
                            profile.map(str::to_owned),
                            dedup.entries(),
                        )
                        .await
                        {
                            tracing::warn!("alert daemon: dedup cache save failed: {e:#}");
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                    }
                }
            }
        }
        AlertsCommand::Test { route, severity } => {
            let ch = parse_route(&route)
                .ok_or_else(|| anyhow::anyhow!("invalid route spec: {route}"))?;
            let http = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let tg = match config.telegram.as_ref() {
                None => None,
                Some(cfg) => Some(crate::hitl::telegram::TelegramGateway::from_config(cfg).await?),
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let event = AlertEvent {
                rule: "_test".into(),
                severity: Severity::parse(&severity),
                target: "_test".into(),
                summary: "synthetic test event from `proxxx alerts test`".into(),
                detail: serde_json::json!({"source": "proxxx alerts test"}),
                at: now,
            };
            send_event(&ch, &event, &http, tg.as_ref()).await?;
            Ok((
                serde_json::json!({
                    "route": route,
                    "channel": format!("{ch:?}"),
                    "status": "sent"
                }),
                0,
            ))
        }
    }
}

/// Hill 3b — time-series metrics CLI. Default emits a Unicode block
/// sparkline + min/max/avg over the chosen field; `--format json`
/// short-circuits and returns the raw rrddata. Auto-discovers the
/// owning node when the user omits `--node` for vm/ct.
pub async fn execute_metrics(
    client: &Arc<crate::api::PxClient>,
    action: MetricsCommand,
) -> Result<(Value, i32)> {
    use crate::api::types::{GuestType, RrdPoint};
    use crate::api::ProxmoxGateway;

    // RrdPng returns a server-side filename — different shape from the
    // numeric sparkline pipeline below, so handle it as an early return.
    if let MetricsCommand::RrdPng {
        vmid,
        ds,
        timeframe,
        cf,
    } = &action
    {
        let (node_name, gt) = crate::cli::common::find_guest(client, *vmid).await?;
        let img = client
            .get_guest_rrd_image(&node_name, *vmid, gt, ds, (*timeframe).into(), (*cf).into())
            .await?;
        return Ok((
            serde_json::json!({
                "vmid": vmid,
                "node": node_name,
                "ds": ds,
                "filename": img.filename,
            }),
            0,
        ));
    }

    // `metrics serve` is long-running — handle before the sparkline path.
    if let MetricsCommand::Serve { bind, port } = action {
        crate::metrics::run_metrics_server(Arc::clone(client), &bind, port).await?;
        return Ok((serde_json::json!({"status": "exited"}), 0));
    }

    // Helper: extract one optional metric from each point. Used for
    // both the sparkline render path AND the summary stats.
    fn extract(p: &RrdPoint, field: MetricField) -> Option<f64> {
        match field {
            MetricField::Cpu => p.cpu,
            // For node, `mem` is often absent; PVE returns memused
            // instead. Fall back so a `--field mem` request on a node
            // doesn't render an all-gap sparkline.
            MetricField::Mem => p.mem.or(p.memused),
            MetricField::Diskread => p.diskread,
            MetricField::Diskwrite => p.diskwrite,
            MetricField::Netin => p.netin,
            MetricField::Netout => p.netout,
            MetricField::Loadavg => p.loadavg,
            MetricField::Iowait => p.iowait,
            // Storage: `used`. Guest: `disk`. Try both.
            MetricField::Used => p.used.or(p.disk),
            MetricField::Total => p.total.or(p.maxdisk),
        }
    }

    // Auto-find owning node when caller omits --node for guests.
    async fn find_node_for_vmid(
        client: &Arc<crate::api::PxClient>,
        vmid: u32,
    ) -> Result<(String, GuestType)> {
        let nodes = client.get_nodes().await?;
        for n in nodes {
            if let Ok(guests) = client.get_guests(&n.node).await {
                if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                    return Ok((n.node.clone(), g.guest_type));
                }
            }
        }
        anyhow::bail!("vmid {vmid} not found on any node — pass --node X to skip discovery")
    }

    let (label, points, field) = match action {
        MetricsCommand::Vm {
            vmid,
            node,
            field,
            timeframe,
            cf,
        } => {
            let (node_name, _) = match node {
                Some(n) => (n, GuestType::Qemu),
                None => find_node_for_vmid(client, vmid).await?,
            };
            let pts = client
                .get_guest_rrddata(
                    &node_name,
                    vmid,
                    GuestType::Qemu,
                    timeframe.into(),
                    cf.into(),
                )
                .await?;
            (format!("VM {vmid} on {node_name}"), pts, field)
        }
        MetricsCommand::Ct {
            vmid,
            node,
            field,
            timeframe,
            cf,
        } => {
            let (node_name, _) = match node {
                Some(n) => (n, GuestType::Lxc),
                None => find_node_for_vmid(client, vmid).await?,
            };
            let pts = client
                .get_guest_rrddata(
                    &node_name,
                    vmid,
                    GuestType::Lxc,
                    timeframe.into(),
                    cf.into(),
                )
                .await?;
            (format!("LXC {vmid} on {node_name}"), pts, field)
        }
        MetricsCommand::Node {
            node,
            field,
            timeframe,
            cf,
        } => {
            let pts = client
                .get_node_rrddata(&node, timeframe.into(), cf.into())
                .await?;
            (format!("node {node}"), pts, field)
        }
        MetricsCommand::Storage {
            node,
            storage,
            field,
            timeframe,
            cf,
        } => {
            let pts = client
                .get_storage_rrddata(&node, &storage, timeframe.into(), cf.into())
                .await?;
            (format!("storage {storage} on {node}"), pts, field)
        }
        // Unreachable — short-circuited above.
        MetricsCommand::RrdPng { .. } => unreachable!("RrdPng handled by early return"),
        MetricsCommand::Serve { .. } => unreachable!("Serve handled by early return"),
    };

    // Pull the requested field from every point as Option<f64>.
    let series: Vec<Option<f64>> = points.iter().map(|p| extract(p, field)).collect();
    let summary = crate::util::sparkline::Summary::of(&series);
    let spark = crate::util::sparkline::render(&series);

    // The CLI table/plain renderer can't show a sparkline meaningfully;
    // emit a JSON envelope with the rendered sparkline + summary, and
    // additionally a `points` array carrying (time, value) pairs so
    // downstream tooling (jq / a charting script) can rebuild the
    // series without parsing the sparkline back.
    let pairs: Vec<Value> = points
        .iter()
        .zip(series.iter())
        .map(|(p, v)| serde_json::json!({"time": p.time, "value": v}))
        .collect();
    let summary_json = summary.map_or(Value::Null, |s| {
        serde_json::json!({
            "count": s.count,
            "min": s.min,
            "max": s.max,
            "avg": s.avg,
        })
    });
    Ok((
        serde_json::json!({
            "label": label,
            "field": format!("{field:?}").to_lowercase(),
            "sparkline": spark,
            "summary": summary_json,
            "points": pairs,
        }),
        0,
    ))
}

/// Cluster-wide metric exporter dispatch. PVE routes mutations
/// per-id (POST/PUT/DELETE on `/cluster/metrics/server/{id}`).
#[allow(clippy::too_many_lines)]
pub async fn execute_metric_servers(
    client: &Arc<crate::api::PxClient>,
    action: MetricServersCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn build_params<'a>(
        typed: Vec<(&'a str, String)>,
        raw: &'a [String],
    ) -> Result<Vec<(&'a str, String)>> {
        let mut out = typed;
        for spec in raw {
            let (k, v) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--raw expects KEY=VAL, got {spec:?}"))?;
            out.retain(|(ek, _)| *ek != k);
            let key_static: &'static str = Box::leak(k.to_string().into_boxed_str());
            out.push((key_static, v.to_string()));
        }
        Ok(out)
    }
    fn as_refs<'a>(v: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
        v.iter().map(|(k, s)| (*k, s.as_str())).collect()
    }

    match action {
        MetricServersCommand::List => {
            let servers = client.list_metric_servers().await?;
            Ok((serde_json::to_value(servers)?, 0))
        }
        MetricServersCommand::Show { id } => {
            let s = client.get_metric_server(&id).await?;
            Ok((serde_json::to_value(s)?, 0))
        }
        MetricServersCommand::Create {
            id,
            server_type,
            server,
            port,
            comment,
            influxdbproto,
            proto,
            organization,
            bucket,
            path,
            token,
            raw,
        } => {
            let mut typed: Vec<(&str, String)> = vec![
                ("type", server_type),
                ("server", server),
                ("port", port.to_string()),
            ];
            let push_opt =
                |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                    if let Some(s) = v {
                        t.push((k, s));
                    }
                };
            push_opt(&mut typed, "comment", comment);
            push_opt(&mut typed, "influxdbproto", influxdbproto);
            push_opt(&mut typed, "proto", proto);
            push_opt(&mut typed, "organization", organization);
            push_opt(&mut typed, "bucket", bucket);
            push_opt(&mut typed, "path", path);
            push_opt(&mut typed, "token", token);
            let owned = build_params(typed, &raw)?;
            client.create_metric_server(&id, &as_refs(&owned)).await?;
            Ok((serde_json::json!({"created": id}), 0))
        }
        MetricServersCommand::Update {
            id,
            server,
            port,
            disable,
            comment,
            raw,
        } => {
            let mut typed: Vec<(&str, String)> = vec![];
            if let Some(s) = server {
                typed.push(("server", s));
            }
            if let Some(p) = port {
                typed.push(("port", p.to_string()));
            }
            if let Some(d) = disable {
                typed.push(("disable", if d { "1" } else { "0" }.to_string()));
            }
            if let Some(c) = comment {
                typed.push(("comment", c));
            }
            if typed.is_empty() && raw.is_empty() {
                anyhow::bail!("update needs at least one field");
            }
            let owned = build_params(typed, &raw)?;
            client.update_metric_server(&id, &as_refs(&owned)).await?;
            Ok((serde_json::json!({"updated": id}), 0))
        }
        MetricServersCommand::Delete { id, yes } => {
            if !yes {
                anyhow::bail!("destructive — pass --yes to confirm");
            }
            client.delete_metric_server(&id).await?;
            Ok((serde_json::json!({"deleted": id}), 0))
        }
    }
}

/// PVE 8+ notifications dispatch. Three sub-trees (endpoint/matcher/
/// targets). Repeated `--target` / `--match-field` / `--match-severity`
/// flags compose into PVE's repeated-form-param wire shape.
#[allow(clippy::too_many_lines)]
pub async fn execute_notifications(
    client: &Arc<crate::api::PxClient>,
    action: NotificationsCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn build_params<'a>(
        typed: Vec<(&'a str, String)>,
        raw: &'a [String],
    ) -> Result<Vec<(&'a str, String)>> {
        let mut out = typed;
        for spec in raw {
            let (k, v) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--raw expects KEY=VAL, got {spec:?}"))?;
            out.retain(|(ek, _)| *ek != k);
            let key_static: &'static str = Box::leak(k.to_string().into_boxed_str());
            out.push((key_static, v.to_string()));
        }
        Ok(out)
    }
    fn as_refs<'a>(v: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
        v.iter().map(|(k, s)| (*k, s.as_str())).collect()
    }
    fn push_repeated(
        typed: &mut Vec<(&'static str, String)>,
        key: &'static str,
        items: Vec<String>,
    ) {
        for v in items {
            typed.push((key, v));
        }
    }

    match action {
        NotificationsCommand::Endpoint(cmd) => match cmd {
            NotificationEndpointCommand::List => {
                let endpoints = client.list_notification_endpoints().await?;
                Ok((serde_json::to_value(endpoints)?, 0))
            }
            NotificationEndpointCommand::Create {
                endpoint_type,
                name,
                comment,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("name", name)];
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                let owned = build_params(typed, &raw)?;
                client
                    .create_notification_endpoint(&endpoint_type, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            NotificationEndpointCommand::Update {
                endpoint_type,
                name,
                comment,
                disable,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                if let Some(d) = disable {
                    typed.push(("disable", if d { "1" } else { "0" }.to_string()));
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_notification_endpoint(&endpoint_type, &name, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": name}), 0))
            }
            NotificationEndpointCommand::Delete {
                endpoint_type,
                name,
                yes,
            } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client
                    .delete_notification_endpoint(&endpoint_type, &name)
                    .await?;
                Ok((serde_json::json!({"deleted": name}), 0))
            }
        },
        NotificationsCommand::Matcher(cmd) => match cmd {
            NotificationMatcherCommand::List => {
                let matchers = client.list_notification_matchers().await?;
                Ok((serde_json::to_value(matchers)?, 0))
            }
            NotificationMatcherCommand::Create {
                name,
                target,
                match_field,
                match_severity,
                mode,
                invert_match,
                comment,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("name", name)];
                push_repeated(&mut typed, "target", target);
                push_repeated(&mut typed, "match-field", match_field);
                push_repeated(&mut typed, "match-severity", match_severity);
                if let Some(m) = mode {
                    typed.push(("mode", m));
                }
                if let Some(i) = invert_match {
                    typed.push(("invert-match", if i { "1" } else { "0" }.to_string()));
                }
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                let owned = build_params(typed, &raw)?;
                client.create_notification_matcher(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            NotificationMatcherCommand::Update {
                name,
                target,
                match_field,
                match_severity,
                mode,
                invert_match,
                disable,
                comment,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                push_repeated(&mut typed, "target", target);
                push_repeated(&mut typed, "match-field", match_field);
                push_repeated(&mut typed, "match-severity", match_severity);
                if let Some(m) = mode {
                    typed.push(("mode", m));
                }
                if let Some(i) = invert_match {
                    typed.push(("invert-match", if i { "1" } else { "0" }.to_string()));
                }
                if let Some(d) = disable {
                    typed.push(("disable", if d { "1" } else { "0" }.to_string()));
                }
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_notification_matcher(&name, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": name}), 0))
            }
            NotificationMatcherCommand::Delete { name, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.delete_notification_matcher(&name).await?;
                Ok((serde_json::json!({"deleted": name}), 0))
            }
        },
        NotificationsCommand::Targets => {
            let targets = client.list_notification_targets().await?;
            Ok((serde_json::to_value(targets)?, 0))
        }
    }
}

/// Mountain #1 — storage health surface.
///
/// All five subcommands are pure read-through to the corresponding
/// PVE endpoint; the CLI emits the typed response as JSON. The TUI
/// integration (renderer + sparklines) is a separate iteration —
/// here we land the data layer + CLI access first.
///
/// Exit code is always 0 on a successful API call (even an empty
/// pool list). A non-success status from PVE bubbles up through
/// `ApiError`, which the top-level `main` maps to its standard
/// non-zero exit category (1 fatal, 4 forbidden, …).
pub async fn execute_disks(
    client: &Arc<crate::api::PxClient>,
    action: DisksCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        DisksCommand::List { node } => {
            let disks = client.list_node_disks(&node).await?;
            Ok((serde_json::to_value(disks)?, 0))
        }
        DisksCommand::Smart { node, disk } => {
            let smart = client.get_disk_smart(&node, &disk).await?;
            Ok((serde_json::to_value(smart)?, 0))
        }
        DisksCommand::Lvm { node } => {
            let vgs = client.list_node_lvm(&node).await?;
            Ok((serde_json::to_value(vgs)?, 0))
        }
        DisksCommand::Lvmthin { node } => {
            let pools = client.list_node_lvmthin(&node).await?;
            Ok((serde_json::to_value(pools)?, 0))
        }
        DisksCommand::Zfs { node } => {
            let pools = client.list_node_zfs(&node).await?;
            Ok((serde_json::to_value(pools)?, 0))
        }
    }
}

/// Feature #5 — HA console CLI.
pub async fn execute_ha(
    client: &Arc<crate::api::PxClient>,
    action: HaCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        HaCommand::Groups => {
            let groups = client.list_ha_groups().await?;
            Ok((serde_json::to_value(groups)?, 0))
        }
        HaCommand::GroupsLegacy => {
            let groups = client.list_ha_groups_legacy().await?;
            Ok((serde_json::to_value(groups)?, 0))
        }
        HaCommand::GroupCreate {
            group,
            nodes,
            restricted,
            nofailback,
            comment,
        } => {
            let restricted_str = if restricted { "1" } else { "0" };
            let nofailback_str = if nofailback { "1" } else { "0" };
            let mut params: Vec<(&str, &str)> = vec![
                ("group", group.as_str()),
                ("nodes", nodes.as_str()),
                ("restricted", restricted_str),
                ("nofailback", nofailback_str),
            ];
            if let Some(c) = comment.as_deref() {
                params.push(("comment", c));
            }
            client.create_ha_group(&params).await?;
            Ok((serde_json::json!({"created": group}), 0))
        }
        HaCommand::GroupUpdate {
            group,
            nodes,
            restricted,
            nofailback,
            comment,
        } => {
            let mut owned: Vec<(&str, String)> = vec![];
            if let Some(n) = nodes {
                owned.push(("nodes", n));
            }
            if let Some(r) = restricted {
                owned.push(("restricted", if r { "1" } else { "0" }.to_string()));
            }
            if let Some(n) = nofailback {
                owned.push(("nofailback", if n { "1" } else { "0" }.to_string()));
            }
            if let Some(c) = comment {
                owned.push(("comment", c));
            }
            if owned.is_empty() {
                anyhow::bail!("update needs at least one field");
            }
            let refs: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
            client.update_ha_group(&group, &refs).await?;
            Ok((serde_json::json!({"updated": group}), 0))
        }
        HaCommand::GroupDelete { group, yes } => {
            if !yes {
                anyhow::bail!("destructive — pass --yes to confirm");
            }
            client.delete_ha_group(&group).await?;
            Ok((serde_json::json!({"deleted": group}), 0))
        }
        HaCommand::Resources => {
            let resources = client.list_ha_resources().await?;
            Ok((serde_json::to_value(resources)?, 0))
        }
        HaCommand::Status => {
            let status = client.ha_manager_status().await?;
            Ok((serde_json::to_value(status)?, 0))
        }
        HaCommand::StatusCurrent => {
            let entries = client.get_ha_status_current().await?;
            Ok((
                serde_json::json!({"count": entries.len(), "entries": entries}),
                0,
            ))
        }
        HaCommand::Preview { node } => {
            // Bring everything we need locally and run the inspector.
            let groups = client.list_ha_groups().await?;
            let resources = client.list_ha_resources().await?;
            let cluster = client.cluster_status().await?;
            let online = crate::app::ha::online_nodes(&cluster);
            // To know each resource's CURRENT node, we look at all guests.
            let nodes = client.get_nodes().await?;
            let mut all_guests: std::collections::HashMap<u32, String> =
                std::collections::HashMap::new();
            for n in &nodes {
                if let Ok(guests) = client.get_guests(&n.node).await {
                    for g in guests {
                        all_guests.insert(g.vmid, g.node);
                    }
                }
            }
            let mut previews = Vec::new();
            for r in &resources {
                let cur = r
                    .vmid()
                    .and_then(|v| all_guests.get(&v).cloned())
                    .unwrap_or_default();
                let outcome = if cur.is_empty() {
                    serde_json::json!({ "kind": "unknown_current_node" })
                } else {
                    match crate::app::ha::preview_failover(r, &groups, &online, &cur, &node) {
                        crate::app::ha::FailoverPreview::Relocate { target, priority } => {
                            serde_json::json!({
                                "kind": "relocate",
                                "target": target,
                                "priority": priority
                            })
                        }
                        crate::app::ha::FailoverPreview::Stuck { restricted, chosen } => {
                            serde_json::json!({
                                "kind": "stuck",
                                "restricted": restricted,
                                "chosen": chosen
                            })
                        }
                        crate::app::ha::FailoverPreview::NotAffected => {
                            serde_json::json!({ "kind": "not_affected" })
                        }
                    }
                };
                previews.push(serde_json::json!({
                    "sid": r.sid,
                    "group": r.group,
                    "current_node": cur,
                    "outcome": outcome,
                }));
            }
            Ok((
                serde_json::json!({
                    "failed_node": node,
                    "previews": previews
                }),
                0,
            ))
        }
    }
}

pub async fn execute_replication(
    client: &Arc<crate::api::PxClient>,
    action: ReplicationCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        ReplicationCommand::Jobs => {
            let jobs = client.list_replication_jobs().await?;
            Ok((serde_json::to_value(jobs)?, 0))
        }
        ReplicationCommand::Status { node } => {
            let status = client.list_replication_status(&node).await?;
            Ok((serde_json::to_value(status)?, 0))
        }
    }
}
