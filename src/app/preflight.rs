//! Pre-flight risk assessment for destructive guest operations.
//!
//! PVE's own guards check the bare minimum: lock file present? guest
//! status compatible? proxxx adds a layer above: surface signals that
//! say "this guest is *probably* serving real traffic" or "this VM is
//! the production reverse-proxy you're about to wipe". The user can
//! always override with `--force`, but they make the choice with
//! eyes open.
//!
//! All checks here read from the already-fetched `Guest` struct — no
//! extra API calls. Future iterations may add deeper signals (listening
//! ports via QGA, snapshot count, backup recency) at the cost of
//! per-check round-trips.
//!
//! ## Risk vs op weighting
//!
//! Some risks are universally severe (a sticky lock blocks every
//! mutation). Others depend on the op:
//!   - `Running` is **severe** for `delete` (PVE refuses too) but only
//!     a **warning** for `stop` (the op IS the stop).
//!   - `HaManaged` is **severe** for `stop` (the CRM will restart
//!     within seconds) but a **warning** for `delete` (route through
//!     `/cluster/ha/resources` instead).
//!
//! `assess(op, guest)` returns the per-risk level for the chosen op.

use crate::api::types::Guest;

/// Destructive operations the pre-flight framework knows how to grade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Delete,
    Stop,
    Restart,
    Migrate,
    MoveDisk,
    ResizeDisk,
}

impl Op {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Migrate => "migrate",
            Self::MoveDisk => "move-disk",
            Self::ResizeDisk => "resize-disk",
        }
    }
}

/// Severity tier. `Severe` blocks the op without `--force`; the lower
/// tiers are advisory and proceed after printing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Notice,
    Warning,
    Severe,
}

impl RiskLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Notice => "NOTICE",
            Self::Warning => "WARN",
            Self::Severe => "SEVERE",
        }
    }
}

/// Individual risk signal. Carries the data needed to render a
/// human message; the level is decided per-op in `assess`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Risk {
    /// PVE has a sticky lock on the guest config (e.g. `lock: backup`).
    /// The op will collide with PVE's own lock and fail with a 500.
    Locked { reason: String },
    /// HA Cluster Resource Manager is managing this guest. Direct
    /// `/status/*` calls bypass the CRM, which will retaliate within
    /// 5–30s by restarting the guest (or fencing the node).
    HaManaged { state: String },
    /// Guest is currently running. Severity depends on op. `uptime_secs`
    /// is the raw seconds for accurate display (h+m for < 1 day,
    /// d+h otherwise — `0d` for a 40-minute VM was confusing).
    Running { uptime_secs: u64 },
    /// Guest has been up for a long time — likely a production
    /// workhorse a casual delete shouldn't touch.
    LongUptime { days: u32 },
    /// One of the guest's tags suggests production scope.
    TaggedProd { tag: String },
    /// Average network throughput since boot exceeds the threshold —
    /// the guest is probably serving real traffic (web server, reverse
    /// proxy, mail relay, …).
    ActiveNetTraffic { avg_bps: u64 },
    /// QGA reported the guest is listening on a well-known service
    /// port (HTTP/HTTPS/DB/SMTP/...). Stronger production signal than
    /// average traffic — this is what the guest is *currently*
    /// configured to serve. Only available for QEMU guests with the
    /// agent installed; LXC and agent-less QEMU skip this check
    /// (the cheap `assess` still runs).
    ListeningOnService { port: u16, name: String },
    /// `assess_deep` could not run the listening-port probe — surfaced
    /// rather than silently skipped so the user knows the deep
    /// signal is missing. Common reasons: LXC (no QGA path); QEMU
    /// without agent installed; agent timeout; permission denied.
    /// Notice-level: doesn't block the op, just informs.
    DeepCheckSkipped { reason: String },
    /// Guest has accumulated many snapshots — the user has invested
    /// in this VM's history. Casual delete wipes them all. Also a
    /// performance signal: deep snapshot chains on QCOW2 / ZFS
    /// noticeably slow read/write throughput.
    HasManySnapshots { count: u32 },
    /// The most recent backup is older than the threshold — destroying
    /// the guest now means losing recent state. Includes the age in
    /// hours so the user can judge the gap.
    BackupAgeWarning { age_hours: u32 },
    /// No backup at all was found across any backup-content storage
    /// on the guest's node. Could be intentional (test VM, brand-new
    /// guest) or an oversight (production VM with broken backup
    /// schedule). Notice-level — proxxx can't tell the difference.
    NoBackupFound,
}

impl Risk {
    /// One-line human description, suitable for CLI output.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Locked { reason } => {
                format!("guest holds a sticky PVE lock: '{reason}' — destructive op will collide")
            }
            Self::HaManaged { state } => format!(
                "HA-managed (CRM state '{state}') — direct ops bypass the CRM and \
                 will be undone within 5–30s; route through /cluster/ha/resources instead"
            ),
            Self::Running { uptime_secs } => {
                format!("guest is running (uptime {})", format_uptime(*uptime_secs))
            }
            Self::LongUptime { days } => {
                format!("long uptime ({days}d) — likely a production workhorse")
            }
            Self::TaggedProd { tag } => {
                format!("tagged '{tag}' in PVE inventory")
            }
            Self::ActiveNetTraffic { avg_bps } => {
                let kbps = *avg_bps / 1024;
                format!(
                    "active network traffic ({kbps} KB/s avg since boot) — \
                     likely serving production workload"
                )
            }
            Self::ListeningOnService { port, name } => format!(
                "guest is listening on TCP {port} ({name}) — \
                 likely a production service"
            ),
            Self::DeepCheckSkipped { reason } => format!(
                "deep risk check skipped — {reason} (cheap risks above are still authoritative)"
            ),
            Self::HasManySnapshots { count } => format!(
                "{count} snapshots on this guest — destroy wipes them all, and \
                 long snapshot chains slow QCOW2/ZFS reads"
            ),
            Self::BackupAgeWarning { age_hours } => {
                if *age_hours < 48 {
                    format!("most recent backup is {age_hours}h old — recent state will be lost")
                } else {
                    let days = *age_hours / 24;
                    format!(
                        "most recent backup is {days}d old ({age_hours}h) — \
                         destroying the guest loses everything since"
                    )
                }
            }
            Self::NoBackupFound => "no backup found on any backup-content storage of \
                this node — destroying the guest is irreversible"
                .to_string(),
        }
    }
}

/// Threshold for `HasManySnapshots` — above this we flag. PVE/QCOW2
/// performance starts to noticeably degrade past ~5–8 snapshots.
const MANY_SNAPSHOTS_THRESHOLD: u32 = 5;

/// Threshold for `BackupAgeWarning` — most-recent backup older than
/// this triggers the flag. 24 hours matches the convention "every VM
/// should be backed up daily".
const BACKUP_STALE_HOURS: u32 = 24;

/// Map a TCP port to a well-known service name. Returns `None` for
/// arbitrary ports we don't track (the listening-port check skips them
/// — only flags recognised production-relevant services).
const fn well_known_port(port: u16) -> Option<&'static str> {
    match port {
        22 => Some("ssh"),
        25 | 465 | 587 => Some("smtp"),
        53 => Some("dns"),
        80 | 8080 => Some("http"),
        443 | 8443 => Some("https"),
        3306 => Some("mysql"),
        5432 => Some("postgres"),
        6379 => Some("redis"),
        27017 => Some("mongodb"),
        // Container orchestration / common app servers
        3000 => Some("node-app"),
        5000 => Some("flask"),
        8000 | 9000 => Some("app-server"),
        9090 => Some("prometheus"),
        9200 => Some("elasticsearch"),
        _ => None,
    }
}

/// Parse `ss -H -tln` or `netstat -tln` output and extract listening
/// TCP ports. Returns deduplicated port numbers — the input often
/// shows the same port on multiple address families (0.0.0.0:80 +
/// [::]:80) and we want one signal per service.
///
/// Tolerates either tool's columnar layout: both have the
/// `local:port` form somewhere in the row, and we extract the
/// trailing integer after the last `:` of each whitespace-split token.
#[must_use]
pub fn parse_listening_ports(output: &str) -> Vec<u16> {
    let mut ports: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Active") || trimmed.starts_with("Proto") {
            continue;
        }
        // ss -tln header line: "State Recv-Q Send-Q Local Address:Port Peer..."
        if trimmed.starts_with("State") {
            continue;
        }
        for tok in trimmed.split_ascii_whitespace() {
            // We're looking for `<addr>:<port>` tokens. Extract everything
            // after the last `:` and try parsing as u16.
            if let Some(colon) = tok.rfind(':') {
                let port_str = &tok[colon + 1..];
                if let Ok(p) = port_str.parse::<u16>() {
                    if p > 0 {
                        ports.insert(p);
                    }
                }
            }
        }
    }
    ports.into_iter().collect()
}

/// Async deep risk assessment — wraps the cheap `assess` and adds
/// signals that need extra API calls (currently: listening-ports via
/// QGA exec). Fails soft on any I/O error: the cheap risks still
/// surface, the deep ones just don't.
///
/// Skipped entirely for LXC (no agent) and stopped guests (no
/// listening sockets).
pub async fn assess_deep(
    client: &crate::api::PxClient,
    pbs: Option<&crate::pbs::PbsClient>,
    op: Op,
    guest: &Guest,
) -> Vec<(Risk, RiskLevel)> {
    use crate::api::types::{GuestStatus, GuestType};
    use crate::api::ProxmoxGateway;
    let mut risks = assess(op, guest);

    // Delete-only deep checks: snapshot history loss + backup recency.
    // Both are 1 extra API call each; for non-Delete ops they're not
    // relevant (snapshots survive other ops, backup recency only matters
    // when destroying the source of truth).
    if matches!(op, Op::Delete) {
        // Snapshot count — exclude the synthetic "current" entry
        // (PVE adds it as a cursor, not a real snapshot).
        if let Ok(snaps) = client
            .list_snapshots(&guest.node, guest.vmid, guest.guest_type)
            .await
        {
            let count =
                u32::try_from(snaps.iter().filter(|s| !s.is_current()).count()).unwrap_or(u32::MAX);
            if count > MANY_SNAPSHOTS_THRESHOLD {
                risks.push((Risk::HasManySnapshots { count }, RiskLevel::Warning));
            }
        }

        // Backup recency — scan vzdump-on-PVE storages on the guest's
        // node AND PBS datastores (when configured), then merge to
        // "most recent across both". PBS is queried only when a
        // `pbs` client is supplied — many homelabs don't run PBS.
        let pve_age = find_recent_backup(client, &guest.node, guest.vmid).await;
        let pbs_age = if let Some(pbs_client) = pbs {
            find_recent_pbs_backup(pbs_client, guest.vmid, guest.guest_type).await
        } else {
            Ok(None)
        };
        match (pve_age, pbs_age) {
            (Ok(p), Ok(b)) => {
                let merged = combine_backup_age(p, b);
                match merged {
                    Some(age_hours) if age_hours > BACKUP_STALE_HOURS => {
                        risks.push((Risk::BackupAgeWarning { age_hours }, RiskLevel::Warning));
                    }
                    Some(_) => { /* fresh — no risk */ }
                    None => {
                        risks.push((Risk::NoBackupFound, RiskLevel::Notice));
                    }
                }
            }
            (Ok(Some(age)), Err(e)) | (Err(e), Ok(Some(age))) => {
                if age > BACKUP_STALE_HOURS {
                    risks.push((
                        Risk::BackupAgeWarning { age_hours: age },
                        RiskLevel::Warning,
                    ));
                }
                risks.push((
                    Risk::DeepCheckSkipped {
                        reason: format!("one backup source failed: {e}"),
                    },
                    RiskLevel::Notice,
                ));
            }
            (Ok(None), Err(e)) | (Err(e), Ok(None)) => {
                risks.push((
                    Risk::DeepCheckSkipped {
                        reason: format!("backup-recency probe failed: {e}"),
                    },
                    RiskLevel::Notice,
                ));
            }
            (Err(e1), Err(_)) => {
                risks.push((
                    Risk::DeepCheckSkipped {
                        reason: format!("backup-recency probe failed (both PVE+PBS): {e1}"),
                    },
                    RiskLevel::Notice,
                ));
            }
        }
    }

    // Stopped guest: no listening sockets; nothing to probe and no
    // notice needed (the user already knows it's off).
    if !matches!(guest.status, GuestStatus::Running) {
        return risks;
    }
    // LXC: PVE has no QGA equivalent (we removed our `/lxc/exec`
    // path in Phase 1 — that endpoint doesn't exist in PVE 9). The
    // deep check is genuinely unavailable, not just absent. Surface
    // as Notice rather than silently skip — user knows the
    // listening-port signal is missing from the assessment.
    if matches!(guest.guest_type, GuestType::Lxc) {
        risks.push((
            Risk::DeepCheckSkipped {
                reason: "LXC has no QGA — listening-port probe unavailable; \
                     use SSH inside the container if you need it"
                    .to_string(),
            },
            RiskLevel::Notice,
        ));
        return risks;
    }
    // QEMU: try the QGA exec. On any failure (agent not installed,
    // wedged, denied) surface a Notice — the cheap risks above are
    // the source of truth, but the user is informed that the deep
    // signal is missing. Previous version silently swallowed the
    // failure ("`Err(_) => return risks`") — that was the gap.
    let cmd = "ss -H -tln 2>/dev/null || netstat -tln 2>/dev/null";
    let result = match client
        .execute_guest_command(&guest.node, guest.vmid, &guest.guest_type, cmd)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            // PVE QGA errors are verbose — first line is enough.
            let short = e
                .to_string()
                .lines()
                .next()
                .unwrap_or("QGA call failed")
                .to_string();
            risks.push((
                Risk::DeepCheckSkipped {
                    reason: format!("QGA exec failed: {short}"),
                },
                RiskLevel::Notice,
            ));
            return risks;
        }
    };
    if result.exit_code != 0 || result.stdout.is_empty() {
        risks.push((
            Risk::DeepCheckSkipped {
                reason: format!(
                    "QGA exec returned exit={} stdout_bytes={} — `ss` and `netstat` both failed",
                    result.exit_code,
                    result.stdout.len()
                ),
            },
            RiskLevel::Notice,
        ));
        return risks;
    }
    for port in parse_listening_ports(&result.stdout) {
        if let Some(name) = well_known_port(port) {
            risks.push((
                Risk::ListeningOnService {
                    port,
                    name: name.to_string(),
                },
                RiskLevel::Warning,
            ));
        }
    }
    risks
}

/// Find the most-recent backup for `vmid` across every backup-content
/// storage on `node`. Returns `Ok(Some(age_hours))` when at least one
/// backup is found, `Ok(None)` when scan completed but no backups
/// exist for this VMID, or `Err` on API failure.
///
/// PBS-tracked backups don't show up here — they're on a separate
/// PBS host, not on a PVE storage. A future iteration could query
/// PBS directly via `proxxx pbs` paths; for now, vzdump-on-PVE is
/// the authoritative source.
/// PBS-side equivalent of `find_recent_backup`. Scans every datastore
/// on the PBS host, filters snapshots by `backup-id == vmid` and the
/// matching `backup-type` (vm | ct), returns age in hours of the
/// most recent snapshot.
///
/// Returns `Ok(None)` when no PBS snapshot exists for this VMID,
/// `Err` on PBS API failure (network, auth). Caller is expected to
/// merge with the PVE-side result via `combine_backup_age`.
pub(crate) async fn find_recent_pbs_backup(
    pbs: &crate::pbs::PbsClient,
    vmid: u32,
    guest_type: crate::api::types::GuestType,
) -> Result<Option<u32>, anyhow::Error> {
    use crate::pbs::PbsGateway;
    let backup_type = match guest_type {
        crate::api::types::GuestType::Qemu => "vm",
        crate::api::types::GuestType::Lxc => "ct",
    };
    let id = vmid.to_string();
    let stores = pbs.list_datastores().await?;
    let mut newest: u64 = 0;
    for st in stores {
        let snaps = match pbs
            .list_snapshots(&st.store, Some(backup_type), Some(&id))
            .await
        {
            Ok(v) => v,
            // Skip stores that error (offline, perm denied) — partial
            // coverage is better than total failure.
            Err(_) => continue,
        };
        for s in snaps {
            if s.backup_time > newest {
                newest = s.backup_time;
            }
        }
    }
    if newest == 0 {
        return Ok(None);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let age_secs = now.saturating_sub(newest);
    Ok(Some(u32::try_from(age_secs / 3600).unwrap_or(u32::MAX)))
}

/// Pick the smaller (= more recent) of two `Option<age_hours>` values.
/// Used to merge PVE-vzdump and PBS results into a single "newest
/// backup across all targets" answer for the preflight risk.
#[must_use]
pub(crate) fn combine_backup_age(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

pub(crate) async fn find_recent_backup(
    client: &crate::api::PxClient,
    node: &str,
    vmid: u32,
) -> Result<Option<u32>, anyhow::Error> {
    use crate::api::ProxmoxGateway;
    let storages = client.get_storage_pools(node).await?;
    let backup_storages: Vec<&str> = storages
        .iter()
        .filter(|s| s.content.split(',').any(|c| c.trim() == "backup"))
        .map(|s| s.storage.as_str())
        .collect();
    let mut newest_ctime: u64 = 0;
    for st in backup_storages {
        // Per-storage list of `backup` content. Filter to entries
        // owning the target vmid (PVE populates `vmid` on backup
        // entries; defaults to None for non-backup content).
        let entries = match client.list_storage_content(node, st, Some("backup")).await {
            Ok(v) => v,
            // Skip storages that error (offline NFS, perm denied, etc.)
            // — partial coverage is still useful.
            Err(_) => continue,
        };
        for e in entries {
            if e.vmid == Some(vmid) && e.ctime > newest_ctime {
                newest_ctime = e.ctime;
            }
        }
    }
    if newest_ctime == 0 {
        return Ok(None);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let age_secs = now.saturating_sub(newest_ctime);
    Ok(Some(u32::try_from(age_secs / 3600).unwrap_or(u32::MAX)))
}

/// Format a duration in seconds as "Xd Yh" or "Xh Ym" or "Ym Zs"
/// — picks the granularity that's actually informative for the user.
fn format_uptime(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m {s}s")
    }
}

/// Long-uptime threshold. Below this we don't flag.
const LONG_UPTIME_DAYS: u32 = 14;

/// Average network throughput threshold (bytes/sec). Above this we flag
/// `ActiveNetTraffic`. 1 KiB/s is well above background ARP / chatter
/// but well below any serving workload.
const ACTIVE_NET_THRESHOLD_BPS: u64 = 1024;

/// Tag values (case-insensitive substring match) that imply prod scope.
const PROD_TAG_NEEDLES: &[&str] = &["prod", "production", "prd", "critical", "live"];

/// Collect all applicable risks for `op` against `guest`. Returns
/// `(Risk, RiskLevel)` pairs — caller decides whether to abort or
/// proceed based on the highest level.
///
/// The function is pure (no I/O, no allocation beyond the result vec)
/// and only reads from the already-fetched `Guest` struct. Adding new
/// risks that need extra API calls should be done in a separate
/// `assess_with_io` flavour rather than here.
#[must_use]
pub fn assess(op: Op, guest: &Guest) -> Vec<(Risk, RiskLevel)> {
    let mut risks: Vec<(Risk, RiskLevel)> = Vec::new();

    // Sticky lock — universally severe. PVE will reject the op anyway,
    // but a client-side surface saves the round-trip and gives the
    // user a clearer message ("backup in progress, retry in N min")
    // than PVE's "got timeout".
    if !guest.lock.is_empty() {
        risks.push((
            Risk::Locked {
                reason: guest.lock.clone(),
            },
            RiskLevel::Severe,
        ));
    }

    // HA-managed: severity depends on op.
    if guest.is_ha_managed() {
        let level = match op {
            Op::Stop | Op::Delete => RiskLevel::Severe,
            Op::Restart | Op::Migrate | Op::MoveDisk | Op::ResizeDisk => RiskLevel::Warning,
        };
        risks.push((
            Risk::HaManaged {
                state: guest.hastate.clone(),
            },
            level,
        ));
    }

    // Running: severity depends on op. PVE already refuses Delete on
    // running guests at the API layer (we surface that earlier in
    // execute_delete). The pre-flight version surfaces it BEFORE the
    // network round-trip.
    let is_running = matches!(guest.status, crate::api::types::GuestStatus::Running);
    if is_running {
        let level = match op {
            Op::Delete => RiskLevel::Severe,
            Op::Stop | Op::Restart | Op::Migrate | Op::MoveDisk | Op::ResizeDisk => {
                RiskLevel::Warning
            }
        };
        risks.push((
            Risk::Running {
                uptime_secs: guest.uptime,
            },
            level,
        ));
    }

    // Long uptime (regardless of running state — could be a stopped
    // template that was once long-lived). Always Notice.
    let uptime_days = (guest.uptime / 86_400).min(u64::from(u32::MAX)) as u32;
    if uptime_days >= LONG_UPTIME_DAYS {
        risks.push((Risk::LongUptime { days: uptime_days }, RiskLevel::Notice));
    }

    // Production tag — case-insensitive substring on each tag.
    let tags_lower = guest.tags.to_lowercase();
    for needle in PROD_TAG_NEEDLES {
        if tags_lower.split(';').any(|t| t.trim() == *needle) {
            risks.push((
                Risk::TaggedProd {
                    tag: (*needle).to_string(),
                },
                RiskLevel::Warning,
            ));
            break;
        }
    }

    // Active network traffic. Only meaningful for running guests.
    // PVE serves cumulative bytes since boot in the list endpoint,
    // so we approximate "current rate" as the long-run average.
    // A web server doing 10 GB / day = ~115 KB/s — well above the
    // 1 KB/s threshold, even averaged over a week.
    if is_running && guest.uptime > 0 {
        let total = guest.netin.saturating_add(guest.netout);
        let avg_bps = total.checked_div(guest.uptime).unwrap_or(0);
        if avg_bps > ACTIVE_NET_THRESHOLD_BPS {
            risks.push((Risk::ActiveNetTraffic { avg_bps }, RiskLevel::Warning));
        }
    }

    risks
}

/// Highest level among a risk list. Returns `Notice` for an empty
/// list — convenient for "if max >= Severe, refuse" logic.
#[must_use]
pub fn max_level(risks: &[(Risk, RiskLevel)]) -> RiskLevel {
    risks
        .iter()
        .map(|(_, l)| *l)
        .max()
        .unwrap_or(RiskLevel::Notice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{Guest, GuestStatus, GuestType};

    fn baseline_running() -> Guest {
        Guest {
            vmid: 100,
            name: "test".into(),
            status: GuestStatus::Running,
            guest_type: GuestType::Qemu,
            node: "pve1".into(),
            cpu: 0.0,
            cpus: 1,
            mem: 0,
            maxmem: 0,
            disk: 0,
            maxdisk: 0,
            uptime: 3600,
            tags: String::new(),
            lock: String::new(),
            hastate: String::new(),
            template: false,
            netin: 0,
            netout: 0,
        }
    }

    #[test]
    fn clean_running_delete_only_flags_running() {
        let g = baseline_running();
        let risks = assess(Op::Delete, &g);
        assert_eq!(risks.len(), 1);
        assert!(matches!(risks[0].0, Risk::Running { .. }));
        assert_eq!(risks[0].1, RiskLevel::Severe);
    }

    #[test]
    fn lock_is_severe_regardless_of_op() {
        let mut g = baseline_running();
        g.lock = "backup".into();
        for op in [Op::Delete, Op::Stop, Op::Restart, Op::Migrate, Op::MoveDisk] {
            let risks = assess(op, &g);
            assert!(
                risks
                    .iter()
                    .any(|(r, l)| { matches!(r, Risk::Locked { .. }) && *l == RiskLevel::Severe }),
                "op {} should report Locked as Severe",
                op.as_str()
            );
        }
    }

    #[test]
    fn ha_managed_is_severe_for_stop_warning_for_migrate() {
        let mut g = baseline_running();
        g.hastate = "started".into();
        let stop_risks = assess(Op::Stop, &g);
        let migrate_risks = assess(Op::Migrate, &g);
        let stop_ha_level = stop_risks
            .iter()
            .find_map(|(r, l)| matches!(r, Risk::HaManaged { .. }).then_some(*l))
            .expect("stop should flag HaManaged");
        let migrate_ha_level = migrate_risks
            .iter()
            .find_map(|(r, l)| matches!(r, Risk::HaManaged { .. }).then_some(*l))
            .expect("migrate should flag HaManaged");
        assert_eq!(stop_ha_level, RiskLevel::Severe);
        assert_eq!(migrate_ha_level, RiskLevel::Warning);
    }

    #[test]
    fn long_uptime_threshold() {
        let mut g = baseline_running();
        g.uptime = 13 * 86_400; // 13 days — below threshold
        let risks = assess(Op::Stop, &g);
        assert!(!risks
            .iter()
            .any(|(r, _)| matches!(r, Risk::LongUptime { .. })));
        g.uptime = 30 * 86_400; // 30 days — above
        let risks = assess(Op::Stop, &g);
        assert!(risks
            .iter()
            .any(|(r, l)| { matches!(r, Risk::LongUptime { .. }) && *l == RiskLevel::Notice }));
    }

    #[test]
    fn prod_tag_detection_case_insensitive() {
        let mut g = baseline_running();
        g.tags = "web;Production;eu-west".into();
        let risks = assess(Op::Delete, &g);
        assert!(risks
            .iter()
            .any(|(r, l)| { matches!(r, Risk::TaggedProd { .. }) && *l == RiskLevel::Warning }));
    }

    #[test]
    fn prod_tag_substring_does_not_falsely_match() {
        // "production-staging" should NOT match "production" because we
        // split on `;` and require exact-segment match.
        let mut g = baseline_running();
        g.tags = "production-staging".into();
        let risks = assess(Op::Delete, &g);
        assert!(!risks
            .iter()
            .any(|(r, _)| matches!(r, Risk::TaggedProd { .. })));
    }

    #[test]
    fn active_net_traffic_threshold() {
        let mut g = baseline_running();
        g.uptime = 3600; // 1h
        g.netin = 0;
        g.netout = 0;
        let risks = assess(Op::Delete, &g);
        assert!(!risks
            .iter()
            .any(|(r, _)| matches!(r, Risk::ActiveNetTraffic { .. })));
        // 1 hour at 5 KB/s = 18 MB
        g.netin = 18 * 1024 * 1024;
        let risks = assess(Op::Delete, &g);
        let net = risks
            .iter()
            .find_map(|(r, l)| match r {
                Risk::ActiveNetTraffic { avg_bps } => Some((*avg_bps, *l)),
                _ => None,
            })
            .expect("should flag ActiveNetTraffic");
        assert!(net.0 > 1024, "avg_bps {} should exceed 1 KB/s", net.0);
        assert_eq!(net.1, RiskLevel::Warning);
    }

    #[test]
    fn stopped_guest_no_running_risk() {
        let mut g = baseline_running();
        g.status = GuestStatus::Stopped;
        let risks = assess(Op::Delete, &g);
        assert!(!risks.iter().any(|(r, _)| matches!(r, Risk::Running { .. })));
    }

    #[test]
    fn max_level_picks_highest() {
        let risks = vec![
            (Risk::LongUptime { days: 30 }, RiskLevel::Notice),
            (Risk::TaggedProd { tag: "prod".into() }, RiskLevel::Warning),
            (
                Risk::Locked {
                    reason: "backup".into(),
                },
                RiskLevel::Severe,
            ),
        ];
        assert_eq!(max_level(&risks), RiskLevel::Severe);
    }

    #[test]
    fn empty_risks_max_level_is_notice() {
        assert_eq!(max_level(&[]), RiskLevel::Notice);
    }

    // ── parse_listening_ports / well_known_port ──────────────

    #[test]
    fn parse_ss_tln_extracts_listening_ports() {
        // Real `ss -H -tln` output with the header stripped (-H).
        let out = "\
LISTEN 0      128                          0.0.0.0:22         0.0.0.0:*
LISTEN 0      128                          0.0.0.0:80         0.0.0.0:*
LISTEN 0      128                             [::]:443           [::]:*
LISTEN 0      128                          0.0.0.0:80         0.0.0.0:*
";
        let ports = super::parse_listening_ports(out);
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn parse_netstat_tln_busybox_form() {
        let out = "\
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp   0      0      0.0.0.0:22              0.0.0.0:*               LISTEN
tcp   0      0      :::443                  :::*                    LISTEN
";
        let ports = super::parse_listening_ports(out);
        assert_eq!(ports, vec![22, 443]);
    }

    #[test]
    fn parse_handles_empty_input() {
        assert!(super::parse_listening_ports("").is_empty());
        assert!(super::parse_listening_ports("\n\n").is_empty());
    }

    #[test]
    fn well_known_port_basics() {
        assert_eq!(super::well_known_port(443), Some("https"));
        assert_eq!(super::well_known_port(80), Some("http"));
        assert_eq!(super::well_known_port(3306), Some("mysql"));
        // Arbitrary high port → None (we don't track random services).
        assert_eq!(super::well_known_port(54321), None);
    }

    // ── find_recent_backup wiremock tests ─────────────────────
    //
    // Spin a fake PVE: list_node_storage_pools returns 2 storages
    // (one with `backup` content, one without); list_storage_content
    // for the backup-content storage returns a fake vzdump entry
    // with a known ctime. Verify that:
    //   1. find_recent_backup() ignores non-backup storages
    //   2. it filters by vmid (a backup for another VM is invisible)
    //   3. it computes age in hours from the ctime
    //   4. an empty backup list yields Ok(None)

    async fn mock_pxclient(server: &wiremock::MockServer) -> crate::api::PxClient {
        // Pass the secret via the cli_secret parameter (resolver priority
        // #1) rather than std::env::set_var. Env vars are process-global
        // and cargo runs unit tests in parallel — set_var here would race
        // with any concurrently-running test that reads PROXXX_TOKEN_SECRET.
        let cfg = crate::config::ProfileConfig {
            url: server.uri(),
            user: "root@pam".into(),
            auth: "token".into(),
            token_id: Some("test".into()),
            token_secret: None,
            token_secret_file: None,
            password: None,
            verify_tls: false,
            rate_limit: Some(100),
            policies: None,
            telegram: None,
            ssh: None,
            pbs: None,
            alerts: None,
        };
        crate::api::PxClient::new(cfg, Some("fake-secret"))
            .await
            .expect("client")
    }

    #[tokio::test]
    async fn find_recent_backup_picks_newest_for_target_vmid() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;

        // Storage list: one with backup content, one without.
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/storage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"storage": "local", "type": "dir", "content": "backup,iso", "active": 1, "total": 100, "used": 10, "avail": 90},
                    {"storage": "local-lvm", "type": "lvmthin", "content": "images,rootdir", "active": 1, "total": 100, "used": 10, "avail": 90}
                ]
            })))
            .mount(&server)
            .await;

        // Backup-content scan: 3 entries — 2 for our vmid, 1 for another.
        // Return ctime such that we can compute age vs current time.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let two_hours_ago = now - 2 * 3600;
        let ten_hours_ago = now - 10 * 3600;
        let one_hour_ago = now - 3600;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/storage/local/content"))
            .and(query_param("content", "backup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    // for vmid=200 — must be ignored by filter
                    {"volid": "local:backup/vzdump-qemu-200-old.vma",
                     "vmid": 200, "ctime": one_hour_ago,
                     "content": "backup", "size": 1, "format": "vma", "subtype": "qemu"},
                    // older for our target vmid=100
                    {"volid": "local:backup/vzdump-qemu-100-old.vma",
                     "vmid": 100, "ctime": ten_hours_ago,
                     "content": "backup", "size": 1, "format": "vma", "subtype": "qemu"},
                    // newest for our target vmid=100 — what we expect to be picked
                    {"volid": "local:backup/vzdump-qemu-100-new.vma",
                     "vmid": 100, "ctime": two_hours_ago,
                     "content": "backup", "size": 1, "format": "vma", "subtype": "qemu"}
                ]
            })))
            .mount(&server)
            .await;
        // Catch-all for the non-backup storage — should NOT be called
        // (the find_recent_backup helper filters by content type before
        // scanning each storage). expect(0) makes the test fail loudly
        // if that filter ever regresses.
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/storage/local-lvm/content"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let client = mock_pxclient(&server).await;
        let age = super::find_recent_backup(&client, "pve1", 100)
            .await
            .expect("find_recent_backup")
            .expect("a backup should be found");
        // Newest backup is 2 hours old. Allow 1h slop for clock drift / test latency.
        assert!((1..=3).contains(&age), "expected ~2h, got {age}h");
    }

    #[tokio::test]
    async fn find_recent_backup_returns_none_when_no_backup_for_vmid() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/storage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"storage": "local", "type": "dir", "content": "backup", "active": 1, "total": 100, "used": 10, "avail": 90}
                ]
            })))
            .mount(&server)
            .await;
        // Backup list: only entries for OTHER vmids.
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/storage/local/content"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"volid": "local:backup/vzdump-qemu-999-x.vma",
                     "vmid": 999, "ctime": 1700000000_u64,
                     "content": "backup", "size": 1, "format": "vma", "subtype": "qemu"}
                ]
            })))
            .mount(&server)
            .await;
        let client = mock_pxclient(&server).await;
        let res = super::find_recent_backup(&client, "pve1", 100)
            .await
            .expect("find_recent_backup");
        assert!(
            res.is_none(),
            "no backup for vmid 100 → expected None, got {res:?}"
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // Phase 9 — coverage for the 5 deep-only risk variants the v0.1.10
    // audit flagged as untested: HasManySnapshots, BackupAgeWarning,
    // NoBackupFound, ListeningOnService, DeepCheckSkipped. These all
    // live in `assess_deep` (not the pure `assess`), so we need a
    // wiremocked PVE client to exercise them.
    // ════════════════════════════════════════════════════════════════════

    fn baseline_stopped_qemu(vmid: u32) -> Guest {
        let mut g = baseline_running();
        g.vmid = vmid;
        g.status = GuestStatus::Stopped;
        g.uptime = 0;
        g
    }

    /// `Op::Delete` on a guest with >5 snapshots emits `HasManySnapshots`
    /// at Warning level. The threshold is `MANY_SNAPSHOTS_THRESHOLD = 5`,
    /// so we mock 6 to land just over.
    #[tokio::test]
    async fn assess_deep_flags_has_many_snapshots_on_delete() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;

        // 6 real snapshots (above threshold) + the synthetic "current"
        // entry which the helper filters out via is_current().
        let mut snaps = vec![serde_json::json!({
            "name": "current", "parent": "snap-3", "description": "",
            "snaptime": 0, "vmstate": 0
        })];
        for i in 0_u64..6 {
            snaps.push(serde_json::json!({
                "name": format!("snap-{i}"),
                "parent": if i == 0 { String::new() } else { format!("snap-{}", i - 1) },
                "description": "",
                "snaptime": 1_700_000_000_u64 + i * 3600,
                "vmstate": 0,
            }));
        }
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/snapshot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": snaps
            })))
            .mount(&server)
            .await;
        // Empty backup-storages list — the backup-recency probe is part
        // of the Delete-only path; we mock its inputs so it doesn't blow
        // up but produces no BackupAgeWarning / NoBackupFound noise we
        // don't want in THIS test's assertions.
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/storage"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })),
            )
            .mount(&server)
            .await;

        let client = mock_pxclient(&server).await;
        let g = baseline_stopped_qemu(100);
        let risks = super::assess_deep(&client, None, Op::Delete, &g).await;

        let (count, level) = risks
            .iter()
            .find_map(|(r, l)| match r {
                Risk::HasManySnapshots { count } => Some((*count, *l)),
                _ => None,
            })
            .expect("HasManySnapshots must be emitted for >5 snapshots on Delete");
        assert_eq!(count, 6);
        assert_eq!(level, RiskLevel::Warning);
    }

    /// `Op::Delete` on a guest with a stale backup (> 24h old) emits
    /// `BackupAgeWarning` at Warning level. We mock a backup with ctime
    /// = now - 30h.
    #[tokio::test]
    async fn assess_deep_flags_backup_age_warning_when_stale() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;

        // No snapshots — keeps the test focused on the backup branch.
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/snapshot"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/storage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"storage": "local", "type": "dir", "content": "backup",
                     "active": 1, "total": 100, "used": 10, "avail": 90}
                ]
            })))
            .mount(&server)
            .await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let thirty_hours_ago = now - 30 * 3600;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/storage/local/content"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"volid": "local:backup/vzdump-qemu-100-stale.vma",
                     "vmid": 100, "ctime": thirty_hours_ago,
                     "content": "backup", "size": 1, "format": "vma", "subtype": "qemu"}
                ]
            })))
            .mount(&server)
            .await;

        let client = mock_pxclient(&server).await;
        let g = baseline_stopped_qemu(100);
        let risks = super::assess_deep(&client, None, Op::Delete, &g).await;

        let (age, level) = risks
            .iter()
            .find_map(|(r, l)| match r {
                Risk::BackupAgeWarning { age_hours } => Some((*age_hours, *l)),
                _ => None,
            })
            .expect("BackupAgeWarning must be emitted for >24h-old backup");
        // Newest backup is 30h old. Allow ±1h slop for test clock latency.
        assert!((29..=31).contains(&age), "expected ~30h, got {age}h");
        assert_eq!(level, RiskLevel::Warning);
    }

    /// `Op::Delete` with zero backups anywhere emits `NoBackupFound` at
    /// Notice level (not Warning — proxxx can't tell intentional from
    /// oversight). The PBS client is None, so only the PVE path runs.
    #[tokio::test]
    async fn assess_deep_flags_no_backup_found_when_storages_empty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/snapshot"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/storage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"storage": "local", "type": "dir", "content": "backup",
                     "active": 1, "total": 100, "used": 10, "avail": 90}
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/storage/local/content"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })),
            )
            .mount(&server)
            .await;

        let client = mock_pxclient(&server).await;
        let g = baseline_stopped_qemu(100);
        let risks = super::assess_deep(&client, None, Op::Delete, &g).await;

        let level = risks
            .iter()
            .find_map(|(r, l)| matches!(r, Risk::NoBackupFound).then_some(*l))
            .expect("NoBackupFound must be emitted when neither PVE nor PBS has a backup");
        assert_eq!(level, RiskLevel::Notice);
    }

    /// `Op::Stop` on a running QEMU guest with QGA reporting port 80 in
    /// `ss -tln` output emits `ListeningOnService { port: 80, name: "http" }`
    /// at Warning level. Stronger production signal than `ActiveNetTraffic`
    /// alone — pin the wiring end-to-end via the two-step agent/exec
    /// + exec-status mock.
    #[tokio::test]
    async fn assess_deep_flags_listening_on_service_when_running_qemu() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;

        // Step 1: agent/exec submit returns the pid.
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/agent/exec"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "pid": 4242 }
            })))
            .mount(&server)
            .await;
        // Step 2: exec-status returns the command output (real `ss -H -tln`
        // shape with port 80 listening — drives well_known_port("http")).
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/agent/exec-status"))
            .and(query_param("pid", "4242"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "exited": true,
                    "exitcode": 0,
                    "out-data": "LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n",
                    "err-data": ""
                }
            })))
            .mount(&server)
            .await;

        let client = mock_pxclient(&server).await;
        let mut g = baseline_running();
        g.vmid = 100;
        // Zero out fields that would emit other Warning-level risks
        // we don't want to assert against here.
        g.uptime = 60; // avoid LongUptime / ActiveNetTraffic noise
        g.netin = 0;
        g.netout = 0;
        let risks = super::assess_deep(&client, None, Op::Stop, &g).await;

        let (port, name, level) = risks
            .iter()
            .find_map(|(r, l)| match r {
                Risk::ListeningOnService { port, name } => Some((*port, name.clone(), *l)),
                _ => None,
            })
            .expect("ListeningOnService must be emitted for port 80 from QGA");
        assert_eq!(port, 80);
        assert_eq!(name, "http");
        assert_eq!(level, RiskLevel::Warning);
    }

    /// Running LXC guest emits `DeepCheckSkipped` at Notice level —
    /// the listening-port probe is structurally unavailable (PVE has
    /// no QGA equivalent for containers). The audit explicitly flagged
    /// this path as untested.
    #[tokio::test]
    async fn assess_deep_emits_deep_check_skipped_for_running_lxc() {
        // No HTTP mocks at all — the LXC short-circuit returns BEFORE
        // any I/O. If this test starts hitting a missing mock,
        // assess_deep regressed and is making an API call for LXC.
        let server = wiremock::MockServer::start().await;
        let client = mock_pxclient(&server).await;
        let mut g = baseline_running();
        g.vmid = 100;
        g.guest_type = GuestType::Lxc;
        // No Delete, so snapshot/backup probes are skipped. Running LXC,
        // so the listening-port branch fires its DeepCheckSkipped notice.
        let risks = super::assess_deep(&client, None, Op::Stop, &g).await;

        let (reason, level) = risks
            .iter()
            .find_map(|(r, l)| match r {
                Risk::DeepCheckSkipped { reason } => Some((reason.clone(), *l)),
                _ => None,
            })
            .expect("DeepCheckSkipped must be emitted for running LXC");
        assert!(
            reason.contains("LXC"),
            "DeepCheckSkipped reason should mention LXC, got {reason:?}"
        );
        assert_eq!(level, RiskLevel::Notice);
    }
}
