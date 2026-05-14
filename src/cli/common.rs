//! Shared CLI helpers consumed by every domain submodule.
//!
//! These were originally inlined in `cli/mod.rs`. Pulling them into a
//! dedicated module keeps the dispatcher (mod.rs) lean and gives the
//! per-domain submodules (`cli::vm`, `cli::ct`, …) a single import
//! source. All items are `pub(crate)` — they are an internal contract
//! between the CLI dispatcher and its domain handlers, not part of the
//! crate's external surface.

use anyhow::Result;
use serde_json::Value;

/// Locate which node owns a given VMID and which guest type it is.
/// Walks `get_nodes()` then `get_guests(node)` per node — O(N nodes)
/// network calls. Used by every per-vmid command (migrate, exec, config,
/// disk, …) that the user invokes by VMID alone, without specifying
/// the node.
pub async fn find_guest(
    client: &crate::api::PxClient,
    vmid: u32,
) -> Result<(String, crate::api::types::GuestType)> {
    use crate::api::ProxmoxGateway;
    let nodes = client.get_nodes().await?;
    let mut node_errors: Vec<String> = Vec::new();
    for n in nodes {
        match client.get_guests(&n.node).await {
            Ok(guests) => {
                if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                    return Ok((n.node.clone(), g.guest_type));
                }
            }
            Err(e) => {
                node_errors.push(format!("{}: {}", n.node, e));
            }
        }
    }
    if node_errors.is_empty() {
        anyhow::bail!("Guest {vmid} not found on any node")
    } else {
        anyhow::bail!(
            "Guest {vmid} not found; {} node(s) returned errors: {}",
            node_errors.len(),
            node_errors.join("; ")
        )
    }
}

/// Same scan as `find_guest`, but returns the full `Guest` so the
/// caller can run pre-flight risk assessment (lock, HA state, uptime,
/// tags, traffic) without a second round-trip.
pub async fn find_guest_full(
    client: &crate::api::PxClient,
    vmid: u32,
) -> Result<crate::api::types::Guest> {
    use crate::api::ProxmoxGateway;
    let nodes = client.get_nodes().await?;
    let mut node_errors: Vec<String> = Vec::new();
    for n in nodes {
        match client.get_guests(&n.node).await {
            Ok(guests) => {
                if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                    return Ok(g.clone());
                }
            }
            Err(e) => {
                node_errors.push(format!("{}: {}", n.node, e));
            }
        }
    }
    if node_errors.is_empty() {
        anyhow::bail!("Guest {vmid} not found on any node")
    } else {
        anyhow::bail!(
            "Guest {vmid} not found; {} node(s) returned errors: {}",
            node_errors.len(),
            node_errors.join("; ")
        )
    }
}

/// Poll a long-running PVE task to completion. Used by `--wait` on
/// async ops (migrate, clone, disk move, backup, template). Returns
/// the final `TaskStatus` once `is_done()`, or bails on timeout.
///
/// `interval` defaults to 1.5s — fast enough that a 10-second backup
/// returns within ~12s, slow enough that a 5-minute disk migrate
/// only generates ~200 polls. `timeout_secs = 0` uses the default cap
/// of 3600 s (1 hour) — tasks that run longer should pass an explicit budget.
const DEFAULT_TASK_TIMEOUT_SECS: u64 = 3600;

pub async fn poll_task_until_done(
    client: &crate::api::PxClient,
    node: &str,
    upid: &str,
    timeout_secs: u64,
) -> Result<crate::api::types::TaskStatus> {
    use crate::api::ProxmoxGateway;
    use std::time::Duration;
    let interval = Duration::from_millis(1500);
    let effective = if timeout_secs > 0 {
        timeout_secs
    } else {
        DEFAULT_TASK_TIMEOUT_SECS
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(effective);
    loop {
        let status = client.get_task_status(node, upid).await?;
        if status.is_done() {
            return Ok(status);
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "task {upid} did not complete within {effective}s (status: {})",
                status.status
            );
        }
        tokio::time::sleep(interval).await;
    }
}

/// Wait for a task and turn its outcome into a CLI exit code:
///   - PVE exitstatus == "OK" → exit 0, `task_status` field surfaces details.
///   - Anything else → exit 1, error message includes PVE's last log.
/// Returns the JSON envelope to embed in the response, the exit code,
/// and a flag indicating whether the wait was actually performed.
pub async fn wait_and_classify(
    client: &crate::api::PxClient,
    node: &str,
    upid: &str,
) -> Result<(serde_json::Value, i32)> {
    let status = poll_task_until_done(client, node, upid, 0).await?;
    let exit = i32::from(!status.is_success());
    Ok((serde_json::to_value(status)?, exit))
}

/// Run pre-flight risk assessment and either bail (on Severe risk
/// without `--force`) or print and proceed. Returns `Ok(())` if the
/// op should proceed, `Err` if we refuse.
///
/// Uses `assess_deep` to also include I/O-based risks (listening
/// ports via QGA). Falls back gracefully if QGA isn't available —
/// the caller still sees the cheap risks.
pub async fn enforce_preflight(
    client: &crate::api::PxClient,
    pbs: Option<&crate::pbs::PbsClient>,
    op: crate::app::preflight::Op,
    guest: &crate::api::types::Guest,
    force: bool,
) -> Result<()> {
    use crate::app::preflight::{assess_deep, max_level, RiskLevel};
    let risks = assess_deep(client, pbs, op, guest).await;
    if risks.is_empty() {
        return Ok(());
    }
    eprintln!(
        "PRE-FLIGHT for {} vmid={} ({}@{}):",
        op.as_str(),
        guest.vmid,
        guest.name,
        guest.node
    );
    for (risk, level) in &risks {
        eprintln!("  [{}] {}", level.as_str(), risk.describe());
    }
    let max = max_level(&risks);
    if max == RiskLevel::Severe && !force {
        // Phase 11 — return a typed PreflightRefusal so main.rs can
        // downcast and map to the documented exit code 6 instead of
        // the generic 1. Anyhow carries the typed error transparently
        // for callers that don't downcast.
        return Err(anyhow::Error::from(crate::app::preflight::PreflightRefusal));
    }
    if max == RiskLevel::Severe && force {
        eprintln!("  --allow-risk passed; overriding SEVERE risk(s) and proceeding.");
    }
    Ok(())
}

/// Parse `key=value` positional args from `vm raw-set` / `ct raw-set`
/// into the `(String, String)` pairs `update_guest_config` expects.
/// Splits on the FIRST `=` so values like `bridge=vmbr0,firewall=1`
/// (which themselves contain `=`) survive intact.
pub fn parse_kv_pairs(kvs: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::with_capacity(kvs.len());
    for kv in kvs {
        let (k, v) = kv.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("raw-set arg '{kv}' missing '=' separator (use `key=value`)")
        })?;
        if k.is_empty() {
            anyhow::bail!("raw-set arg '{kv}' has empty key");
        }
        out.push((k.to_string(), v.to_string()));
    }
    Ok(out)
}

/// Refuse to issue a config-update with no parameters — PVE accepts
/// it as a no-op but the user almost certainly typed something wrong.
/// Catches `proxxx vm set 100` (no flags) at the boundary.
pub fn require_non_empty_params(params: &[(String, String)]) -> Result<()> {
    if params.is_empty() {
        anyhow::bail!("no config keys passed — pass at least one --flag or use `raw-set`")
    }
    Ok(())
}

/// After `update_guest_config`, classify which of the requested keys
/// took effect immediately (hot-plug or guest stopped) versus which
/// queued as pending until the next reboot. Calls `/pending` and
/// intersects with our submitted keys.
///
/// On error (endpoint unsupported, transient network), returns
/// (`requested.clone()`, []) and an `Option<Err>` the caller can
/// surface as a warning — degrading gracefully rather than failing
/// the whole operation after the update has already landed.
pub async fn classify_pending(
    client: &crate::api::PxClient,
    node: &str,
    vmid: u32,
    gt: crate::api::types::GuestType,
    requested: &[String],
) -> (Vec<String>, Vec<String>, Option<String>) {
    use crate::api::ProxmoxGateway;
    use std::collections::HashSet;
    let pending_resp = match client.list_pending_config(node, vmid, gt).await {
        Ok(p) => p,
        Err(e) => return (requested.to_vec(), Vec::new(), Some(e.to_string())),
    };
    let pending_keys: HashSet<&str> = pending_resp
        .iter()
        .filter(|e| e.pending.is_some() || e.delete.is_some())
        .map(|e| e.key.as_str())
        .collect();
    let mut applied_now = Vec::new();
    let mut pending_reboot = Vec::new();
    for k in requested {
        if pending_keys.contains(k.as_str()) {
            pending_reboot.push(k.clone());
        } else {
            applied_now.push(k.clone());
        }
    }
    (applied_now, pending_reboot, None)
}

/// Trait object used by `patch plan` where SSH is never invoked. Panics
/// loudly if anyone tries to use it — that would be a programming error,
/// not a user-recoverable one.
pub struct NoSsh;

#[async_trait::async_trait]
impl crate::ssh::SshGateway for NoSsh {
    async fn exec(
        &self,
        _node: &str,
        _command: &str,
        _opts: crate::ssh::ExecOptions,
    ) -> Result<crate::ssh::ExecResult> {
        anyhow::bail!("internal: SSH should not be invoked during plan-only execution")
    }
}

#[derive(Clone, Copy)]
pub enum BatchOp {
    Start,
    Stop { force: bool, timeout_secs: u32 },
    Restart,
    Suspend,
    Resume,
}

/// Execution policy for multi-VMID batch operations.
///
/// - `Full`: fire all targets fully-parallel (capped at 32 in-flight).
///   This is the existing default behaviour.
/// - `Canary`: run on a small pilot slice first (ceil(N × percent / 100)
///   targets). If any pilot target fails, the rest are skipped and the
///   exit code reflects partial failure. If the pilot succeeds, the
///   remaining targets run in `Full` parallel.
/// - `Rolling`: run in sequential waves of `wave_size` targets. Each wave
///   is fired fully-parallel within itself; the next wave only starts
///   when the previous one completes without error. A failing wave aborts
///   the remaining waves.
#[derive(Debug, Clone, Copy)]
pub enum BatchPolicy {
    Full,
    Canary { percent: u8 },
    Rolling { wave_size: usize },
}

impl BatchPolicy {
    /// Parse from a user-supplied string:
    /// - `"full"` → `Full`
    /// - `"canary"` → `Canary { percent: 5 }`
    /// - `"canary=N"` → `Canary { percent: N }` (N: 1–100)
    /// - `"rolling"` → `Rolling { wave_size: 10 }`
    /// - `"rolling=K"` → `Rolling { wave_size: K }` (K ≥ 1)
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("full") {
            return Ok(Self::Full);
        }
        if let Some(rest) = s.to_ascii_lowercase().strip_prefix("canary") {
            let percent = if rest.is_empty() {
                5
            } else if let Some(n) = rest.strip_prefix('=') {
                n.parse::<u8>()
                    .ok()
                    .filter(|&p| p >= 1 && p <= 100)
                    .ok_or_else(|| anyhow::anyhow!("canary percent must be 1–100, got {n}"))?
            } else {
                anyhow::bail!("unrecognised policy: {s}")
            };
            return Ok(Self::Canary { percent });
        }
        if let Some(rest) = s.to_ascii_lowercase().strip_prefix("rolling") {
            let wave_size = if rest.is_empty() {
                10
            } else if let Some(n) = rest.strip_prefix('=') {
                n.parse::<usize>()
                    .ok()
                    .filter(|&k| k >= 1)
                    .ok_or_else(|| anyhow::anyhow!("rolling wave-size must be ≥ 1, got {n}"))?
            } else {
                anyhow::bail!("unrecognised policy: {s}")
            };
            return Ok(Self::Rolling { wave_size });
        }
        anyhow::bail!("unrecognised batch policy '{s}' (valid: full, canary[=N%], rolling[=K])")
    }
}

pub async fn execute_batch_op(
    client: &std::sync::Arc<crate::api::PxClient>,
    op: BatchOp,
    vmids: &[u32],
    config: &crate::config::ProfileConfig,
    strict: bool,
) -> Result<(Value, i32)> {
    execute_batch_op_with_policy(client, op, vmids, config, strict, BatchPolicy::Full).await
}

/// Canary pilot slice size: ceil(N × percent / 100), clamped to [1, N].
pub fn canary_pilot_count(n: usize, percent: u8) -> usize {
    std::cmp::min(n, std::cmp::max(1, (n * usize::from(percent) + 99) / 100))
}

pub async fn execute_batch_op_with_policy(
    client: &std::sync::Arc<crate::api::PxClient>,
    op: BatchOp,
    vmids: &[u32],
    config: &crate::config::ProfileConfig,
    strict: bool,
    policy: BatchPolicy,
) -> Result<(Value, i32)> {
    match policy {
        BatchPolicy::Full => execute_batch_op_full(client, op, vmids, config, strict).await,
        BatchPolicy::Canary { percent } => {
            let n = vmids.len();
            let pilot_count = canary_pilot_count(n, percent);
            let (pilot, rest) = vmids.split_at(pilot_count);
            tracing::info!(
                "canary policy: running {pilot_count}/{n} pilot targets first ({}%)",
                percent
            );
            let (mut pilot_val, pilot_code) =
                execute_batch_op_full(client, op, pilot, config, strict).await?;
            let pilot_arr = if let Some(a) = pilot_val.as_array_mut() {
                a
            } else {
                unreachable!("execute_batch_op_full always returns Array")
            };
            // Abort if any pilot target errored OR if the pilot as a whole
            // produced a non-zero exit (covers HITL-pending exit=3, strict
            // abort exit=1, partial-failure exit=2 — all mean "don't promote").
            let pilot_has_error = pilot_arr
                .iter()
                .any(|r| r.get("status").and_then(|s| s.as_str()) == Some("error"));
            let pilot_failed = pilot_has_error || pilot_code >= 2;
            if pilot_failed {
                tracing::warn!(
                    "canary pilot had failures — skipping {} remaining target(s)",
                    rest.len()
                );
                let mut all = pilot_arr.clone();
                for &vmid in rest {
                    all.push(serde_json::json!({
                        "vmid": vmid,
                        "status": "skipped",
                        "reason": "canary pilot failed — remainder aborted"
                    }));
                }
                return Ok((serde_json::Value::Array(all), 2));
            }
            if rest.is_empty() {
                return Ok((pilot_val, pilot_code));
            }
            tracing::info!(
                "canary pilot succeeded — promoting {} remaining target(s)",
                rest.len()
            );
            let (rest_val, rest_code) =
                execute_batch_op_full(client, op, rest, config, strict).await?;
            let mut all = pilot_arr.clone();
            if let Some(arr) = rest_val.as_array() {
                all.extend(arr.iter().cloned());
            }
            let code = if pilot_code != 0 || rest_code != 0 {
                std::cmp::max(pilot_code, rest_code)
            } else {
                0
            };
            Ok((serde_json::Value::Array(all), code))
        }
        BatchPolicy::Rolling { wave_size } => {
            let mut all_results = Vec::new();
            let mut overall_code = 0_i32;
            for (wave_idx, wave) in vmids.chunks(wave_size).enumerate() {
                tracing::info!(
                    "rolling policy: wave {} — {} target(s)",
                    wave_idx + 1,
                    wave.len()
                );
                let (wave_val, wave_code) =
                    execute_batch_op_full(client, op, wave, config, strict).await?;
                let wave_arr = wave_val.into_array().unwrap_or_default();
                let wave_failed = wave_arr
                    .iter()
                    .any(|r| r.get("status").and_then(|s| s.as_str()) == Some("error"));
                all_results.extend(wave_arr);
                if wave_code != 0 {
                    overall_code = std::cmp::max(overall_code, wave_code);
                }
                if wave_failed {
                    // Use the actual end-of-wave offset, not (wave_idx+1)*wave_size
                    // — the last wave may be shorter than wave_size.
                    let remaining_start = wave_idx * wave_size + wave.len();
                    tracing::warn!(
                        "rolling wave {} failed — skipping {} remaining target(s)",
                        wave_idx + 1,
                        vmids.len().saturating_sub(remaining_start)
                    );
                    for &vmid in vmids.get(remaining_start..).unwrap_or_default() {
                        all_results.push(serde_json::json!({
                            "vmid": vmid,
                            "status": "skipped",
                            "reason": format!("rolling wave {} failed — remainder aborted", wave_idx + 1)
                        }));
                    }
                    if overall_code == 0 {
                        overall_code = 2;
                    }
                    break;
                }
            }
            Ok((serde_json::Value::Array(all_results), overall_code))
        }
    }
}

// Helper: `serde_json::Value::into_array` doesn't exist; add a local extension.
trait IntoArray {
    fn into_array(self) -> Option<Vec<serde_json::Value>>;
}
impl IntoArray for serde_json::Value {
    fn into_array(self) -> Option<Vec<serde_json::Value>> {
        if let serde_json::Value::Array(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

async fn execute_batch_op_full(
    client: &std::sync::Arc<crate::api::PxClient>,
    op: BatchOp,
    vmids: &[u32],
    config: &crate::config::ProfileConfig,
    strict: bool,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    use tracing::{error, warn};

    let nodes = client.get_nodes().await?;
    let mut guest_map = std::collections::HashMap::new();

    let mut join_set = tokio::task::JoinSet::new();
    for node in nodes {
        let client_c = std::sync::Arc::clone(client);
        let node_name = node.node.clone();
        join_set.spawn(async move {
            let res = client_c.get_guests(&node_name).await;
            (node_name, res)
        });
    }

    while let Some(res) = join_set.join_next().await {
        match res {
            Ok((_node_name, Ok(guests))) => {
                for g in guests {
                    guest_map.insert(g.vmid, g);
                }
            }
            Ok((node_name, Err(e))) => {
                tracing::warn!("get_guests({node_name}) failed during batch scan: {e:#}");
            }
            Err(join_err) => {
                tracing::warn!("get_guests task panicked during batch scan: {join_err}");
            }
        }
    }

    let mut results = Vec::new();
    let mut has_failure = false;
    let mut hitl_pending = false;
    let mut op_join_set = tokio::task::JoinSet::new();
    // (Gemini audit) — bound concurrent in-flight HTTPS
    // requests. Without this, `op_join_set.spawn(...)` per VMID with
    // 500+ selected guests would open 500 simultaneous TCP+TLS
    // connections, hitting `ulimit -n 1024` and cascading "Too many
    // open files" errors into the SQLite cache, log file, etc.
    //
    // 32 in-flight is a comfortable margin under any sensible ulimit
    // and well above what reqwest's per-host pool would dedupe to.
    const MAX_INFLIGHT_OPS: usize = 32;
    let inflight_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_OPS));

    let action_str = match op {
        BatchOp::Start => "start",
        BatchOp::Stop { .. } => "stop",
        BatchOp::Restart => "restart",
        BatchOp::Suspend => "suspend",
        BatchOp::Resume => "resume",
    };

    let policies = config.policies.as_deref().unwrap_or_default();

    let tg_gateway = match config.telegram.as_ref() {
        None => None,
        Some(cfg) => Some(crate::hitl::telegram::TelegramGateway::from_config(cfg).await?),
    };

    if strict {
        let mut missing = Vec::new();
        for vmid in vmids {
            if !guest_map.contains_key(vmid) {
                missing.push(*vmid);
            }
        }
        if !missing.is_empty() {
            anyhow::bail!("Strict mode: Guests not found: {missing:?}");
        }
    }

    for vmid in vmids {
        if let Some(guest) = guest_map.get(vmid).cloned() {
            // Template guard — preventive. Templates cannot be
            // started or restarted; PVE would reject with a 500
            // message that doesn't tell the user how to proceed.
            // We catch it client-side and point them at `clone`.
            // Stop is allowed to fall through (templates are
            // always stopped, so PVE returns harmless no-op).
            if guest.is_template() && matches!(op, BatchOp::Start | BatchOp::Restart) {
                results.push(serde_json::json!({
                    "vmid": vmid,
                    "status": "rejected",
                    "reason": format!(
                        "guest {vmid} is a template — cannot {action_str}. \
                         Use `proxxx clone {vmid} --name <new>` to produce a \
                         startable copy."
                    ),
                }));
                has_failure = true;
                continue;
            }

            // Check HITL Policies
            let tags = guest.tag_list();
            if let Some(policy) =
                crate::hitl::policy::check_policies(policies, action_str, &vmid.to_string(), &tags)
            {
                warn!(
                    "HITL intercepted: {} on {} (Matched Policy: {} {})",
                    action_str, vmid, policy.action, policy.target
                );

                let txn_id = format!("{action_str}:{vmid}");

                if let Some(ref tg) = tg_gateway {
                    let reason = format!("CLI requested batch op: {action_str}");
                    if let Err(e) = tg
                        .request_approval(action_str, &vmid.to_string(), &reason, &txn_id)
                        .await
                    {
                        error!("Failed to send Telegram approval request: {}", e);
                    }
                }

                results.push(serde_json::json!({
                    "vmid": vmid,
                    "status": "pending_hitl",
                    "txn_id": txn_id,
                    "message": format!("Operation requires {} approval(s) via {}", policy.require, policy.channel)
                }));
                hitl_pending = true;
                continue; // Skip execution
            }

            let client_c = std::sync::Arc::clone(client);
            let v = *vmid;
            let node = guest.node;
            let gt = guest.guest_type;
            let operation = match op {
                BatchOp::Start => BatchOp::Start,
                BatchOp::Stop {
                    force,
                    timeout_secs,
                } => BatchOp::Stop {
                    force,
                    timeout_secs,
                },
                BatchOp::Restart => BatchOp::Restart,
                BatchOp::Suspend => BatchOp::Suspend,
                BatchOp::Resume => BatchOp::Resume,
            };

            if strict {
                // Bug #1+#2 fix: dispatch by guest_type, route force=false to shutdown.
                let res = match operation {
                    BatchOp::Start => client_c.start_guest(&node, v, gt).await,
                    BatchOp::Stop { force: true, .. } => {
                        client_c.stop_guest(&node, v, gt, true).await
                    }
                    BatchOp::Stop {
                        force: false,
                        timeout_secs,
                    } => client_c.shutdown_guest(&node, v, gt, timeout_secs).await,
                    BatchOp::Restart => client_c.restart_guest(&node, v, gt).await,
                    BatchOp::Suspend => client_c.suspend_guest(&node, v, gt).await,
                    BatchOp::Resume => client_c.resume_guest(&node, v, gt).await,
                };
                match res {
                    Ok(upid) => {
                        results.push(serde_json::json!({
                            "vmid": vmid,
                            "status": "success",
                            "upid": upid
                        }));
                    }
                    Err(e) => {
                        warn!("Operation failed for guest {}: {}", vmid, e);
                        results.push(serde_json::json!({
                            "vmid": vmid,
                            "status": "error",
                            "message": e.to_string()
                        }));
                        anyhow::bail!("Strict mode: Operation failed for guest {vmid}: {e}");
                    }
                }
            } else {
                let sem = std::sync::Arc::clone(&inflight_sem);
                op_join_set.spawn(async move {
                    // Acquire a permit before issuing the request. If
                    // 32 are already in flight, await here — the
                    // semaphore is the FD-exhaustion gate.
                    let _permit = sem.acquire_owned().await;
                    let res = match operation {
                        BatchOp::Start => client_c.start_guest(&node, v, gt).await,
                        BatchOp::Stop { force: true, .. } => {
                            client_c.stop_guest(&node, v, gt, true).await
                        }
                        BatchOp::Stop {
                            force: false,
                            timeout_secs,
                        } => client_c.shutdown_guest(&node, v, gt, timeout_secs).await,
                        BatchOp::Restart => client_c.restart_guest(&node, v, gt).await,
                        BatchOp::Suspend => client_c.suspend_guest(&node, v, gt).await,
                        BatchOp::Resume => client_c.resume_guest(&node, v, gt).await,
                    };
                    (v, res)
                });
            }
        } else {
            warn!("Guest {} not found across any node", vmid);
            results.push(serde_json::json!({
                "vmid": vmid,
                "status": "error",
                "message": "Guest not found"
            }));
            has_failure = true;
        }
    }

    if !strict {
        while let Some(res) = op_join_set.join_next().await {
            match res {
                Ok((vmid, Ok(upid))) => {
                    results.push(serde_json::json!({
                        "vmid": vmid,
                        "status": "success",
                        "upid": upid
                    }));
                }
                Ok((vmid, Err(e))) => {
                    warn!("Operation failed for guest {vmid}: {e}");
                    results.push(serde_json::json!({
                        "vmid": vmid,
                        "status": "error",
                        "message": e.to_string()
                    }));
                    has_failure = true;
                }
                Err(join_err) => {
                    warn!("Batch op task panicked: {join_err}");
                    has_failure = true;
                }
            }
        }
    }

    let exit_code = if hitl_pending {
        3 // HITL Pending takes precedence in batch semantics
    } else if has_failure {
        2 // Partial Failure
    } else {
        0 // Full Success
    };

    Ok((serde_json::Value::Array(results), exit_code))
}

#[cfg(test)]
mod parse_kv_pairs_tests {
    use super::parse_kv_pairs;

    #[test]
    fn simple_pairs() {
        let kvs = vec!["cores=4".to_string(), "memory=8192".to_string()];
        let out = parse_kv_pairs(&kvs).expect("parse");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], ("cores".to_string(), "4".to_string()));
        assert_eq!(out[1], ("memory".to_string(), "8192".to_string()));
    }

    #[test]
    fn value_containing_equals_signs_survives() {
        // PVE property strings often contain `=` inside values, e.g.
        //   net0=virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0
        // Splitting on the FIRST `=` only is the whole point of this
        // helper — pin the behaviour against future "clever" rewrites.
        let kvs = vec!["net0=virtio=AA:BB,bridge=vmbr0,firewall=1".to_string()];
        let out = parse_kv_pairs(&kvs).expect("parse");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "net0");
        assert_eq!(out[0].1, "virtio=AA:BB,bridge=vmbr0,firewall=1");
    }

    #[test]
    fn empty_value_is_allowed() {
        // PVE accepts `delete` semantics via empty values on some keys.
        let kvs = vec!["description=".to_string()];
        let out = parse_kv_pairs(&kvs).expect("parse");
        assert_eq!(out[0], ("description".to_string(), String::new()));
    }

    #[test]
    fn missing_equals_separator_errors() {
        let kvs = vec!["cores4".to_string()];
        let err = parse_kv_pairs(&kvs).expect_err("must reject");
        assert!(err.to_string().contains("missing '=' separator"));
    }

    #[test]
    fn empty_key_errors() {
        let kvs = vec!["=4".to_string()];
        let err = parse_kv_pairs(&kvs).expect_err("must reject");
        assert!(err.to_string().contains("empty key"));
    }
}

#[cfg(test)]
mod enforce_preflight_tests {
    //! Phase 9 — pins the `--allow-risk` bypass semantics that the
    //! v0.1.10 audit flagged as untested. The CLI flag flows through
    //! to `force: bool` here; the contract is:
    //!
    //! - max risk == Severe  + force == false → bail with a paste-able
    //!   "re-run with --allow-risk" message (this is the gate)
    //! - max risk == Severe  + force == true  → proceed (operator owns it)
    //! - max risk <= Warning + force any       → proceed (notices/warnings
    //!   are informational)
    //!
    //! All four cases below construct a Guest that exercises the cheap
    //! `assess` path so we don't need to mock anything more than the
    //! shell `PxClient` wiremock harness — `assess_deep` short-circuits
    //! before any I/O when the guest is Stopped (no listening probe)
    //! AND the op is not Delete (no snapshot/backup probes).
    use super::enforce_preflight;
    use crate::api::types::{Guest, GuestStatus, GuestType};
    use crate::app::preflight::Op;

    /// Stock Stopped QEMU guest — no risks unless caller mutates a field.
    fn stopped_qemu(vmid: u32) -> Guest {
        Guest {
            vmid,
            name: "test".into(),
            status: GuestStatus::Stopped,
            guest_type: GuestType::Qemu,
            node: "pve1".into(),
            cpu: 0.0,
            cpus: 1,
            mem: 0,
            maxmem: 0,
            disk: 0,
            maxdisk: 0,
            uptime: 0,
            tags: String::new(),
            lock: String::new(),
            hastate: String::new(),
            template: false,
            netin: 0,
            netout: 0,
        }
    }

    /// Build a `PxClient` pointed at a fresh wiremock server. No mocks
    /// are mounted — the tests use `Op::Stop` on Stopped guests so
    /// `assess_deep` makes no API calls. The client is just a structural
    /// dependency of `enforce_preflight`.
    ///
    /// Returns `(client, server)` — callers must keep `_server` alive for the
    /// duration of the test so the bound port stays open.
    async fn idle_client() -> (crate::api::PxClient, wiremock::MockServer) {
        let server = wiremock::MockServer::start().await;
        let cfg = crate::config::ProfileConfig {
            url: server.uri(),
            user: "root@pam".into(),
            auth: "token".into(),
            token_id: Some("test".into()),
            token_secret: None,
            token_secret_file: None,
            password: None,
            verify_tls: false,
            tls_pin_mode: None,
            rate_limit: Some(100),
            policies: None,
            telegram: None,
            ssh: None,
            pbs: None,
            alerts: None,
            mcp_token: None,
        };
        let client = crate::api::PxClient::new(cfg, Some("fake-secret"))
            .await
            .expect("client builds");
        (client, server)
    }

    /// max == Severe, force == false → bails. The error message must
    /// mention `--allow-risk` so the operator knows the escape hatch.
    /// The chain must also carry a typed `PreflightRefusal` so main.rs
    /// can map it to exit code 6.
    #[tokio::test]
    async fn enforce_preflight_bails_on_severe_without_force() {
        let (client, _server) = idle_client().await;
        let mut g = stopped_qemu(100);
        g.lock = "backup".into(); // Locked → Severe regardless of op
        let res = enforce_preflight(&client, None, Op::Stop, &g, false).await;
        let err = res.expect_err("Severe + !force must bail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--allow-risk"),
            "error must point operator at --allow-risk, got: {msg}"
        );
        assert!(
            msg.contains("SEVERE"),
            "error must name SEVERE risk level, got: {msg}"
        );
        // Phase 11: the chain must carry the typed PreflightRefusal so
        // main.rs can downcast and map it to exit code 6. Without this
        // assertion, a future refactor could revert to `anyhow::bail!`
        // (untyped) and the exit-code contract would silently break.
        let refusal = err
            .chain()
            .find_map(|c| c.downcast_ref::<crate::app::preflight::PreflightRefusal>());
        assert!(
            refusal.is_some(),
            "error chain must carry PreflightRefusal for exit-code 6 mapping"
        );
    }

    /// max == Severe, force == true → proceeds. This is the bypass
    /// path the v0.1.10 audit found zero coverage for.
    #[tokio::test]
    async fn enforce_preflight_proceeds_on_severe_with_force() {
        let (client, _server) = idle_client().await;
        let mut g = stopped_qemu(100);
        g.lock = "backup".into();
        enforce_preflight(&client, None, Op::Stop, &g, true)
            .await
            .expect("Severe + force must proceed (operator owns the consequence)");
    }

    /// max == Warning, force == false → proceeds. Warnings are
    /// informational only; the gate refuses ONLY on Severe.
    /// `Op::Stop` on a tagged-prod stopped guest yields `TaggedProd` (Warning).
    #[tokio::test]
    async fn enforce_preflight_proceeds_on_warning_without_force() {
        let (client, _server) = idle_client().await;
        let mut g = stopped_qemu(100);
        g.tags = "production".into();
        enforce_preflight(&client, None, Op::Stop, &g, false)
            .await
            .expect("Warning + !force must proceed (only Severe bails)");
    }

    /// No risks at all → Ok regardless of force. Empty-risk path: pure
    /// stopped guest with no tags/lock/hastate. The function should
    /// return Ok immediately without printing the risk header.
    #[tokio::test]
    async fn enforce_preflight_returns_ok_on_clean_guest() {
        let (client, _server) = idle_client().await;
        let g = stopped_qemu(100);
        enforce_preflight(&client, None, Op::Stop, &g, false)
            .await
            .expect("clean guest + !force must proceed");
        enforce_preflight(&client, None, Op::Stop, &g, true)
            .await
            .expect("clean guest + force must proceed");
    }
}

#[cfg(test)]
mod batch_policy_tests {
    use super::BatchPolicy;

    #[test]
    fn parse_full() {
        assert!(matches!(
            BatchPolicy::parse("full").unwrap(),
            BatchPolicy::Full
        ));
        assert!(matches!(
            BatchPolicy::parse("FULL").unwrap(),
            BatchPolicy::Full
        ));
    }

    #[test]
    fn parse_canary_default() {
        let BatchPolicy::Canary { percent } = BatchPolicy::parse("canary").unwrap() else {
            panic!("expected Canary")
        };
        assert_eq!(percent, 5);
    }

    #[test]
    fn parse_canary_custom() {
        let BatchPolicy::Canary { percent } = BatchPolicy::parse("canary=20").unwrap() else {
            panic!("expected Canary")
        };
        assert_eq!(percent, 20);
    }

    #[test]
    fn parse_canary_100_is_valid() {
        let BatchPolicy::Canary { percent } = BatchPolicy::parse("canary=100").unwrap() else {
            panic!()
        };
        assert_eq!(percent, 100);
    }

    #[test]
    fn parse_canary_0_is_rejected() {
        assert!(BatchPolicy::parse("canary=0").is_err());
    }

    #[test]
    fn parse_canary_101_is_rejected() {
        assert!(BatchPolicy::parse("canary=101").is_err());
    }

    #[test]
    fn parse_rolling_default() {
        let BatchPolicy::Rolling { wave_size } = BatchPolicy::parse("rolling").unwrap() else {
            panic!("expected Rolling")
        };
        assert_eq!(wave_size, 10);
    }

    #[test]
    fn parse_rolling_custom() {
        let BatchPolicy::Rolling { wave_size } = BatchPolicy::parse("rolling=25").unwrap() else {
            panic!()
        };
        assert_eq!(wave_size, 25);
    }

    #[test]
    fn parse_rolling_zero_is_rejected() {
        assert!(BatchPolicy::parse("rolling=0").is_err());
    }

    #[test]
    fn parse_unknown_is_rejected() {
        assert!(BatchPolicy::parse("random").is_err());
        assert!(BatchPolicy::parse("canary=abc").is_err());
    }

    /// Canary pilot slice sizing: ceil(N * percent / 100).
    /// With 20 targets and 5%, ceil(20 * 5 / 100) = ceil(1) = 1.
    /// With 20 targets and 10%, ceil(20 * 10 / 100) = 2.
    /// With 3 targets and 5%, ceil(3 * 5 / 100) = ceil(0.15) = 1 (minimum 1).
    #[test]
    fn canary_pilot_count_formula() {
        use super::canary_pilot_count;
        assert_eq!(canary_pilot_count(20, 5), 1);
        assert_eq!(canary_pilot_count(20, 10), 2);
        // Minimum 1 even when percent rounds down to 0 of N.
        assert_eq!(canary_pilot_count(3, 5), 1);
        // 100% should equal all N.
        assert_eq!(canary_pilot_count(7, 100), 7);
    }
}
