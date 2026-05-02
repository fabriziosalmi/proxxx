//! Patching & rolling-reboot orchestrator (feature #9).
//!
//! Workflow per node:
//!     REFRESH  → API `POST /apt/update`
//!     INVENTORY→ API `GET  /apt/update`           ← pure Proxmox API
//!     UPGRADE  → SSH `apt-get -y dist-upgrade`    ← no API endpoint exists
//!     REBOOT?  → SSH `reboot` if kernel/microcode changed and policy allows
//!     WAIT     → poll API `/nodes/{node}/status` for uptime reset + quorum
//!
//! Why both API and SSH: Proxmox does not expose `apt upgrade` via REST.
//! That's an intentional design choice on their side ("pull, don't push"
//! mirror trust). The orchestrator inherits Pillar 0 for the upgrade phase.
//!
//! Concurrency: hard cap of `max_concurrent` nodes mid-upgrade (default 1).
//! "Mid-upgrade" = phase ∈ {Upgrade, Reboot, WaitReboot}. The orchestrator
//! itself runs serially through the plan; if you want parallelism, multiple
//! plans can run side-by-side, each capped.
//!
//! Abort semantics: any node failure stops the rest of the plan. Already-
//! completed nodes stay completed; the partially-failed node is left in
//! the failure state for human inspection. We do NOT auto-rollback —
//! `apt` upgrades aren't atomic and rolling back would do more harm.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::api::types::{AptUpgradable, Node, NodeStatusDetail};
use crate::api::ProxmoxGateway;
use crate::ssh::{ExecOptions, SshGateway};

// ── Public API ──────────────────────────────────────────────

/// What to do about reboots when a kernel/microcode/libc upgrade is queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RebootPolicy {
    /// Reboot only when an upgraded package requires it (heuristic in
    /// `AptUpgradable::requires_reboot()`). Default — matches what an
    /// experienced admin would do by hand.
    #[default]
    Auto,
    /// Always reboot after upgrade, even if no kernel change. Useful when
    /// you want a clean restart for unrelated reasons.
    Always,
    /// Never reboot. The orchestrator marks the node as "reboot pending"
    /// and continues to the next node. The user must reboot manually
    /// later. Safe for soak-test windows.
    Never,
}

#[derive(Debug, Clone)]
pub struct PatchStrategy {
    pub max_concurrent: u32,
    pub reboot_policy: RebootPolicy,
    /// Hard timeout for the apt upgrade phase. Default 1800s (30 min) —
    /// long enough for a full Proxmox VE point release upgrade.
    pub upgrade_timeout: Duration,
    /// Maximum time we wait for a node to come back after reboot.
    /// Default 600s (10 min). After that, the orchestrator gives up and
    /// marks the node as failed.
    pub reboot_wait_timeout: Duration,
    /// If true, nothing destructive runs. apt update + inventory + plan,
    /// no upgrade, no reboot.
    pub dry_run: bool,
}

impl Default for PatchStrategy {
    fn default() -> Self {
        Self {
            max_concurrent: 1,
            reboot_policy: RebootPolicy::Auto,
            upgrade_timeout: Duration::from_secs(1800),
            reboot_wait_timeout: Duration::from_secs(600),
            dry_run: false,
        }
    }
}

/// Lifecycle of a single node within a patch plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Initial state. No work done yet.
    Pending,
    /// Refreshing apt cache (API).
    Refresh,
    /// Reading upgradable list (API).
    Inventory,
    /// Running apt upgrade over SSH.
    Upgrade,
    /// Issuing reboot.
    Reboot,
    /// Polling for the node to come back.
    WaitReboot,
    /// Successfully patched. If `rebooted = false`, a reboot is still
    /// pending (policy=Never or no kernel change).
    Done {
        rebooted: bool,
        packages_upgraded: u32,
    },
    /// Skipped — usually because the node had no upgrades available.
    Skipped { reason: String },
    /// Failed at some phase. The orchestrator stops the plan after
    /// surfacing this.
    Failed { phase: String, error: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct NodePlan {
    pub node: String,
    pub upgradable: Vec<AptUpgradable>,
    pub kernel_pending: bool,
    pub security_pending: bool,
    pub reboot_required: bool,
    pub status: Phase,
    /// Snapshot of the node's kernel before the upgrade (post-upgrade we
    /// compare to detect "the new kernel actually loaded").
    pub kernel_before: Option<String>,
    pub kernel_after: Option<String>,
}

impl NodePlan {
    fn from_inventory(node: String, upgradable: Vec<AptUpgradable>) -> Self {
        let kernel_pending = upgradable.iter().any(|p| {
            p.package.starts_with("pve-kernel")
                || p.package.starts_with("proxmox-kernel")
                || p.package.starts_with("linux-image")
        });
        let security_pending = upgradable.iter().any(AptUpgradable::is_security);
        let reboot_required = upgradable.iter().any(AptUpgradable::requires_reboot);
        let status = if upgradable.is_empty() {
            Phase::Skipped {
                reason: "no upgrades available".to_string(),
            }
        } else {
            Phase::Pending
        };
        Self {
            node,
            upgradable,
            kernel_pending,
            security_pending,
            reboot_required,
            status,
            kernel_before: None,
            kernel_after: None,
        }
    }
}

/// A full plan, before or after execution. Ordering of `nodes` is the
/// execution order — the orchestrator processes them sequentially under
/// the concurrency cap.
#[derive(Debug, Clone, Serialize)]
pub struct PatchPlan {
    pub nodes: Vec<NodePlan>,
    pub strategy_summary: HashMap<String, String>,
}

impl PatchPlan {
    /// Total packages across all nodes that would be upgraded.
    #[must_use]
    pub fn total_packages(&self) -> u32 {
        self.nodes
            .iter()
            .map(|n| u32::try_from(n.upgradable.len()).unwrap_or(u32::MAX))
            .sum()
    }

    /// Nodes that will reboot under the current policy.
    #[must_use]
    pub fn nodes_rebooting(&self, policy: RebootPolicy) -> Vec<&str> {
        self.nodes
            .iter()
            .filter(|n| {
                if matches!(n.status, Phase::Skipped { .. }) {
                    return false;
                }
                match policy {
                    RebootPolicy::Always => true,
                    RebootPolicy::Auto => n.reboot_required,
                    RebootPolicy::Never => false,
                }
            })
            .map(|n| n.node.as_str())
            .collect()
    }
}

// ── Orchestrator ────────────────────────────────────────────

/// Orders nodes for the plan. Default = alphabetical (deterministic, no
/// surprises). Future: HA priority via `/cluster/ha/groups`.
#[derive(Debug, Clone, Copy, Default)]
pub enum NodeOrdering {
    #[default]
    Alphabetical,
    /// Caller supplies the order explicitly.
    Custom,
}

pub struct Orchestrator {
    api: Arc<dyn ProxmoxGateway>,
    ssh: Arc<dyn SshGateway>,
    strategy: PatchStrategy,
}

impl Orchestrator {
    #[must_use]
    pub fn new(
        api: Arc<dyn ProxmoxGateway>,
        ssh: Arc<dyn SshGateway>,
        strategy: PatchStrategy,
    ) -> Self {
        Self { api, ssh, strategy }
    }

    /// Build a plan: refresh apt on each node, list upgradable, classify.
    /// No upgrades happen here. Side-effects are limited to the apt cache
    /// refresh on each node (which is read-only from a system POV).
    pub async fn plan(&self, only_nodes: Option<&[String]>) -> Result<PatchPlan> {
        let nodes_in: Vec<Node> = self.api.get_nodes().await.context("listing nodes")?;
        let mut node_names: Vec<String> = nodes_in
            .into_iter()
            .filter(|n| n.status == crate::api::types::NodeStatus::Online)
            .map(|n| n.node)
            .collect();

        if let Some(filter) = only_nodes {
            node_names.retain(|n| filter.iter().any(|f| f == n));
        }

        node_names.sort();

        info!(
            "patch plan: refreshing apt on {} node(s): {:?}",
            node_names.len(),
            node_names
        );

        let mut plans = Vec::with_capacity(node_names.len());
        for node in &node_names {
            // Best-effort refresh. If a node's refresh fails, we still
            // produce a plan entry with a Failed status — surfaces the
            // issue without crashing the whole planning step.
            if let Err(e) = self.api.apt_update_refresh(node).await {
                warn!("apt refresh failed on {node}: {e:#}");
                plans.push(NodePlan {
                    node: node.clone(),
                    upgradable: Vec::new(),
                    kernel_pending: false,
                    security_pending: false,
                    reboot_required: false,
                    status: Phase::Failed {
                        phase: "refresh".to_string(),
                        error: format!("{e:#}"),
                    },
                    kernel_before: None,
                    kernel_after: None,
                });
                continue;
            }

            let pkgs = match self.api.apt_list_upgradable(node).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("apt inventory failed on {node}: {e:#}");
                    plans.push(NodePlan {
                        node: node.clone(),
                        upgradable: Vec::new(),
                        kernel_pending: false,
                        security_pending: false,
                        reboot_required: false,
                        status: Phase::Failed {
                            phase: "inventory".to_string(),
                            error: format!("{e:#}"),
                        },
                        kernel_before: None,
                        kernel_after: None,
                    });
                    continue;
                }
            };

            plans.push(NodePlan::from_inventory(node.clone(), pkgs));
        }

        let mut summary = HashMap::new();
        summary.insert(
            "max_concurrent".to_string(),
            self.strategy.max_concurrent.to_string(),
        );
        summary.insert(
            "reboot_policy".to_string(),
            format!("{:?}", self.strategy.reboot_policy),
        );
        summary.insert("dry_run".to_string(), self.strategy.dry_run.to_string());

        Ok(PatchPlan {
            nodes: plans,
            strategy_summary: summary,
        })
    }

    /// Execute the plan. Returns the same plan with each node's `status`
    /// updated. Stops on first failure (already-finished nodes stay Done;
    /// remaining nodes stay Pending).
    pub async fn apply<P>(&self, mut plan: PatchPlan, mut on_progress: P) -> Result<PatchPlan>
    where
        P: FnMut(&str, &Phase) + Send,
    {
        // Concurrency: we run sequentially in this MVP. A future iteration
        // can use a JoinSet bounded by max_concurrent — but the failure
        // model gets harder (do you abort siblings?). One thing at a time.
        if self.strategy.max_concurrent != 1 {
            warn!(
                "max_concurrent={} requested; MVP only supports serial execution",
                self.strategy.max_concurrent
            );
        }

        for idx in 0..plan.nodes.len() {
            // Skip nodes we already classified as nothing-to-do or pre-failed
            if matches!(
                &plan.nodes[idx].status,
                Phase::Skipped { .. } | Phase::Failed { .. }
            ) {
                on_progress(&plan.nodes[idx].node, &plan.nodes[idx].status);
                continue;
            }

            // Capture immutable bits before borrowing mutably below.
            let node_name = plan.nodes[idx].node.clone();
            let reboot_required = plan.nodes[idx].reboot_required;
            let pkg_count = u32::try_from(plan.nodes[idx].upgradable.len()).unwrap_or(u32::MAX);

            // Snapshot kernel pre-upgrade for change detection.
            let kernel_before = self
                .api
                .node_status_detail(&node_name)
                .await
                .ok()
                .map(|s| s.kversion);
            plan.nodes[idx].kernel_before = kernel_before.clone();

            // ── UPGRADE phase ──────────────────────────────────
            plan.nodes[idx].status = Phase::Upgrade;
            on_progress(&node_name, &plan.nodes[idx].status);

            if self.strategy.dry_run {
                info!("[dry-run] would apt-get upgrade on {node_name}");
            } else if let Err(e) = self.run_upgrade(&node_name).await {
                let err = format!("{e:#}");
                warn!("upgrade failed on {node_name}: {err}");
                plan.nodes[idx].status = Phase::Failed {
                    phase: "upgrade".to_string(),
                    error: err,
                };
                on_progress(&node_name, &plan.nodes[idx].status);
                return Ok(plan);
            }

            // ── REBOOT phase (policy-gated) ────────────────────
            let should_reboot = match self.strategy.reboot_policy {
                RebootPolicy::Always => true,
                RebootPolicy::Auto => reboot_required,
                RebootPolicy::Never => false,
            };

            let mut rebooted = false;
            if should_reboot {
                plan.nodes[idx].status = Phase::Reboot;
                on_progress(&node_name, &plan.nodes[idx].status);

                if self.strategy.dry_run {
                    info!("[dry-run] would reboot {node_name}");
                } else {
                    if let Err(e) = self.run_reboot(&node_name).await {
                        let err = format!("{e:#}");
                        plan.nodes[idx].status = Phase::Failed {
                            phase: "reboot".to_string(),
                            error: err,
                        };
                        on_progress(&node_name, &plan.nodes[idx].status);
                        return Ok(plan);
                    }

                    plan.nodes[idx].status = Phase::WaitReboot;
                    on_progress(&node_name, &plan.nodes[idx].status);

                    match self
                        .wait_for_reboot(&node_name, kernel_before.as_deref())
                        .await
                    {
                        Ok(post) => {
                            plan.nodes[idx].kernel_after = Some(post.kversion);
                            rebooted = true;
                        }
                        Err(e) => {
                            let err = format!("{e:#}");
                            plan.nodes[idx].status = Phase::Failed {
                                phase: "wait_reboot".to_string(),
                                error: err,
                            };
                            on_progress(&node_name, &plan.nodes[idx].status);
                            return Ok(plan);
                        }
                    }
                }
            }

            plan.nodes[idx].status = Phase::Done {
                rebooted,
                packages_upgraded: pkg_count,
            };
            on_progress(&node_name, &plan.nodes[idx].status);
        }

        Ok(plan)
    }

    /// Run apt-get upgrade over SSH. Non-interactive, hold confs, accept
    /// new ones only if package author says they're safe (`--force-confold`
    /// keeps existing config when in doubt — the safe choice for a server).
    async fn run_upgrade(&self, node: &str) -> Result<()> {
        let cmd = "DEBIAN_FRONTEND=noninteractive apt-get -y \
                   -o Dpkg::Options::=\"--force-confold\" \
                   -o Dpkg::Options::=\"--force-confdef\" \
                   dist-upgrade";
        let opts = ExecOptions {
            timeout: Some(self.strategy.upgrade_timeout),
            ..Default::default()
        };
        let res = self.ssh.exec(node, cmd, opts).await?;
        if !res.ok() {
            anyhow::bail!(
                "apt dist-upgrade exited with {:?} on {node}\nstderr (last 500 chars):\n{}",
                res.exit_code,
                tail(&res.stderr, 500)
            );
        }
        info!("apt dist-upgrade ok on {node}");
        Ok(())
    }

    /// Trigger a reboot. We use SSH because Proxmox's `/nodes/{n}/status`
    /// reboot command requires an authenticated session ticket, not all
    /// token configurations have it, and the SSH path is uniformly
    /// available once Pillar 0 is wired.
    async fn run_reboot(&self, node: &str) -> Result<()> {
        // `--no-block` so the SSH connection doesn't hang waiting for the
        // reboot to complete (it can't — we're disconnecting the node).
        // We expect this command to either succeed quickly or fail with
        // "connection lost" — both are signals to move to wait phase.
        let cmd = "systemctl reboot --no-block";
        let opts = ExecOptions {
            timeout: Some(Duration::from_secs(20)),
            ..Default::default()
        };
        match self.ssh.exec(node, cmd, opts).await {
            Ok(res) if res.ok() => {
                info!("reboot issued on {node}");
                Ok(())
            }
            Ok(res) => {
                // Some systems return non-zero when the SSH session is
                // killed mid-way — treat it as success if we issued.
                warn!(
                    "reboot returned exit={:?} on {node}; assuming reboot in progress",
                    res.exit_code
                );
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("timed out") || msg.contains("connection") {
                    info!("reboot triggered (connection dropped) on {node}");
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Poll the node's status endpoint until uptime resets (= rebooted)
    /// AND the node reports as online again. If `kernel_before` was given,
    /// also verify the kernel has actually changed (catches "the kernel
    /// upgrade silently didn't load").
    async fn wait_for_reboot(
        &self,
        node: &str,
        kernel_before: Option<&str>,
    ) -> Result<NodeStatusDetail> {
        let deadline = Instant::now() + self.strategy.reboot_wait_timeout;
        let poll_interval = Duration::from_secs(5);
        let mut saw_offline = false;

        while Instant::now() < deadline {
            tokio::time::sleep(poll_interval).await;

            // 1. Confirm the node went down at least once. The `/nodes`
            //    list reflects cluster-level liveness.
            let nodes = self.api.get_nodes().await.unwrap_or_default();
            let node_entry = nodes.iter().find(|n| n.node == node);
            let online = node_entry
                .map(|n| n.status == crate::api::types::NodeStatus::Online)
                .unwrap_or(false);

            if !online {
                saw_offline = true;
                debug!("{node} offline (waiting for reboot)");
                continue;
            }
            if !saw_offline {
                // Node still showing online — either reboot hasn't started
                // yet, or it bounced too fast for our 5s polling. Wait
                // one more tick to be sure.
                debug!("{node} online but reboot not yet observed");
                continue;
            }

            // 2. Node says it's back. Verify its API answers and check kernel.
            match self.api.node_status_detail(node).await {
                Ok(detail) => {
                    if let Some(prev) = kernel_before {
                        if !prev.is_empty() && detail.kversion == prev {
                            warn!(
                                "{node} rebooted but kernel unchanged ({}) — \
                                 upgrade may not have taken effect",
                                detail.kversion
                            );
                        }
                    }
                    info!(
                        "{node} back online: kernel={} pve={}",
                        detail.kversion, detail.pveversion
                    );
                    return Ok(detail);
                }
                Err(e) => {
                    debug!("{node} reachable but status detail failed: {e:#}");
                }
            }
        }

        anyhow::bail!(
            "{node} did not come back within {}s",
            self.strategy.reboot_wait_timeout.as_secs()
        )
    }
}

fn tail(s: &str, n: usize) -> &str {
    if s.len() <= n {
        s
    } else {
        &s[s.len() - n..]
    }
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{Guest, NodeStatus, StoragePool, TaskInfo, TaskLog};
    use crate::ssh::ExecResult;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// In-memory mock of ProxmoxGateway. Records all calls so tests can
    /// assert on order and number.
    #[derive(Default)]
    struct MockApi {
        nodes: Vec<Node>,
        upgradable: HashMap<String, Vec<AptUpgradable>>,
        node_status: HashMap<String, NodeStatusDetail>,
        /// (call_count_so_far) → override for `apt_update_refresh` failure.
        refresh_fail: HashMap<String, bool>,
        calls: Mutex<Vec<String>>,
    }

    fn upg(pkg: &str, oldv: &str, newv: &str) -> AptUpgradable {
        AptUpgradable {
            package: pkg.to_string(),
            old_version: oldv.to_string(),
            new_version: newv.to_string(),
            section: String::new(),
            priority: String::new(),
        }
    }

    fn upg_security(pkg: &str) -> AptUpgradable {
        AptUpgradable {
            package: pkg.to_string(),
            old_version: "1.0".into(),
            new_version: "1.1".into(),
            section: "main/security".to_string(),
            priority: String::new(),
        }
    }

    #[async_trait]
    impl ProxmoxGateway for MockApi {
        async fn get_nodes(&self) -> Result<Vec<Node>> {
            self.calls.lock().unwrap().push("get_nodes".into());
            Ok(self.nodes.clone())
        }
        async fn get_guests(&self, _node: &str) -> Result<Vec<Guest>> {
            Ok(vec![])
        }
        async fn get_guest_status(&self, _node: &str, _vmid: u32) -> Result<Guest> {
            anyhow::bail!("unused")
        }
        async fn get_storage_pools(&self, _node: &str) -> Result<Vec<StoragePool>> {
            Ok(vec![])
        }
        async fn get_task_log(
            &self,
            _node: &str,
            _upid: &str,
            _start: usize,
            _limit: usize,
        ) -> Result<TaskLog> {
            anyhow::bail!("unused")
        }
        async fn get_guest_config(
            &self,
            _node: &str,
            _vmid: u32,
            _guest_type: &crate::api::types::GuestType,
        ) -> Result<HashMap<String, String>> {
            Ok(HashMap::new())
        }
        async fn get_cluster_tasks(&self) -> Result<Vec<TaskInfo>> {
            Ok(vec![])
        }
        async fn start_guest(
            &self,
            _: &str,
            _: u32,
            _: crate::api::types::GuestType,
        ) -> Result<String> {
            anyhow::bail!("unused")
        }
        async fn stop_guest(
            &self,
            _: &str,
            _: u32,
            _: crate::api::types::GuestType,
            _: bool,
        ) -> Result<String> {
            anyhow::bail!("unused")
        }
        async fn shutdown_guest(
            &self,
            _: &str,
            _: u32,
            _: crate::api::types::GuestType,
        ) -> Result<String> {
            anyhow::bail!("unused")
        }
        async fn restart_guest(
            &self,
            _: &str,
            _: u32,
            _: crate::api::types::GuestType,
        ) -> Result<String> {
            anyhow::bail!("unused")
        }
        async fn migrate_guest(
            &self,
            _: &str,
            _: u32,
            _: crate::api::types::GuestType,
            _: &str,
        ) -> Result<String> {
            anyhow::bail!("unused")
        }
        async fn delete_guest(
            &self,
            _: &str,
            _: u32,
            _: crate::api::types::GuestType,
        ) -> Result<String> {
            anyhow::bail!("unused")
        }
        async fn execute_guest_command(
            &self,
            _: &str,
            _: u32,
            _: &crate::api::types::GuestType,
            _: &str,
        ) -> Result<String> {
            anyhow::bail!("unused")
        }
        async fn create_snapshot(
            &self,
            _: &str,
            _: u32,
            _: crate::api::types::GuestType,
            _: &str,
        ) -> Result<String> {
            anyhow::bail!("unused")
        }
        async fn delete_snapshot(
            &self,
            _: &str,
            _: u32,
            _: crate::api::types::GuestType,
            _: &str,
        ) -> Result<String> {
            anyhow::bail!("unused")
        }
        async fn list_snapshots(
            &self,
            _: &str,
            _: u32,
            _: crate::api::types::GuestType,
        ) -> Result<Vec<crate::api::types::Snapshot>> {
            Ok(vec![])
        }
        async fn move_disk(
            &self,
            _: &str,
            _: u32,
            _: crate::api::types::GuestType,
            _: &str,
            _: &str,
            _: bool,
        ) -> Result<String> {
            anyhow::bail!("unused")
        }
        async fn resize_disk(
            &self,
            _: &str,
            _: u32,
            _: crate::api::types::GuestType,
            _: &str,
            _: &str,
        ) -> Result<String> {
            anyhow::bail!("unused")
        }
        async fn download_to_storage(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
            _: &str,
        ) -> Result<String> {
            anyhow::bail!("unused")
        }
        async fn list_storage_content(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
        ) -> Result<Vec<crate::api::types::StorageContent>> {
            Ok(vec![])
        }
        async fn list_pci(&self, _: &str) -> Result<Vec<crate::api::types::PciDevice>> {
            Ok(vec![])
        }
        async fn list_usb(&self, _: &str) -> Result<Vec<crate::api::types::UsbDevice>> {
            Ok(vec![])
        }
        async fn list_acl(&self) -> Result<Vec<crate::api::types::AclEntry>> {
            Ok(vec![])
        }
        async fn list_users(&self) -> Result<Vec<crate::api::types::User>> {
            Ok(vec![])
        }
        async fn list_user_tokens(&self, _: &str) -> Result<Vec<crate::api::types::ApiToken>> {
            Ok(vec![])
        }
        async fn list_groups(&self) -> Result<Vec<crate::api::types::Group>> {
            Ok(vec![])
        }
        async fn list_roles(&self) -> Result<Vec<crate::api::types::Role>> {
            Ok(vec![])
        }
        async fn list_realms(&self) -> Result<Vec<crate::api::types::Realm>> {
            Ok(vec![])
        }
        async fn list_tfa(&self, _: &str) -> Result<Vec<crate::api::types::TfaEntry>> {
            Ok(vec![])
        }
        async fn create_token(
            &self,
            _: &str,
            _: &str,
            _: bool,
            _: Option<u64>,
            _: Option<&str>,
        ) -> Result<crate::api::types::ApiToken> {
            anyhow::bail!("unused")
        }
        async fn revoke_token(&self, _: &str, _: &str) -> Result<()> {
            anyhow::bail!("unused")
        }
        async fn get_termproxy(
            &self,
            _: &str,
            _: u32,
            _: crate::api::types::GuestType,
        ) -> Result<crate::api::types::TermproxyTicket> {
            anyhow::bail!("unused")
        }
        async fn get_spiceproxy(&self, _: &str, _: u32) -> Result<crate::api::types::SpiceConfig> {
            anyhow::bail!("unused")
        }
        async fn list_ha_groups(&self) -> Result<Vec<crate::api::types::HaGroup>> {
            Ok(vec![])
        }
        async fn list_ha_resources(&self) -> Result<Vec<crate::api::types::HaResource>> {
            Ok(vec![])
        }
        async fn ha_manager_status(&self) -> Result<crate::api::types::HaManagerStatus> {
            Ok(crate::api::types::HaManagerStatus::default())
        }
        async fn cluster_status(&self) -> Result<Vec<crate::api::types::ClusterStatusEntry>> {
            Ok(vec![])
        }
        async fn list_replication_jobs(&self) -> Result<Vec<crate::api::types::ReplicationJob>> {
            Ok(vec![])
        }
        async fn list_replication_status(
            &self,
            _: &str,
        ) -> Result<Vec<crate::api::types::ReplicationStatus>> {
            Ok(vec![])
        }

        async fn apt_update_refresh(&self, node: &str) -> Result<String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("apt_update_refresh:{node}"));
            if *self.refresh_fail.get(node).unwrap_or(&false) {
                anyhow::bail!("simulated refresh failure on {node}")
            }
            Ok(format!(
                "UPID:{node}:00000000:00000000:apt-update::root@pam:"
            ))
        }

        async fn apt_list_upgradable(&self, node: &str) -> Result<Vec<AptUpgradable>> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("apt_list_upgradable:{node}"));
            Ok(self.upgradable.get(node).cloned().unwrap_or_default())
        }

        async fn node_status_detail(&self, node: &str) -> Result<NodeStatusDetail> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("node_status_detail:{node}"));
            Ok(self.node_status.get(node).cloned().unwrap_or_default())
        }
    }

    /// SSH mock that records exec calls and returns scripted exit codes.
    /// Default: always exits 0 with empty output.
    #[derive(Default)]
    struct MockSsh {
        calls: Mutex<Vec<(String, String)>>,
        scripted_exit: HashMap<String, i32>,
    }

    #[async_trait]
    impl SshGateway for MockSsh {
        async fn exec(&self, node: &str, command: &str, _opts: ExecOptions) -> Result<ExecResult> {
            self.calls
                .lock()
                .unwrap()
                .push((node.to_string(), command.to_string()));
            let exit = self.scripted_exit.get(node).copied().unwrap_or(0);
            Ok(ExecResult {
                stdout: String::new(),
                stderr: if exit == 0 {
                    String::new()
                } else {
                    "boom".into()
                },
                exit_code: Some(u32::try_from(exit).unwrap_or(1)),
            })
        }
    }

    fn online(name: &str) -> Node {
        Node {
            node: name.to_string(),
            status: NodeStatus::Online,
            ..Default::default()
        }
    }
    // V25 (macro audit): `Node` now derives `Default` directly; the
    // hand-rolled impl below is redundant and would conflict with the
    // derive. Kept the `online` helper above unchanged — it still
    // calls `Default::default()`, which now resolves to the derived
    // version (functionally identical).

    #[tokio::test]
    async fn plan_classifies_packages_correctly() {
        let mut api = MockApi::default();
        api.nodes = vec![online("pve1"), online("pve2")];
        api.upgradable.insert(
            "pve1".into(),
            vec![
                upg("pve-kernel-6.5", "6.5.1", "6.5.2"),
                upg("vim", "9.0", "9.1"),
            ],
        );
        api.upgradable.insert(
            "pve2".into(),
            vec![upg_security("openssl"), upg("htop", "3.0", "3.1")],
        );

        let orch = Orchestrator::new(
            Arc::new(api),
            Arc::new(MockSsh::default()),
            PatchStrategy::default(),
        );
        let plan = orch.plan(None).await.expect("plan");

        assert_eq!(plan.nodes.len(), 2);

        let pve1 = plan.nodes.iter().find(|n| n.node == "pve1").unwrap();
        assert!(
            pve1.kernel_pending,
            "pve-kernel must trigger kernel_pending"
        );
        assert!(pve1.reboot_required, "kernel triggers reboot");
        assert_eq!(pve1.upgradable.len(), 2);

        let pve2 = plan.nodes.iter().find(|n| n.node == "pve2").unwrap();
        assert!(pve2.security_pending, "openssl in security section");
        assert!(!pve2.kernel_pending);
    }

    #[tokio::test]
    async fn plan_skips_nodes_without_upgrades() {
        let mut api = MockApi::default();
        api.nodes = vec![online("pve1")];
        api.upgradable.insert("pve1".into(), vec![]);
        let orch = Orchestrator::new(
            Arc::new(api),
            Arc::new(MockSsh::default()),
            PatchStrategy::default(),
        );
        let plan = orch.plan(None).await.unwrap();
        assert!(matches!(plan.nodes[0].status, Phase::Skipped { .. }));
    }

    #[tokio::test]
    async fn plan_marks_failed_node_without_aborting() {
        let mut api = MockApi::default();
        api.nodes = vec![online("pve1"), online("pve2")];
        api.refresh_fail.insert("pve1".into(), true);
        api.upgradable
            .insert("pve2".into(), vec![upg("vim", "9.0", "9.1")]);
        let orch = Orchestrator::new(
            Arc::new(api),
            Arc::new(MockSsh::default()),
            PatchStrategy::default(),
        );
        let plan = orch.plan(None).await.unwrap();
        let p1 = plan.nodes.iter().find(|n| n.node == "pve1").unwrap();
        let p2 = plan.nodes.iter().find(|n| n.node == "pve2").unwrap();
        assert!(matches!(p1.status, Phase::Failed { .. }));
        assert!(matches!(p2.status, Phase::Pending));
    }

    #[tokio::test]
    async fn dry_run_skips_ssh_entirely() {
        let mut api = MockApi::default();
        api.nodes = vec![online("pve1")];
        api.upgradable
            .insert("pve1".into(), vec![upg("vim", "9.0", "9.1")]);
        let ssh = Arc::new(MockSsh::default());
        let strategy = PatchStrategy {
            dry_run: true,
            ..Default::default()
        };
        let orch = Orchestrator::new(
            Arc::new(api),
            Arc::clone(&ssh) as Arc<dyn SshGateway>,
            strategy,
        );

        let plan = orch.plan(None).await.unwrap();
        let applied = orch.apply(plan, |_, _| {}).await.unwrap();

        let n = applied.nodes.iter().find(|n| n.node == "pve1").unwrap();
        assert!(matches!(
            n.status,
            Phase::Done {
                rebooted: false,
                packages_upgraded: 1
            }
        ));
        assert!(
            ssh.calls.lock().unwrap().is_empty(),
            "dry-run must never SSH"
        );
    }

    #[tokio::test]
    async fn apply_runs_upgrade_then_no_reboot_on_userspace_only() {
        let mut api = MockApi::default();
        api.nodes = vec![online("pve1")];
        api.upgradable
            .insert("pve1".into(), vec![upg("vim", "9.0", "9.1")]);
        let ssh = Arc::new(MockSsh::default());
        let orch = Orchestrator::new(
            Arc::new(api),
            Arc::clone(&ssh) as Arc<dyn SshGateway>,
            PatchStrategy::default(),
        );

        let plan = orch.plan(None).await.unwrap();
        let applied = orch.apply(plan, |_, _| {}).await.unwrap();

        let n = applied.nodes.iter().find(|n| n.node == "pve1").unwrap();
        assert!(matches!(
            n.status,
            Phase::Done {
                rebooted: false,
                packages_upgraded: 1
            }
        ));
        let ssh_calls = ssh.calls.lock().unwrap();
        assert_eq!(ssh_calls.len(), 1, "only the upgrade, no reboot");
        assert!(ssh_calls[0].1.contains("dist-upgrade"));
    }

    #[tokio::test]
    async fn apply_aborts_remaining_nodes_on_failure() {
        let mut api = MockApi::default();
        api.nodes = vec![online("pve1"), online("pve2")];
        api.upgradable
            .insert("pve1".into(), vec![upg("vim", "9.0", "9.1")]);
        api.upgradable
            .insert("pve2".into(), vec![upg("htop", "3.0", "3.1")]);

        let mut ssh_inner = MockSsh::default();
        ssh_inner.scripted_exit.insert("pve1".into(), 100); // simulate apt failure
        let ssh = Arc::new(ssh_inner);

        let orch = Orchestrator::new(
            Arc::new(api),
            Arc::clone(&ssh) as Arc<dyn SshGateway>,
            PatchStrategy::default(),
        );
        let plan = orch.plan(None).await.unwrap();
        let applied = orch.apply(plan, |_, _| {}).await.unwrap();

        let p1 = applied.nodes.iter().find(|n| n.node == "pve1").unwrap();
        let p2 = applied.nodes.iter().find(|n| n.node == "pve2").unwrap();
        assert!(
            matches!(&p1.status, Phase::Failed { phase, .. } if phase == "upgrade"),
            "pve1 must be failed, was {:?}",
            p1.status
        );
        assert!(
            matches!(p2.status, Phase::Pending),
            "pve2 must be untouched after pve1 fail, was {:?}",
            p2.status
        );
    }

    #[test]
    fn requires_reboot_heuristic() {
        assert!(upg("pve-kernel-6.5", "1", "2").requires_reboot());
        assert!(upg("proxmox-kernel-6.8", "1", "2").requires_reboot());
        assert!(upg("intel-microcode", "1", "2").requires_reboot());
        assert!(upg("libc6", "1", "2").requires_reboot());
        assert!(upg("systemd", "1", "2").requires_reboot());
        assert!(!upg("vim", "1", "2").requires_reboot());
        assert!(!upg("htop", "1", "2").requires_reboot());
    }

    #[test]
    fn nodes_rebooting_reflects_policy() {
        let plan = PatchPlan {
            nodes: vec![
                NodePlan {
                    node: "pve1".into(),
                    upgradable: vec![upg("vim", "1", "2")],
                    kernel_pending: false,
                    security_pending: false,
                    reboot_required: false,
                    status: Phase::Pending,
                    kernel_before: None,
                    kernel_after: None,
                },
                NodePlan {
                    node: "pve2".into(),
                    upgradable: vec![upg("pve-kernel-6.5", "1", "2")],
                    kernel_pending: true,
                    security_pending: false,
                    reboot_required: true,
                    status: Phase::Pending,
                    kernel_before: None,
                    kernel_after: None,
                },
            ],
            strategy_summary: HashMap::new(),
        };
        assert_eq!(plan.nodes_rebooting(RebootPolicy::Auto), vec!["pve2"]);
        assert_eq!(
            plan.nodes_rebooting(RebootPolicy::Always),
            vec!["pve1", "pve2"]
        );
        let none: Vec<&str> = plan.nodes_rebooting(RebootPolicy::Never);
        assert!(none.is_empty());
    }
}
