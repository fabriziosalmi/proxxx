//! Cluster patching orchestrator (apt update / dist-upgrade / reboot).
//!
//! `plan` is API-only — no SSH. `apply` requires `[profiles.X.ssh]`
//! configured because PVE doesn't expose dist-upgrade over its REST API.

use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use serde_json::Value;
use std::sync::Arc;

use crate::cli::common::NoSsh;

#[derive(Debug, Subcommand)]
pub enum PatchCommand {
    /// Show what would be upgraded across the cluster (apt update + list).
    /// No SSH required — pure API.
    Plan {
        /// Restrict to specific node(s). Repeatable.
        #[arg(long)]
        node: Vec<String>,
    },
    /// Execute the patch plan. Requires `[profiles.X.ssh]` configured.
    Apply {
        /// Restrict to specific node(s). Repeatable.
        #[arg(long)]
        node: Vec<String>,
        /// Reboot policy.
        #[arg(long, value_enum, default_value_t = RebootCli::Auto)]
        reboot: RebootCli,
        /// Plan and walk the state machine without running apt or rebooting.
        #[arg(long)]
        dry_run: bool,
        /// Hard timeout for apt upgrade per node (seconds).
        #[arg(long, default_value_t = 1800)]
        upgrade_timeout: u64,
        /// Hard timeout for post-reboot wait per node (seconds).
        #[arg(long, default_value_t = 600)]
        reboot_wait: u64,
    },
    /// Show configured apt repositories on a node (sources.list +
    /// sources.list.d). Helps diagnose "why isn't this update visible
    /// to me" — usually a missing or disabled repo.
    Repositories {
        #[arg(long)]
        node: String,
    },
    /// Plain-text changelog for one installed package on a node.
    /// Useful for "what's actually changed" before running `apply`.
    Changelog {
        #[arg(long)]
        node: String,
        /// Package name, e.g. `proxmox-ve`, `pve-manager`, `linux-image-amd64`.
        #[arg(long)]
        package: String,
    },
    /// List every installed package on a node with version + state.
    /// Useful for kernel/manager-version drift across the cluster
    /// (`proxxx patch versions --node X | jq '.[] | select(.package=="proxmox-ve")'`).
    Versions {
        #[arg(long)]
        node: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RebootCli {
    Auto,
    Always,
    Never,
}

impl From<RebootCli> for crate::app::patch::RebootPolicy {
    fn from(v: RebootCli) -> Self {
        match v {
            RebootCli::Auto => Self::Auto,
            RebootCli::Always => Self::Always,
            RebootCli::Never => Self::Never,
        }
    }
}

pub async fn execute(
    client: Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    action: PatchCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    use crate::app::patch::{Orchestrator, PatchStrategy, Phase};
    use crate::ssh::{SshGateway, SshPool};

    // Clone the Arc so the new Repositories/Changelog/Versions arms
    // (which call methods on `client` after the orchestrator has
    // consumed `api`) keep their reference. Both Arcs point at the
    // same PxClient.
    let api: Arc<dyn ProxmoxGateway> = Arc::clone(&client) as Arc<dyn ProxmoxGateway>;

    match action {
        PatchCommand::Plan { node } => {
            // Plan only needs API. SSH not required at all.
            let strategy = PatchStrategy::default();
            // For plan-only we still need *some* SshGateway since the
            // Orchestrator type takes one — provide a trait object that
            // panics on use. Plan never calls .ssh.exec().
            let ssh: Arc<dyn SshGateway> = Arc::new(NoSsh);
            let orch = Orchestrator::new(api, ssh, strategy);
            let only = if node.is_empty() {
                None
            } else {
                Some(node.as_slice())
            };
            let plan = orch.plan(only).await?;
            Ok((serde_json::to_value(plan)?, 0))
        }
        PatchCommand::Apply {
            node,
            reboot,
            dry_run,
            upgrade_timeout,
            reboot_wait,
        } => {
            let ssh_cfg = config.ssh.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "patch apply requires `[profiles.X.ssh]` configured (key_path, etc.)"
                )
            })?;
            let pool = SshPool::new(ssh_cfg, None)?;
            let ssh: Arc<dyn SshGateway> = Arc::new(pool);

            let strategy = PatchStrategy {
                reboot_policy: reboot.into(),
                dry_run,
                upgrade_timeout: std::time::Duration::from_secs(upgrade_timeout),
                reboot_wait_timeout: std::time::Duration::from_secs(reboot_wait),
                ..Default::default()
            };
            let orch = Orchestrator::new(api, ssh, strategy);
            let only = if node.is_empty() {
                None
            } else {
                Some(node.as_slice())
            };
            let plan = orch.plan(only).await?;
            let progress = |node: &str, phase: &Phase| {
                tracing::info!("patch [{node}] → {phase:?}");
            };
            let applied = orch.apply(plan, progress).await?;

            // Exit non-zero if any node failed
            let exit = i32::from(
                applied
                    .nodes
                    .iter()
                    .any(|n| matches!(n.status, Phase::Failed { .. })),
            );
            Ok((serde_json::to_value(applied)?, exit))
        }
        PatchCommand::Repositories { node } => {
            let repos = client.node_apt_repositories(&node).await?;
            Ok((repos, 0))
        }
        PatchCommand::Changelog { node, package } => {
            let log = client.node_apt_changelog(&node, &package).await?;
            // Plain-text changelog wrapped in a `{"changelog": "..."}`
            // envelope so JSON consumers stay sane (vs returning a
            // bare string which `--format json` would emit unquoted).
            Ok((serde_json::json!({"package": package, "changelog": log}), 0))
        }
        PatchCommand::Versions { node } => {
            let pkgs = client.node_apt_versions(&node).await?;
            Ok((serde_json::to_value(pkgs)?, 0))
        }
    }
}
