//! LXC container hardware/options CLI domain.

use anyhow::Result;
use clap::Subcommand;
use serde_json::Value;
use std::sync::Arc;

use crate::cli::common::{classify_pending, find_guest, parse_kv_pairs, require_non_empty_params};

/// LXC `ct` subcommand tree. Smaller than VM — no cloud-init.
#[derive(Debug, Subcommand)]
pub enum CtCommand {
    /// Update container hardware/options.
    Set {
        /// Container VMID
        vmid: u32,
        /// CPU cores
        #[arg(long)]
        cores: Option<u32>,
        /// Memory in MiB
        #[arg(long)]
        memory: Option<u64>,
        /// Swap in MiB
        #[arg(long)]
        swap: Option<u64>,
        /// Container hostname
        #[arg(long)]
        hostname: Option<String>,
        /// Description
        #[arg(long)]
        description: Option<String>,
    },
    /// Bypass typed flags and submit raw `key=value` pairs.
    #[command(name = "raw-set")]
    RawSet {
        /// Container VMID
        vmid: u32,
        /// `key=value` pairs (one per positional arg)
        #[arg(required = true)]
        kvs: Vec<String>,
    },
    /// Container network interfaces (PVE shells to `lxc-info` /
    /// `ip addr` in the container's netns). LXC equivalent of QEMU's
    /// QGA `network-get-interfaces` — works without an agent in
    /// the container.
    Interfaces { vmid: u32 },
}

pub async fn execute(
    client: &Arc<crate::api::PxClient>,
    action: CtCommand,
) -> Result<(Value, i32)> {
    use crate::api::types::GuestType;
    use crate::api::ProxmoxGateway;
    match action {
        CtCommand::Set {
            vmid,
            cores,
            memory,
            swap,
            hostname,
            description,
        } => {
            // Build params first, fail fast on empty before the cluster scan.
            let mut params: Vec<(String, String)> = Vec::new();
            if let Some(v) = cores {
                params.push(("cores".into(), v.to_string()));
            }
            if let Some(v) = memory {
                params.push(("memory".into(), v.to_string()));
            }
            if let Some(v) = swap {
                params.push(("swap".into(), v.to_string()));
            }
            if let Some(v) = hostname {
                params.push(("hostname".into(), v));
            }
            if let Some(v) = description {
                params.push(("description".into(), v));
            }
            require_non_empty_params(&params)?;
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Lxc) {
                anyhow::bail!("VMID {vmid} is a QEMU VM — use `proxxx vm set` instead");
            }
            let task = client.update_guest_config(&node, vmid, gt, &params).await?;
            let requested: Vec<String> = params.iter().map(|(k, _)| k.clone()).collect();
            let (applied_now, pending_reboot, classify_warn) =
                classify_pending(client, &node, vmid, gt, &requested).await;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "node": node,
                    "requested": requested,
                    "applied_immediately": applied_now,
                    "pending_reboot": pending_reboot,
                    "classify_warning": classify_warn,
                    "task": task,
                }),
                0,
            ))
        }
        CtCommand::RawSet { vmid, kvs } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Lxc) {
                anyhow::bail!("VMID {vmid} is a QEMU VM — use `proxxx vm raw-set` instead");
            }
            let params = parse_kv_pairs(&kvs)?;
            let task = client.update_guest_config(&node, vmid, gt, &params).await?;
            let requested: Vec<String> = params.iter().map(|(k, _)| k.clone()).collect();
            let (applied_now, pending_reboot, classify_warn) =
                classify_pending(client, &node, vmid, gt, &requested).await;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "node": node,
                    "requested": requested,
                    "applied_immediately": applied_now,
                    "pending_reboot": pending_reboot,
                    "classify_warning": classify_warn,
                    "raw": true,
                    "task": task,
                }),
                0,
            ))
        }
        CtCommand::Interfaces { vmid } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Lxc) {
                anyhow::bail!("interfaces is LXC-only — vmid {vmid} is a QEMU VM (use `proxxx qga {vmid} net` instead)");
            }
            let ifaces = client.list_lxc_interfaces(&node, vmid).await?;
            Ok((
                serde_json::json!({"vmid": vmid, "node": node, "interfaces": ifaces}),
                0,
            ))
        }
    }
}
