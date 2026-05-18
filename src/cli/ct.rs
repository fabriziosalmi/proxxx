//! LXC container hardware/options CLI domain.

use anyhow::Result;
use clap::Subcommand;
use serde_json::Value;
use std::sync::Arc;

use crate::cli::common::{
    classify_pending, find_guest, parse_kv_pairs, require_non_empty_params, wait_and_classify,
};

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
    /// Create a new LXC container from an OS template. Returns the UPID.
    Create {
        /// Target node name
        #[arg(long)]
        node: String,
        /// VMID (auto-assigned from cluster if omitted)
        #[arg(long)]
        vmid: Option<u32>,
        /// Container hostname
        #[arg(long)]
        hostname: Option<String>,
        /// OS template volid (e.g. `local:vztmpl/debian-12-standard_12.0-1_amd64.tar.zst`)
        #[arg(long, required = true)]
        template: String,
        /// Memory in MiB
        #[arg(long, default_value_t = 512)]
        memory: u64,
        /// CPU cores
        #[arg(long, default_value_t = 1)]
        cores: u32,
        /// Root filesystem spec — `storage:sizeG`
        #[arg(long, default_value = "local-lvm:8")]
        rootfs: String,
        /// Network bridge
        #[arg(long, default_value = "vmbr0")]
        bridge: String,
        /// Root password (set in container)
        #[arg(long)]
        password: Option<String>,
        /// Wait for creation task to complete before returning
        #[arg(long)]
        wait: bool,
    },
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
        CtCommand::Create {
            node,
            vmid,
            hostname,
            template,
            memory,
            cores,
            rootfs,
            bridge,
            password,
            wait,
        } => {
            let vmid = match vmid {
                Some(v) => v,
                None => client.get_next_vmid().await?,
            };
            let mut params: Vec<(String, String)> = vec![
                ("vmid".into(), vmid.to_string()),
                ("ostemplate".into(), template.clone()),
                ("memory".into(), memory.to_string()),
                ("cores".into(), cores.to_string()),
                ("rootfs".into(), rootfs.clone()),
                ("net0".into(), format!("name=eth0,bridge={bridge},ip=dhcp")),
            ];
            if let Some(h) = &hostname {
                params.push(("hostname".into(), h.clone()));
            }
            if let Some(p) = &password {
                params.push(("password".into(), p.clone()));
            }
            let as_refs: Vec<(&str, &str)> = params
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let upid = client.create_lxc(&node, &as_refs).await?;
            if wait && !upid.is_empty() {
                wait_and_classify(client, &node, &upid).await
            } else {
                Ok((
                    serde_json::json!({"vmid": vmid, "upid": upid, "node": node}),
                    0,
                ))
            }
        }
    }
}
