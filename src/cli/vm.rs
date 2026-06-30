//! QEMU VM-specific surface: config CRUD (typed + raw-set), cloud-init
//! lifecycle, snapshots, live disk move/resize (pre-flight gated), and
//! QEMU Guest Agent file ops + network introspection.

use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Deserialize;
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;

use crate::cli::common::{
    classify_pending, enforce_preflight, find_guest, find_guest_full, parse_kv_pairs,
    require_non_empty_params, wait_and_classify,
};

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}/{}", home.to_string_lossy(), rest);
        }
    }
    path.to_owned()
}

/// TOML profile for cloud-init customization at clone time. Every
/// field is optional — the user file pulls in just the keys they
/// want to override. `sshkey_file` is a convenience: read a public
/// key from disk so callers don't have to inline a multi-line key.
#[derive(Debug, Default, Deserialize)]
pub struct CloudInitProfile {
    pub ciuser: Option<String>,
    pub cipassword: Option<String>,
    pub sshkey: Option<String>,
    pub sshkey_file: Option<String>,
    pub ipconfig0: Option<String>,
    pub searchdomain: Option<String>,
    pub nameserver: Option<String>,
}

impl CloudInitProfile {
    pub fn from_toml_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read cloud-init profile {}", path.display()))?;
        let mut p: Self = toml::from_str(&raw)
            .with_context(|| format!("parse cloud-init profile {}", path.display()))?;
        if let Some(kf) = &p.sshkey_file {
            let kp = expand_tilde(kf);
            let key =
                std::fs::read_to_string(&kp).with_context(|| format!("read sshkey_file {kp}"))?;
            let key = key.trim().to_string();
            if p.sshkey.is_some() {
                anyhow::bail!("cloud-init profile: set either `sshkey` or `sshkey_file`, not both");
            }
            p.sshkey = Some(key);
        }
        Ok(p)
    }

    pub fn to_params(&self) -> Result<Vec<(String, String)>> {
        let mut params: Vec<(String, String)> = Vec::new();
        if let Some(v) = &self.ciuser {
            params.push(("ciuser".into(), v.clone()));
        }
        if let Some(v) = &self.cipassword {
            params.push(("cipassword".into(), v.clone()));
        }
        if let Some(v) = &self.sshkey {
            params.push(("sshkeys".into(), v.clone()));
        }
        if let Some(v) = &self.ipconfig0 {
            use std::str::FromStr;
            let parsed = crate::api::types::Ipconfig::from_str(v)?;
            params.push(("ipconfig0".into(), parsed.to_string()));
        }
        if let Some(v) = &self.searchdomain {
            params.push(("searchdomain".into(), v.clone()));
        }
        if let Some(v) = &self.nameserver {
            params.push(("nameserver".into(), v.clone()));
        }
        Ok(params)
    }
}

/// Apply a `CloudInitProfile` to a QEMU guest and regenerate the
/// cloud-init drive. No-op on empty profile (returns
/// `applied=false`). LXC is rejected — cloud-init is QEMU-only.
pub async fn apply_cloudinit_and_regen(
    client: &crate::api::PxClient,
    node: &str,
    vmid: u32,
    gt: crate::api::types::GuestType,
    profile: &CloudInitProfile,
) -> Result<Value> {
    use crate::api::types::GuestType;
    use crate::api::ProxmoxGateway;
    if !matches!(gt, GuestType::Qemu) {
        anyhow::bail!("cloud-init is QEMU-only — VMID {vmid} is an LXC container");
    }
    let params = profile.to_params()?;
    if params.is_empty() {
        return Ok(serde_json::json!({ "applied": false }));
    }
    let task_set = client.update_guest_config(node, vmid, gt, &params).await?;
    let task_regen = client.regenerate_cloudinit(node, vmid).await?;
    let keys: Vec<String> = params.iter().map(|(k, _)| k.clone()).collect();
    Ok(serde_json::json!({
        "applied": true,
        "keys": keys,
        "config_task": task_set,
        "regen_task": task_regen,
    }))
}

/// QEMU `vm` subcommand tree. Three branches:
///   - `set` — type-checked top-level config keys (cores, memory, …)
///   - `raw-set` — generic key=value escape hatch
///   - `cloudinit` — cloud-init lifecycle (set + regen)
#[derive(Debug, Subcommand)]
pub enum VmCommand {
    /// Update VM hardware/options. Each flag maps to one PVE config
    /// key; only flags actually passed are sent (no accidental
    /// "reset to default" if you pass `--cores 4` without
    /// `--memory`). For obscure keys, use `proxxx vm raw-set`.
    Set {
        /// Guest VMID
        vmid: u32,
        /// Number of CPU cores (sockets × cores = total vCPUs)
        #[arg(long)]
        cores: Option<u32>,
        /// CPU sockets (defaults to 1 in PVE)
        #[arg(long)]
        sockets: Option<u32>,
        /// Memory in MiB (e.g. `8192` for 8 GiB)
        #[arg(long)]
        memory: Option<u64>,
        /// Balloon target in MiB. Set ≤ `memory` for memory ballooning.
        /// `0` disables ballooning entirely.
        #[arg(long)]
        balloon: Option<u64>,
        /// CPU model (e.g. `host`, `kvm64`, `x86-64-v2-AES`)
        #[arg(long)]
        cpu: Option<String>,
        /// VM display name
        #[arg(long)]
        name: Option<String>,
        /// VM description (markdown supported in PVE web UI)
        #[arg(long)]
        description: Option<String>,
        /// Guest OS type (e.g. `l26` Linux 2.6+, `win11`, `other`)
        #[arg(long)]
        ostype: Option<String>,
    },
    /// Bypass typed flags and submit raw `key=value` pairs straight
    /// to PVE. Use for niche options not covered by `vm set`.
    /// Caller owns correctness — PVE will return a 400 schema error
    /// if a key is misspelled.
    #[command(name = "raw-set")]
    RawSet {
        /// Guest VMID
        vmid: u32,
        /// `key=value` pairs (one per positional arg)
        #[arg(required = true)]
        kvs: Vec<String>,
    },
    /// Cloud-init lifecycle for QEMU VMs.
    Cloudinit {
        #[command(subcommand)]
        action: CloudinitCommand,
    },
    /// Send a key sequence to a QEMU VM via QMP. Common uses: NMI/sysrq
    /// for kernel debugging (`sysrq` then send `t` for task list,
    /// `s` for sync, `c` for crash). `key` syntax follows QMP:
    /// `ctrl-alt-delete`, `sysrq`, single chars, raw scancodes
    /// (`0x42`).
    Sendkey {
        vmid: u32,
        /// Key sequence (e.g. `ctrl-alt-delete`, `sysrq`).
        #[arg(long)]
        key: String,
    },
    /// Detach a disk from a VM's config. Default leaves the underlying
    /// volume — operator can move/reattach later. `--force` ALSO
    /// deletes the volume (destructive — pair with `--yes`).
    Unlink {
        vmid: u32,
        /// CSV of disk ids to detach (e.g. `scsi1,scsi2`).
        #[arg(long)]
        idlist: String,
        /// Also delete the underlying volume(s). Destructive.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Required when `--force` is set.
        #[arg(long)]
        yes: bool,
    },
    /// Dump the cloud-init data PVE will serve to the guest on next
    /// boot. Useful for debugging template inheritance / verifying
    /// `qm set --cipassword/--ciuser/--ipconfig0` actually landed.
    /// `kind` selects which section: `user` | `network` | `meta`.
    CloudinitDump {
        vmid: u32,
        /// `user` (default) | `network` | `meta`.
        #[arg(long, default_value = "user")]
        kind: String,
    },
    /// Create a new QEMU VM from scratch. Returns the UPID — track via
    /// `proxxx tasks`. For cloning from a template, use `proxxx clone`.
    Create {
        /// Target node name
        #[arg(long)]
        node: String,
        /// VMID (auto-assigned from cluster if omitted)
        #[arg(long)]
        vmid: Option<u32>,
        /// VM display name
        #[arg(long)]
        name: Option<String>,
        /// Memory in MiB
        #[arg(long, default_value_t = 1024)]
        memory: u64,
        /// CPU cores
        #[arg(long, default_value_t = 1)]
        cores: u32,
        /// Boot disk — `storage:sizeG` (e.g. `local-lvm:32`).
        /// Omit for diskless (e.g. net-boot).
        #[arg(long)]
        disk: Option<String>,
        /// ISO image volid for CD-ROM (e.g. `local:iso/ubuntu-24.04.iso`)
        #[arg(long)]
        iso: Option<String>,
        /// Guest OS type (l26, win11, other, …)
        #[arg(long, default_value = "l26")]
        ostype: String,
        /// Network bridge
        #[arg(long, default_value = "vmbr0")]
        bridge: String,
        /// Wait for creation task to complete before returning
        #[arg(long)]
        wait: bool,
    },
}

/// Cloud-init operations. After `set`, run `regen` to rebuild the
/// cloud-init drive — without it, the next boot reads stale data.
#[derive(Debug, Subcommand)]
pub enum CloudinitCommand {
    /// Set cloud-init parameters. Remember to run `proxxx vm
    /// cloudinit regen <vmid>` after — without that step the
    /// next boot reads the previous image.
    Set {
        /// Guest VMID
        vmid: u32,
        /// Cloud-init user (default account name)
        #[arg(long)]
        ciuser: Option<String>,
        /// Cloud-init password (sensitive — prefer SSH keys)
        #[arg(long)]
        cipassword: Option<String>,
        /// SSH public keys (concatenate multiple with `\n`)
        #[arg(long)]
        sshkey: Option<String>,
        /// First-NIC IP config (e.g. `ip=10.0.0.5/24,gw=10.0.0.1`
        /// or `ip=dhcp`)
        #[arg(long)]
        ipconfig0: Option<String>,
        /// DNS search domain
        #[arg(long)]
        searchdomain: Option<String>,
        /// DNS resolver IP
        #[arg(long)]
        nameserver: Option<String>,
    },
    /// Regenerate the cloud-init drive. Required after any `set`.
    Regen {
        /// Guest VMID
        vmid: u32,
    },
}

/// QGA file ops + network introspection. Three commands, one per
/// underlying agent endpoint. `read` and `write` are file ops bounded
/// by QGA's buffer (~16 KiB by default — `read` surfaces a
/// `truncated` flag); `net` returns the per-interface IP table the
/// guest's kernel currently believes.
#[derive(Debug, Subcommand)]
pub enum QgaCommand {
    /// Read a file from inside the guest. Bounded by QGA's read buffer
    /// (~16 KiB default) — operator gets a warning when truncated.
    Read {
        /// Absolute path inside the guest, e.g. `/etc/hostname`.
        #[arg(long)]
        file: String,
    },
    /// Write content to a file inside the guest. PVE base64-encodes
    /// the content before passing to QGA, so plain text is fine.
    Write {
        #[arg(long)]
        file: String,
        /// File content (literal). Use shell quoting for newlines etc.
        #[arg(long)]
        content: String,
    },
    /// Ask the guest's kernel for current network interfaces (names,
    /// MACs, live IPs). Authoritative — beats reading cloud-init.
    Net,
}

#[derive(Debug, Subcommand)]
pub enum DiskCommand {
    /// Move a disk to a different storage backend.
    Move {
        /// Guest VMID
        vmid: u32,
        /// Disk identifier (e.g. `scsi0` for QEMU, `rootfs` or `mp0` for LXC)
        #[arg(long)]
        disk: String,
        /// Target storage name (e.g. `ceph-rbd`, `local-lvm`)
        #[arg(long)]
        storage: String,
        /// Remove source disk after copy. Default: keep as `unused0:`
        /// (avoids storage leak on long-lived workflows; CLI default
        /// errs on the side of preserving user data).
        #[arg(long)]
        delete_source: bool,
        /// Required: confirms this destructive op
        #[arg(long)]
        yes: bool,
        /// Override proxxx pre-flight risk checks (e.g. PVE lock from
        /// concurrent op, HA-managed guest, active traffic).
        #[arg(long)]
        allow_risk: bool,
        /// Block until the move task completes. Without this, returns
        /// the UPID immediately and the caller must poll. With it,
        /// proxxx polls `/tasks/{upid}/status` and exits 0/1 based on
        /// task exitstatus.
        #[arg(long)]
        wait: bool,
    },
    /// Resize a disk. Proxmox forbids shrinking — `size` must be larger.
    Resize {
        /// Guest VMID
        vmid: u32,
        /// Disk identifier
        #[arg(long)]
        disk: String,
        /// New size — Proxmox accepts `+10G` (delta) or `100G` (absolute target)
        #[arg(long)]
        size: String,
        /// Required: confirms this destructive op
        #[arg(long)]
        yes: bool,
        /// Override proxxx pre-flight risk checks.
        #[arg(long)]
        allow_risk: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum SnapshotCommand {
    /// Create a snapshot
    Create {
        vmid: u32,
        #[arg(long)]
        name: String,
    },
    /// Delete a snapshot
    Delete {
        vmid: u32,
        #[arg(long)]
        name: String,
    },
}

pub async fn execute_vm(
    client: &Arc<crate::api::PxClient>,
    action: VmCommand,
) -> Result<(Value, i32)> {
    use crate::api::types::GuestType;
    use crate::api::ProxmoxGateway;
    match action {
        VmCommand::Set {
            vmid,
            cores,
            sockets,
            memory,
            balloon,
            cpu,
            name,
            description,
            ostype,
        } => {
            // Build params BEFORE the network round-trip so empty
            // invocations (`proxxx vm set 100`) fail fast with the
            // right diagnostic, not "Guest not found" after a useless
            // cluster scan.
            let mut params: Vec<(String, String)> = Vec::new();
            if let Some(v) = cores {
                params.push(("cores".into(), v.to_string()));
            }
            if let Some(v) = sockets {
                params.push(("sockets".into(), v.to_string()));
            }
            if let Some(v) = memory {
                params.push(("memory".into(), v.to_string()));
            }
            if let Some(v) = balloon {
                params.push(("balloon".into(), v.to_string()));
            }
            if let Some(v) = cpu {
                params.push(("cpu".into(), v));
            }
            if let Some(v) = name {
                params.push(("name".into(), v));
            }
            if let Some(v) = description {
                params.push(("description".into(), v));
            }
            if let Some(v) = ostype {
                params.push(("ostype".into(), v));
            }
            require_non_empty_params(&params)?;
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Qemu) {
                anyhow::bail!("VMID {vmid} is an LXC container — use `proxxx ct set` instead");
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
        VmCommand::RawSet { vmid, kvs } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Qemu) {
                anyhow::bail!("VMID {vmid} is an LXC container — use `proxxx ct raw-set` instead");
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
        VmCommand::Cloudinit { action } => execute_cloudinit(client, action).await,
        VmCommand::Sendkey { vmid, key } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, crate::api::types::GuestType::Qemu) {
                anyhow::bail!("sendkey is QEMU-only — vmid {vmid} is an LXC");
            }
            client.send_qemu_key(&node, vmid, &key).await?;
            Ok((
                serde_json::json!({"vmid": vmid, "node": node, "key": key, "sent": true}),
                0,
            ))
        }
        VmCommand::Unlink {
            vmid,
            idlist,
            force,
            yes,
        } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, crate::api::types::GuestType::Qemu) {
                anyhow::bail!("unlink is QEMU-only — vmid {vmid} is an LXC");
            }
            if force && !yes {
                anyhow::bail!("--force deletes the underlying volume — pass --yes to confirm");
            }
            client.unlink_qemu_disk(&node, vmid, &idlist, force).await?;
            Ok((
                serde_json::json!({
                    "vmid": vmid, "node": node, "idlist": idlist,
                    "deleted_volume": force,
                }),
                0,
            ))
        }
        VmCommand::CloudinitDump { vmid, kind } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, crate::api::types::GuestType::Qemu) {
                anyhow::bail!("cloudinit-dump is QEMU-only — vmid {vmid} is an LXC");
            }
            let content = client.dump_qemu_cloudinit(&node, vmid, &kind).await?;
            Ok((
                serde_json::json!({
                    "vmid": vmid, "node": node, "kind": kind,
                    "bytes": content.len(), "content": content,
                }),
                0,
            ))
        }
        VmCommand::Create {
            node,
            vmid,
            name,
            memory,
            cores,
            disk,
            iso,
            ostype,
            bridge,
            wait,
        } => {
            let vmid = match vmid {
                Some(v) => v,
                None => client.get_next_vmid().await?,
            };
            let mut params: Vec<(String, String)> = vec![
                ("vmid".into(), vmid.to_string()),
                ("memory".into(), memory.to_string()),
                ("cores".into(), cores.to_string()),
                ("ostype".into(), ostype.clone()),
                ("scsihw".into(), "virtio-scsi-pci".into()),
                ("net0".into(), format!("virtio,bridge={bridge}")),
            ];
            if let Some(n) = &name {
                params.push(("name".into(), n.clone()));
            }
            if let Some(d) = &disk {
                params.push(("scsi0".into(), d.clone()));
            }
            if let Some(i) = &iso {
                params.push(("cdrom".into(), i.clone()));
            }
            let as_refs: Vec<(&str, &str)> = params
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let upid = client.create_qemu(&node, &as_refs).await?;
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

pub async fn execute_cloudinit(
    client: &Arc<crate::api::PxClient>,
    action: CloudinitCommand,
) -> Result<(Value, i32)> {
    use crate::api::types::GuestType;
    use crate::api::ProxmoxGateway;
    match action {
        CloudinitCommand::Set {
            vmid,
            ciuser,
            cipassword,
            sshkey,
            ipconfig0,
            searchdomain,
            nameserver,
        } => {
            // Build params first, fail fast on empty before the cluster scan.
            let mut params: Vec<(String, String)> = Vec::new();
            if let Some(v) = ciuser {
                params.push(("ciuser".into(), v));
            }
            if let Some(v) = cipassword {
                params.push(("cipassword".into(), v));
            }
            if let Some(v) = sshkey {
                // PVE expects URL-encoded SSH keys in `sshkeys`. The
                // raw newline-separated form must survive the form
                // serialization — reqwest handles URL-encoding for
                // form bodies, so we pass the raw key here.
                params.push(("sshkeys".into(), v));
            }
            if let Some(v) = ipconfig0 {
                // Parse-time validation via the typed `Ipconfig`
                // struct — a malformed value like
                //   --ipconfig0 "ip=10.0.0.5,brokenkeynoeq,gw=10.0.0.1"
                // is rejected here with a precise error instead of
                // surviving until PVE returns a generic 400.
                // Round-trip through Display normalises spacing.
                use std::str::FromStr;
                let parsed = crate::api::types::Ipconfig::from_str(&v)?;
                params.push(("ipconfig0".into(), parsed.to_string()));
            }
            if let Some(v) = searchdomain {
                params.push(("searchdomain".into(), v));
            }
            if let Some(v) = nameserver {
                params.push(("nameserver".into(), v));
            }
            require_non_empty_params(&params)?;
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Qemu) {
                anyhow::bail!("cloud-init is QEMU-only — VMID {vmid} is an LXC container");
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
                    "next_step": "run `proxxx vm cloudinit regen <vmid>` to rebuild the cloud-init drive",
                    "task": task,
                }),
                0,
            ))
        }
        CloudinitCommand::Regen { vmid } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Qemu) {
                anyhow::bail!("cloud-init is QEMU-only — VMID {vmid} is an LXC container");
            }
            let task = client.regenerate_cloudinit(&node, vmid).await?;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "node": node,
                    "task": task,
                }),
                0,
            ))
        }
    }
}

pub async fn execute_disk(
    client: &Arc<crate::api::PxClient>,
    action: DiskCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    match action {
        DiskCommand::Move {
            vmid,
            disk,
            storage,
            delete_source,
            yes,
            allow_risk,
            wait,
        } => {
            crate::cli::common::require_yes(yes, "disk move")?;
            // GAP 1 fix: pre-flight read of `lock` (and other risks)
            // catches a concurrent move/clone/backup before we eat a
            // 30-second PVE timeout. The lock check is zero extra
            // I/O — `find_guest_full` already round-trips guest list.
            let g = find_guest_full(client, vmid).await?;
            enforce_preflight(
                client,
                None,
                crate::app::preflight::Op::MoveDisk,
                &g,
                allow_risk,
            )
            .await?;
            let upid = client
                .move_disk(&g.node, vmid, g.guest_type, &disk, &storage, delete_source)
                .await?;
            let envelope = serde_json::json!({
                "vmid": vmid,
                "disk": disk,
                "target_storage": storage,
                "delete_source": delete_source,
                "node": g.node,
                "upid": upid,
                "status": "queued"
            });
            if wait {
                let (status_json, exit) = wait_and_classify(client, &g.node, &upid).await?;
                Ok((
                    serde_json::json!({
                        "request": envelope,
                        "task_status": status_json,
                    }),
                    exit,
                ))
            } else {
                Ok((envelope, 0))
            }
        }
        DiskCommand::Resize {
            vmid,
            disk,
            size,
            yes,
            allow_risk,
        } => {
            crate::cli::common::require_yes(yes, "disk resize")?;
            let g = find_guest_full(client, vmid).await?;
            enforce_preflight(
                client,
                None,
                crate::app::preflight::Op::ResizeDisk,
                &g,
                allow_risk,
            )
            .await?;
            let upid = client
                .resize_disk(&g.node, vmid, g.guest_type, &disk, &size)
                .await?;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "disk": disk,
                    "size": size,
                    "node": g.node,
                    "upid": upid,
                    "status": "queued"
                }),
                0,
            ))
        }
    }
}

/// Bug #3 fix: implement `proxxx snapshot create/delete` (was stub).
pub async fn execute_snapshot(
    client: &Arc<crate::api::PxClient>,
    action: SnapshotCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    let (vmid, name, is_create) = match action {
        SnapshotCommand::Create { vmid, name } => (vmid, name, true),
        SnapshotCommand::Delete { vmid, name } => (vmid, name, false),
    };

    // Locate the guest to get its node + type (bug #1 dispatch).
    let (node, gt) = client
        .find_guest(vmid)
        .await?
        .map(|g| (g.node, g.guest_type))
        .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;

    let upid = if is_create {
        client.create_snapshot(&node, vmid, gt, &name).await?
    } else {
        client.delete_snapshot(&node, vmid, gt, &name).await?
    };

    Ok((
        serde_json::json!({
            "vmid": vmid,
            "snapshot": name,
            "action": if is_create { "create" } else { "delete" },
            "node": node,
            "upid": upid,
            "status": "success"
        }),
        0,
    ))
}

/// QEMU Guest Agent file ops + network introspection. Auto-discovers
/// the VMID's node and guest type, then bails clearly if the guest is
/// LXC (no QGA on the container side). Emits a `truncated` warning on
/// the JSON output when a file read came back partial — operators
/// glancing at the result get a clear signal not to trust the content.
pub async fn execute_qga(
    client: &Arc<crate::api::PxClient>,
    vmid: u32,
    action: QgaCommand,
) -> Result<(Value, i32)> {
    use crate::api::types::GuestType;
    use crate::api::ProxmoxGateway;

    let (node, gt) = find_guest(client, vmid).await?;
    if !matches!(gt, GuestType::Qemu) {
        anyhow::bail!(
            "qga commands require QEMU — vmid {vmid} is an LXC \
             (no guest-agent surface; use `proxxx exec` or SSH instead)"
        );
    }

    match action {
        QgaCommand::Read { file } => {
            let res = client.qemu_agent_file_read(&node, vmid, &file).await?;
            Ok((
                serde_json::json!({
                    "file": file,
                    "content": res.content,
                    "truncated": res.truncated,
                }),
                0,
            ))
        }
        QgaCommand::Write { file, content } => {
            client
                .qemu_agent_file_write(&node, vmid, &file, &content)
                .await?;
            Ok((
                serde_json::json!({"file": file, "bytes": content.len(), "written": true}),
                0,
            ))
        }
        QgaCommand::Net => {
            let ifaces = client
                .qemu_agent_network_get_interfaces(&node, vmid)
                .await?;
            Ok((serde_json::json!({"vmid": vmid, "interfaces": ifaces}), 0))
        }
    }
}
