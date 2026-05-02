use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use serde_json::Value;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List resources (aliases: get)
    #[command(alias = "get")]
    Ls {
        /// Resource type: nodes, guests, storage
        resource: String,
    },
    /// Start a guest
    Start {
        /// Guest VMID(s)
        vmids: Vec<u32>,
        #[arg(long)]
        strict: bool,
    },
    /// Stop a guest
    Stop {
        /// Guest VMID(s)
        vmids: Vec<u32>,
        /// Force stop without graceful shutdown
        #[arg(long)]
        force: bool,
        #[arg(long)]
        strict: bool,
    },
    /// Restart a guest
    Restart {
        /// Guest VMID(s)
        vmids: Vec<u32>,
        #[arg(long)]
        strict: bool,
    },
    /// Delete a guest (VM or LXC)
    Delete {
        /// Guest VMID(s)
        vmids: Vec<u32>,
        /// Don't prompt; required for non-interactive use
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        strict: bool,
    },
    /// Manage snapshots
    Snapshot {
        #[command(subcommand)]
        action: SnapshotCommand,
    },
    /// MCP server mode
    Mcp {
        #[command(subcommand)]
        action: McpCommand,
    },
    /// Watch for cluster changes or wait for a condition
    Watch {
        /// Watch changes since a given time (e.g. 1h, 30m)
        #[arg(long)]
        since: Option<String>,

        /// Target to watch (e.g., vm-100, task UPID, storage pool)
        #[arg(long, short)]
        target: Option<String>,

        /// Wait until condition is met (e.g. status=running, usage<70%)
        #[arg(long, short)]
        until: Option<String>,

        /// Channel to notify when condition is met (e.g. telegram)
        #[arg(long, short)]
        notify: Option<String>,
    },
    /// Replay the cluster state at a given timestamp
    Replay { timestamp: u64 },
    /// Cluster-wide fuzzy search across nodes, guests, and storage.
    /// Bug #4: was missing — caller would get clap "unknown subcommand".
    Search {
        /// Query string. Matches name, vmid, tags, status.
        query: String,
        /// Limit results (default 20).
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// HITL daemon management
    Hitl {
        #[command(subcommand)]
        action: HitlCommand,
    },
    /// Cluster patching orchestrator (apt update + dist-upgrade + rolling reboot)
    Patch {
        #[command(subcommand)]
        action: PatchCommand,
    },
    /// Live disk operations (move between storage / grow). Destructive —
    /// requires `--yes`. Always routes through Proxmox API directly
    /// (CLI does not enqueue; the queue is a TUI concept).
    Disk {
        #[command(subcommand)]
        action: DiskCommand,
    },
    /// ISO / cloud-image library (curated catalog + server-side download).
    Iso {
        #[command(subcommand)]
        action: IsoCommand,
    },
    /// Proxmox Backup Server: list snapshots and restore archives.
    /// Read-only browse via REST API; restore shells out to
    /// `proxmox-backup-client` (Linux required).
    Pbs {
        #[command(subcommand)]
        action: PbsCommand,
    },
    /// HA + replication console (read-only inspector).
    Ha {
        #[command(subcommand)]
        action: HaCommand,
    },
    /// Storage replication jobs and per-node runtime status.
    Replication {
        #[command(subcommand)]
        action: ReplicationCommand,
    },
    /// Hardware passthrough inventory + conflict detector (read-only).
    Hw {
        #[command(subcommand)]
        action: HwCommand,
    },
    /// Alerting & notification routing (rule engine + Telegram/ntfy/webhook).
    Alerts {
        #[command(subcommand)]
        action: AlertsCommand,
    },
    /// Access control: ACL, users, groups, roles, realms, TFA.
    Access {
        #[command(subcommand)]
        action: AccessCommand,
    },
    /// API token management (list / create / revoke).
    Token {
        #[command(subcommand)]
        action: TokenCommand,
    },
    /// Open the SPICE graphical console (QEMU only) by writing a `.vv`
    /// virt-viewer ConfigFile and launching `remote-viewer`. Falls back
    /// to the system default handler for `.vv` files when remote-viewer
    /// is not on PATH.
    Spice {
        /// Guest VMID (QEMU only).
        vmid: u32,
        #[arg(long)]
        node: String,
        /// Write the `.vv` to a fixed path instead of the temp dir.
        /// Useful for piping to a different launcher.
        #[arg(long)]
        write_vv: Option<std::path::PathBuf>,
        /// Don't auto-launch — print the `.vv` path and exit.
        #[arg(long)]
        no_launch: bool,
    },
    /// Open the noVNC console in the system browser. The user must
    /// already be logged into the Proxmox web UI (we do NOT inject
    /// auth tickets into the URL — that pattern leaks tokens via
    /// browser history). QEMU + LXC supported.
    Novnc {
        vmid: u32,
        #[arg(long)]
        node: String,
        /// Guest type. Auto-detected from cluster if omitted.
        #[arg(long, value_enum)]
        kind: Option<SerialKind>,
        /// Don't auto-launch — print the URL and exit.
        #[arg(long)]
        no_launch: bool,
    },
    /// Open a serial console to a guest via Proxmox termproxy (WebSocket).
    /// Useful for VM recovery when network/agent is dead. Puts the
    /// terminal in raw mode; press Ctrl+] then `q` to disconnect.
    Serial {
        /// Guest VMID.
        vmid: u32,
        /// Proxmox node hosting the guest.
        #[arg(long)]
        node: String,
        /// Guest type. Auto-detected from cluster if omitted.
        #[arg(long, value_enum)]
        kind: Option<SerialKind>,
    },
    /// Effective permissions for a user — shells out to `pveum user
    /// permissions` on a Proxmox node via Pillar 0 (SSH). Per the
    /// architectural review, we don't reimplement the algorithm; the
    /// Perl code on the node is the authority.
    Perms {
        /// User id (e.g. `oncall@pve`).
        userid: String,
        /// Optional path filter (e.g. `/vms/100`).
        #[arg(long)]
        path: Option<String>,
        /// Which Proxmox node to run `pveum` on (any one will do —
        /// they all share cluster ACL state).
        #[arg(long)]
        node: String,
    },
    /// BLOCKER 3 smoke test: trigger a controlled panic to verify the
    /// flight-recorder hook restores the terminal and writes the trace
    /// to the audit log. Use only as a manual smoke test.
    DevPanic {
        /// Panic message payload. Default `"manual smoke test"`.
        #[arg(long, default_value = "manual smoke test")]
        message: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// List ACL entries.
    Acl {
        /// Filter to a specific path (substring match).
        #[arg(long)]
        path: Option<String>,
    },
    /// List users.
    Users,
    /// List groups.
    Groups,
    /// List roles (with their privileges).
    Roles,
    /// List authentication realms (PAM/PVE/AD/LDAP/OIDC).
    Realms,
    /// List TFA entries for a user.
    Tfa { userid: String },
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// List tokens for a user.
    List { userid: String },
    /// Create a new token. The secret is printed ONCE — capture it,
    /// proxxx can't recover it later.
    Create {
        userid: String,
        tokenid: String,
        /// Privilege separation (recommended: leave default = true).
        #[arg(long, default_value_t = true)]
        privsep: bool,
        /// Expire timestamp (Unix seconds). Omit for never.
        #[arg(long)]
        expire: Option<u64>,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Revoke a token. Required: `--yes`.
    Revoke {
        userid: String,
        tokenid: String,
        #[arg(long)]
        yes: bool,
    },
}

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

#[derive(Debug, Subcommand)]
pub enum HwCommand {
    /// List PCI devices on a node, including IOMMU group ids.
    Pci {
        #[arg(long)]
        node: String,
    },
    /// List USB devices on a node.
    Usb {
        #[arg(long)]
        node: String,
    },
    /// Detect passthrough conflicts (direct shared + IOMMU group split).
    /// Scans every guest's config and cross-references with the node's
    /// hardware list.
    Conflicts {
        #[arg(long)]
        node: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum HaCommand {
    /// List HA groups.
    Groups,
    /// List HA-managed resources (VMs/CTs).
    Resources,
    /// Show the HA manager runtime status.
    Status,
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

#[derive(Debug, Subcommand)]
pub enum PbsCommand {
    /// List datastores on the configured PBS server.
    Datastores,
    /// List snapshots in a datastore. Optional filters by guest type/id.
    Snapshots {
        #[arg(long)]
        store: String,
        /// Filter: backup type (`vm`, `ct`, `host`).
        #[arg(long)]
        backup_type: Option<String>,
        /// Filter: backup id (e.g. `100`).
        #[arg(long)]
        backup_id: Option<String>,
    },
    /// List archive files inside a specific snapshot.
    Files {
        #[arg(long)]
        store: String,
        #[arg(long = "type")]
        backup_type: String,
        #[arg(long)]
        backup_id: String,
        /// Snapshot timestamp (Unix seconds).
        #[arg(long = "time")]
        backup_time: u64,
    },
    /// Restore a full archive to a local target directory.
    /// Single-file extraction is NOT supported in this MVP — see
    /// features.md for the cuts dichiarati.
    Restore {
        #[arg(long)]
        store: String,
        /// Snapshot reference, e.g. `vm/100/2024-01-15T10:00:00Z`.
        #[arg(long)]
        snapshot: String,
        /// Archive name, e.g. `root.pxar.didx`.
        #[arg(long)]
        archive: String,
        /// Local directory to restore into.
        #[arg(long)]
        target: std::path::PathBuf,
        /// Required: confirms this writes to the local filesystem.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum IsoCommand {
    /// List the curated library entries (id, distro, version, sha256).
    List,
    /// Download a curated entry by id, or a custom URL.
    Download {
        /// Library entry id (see `iso list`). Mutually exclusive with `--url`.
        #[arg(long)]
        id: Option<String>,
        /// Custom URL (overrides `--id`). Pair with `--filename`.
        #[arg(long)]
        url: Option<String>,
        /// Filename to store as. Required with `--url`.
        #[arg(long)]
        filename: Option<String>,
        /// Optional SHA-256 to pin (Proxmox verifies).
        #[arg(long)]
        sha256: Option<String>,
        /// Content category: iso | import | vztmpl. Required with `--url`.
        #[arg(long)]
        content: Option<String>,
        /// Target node (which Proxmox node performs the download).
        #[arg(long)]
        node: String,
        /// Target storage name on that node.
        #[arg(long)]
        storage: String,
    },
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
        #[arg(long)]
        delete_source: bool,
        /// Required: confirms this destructive op
        #[arg(long)]
        yes: bool,
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
    },
}

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
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RebootCli {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SerialKind {
    Qemu,
    Lxc,
}

impl From<SerialKind> for crate::api::types::GuestType {
    fn from(s: SerialKind) -> Self {
        match s {
            SerialKind::Qemu => Self::Qemu,
            SerialKind::Lxc => Self::Lxc,
        }
    }
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

#[derive(Debug, Subcommand)]
pub enum HitlCommand {
    /// Start the HITL Telegram daemon
    Serve,
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

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Start MCP server
    Serve,
    /// List available tools
    Tools {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        checksum: bool,
    },
}

/// Execute a CLI command — returns JSON-serializable result and exit code.
/// `_secure` is reserved for future per-command HITL gating in pipelines;
/// it's currently honoured by the TUI only (see `state.secure_mode`).
pub async fn execute(
    cmd: Command,
    profile: Option<&str>,
    cli_secret: Option<&str>,
    _secure: bool,
) -> Result<(Value, i32)> {
    // MCP introspection commands don't need a Proxmox connection
    if let Command::Mcp { ref action } = cmd {
        if let McpCommand::Tools { checksum, .. } = action {
            if *checksum {
                let hash = crate::mcp::tools::registry_checksum();
                return Ok((serde_json::json!({"checksum": hash}), 0));
            }
            return Ok((crate::mcp::tools::registry_json(), 0));
        }
    }

    let config = crate::config::load_config(profile)?;
    let client = std::sync::Arc::new(crate::api::PxClient::new(config.clone(), cli_secret).await?);

    use crate::api::ProxmoxGateway;

    match cmd {
        Command::Ls { resource } => match resource.as_str() {
            "nodes" => {
                let nodes = client.get_nodes().await?;
                Ok((serde_json::to_value(nodes)?, 0))
            }
            "guests" => {
                let nodes = client.get_nodes().await?;
                let mut all_guests = Vec::new();
                for node in &nodes {
                    if let Ok(guests) = client.get_guests(&node.node).await {
                        all_guests.extend(guests);
                    }
                }
                Ok((serde_json::to_value(all_guests)?, 0))
            }
            "storage" => {
                let nodes = client.get_nodes().await?;
                let mut all_storage = Vec::new();
                for node in &nodes {
                    if let Ok(pools) = client.get_storage_pools(&node.node).await {
                        all_storage.extend(pools);
                    }
                }
                Ok((serde_json::to_value(all_storage)?, 0))
            }
            other => anyhow::bail!("Unknown resource: {other}. Use: nodes, guests, storage"),
        },
        Command::Start { vmids, strict } => {
            execute_batch_op(&client, BatchOp::Start, &vmids, &config, strict).await
        }
        Command::Stop {
            vmids,
            force,
            strict,
        } => execute_batch_op(&client, BatchOp::Stop { force }, &vmids, &config, strict).await,
        Command::Restart { vmids, strict } => {
            execute_batch_op(&client, BatchOp::Restart, &vmids, &config, strict).await
        }
        Command::Delete { vmids, yes, strict } => {
            if !yes {
                anyhow::bail!("`proxxx delete` is destructive — re-run with --yes to confirm");
            }
            execute_delete(&client, &vmids, strict).await
        }
        Command::Snapshot { action } => execute_snapshot(&client, action).await,
        Command::Mcp { action } => match action {
            McpCommand::Serve => {
                crate::mcp::server::run_server(
                    std::sync::Arc::clone(&client),
                    std::sync::Arc::new(config),
                )
                .await?;
                Ok((serde_json::json!({"status": "MCP server stopped"}), 0))
            }
            _ => unreachable!(),
        },
        Command::Replay { timestamp } => {
            let state = crate::app::cache::load_state_at(profile, timestamp)?;
            Ok((serde_json::to_value(state)?, 0))
        }
        Command::Watch {
            since,
            target,
            until,
            notify,
        } => {
            if let Some(target) = target {
                let until = until.unwrap_or_else(|| "status=running".to_string());
                use crate::api::ProxmoxGateway;
                use tokio::time::{sleep, Duration};

                let (key, value) = if let Some((k, v)) = until.split_once('=') {
                    (k.trim().to_lowercase(), v.trim().to_lowercase())
                } else {
                    anyhow::bail!("Invalid condition format. Use key=value");
                };

                let mut met = false;
                tracing::info!("Watching {} until {}={}", target, key, value);

                while !met {
                    sleep(Duration::from_secs(2)).await;

                    if target.starts_with("vm-") || target.chars().all(char::is_numeric) {
                        let vmid_str = target.trim_start_matches("vm-");
                        if let Ok(vmid) = vmid_str.parse::<u32>() {
                            let mut found = false;
                            let nodes = client.get_nodes().await?;
                            for node in nodes {
                                if let Ok(guests) = client.get_guests(&node.node).await {
                                    if let Some(guest) = guests.into_iter().find(|g| g.vmid == vmid)
                                    {
                                        found = true;
                                        let current_val = match key.as_str() {
                                            "status" => {
                                                format!("{:?}", guest.status).to_lowercase()
                                            }
                                            _ => {
                                                anyhow::bail!("Unsupported condition key: {}", key)
                                            }
                                        };

                                        if current_val == value {
                                            met = true;
                                        }
                                        break;
                                    }
                                }
                            }
                            if !found {
                                anyhow::bail!("Target guest {} not found", target);
                            }
                        } else {
                            anyhow::bail!("Invalid VMID format: {}", target);
                        }
                    } else if target.starts_with("storage-") {
                        let pool_id = target.trim_start_matches("storage-");
                        let mut found = false;
                        let nodes = client.get_nodes().await?;
                        for node in nodes {
                            if let Ok(pools) = client.get_storage_pools(&node.node).await {
                                if let Some(pool) = pools.into_iter().find(|p| p.storage == pool_id)
                                {
                                    found = true;
                                    if key == "usage" {
                                        let usage_pct =
                                            (pool.used as f64 / pool.total as f64) * 100.0;
                                        let threshold: f64 = value.trim_end_matches('%').parse()?;
                                        if value.starts_with('<') {
                                            if usage_pct < threshold {
                                                met = true;
                                            }
                                        } else if usage_pct > threshold {
                                            met = true;
                                        }
                                    } else {
                                        anyhow::bail!(
                                            "Unsupported condition key for storage: {}",
                                            key
                                        );
                                    }
                                    break;
                                }
                            }
                        }
                        if !found {
                            anyhow::bail!("Target storage {} not found", target);
                        }
                    } else {
                        anyhow::bail!("Unsupported target format. Use vm-<id> or storage-<id>");
                    }
                }

                let msg = format!("Watch condition met: {} is now {}", target, until);

                if let Some(channel) = notify {
                    if channel == "telegram" {
                        if let Some(tg) = config.telegram.as_ref() {
                            let gateway = crate::hitl::telegram::TelegramGateway::new(tg.clone());
                            gateway.send_message(&msg).await?;
                        }
                    }
                }

                return Ok((
                    serde_json::json!({"status": "condition_met", "target": target, "condition": until}),
                    0,
                ));
            } else if let Some(since) = since {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let seconds = if since.ends_with('h') {
                    since.trim_end_matches('h').parse::<u64>().unwrap_or(1) * 3600
                } else if since.ends_with('m') {
                    since.trim_end_matches('m').parse::<u64>().unwrap_or(30) * 60
                } else {
                    since.parse::<u64>().unwrap_or(3600)
                };

                let past = now.saturating_sub(seconds);
                let state_past = crate::app::cache::load_state_at(profile, past)?;
                let state_now = crate::app::cache::load_state(profile)?;

                let mut diff = Vec::new();

                let past_map: std::collections::HashMap<_, _> =
                    state_past.guests.into_iter().map(|g| (g.vmid, g)).collect();
                let now_map: std::collections::HashMap<_, _> =
                    state_now.guests.into_iter().map(|g| (g.vmid, g)).collect();

                for (vmid, guest_now) in &now_map {
                    if let Some(guest_past) = past_map.get(vmid) {
                        if guest_past.status != guest_now.status {
                            diff.push(serde_json::json!({
                                "vmid": vmid,
                                "type": "status_change",
                                "from": format!("{:?}", guest_past.status),
                                "to": format!("{:?}", guest_now.status)
                            }));
                        }
                    } else {
                        diff.push(serde_json::json!({
                            "vmid": vmid,
                            "type": "created",
                            "status": format!("{:?}", guest_now.status)
                        }));
                    }
                }

                for vmid in past_map.keys() {
                    if !now_map.contains_key(vmid) {
                        diff.push(serde_json::json!({
                            "vmid": vmid,
                            "type": "deleted"
                        }));
                    }
                }

                Ok((
                    serde_json::json!({
                        "past_timestamp": state_past.timestamp,
                        "now_timestamp": state_now.timestamp,
                        "diff": diff
                    }),
                    0,
                ))
            } else {
                anyhow::bail!("Watch requires either --since or --target");
            }
        }
        Command::Search { query, limit } => execute_search(&client, &query, limit).await,
        Command::Hitl { action } => match action {
            HitlCommand::Serve => {
                hitl_serve(client, config).await?;
                Ok((serde_json::json!({"status": "HITL daemon stopped"}), 0))
            }
        },
        Command::Patch { action } => execute_patch(client, &config, action).await,
        Command::Disk { action } => execute_disk(&client, action).await,
        Command::Iso { action } => execute_iso(&client, action).await,
        Command::Pbs { action } => execute_pbs(&config, action, cli_secret).await,
        Command::Ha { action } => execute_ha(&client, action).await,
        Command::Replication { action } => execute_replication(&client, action).await,
        Command::Hw { action } => execute_hw(&client, action).await,
        Command::Alerts { action } => execute_alerts(&client, &config, action).await,
        Command::Access { action } => execute_access(&client, action).await,
        Command::Token { action } => execute_token(&client, action).await,
        Command::Perms { userid, path, node } => {
            execute_perms(&config, &userid, path.as_deref(), &node).await
        }
        Command::Serial { vmid, node, kind } => {
            execute_serial(&client, &config, vmid, &node, kind).await
        }
        Command::Spice {
            vmid,
            node,
            write_vv,
            no_launch,
        } => execute_spice(&client, vmid, &node, write_vv, no_launch).await,
        Command::Novnc {
            vmid,
            node,
            kind,
            no_launch,
        } => execute_novnc(&client, &config, vmid, &node, kind, no_launch).await,
        Command::DevPanic { message } => {
            // BLOCKER 3 smoke test. Caught by the global panic hook
            // installed in main() — verifies terminal restoration +
            // audit-log capture on a real panic. This is the ONLY
            // production panic in the codebase; clippy's `panic = deny`
            // is opted out here because a panic IS the test.
            #[allow(clippy::panic)]
            {
                panic!("[dev-panic] {message}");
            }
        }
    }
}

/// Feature #10 — read-only access browse.
async fn execute_access(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: AccessCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        AccessCommand::Acl { path } => {
            let mut acl = client.list_acl().await?;
            if let Some(p) = path {
                acl.retain(|e| e.path.contains(&p));
            }
            Ok((serde_json::to_value(acl)?, 0))
        }
        AccessCommand::Users => {
            let users = client.list_users().await?;
            Ok((serde_json::to_value(users)?, 0))
        }
        AccessCommand::Groups => {
            let groups = client.list_groups().await?;
            Ok((serde_json::to_value(groups)?, 0))
        }
        AccessCommand::Roles => {
            let roles = client.list_roles().await?;
            Ok((serde_json::to_value(roles)?, 0))
        }
        AccessCommand::Realms => {
            let realms = client.list_realms().await?;
            Ok((serde_json::to_value(realms)?, 0))
        }
        AccessCommand::Tfa { userid } => {
            let tfa = client.list_tfa(&userid).await?;
            Ok((serde_json::to_value(tfa)?, 0))
        }
    }
}

/// Feature #10 — token CRUD.
async fn execute_token(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: TokenCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        TokenCommand::List { userid } => {
            let tokens = client.list_user_tokens(&userid).await?;
            Ok((serde_json::to_value(tokens)?, 0))
        }
        TokenCommand::Create {
            userid,
            tokenid,
            privsep,
            expire,
            comment,
        } => {
            let tok = client
                .create_token(&userid, &tokenid, privsep, expire, comment.as_deref())
                .await?;
            // The secret in `value` is shown ONCE. Highlight that fact
            // both in the JSON and in plain output via a banner.
            Ok((
                serde_json::json!({
                    "userid": userid,
                    "tokenid": tokenid,
                    "privsep": tok.privsep,
                    "expire": tok.expire,
                    "comment": tok.comment,
                    "value": tok.value,
                    "warning": "the token `value` is the secret and is shown ONCE — capture it now"
                }),
                0,
            ))
        }
        TokenCommand::Revoke {
            userid,
            tokenid,
            yes,
        } => {
            if !yes {
                anyhow::bail!("token revoke is destructive — re-run with --yes");
            }
            client.revoke_token(&userid, &tokenid).await?;
            Ok((
                serde_json::json!({
                    "userid": userid,
                    "tokenid": tokenid,
                    "status": "revoked"
                }),
                0,
            ))
        }
    }
}

/// Feature #10 — effective permissions via SSH shell-out (Option A).
async fn execute_perms(
    config: &crate::config::ProfileConfig,
    userid: &str,
    path_filter: Option<&str>,
    node: &str,
) -> Result<(Value, i32)> {
    use crate::ssh::{ExecOptions, SshPool};

    let ssh_cfg = config.ssh.clone().ok_or_else(|| {
        anyhow::anyhow!("[profiles.X.ssh] not configured — `proxxx perms` shells out via SSH")
    })?;
    let pool = SshPool::new(ssh_cfg, None)?;
    // Build the command. We pass userid through unchanged — pveum quotes
    // it server-side. We DO defend against shell-injection by refusing
    // any userid that contains shell metachars.
    // Vector 3 (Gemini audit) — defence in depth, three layers:
    //  1. Refuse-list of obvious shell metachars (early-out for the
    //     common attack patterns; produces a clearer error than a
    //     downstream pveum failure).
    //  2. `shell_quote`: wraps the value in single quotes and escapes
    //     internal `'` as `'\''`. Inside `'…'` bash does NOT interpret
    //     ANY metachar — backticks, $(), $VAR, `\` are all literal.
    //     The only escape is another `'`, which we handle. This is
    //     mathematically injection-proof at the shell layer.
    //  3. `--` separator before `{userid}`: even if pveum's argparser
    //     accepts flags after positionals, the `--` sentinel forces it
    //     to treat everything that follows as positional. This blocks
    //     argument-injection vectors like `--config-file=/etc/passwd`.
    if userid
        .chars()
        .any(|c| matches!(c, '`' | '$' | ';' | '&' | '|' | '\n' | '\r'))
    {
        anyhow::bail!("userid contains shell metacharacters — refusing");
    }
    let cmd = format!("pveum user permissions -- {}", shell_quote(userid));
    let res = pool.exec(node, &cmd, ExecOptions::default()).await?;
    if !res.ok() {
        anyhow::bail!(
            "pveum exited {:?}: {}",
            res.exit_code,
            res.stderr.trim().chars().take(500).collect::<String>()
        );
    }

    let mut perms = crate::access::parse_user_permissions(userid, &res.stdout);
    if let Some(p) = path_filter {
        perms.paths.retain(|x| x.path.contains(p));
    }
    // Render to JSON manually — `EffectivePermissions` isn't Serialize
    // (pure logic crate), so we shape it inline for the CLI.
    let json = serde_json::json!({
        "userid": perms.userid,
        "paths": perms.paths.iter().map(|pp| {
            serde_json::json!({
                "path": pp.path,
                "privileges": pp.privileges.iter().map(|(n, prop)| {
                    serde_json::json!({ "name": n, "propagate": prop })
                }).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>()
    });
    Ok((json, 0))
}

/// Feature #1c — SPICE handoff CLI. Issues spiceproxy ticket, writes
/// `.vv` ConfigFile, launches remote-viewer (or system default).
async fn execute_spice(
    client: &std::sync::Arc<crate::api::PxClient>,
    vmid: u32,
    node: &str,
    write_vv: Option<std::path::PathBuf>,
    no_launch: bool,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    let cfg = client.get_spiceproxy(node, vmid).await?;
    // Vector 2 audit: when the user passes `--write-vv <path>` we
    // honour it (they own the path). Without that flag we delegate to
    // the TOCTOU-safe `write_vv_file` which uses tempfile + O_EXCL +
    // 0600 atomically.
    let path = if let Some(p) = write_vv {
        crate::handoff::write_vv_at(&p, &cfg)?;
        p
    } else {
        crate::handoff::write_vv_file(vmid, &cfg)?
    };

    let mut launcher_used: Option<&'static str> = None;
    if !no_launch {
        match crate::handoff::open_spice_vv(&path) {
            Ok(name) => launcher_used = Some(name),
            Err(e) => {
                tracing::warn!("could not auto-launch SPICE viewer: {e:#}");
            }
        }
    }

    Ok((
        serde_json::json!({
            "vmid": vmid,
            "node": node,
            "vv_file": path.to_string_lossy(),
            "host": cfg.host(),
            "launcher": launcher_used,
            "launched": launcher_used.is_some(),
        }),
        0,
    ))
}

/// Feature #1c — noVNC handoff CLI. Builds the deep-link URL and opens
/// it via the system default handler. Authentication is left to the
/// browser's existing PVEAuthCookie session.
async fn execute_novnc(
    client: &std::sync::Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    vmid: u32,
    node: &str,
    kind_override: Option<SerialKind>,
    no_launch: bool,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    let guest_type = if let Some(k) = kind_override {
        k.into()
    } else {
        let guests = client.get_guests(node).await?;
        let g = guests
            .iter()
            .find(|g| g.vmid == vmid)
            .ok_or_else(|| anyhow::anyhow!("guest {vmid} not on node {node}"))?;
        g.guest_type
    };
    let url = crate::handoff::build_novnc_url(&config.url, node, vmid, guest_type);

    let mut launched = false;
    if !no_launch {
        if let Err(e) = crate::handoff::open_with_default(&url) {
            tracing::warn!("could not auto-launch browser: {e:#}");
        } else {
            launched = true;
        }
    }

    Ok((
        serde_json::json!({
            "vmid": vmid,
            "node": node,
            "type": format!("{:?}", guest_type).to_lowercase(),
            "url": url,
            "launched": launched,
            "note": "user must be logged into the Proxmox web UI for the deep-link to work without re-auth"
        }),
        0,
    ))
}

/// Feature #1b — serial console CLI. Issues a termproxy ticket via REST,
/// connects WSS, puts the terminal in raw mode, copies bytes both ways
/// until Ctrl+] then `q`.
///
/// Honest limitations:
/// - Linux/macOS only (crossterm raw mode + signal handling assumes UNIX).
/// - No scrollback (raw passthrough — use `tmux` if you need it).
/// - Exit chord is hardcoded `Ctrl+] q` (telnet-style).
async fn execute_serial(
    client: &std::sync::Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    vmid: u32,
    node: &str,
    kind_override: Option<SerialKind>,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    // Auto-detect guest type from cluster state if not given.
    let guest_type = if let Some(k) = kind_override {
        k.into()
    } else {
        let guests = client.get_guests(node).await?;
        let g = guests
            .iter()
            .find(|g| g.vmid == vmid)
            .ok_or_else(|| anyhow::anyhow!("guest {vmid} not on node {node}"))?;
        g.guest_type
    };

    // Issue the termproxy ticket — short-lived, must connect immediately.
    let ticket = client.get_termproxy(node, vmid, guest_type).await?;
    let target = crate::wsterm::build_ws_target(
        &config.url,
        node,
        vmid,
        guest_type,
        ticket.port,
        &ticket.ticket,
        &ticket.user,
    );

    let mut ws = crate::wsterm::connect(&target, config.verify_tls).await?;

    // Put the local terminal in raw mode + alternate screen so the
    // remote shell controls every keystroke. The global panic hook
    // (BLOCKER 3) already restores raw mode on crash; we also do an
    // explicit cleanup at function end.
    use anyhow::Context;
    use crossterm::{execute, terminal};
    use std::io::{stdout, Write};

    terminal::enable_raw_mode().context("enable raw mode")?;
    execute!(
        stdout(),
        terminal::EnterAlternateScreen,
        crossterm::cursor::Hide,
    )
    .context("enter alt screen")?;

    let _ = write!(
        stdout(),
        "\x1b[2J\x1b[H[serial console: vmid {vmid} on {node}]  Ctrl+] then 'q' to exit\r\n"
    );
    let _ = stdout().flush();

    // Initial size sync.
    if let Ok((cols, rows)) = terminal::size() {
        let _ = crate::wsterm::send_resize(&mut ws, cols, rows).await;
    }

    let exit_code = serial_loop(&mut ws).await;

    // Cleanup — best-effort. The panic hook is the safety net for the
    // unhappy path.
    let _ = execute!(
        stdout(),
        terminal::LeaveAlternateScreen,
        crossterm::cursor::Show,
    );
    let _ = terminal::disable_raw_mode();

    Ok((
        serde_json::json!({
            "vmid": vmid,
            "node": node,
            "type": format!("{:?}", guest_type).to_lowercase(),
            "user": ticket.user,
            "exit_code": exit_code,
        }),
        exit_code,
    ))
}

/// Inner loop: keystrokes → WS, WS frames → stdout. Returns exit code.
async fn serial_loop<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> i32
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use crossterm::event::{Event, EventStream, KeyCode, KeyModifiers};
    use futures_util::{SinkExt, StreamExt};
    use std::io::{stdout, Write};
    use tokio_tungstenite::tungstenite::protocol::Message;

    let mut events = EventStream::new();
    // State for the Ctrl+] q exit chord.
    let mut prefix_armed = false;

    loop {
        tokio::select! {
            // Local terminal events.
            evt = events.next() => {
                let Some(Ok(evt)) = evt else { break; };
                match evt {
                    Event::Key(key) => {
                        // Exit chord: Ctrl+] then 'q'.
                        if !prefix_armed
                            && key.modifiers.contains(KeyModifiers::CONTROL)
                            && matches!(key.code, KeyCode::Char(']'))
                        {
                            prefix_armed = true;
                            continue;
                        }
                        if prefix_armed {
                            prefix_armed = false;
                            if matches!(key.code, KeyCode::Char('q')) {
                                let _ = ws.send(Message::Close(None)).await;
                                return 0;
                            }
                            // Not the exit chord — forward Ctrl+] then this key.
                            let _ = crate::wsterm::send_input(ws, &[0x1D]).await;
                        }
                        // Encode + forward.
                        if let Some(bytes) = crate::ssh::pty::encode_key(&key) {
                            if crate::wsterm::send_input(ws, &bytes).await.is_err() {
                                return 1;
                            }
                        }
                    }
                    Event::Resize(cols, rows) => {
                        let _ = crate::wsterm::send_resize(ws, cols, rows).await;
                    }
                    _ => {}
                }
            }
            // Remote bytes.
            msg = ws.next() => {
                let Some(msg) = msg else { break; };
                match msg {
                    Ok(Message::Binary(payload)) => {
                        if let Some(bytes) = crate::wsterm::decode_data_frame(&payload) {
                            let _ = stdout().write_all(bytes);
                            let _ = stdout().flush();
                        }
                    }
                    Ok(Message::Text(t)) => {
                        let _ = stdout().write_all(t.as_bytes());
                        let _ = stdout().flush();
                    }
                    Ok(Message::Close(_)) => return 0,
                    Ok(_) => {}
                    Err(_) => return 1,
                }
            }
        }
    }
    0
}

/// Single-quote a string for safe inclusion in a shell command. Replaces
/// every `'` in the input with `'\''` (close, escape, open). Plain ASCII
/// userids skip the quoting cost.
fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '!' | '_' | '-' | '.'))
    {
        return s.to_string();
    }
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

#[cfg(test)]
mod shell_quote_tests {
    use super::shell_quote;

    /// Vector 3 (Gemini audit) — single-quote wrapping is mathematically
    /// injection-proof. Inside single quotes, bash interprets nothing
    /// except another single quote (which we escape via the
    /// close-escape-reopen idiom `'\''`).
    #[test]
    fn ascii_userid_passes_through_unquoted() {
        // Bare-ASCII userids are safe to pass through; the test pins
        // the optimisation so a refactor doesn't regress it.
        assert_eq!(shell_quote("root@pam"), "root@pam");
        assert_eq!(shell_quote("svc-readonly"), "svc-readonly");
    }

    #[test]
    fn embedded_single_quote_is_escaped() {
        // The textbook tricky input: a value containing a single quote.
        // Output must produce a literal `'` after shell parsing.
        assert_eq!(shell_quote("o'reilly"), "'o'\\''reilly'");
    }

    #[test]
    fn metachars_become_literal_inside_single_quotes() {
        // Inside `'…'` bash does NOT interpret $, `, \, ;, |, &, (, )
        // — they all become literal.
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(shell_quote("`whoami`"), "'`whoami`'");
        assert_eq!(shell_quote("a;b|c&d"), "'a;b|c&d'");
        assert_eq!(shell_quote("a\\b\"c"), "'a\\b\"c'");
    }

    #[test]
    fn injection_attempt_from_audit_becomes_inert_literal() {
        // Gemini's exact attack string, re-shell-parsed:
        //   input: test'; touch /tmp/pwned; '
        //   shell_quote → 'test'\''; touch /tmp/pwned; '\'''
        // Bash parses that as a single concatenated literal:
        //   'test' + \' + '; touch /tmp/pwned; ' + \' + ''
        // = test'; touch /tmp/pwned; '
        // pveum then sees a single argument with the metachars inert.
        let q = shell_quote("test'; touch /tmp/pwned; '");
        // Closure invariants: starts with a single quote, ends with one,
        // and every embedded `'` is closed before being escaped.
        assert!(q.starts_with('\''));
        assert!(q.ends_with('\''));
        // The escaped form `'\''` must appear for each input `'`.
        assert_eq!(q.matches("'\\''").count(), 2);
        // No raw shell-active sequence outside of quotes survives.
        assert!(!q.contains(";'") || q.contains("'\\''"));
    }
}

/// Feature #8 — alerts CLI dispatch.
async fn execute_alerts(
    client: &std::sync::Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
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
            let tg = config
                .telegram
                .clone()
                .map(crate::hitl::telegram::TelegramGateway::new);

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
            let mut dedup = DedupCache::default();
            tracing::info!(
                "alert daemon starting: {} rules, interval {}s",
                rules.len(),
                interval
            );
            // Vector 21 (macro audit) — graceful shutdown on
            // SIGTERM/SIGINT. The select! races the daemon's tick
            // against the signal handler; whichever fires first wins.
            // On SIGTERM systemd waits up to 90 s before SIGKILL —
            // we comfortably exit within milliseconds.
            loop {
                tokio::select! {
                    biased; // signals are higher priority than the next tick
                    () = crate::util::shutdown::wait_for_shutdown_signal() => {
                        tracing::info!("alert daemon: shutdown signal received, exiting cleanly");
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
            let tg = config
                .telegram
                .clone()
                .map(crate::hitl::telegram::TelegramGateway::new);
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

/// Feature #4 — hardware inventory CLI.
async fn execute_hw(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: HwCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        HwCommand::Pci { node } => {
            let pci = client.list_pci(&node).await?;
            Ok((serde_json::to_value(pci)?, 0))
        }
        HwCommand::Usb { node } => {
            let usb = client.list_usb(&node).await?;
            Ok((serde_json::to_value(usb)?, 0))
        }
        HwCommand::Conflicts { node } => {
            // Pull devices + every guest's config; run the pure-logic
            // detector. Exit code reflects "any conflicts found".
            let pci = client.list_pci(&node).await?;
            let nodes = client.get_nodes().await?;
            let mut configs: std::collections::HashMap<
                u32,
                std::collections::HashMap<String, String>,
            > = std::collections::HashMap::new();
            for n in &nodes {
                if let Ok(guests) = client.get_guests(&n.node).await {
                    for g in guests {
                        if let Ok(cfg) = client
                            .get_guest_config(&g.node, g.vmid, &g.guest_type)
                            .await
                        {
                            configs.insert(g.vmid, cfg);
                        }
                    }
                }
            }
            let (assignments, _) = crate::app::hw::scan_assignments(&configs);
            let conflicts = crate::app::hw::detect_pci_conflicts(&assignments, &pci);

            // Serialize to JSON: tag-distinguished variants.
            let serialized: Vec<serde_json::Value> = conflicts
                .iter()
                .map(|c| match c {
                    crate::app::hw::PciConflict::DirectShared { address, vmids } => {
                        serde_json::json!({
                            "kind": "direct_shared",
                            "address": address,
                            "vmids": vmids
                        })
                    }
                    crate::app::hw::PciConflict::IommuGroupSplit { group, members } => {
                        serde_json::json!({
                            "kind": "iommu_group_split",
                            "group": group,
                            "members": members
                                .iter()
                                .map(|(a, v)| serde_json::json!({ "address": a, "vmid": v }))
                                .collect::<Vec<_>>()
                        })
                    }
                })
                .collect();
            let exit = if conflicts.is_empty() { 0 } else { 1 };
            Ok((
                serde_json::json!({
                    "node": node,
                    "conflicts": serialized,
                    "count": conflicts.len()
                }),
                exit,
            ))
        }
    }
}

/// Feature #5 — HA console CLI.
async fn execute_ha(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: HaCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        HaCommand::Groups => {
            let groups = client.list_ha_groups().await?;
            Ok((serde_json::to_value(groups)?, 0))
        }
        HaCommand::Resources => {
            let resources = client.list_ha_resources().await?;
            Ok((serde_json::to_value(resources)?, 0))
        }
        HaCommand::Status => {
            let status = client.ha_manager_status().await?;
            Ok((serde_json::to_value(status)?, 0))
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

async fn execute_replication(
    client: &std::sync::Arc<crate::api::PxClient>,
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

/// Feature #3 CLI dispatch. PBS lives in its own profile block; we don't
/// reuse the Proxmox API client. If `[profiles.X.pbs]` is missing, every
/// subcommand fails fast with a clear "configure PBS" message.
async fn execute_pbs(
    config: &crate::config::ProfileConfig,
    action: PbsCommand,
    cli_secret: Option<&str>,
) -> Result<(Value, i32)> {
    use crate::pbs::{PbsClient, PbsGateway};

    let pbs_cfg = config.pbs.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "no [profiles.X.pbs] block configured — add url, user, token_id, token_secret(_file)"
        )
    })?;

    match action {
        PbsCommand::Datastores => {
            let client = PbsClient::new(pbs_cfg, cli_secret).await?;
            let stores = client.list_datastores().await?;
            Ok((serde_json::to_value(stores)?, 0))
        }
        PbsCommand::Snapshots {
            store,
            backup_type,
            backup_id,
        } => {
            let client = PbsClient::new(pbs_cfg, cli_secret).await?;
            let snaps = client
                .list_snapshots(&store, backup_type.as_deref(), backup_id.as_deref())
                .await?;
            Ok((serde_json::to_value(snaps)?, 0))
        }
        PbsCommand::Files {
            store,
            backup_type,
            backup_id,
            backup_time,
        } => {
            let client = PbsClient::new(pbs_cfg, cli_secret).await?;
            let files = client
                .list_snapshot_files(&store, &backup_type, &backup_id, backup_time)
                .await?;
            Ok((serde_json::to_value(files)?, 0))
        }
        PbsCommand::Restore {
            store,
            snapshot,
            archive,
            target,
            yes,
        } => {
            if !yes {
                anyhow::bail!("`pbs restore` writes to the local filesystem — re-run with --yes");
            }
            crate::pbs::restore::validate_target(&target)?;
            // Pre-flight: surface a clean error if the binary is missing
            // before we start streaming.
            if crate::pbs::detect_client_binary().is_none() {
                anyhow::bail!(
                    "proxmox-backup-client not found. Install the PBS client \
                     (apt install proxmox-backup-client on Debian/Ubuntu/PVE). \
                     Note: macOS / Windows clients aren't available upstream."
                );
            }
            let req = crate::pbs::RestoreRequest {
                snapshot: snapshot.clone(),
                archive: archive.clone(),
                target: target.clone(),
                store: store.clone(),
            };
            let mut tail: Vec<String> = Vec::new();
            let result = crate::pbs::run_restore(&pbs_cfg, cli_secret, req, |line| {
                tail.push(line.to_string());
                if tail.len() > 50 {
                    tail.drain(..tail.len() - 50);
                }
            })
            .await?;

            let exit = if result.exit_code == Some(0) { 0 } else { 1 };
            Ok((
                serde_json::json!({
                    "store": store,
                    "snapshot": snapshot,
                    "archive": archive,
                    "target": target,
                    "exit_code": result.exit_code,
                    "last_lines": result.last_lines,
                    "status": if exit == 0 { "ok" } else { "error" },
                }),
                exit,
            ))
        }
    }
}

/// Bug #4 fix: cluster-wide fuzzy search via the existing in-memory
/// search engine. Reuses `app::search::SearchItem` + `nucleo_matcher`.
/// One-shot: fetches state, runs the matcher, prints JSON results.
async fn execute_search(
    client: &std::sync::Arc<crate::api::PxClient>,
    query: &str,
    limit: usize,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    let nodes = client.get_nodes().await?;
    let mut all_guests = Vec::new();
    let mut all_storage = Vec::new();
    for n in &nodes {
        if let Ok(guests) = client.get_guests(&n.node).await {
            all_guests.extend(guests);
        }
        if let Ok(pools) = client.get_storage_pools(&n.node).await {
            all_storage.extend(pools);
        }
    }
    let q_lower = query.to_lowercase();
    let mut results: Vec<serde_json::Value> = Vec::new();
    for g in &all_guests {
        let hay = format!(
            "{} {} {} {:?} {} {}",
            g.vmid, g.name, g.tags, g.status, g.node, g.guest_type as u8
        )
        .to_lowercase();
        if hay.contains(&q_lower) {
            results.push(serde_json::json!({
                "kind": "guest",
                "vmid": g.vmid,
                "name": g.name,
                "node": g.node,
                "status": format!("{:?}", g.status),
                "type": format!("{:?}", g.guest_type),
                "tags": g.tags,
            }));
        }
    }
    for n in &nodes {
        let hay = format!("{} {:?}", n.node, n.status).to_lowercase();
        if hay.contains(&q_lower) {
            results.push(serde_json::json!({
                "kind": "node",
                "name": n.node,
                "status": format!("{:?}", n.status),
            }));
        }
    }
    for s in &all_storage {
        let hay = format!("{} {} {}", s.storage, s.storage_type, s.content).to_lowercase();
        if hay.contains(&q_lower) {
            results.push(serde_json::json!({
                "kind": "storage",
                "name": s.storage,
                "type": s.storage_type,
            }));
        }
    }
    results.truncate(limit);
    Ok((serde_json::Value::Array(results), 0))
}

/// Feature #2 CLI dispatch.
async fn execute_iso(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: IsoCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    use crate::app::iso_library;

    match action {
        IsoCommand::List => {
            let entries: Vec<serde_json::Value> = iso_library::LIBRARY
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "id": e.id,
                        "distro": e.distro,
                        "version": e.version,
                        "arch": e.arch,
                        "url": e.url,
                        // `checksum` is { "algo": "sha256"|"sha512", "digest": "..." }
                        // when pinned, or `null` when not (BLOCKER 1 schema).
                        "checksum": e.checksum,
                        "content": e.content,
                        "size_mib": e.size_mib,
                        "notes": e.notes,
                    })
                })
                .collect();
            Ok((serde_json::Value::Array(entries), 0))
        }
        IsoCommand::Download {
            id,
            url,
            filename,
            sha256,
            content,
            node,
            storage,
        } => {
            // Resolve either a library entry or a custom URL+filename+content.
            // We refuse ambiguous combinations loudly — pipelines should
            // know exactly what they asked for.
            //
            // `final_checksum` is `(algo, hex)` so curated entries that
            // ship SHA-512 (Debian) flow through unchanged.
            let (final_url, final_filename, final_checksum, final_content): (
                String,
                String,
                Option<(String, String)>,
                String,
            ) = match (id, url) {
                (Some(_), Some(_)) => {
                    anyhow::bail!("specify either --id or --url, not both");
                }
                (Some(entry_id), None) => {
                    let entry = iso_library::by_id(&entry_id)
                        .ok_or_else(|| anyhow::anyhow!("library id '{entry_id}' not found"))?;
                    // BLOCKER 1 gate: curated entry must be pinned.
                    let checksum = entry.checksum.ok_or_else(|| {
                        anyhow::anyhow!(
                            "library entry '{entry_id}' has no pinned checksum. \
                             Use --url <X> --sha256 <Y> to download with caller-supplied checksum."
                        )
                    })?;
                    let (algo, hex) = checksum.proxmox_pair();
                    let derived_filename = entry
                        .url
                        .rsplit('/')
                        .next()
                        .unwrap_or("download.img")
                        .to_string();
                    (
                        entry.url.to_string(),
                        derived_filename,
                        Some((algo.to_string(), hex.to_string())),
                        entry.content.to_string(),
                    )
                }
                (None, Some(custom_url)) => {
                    let fname =
                        filename.ok_or_else(|| anyhow::anyhow!("--url requires --filename"))?;
                    let cnt = content.ok_or_else(|| {
                        anyhow::anyhow!("--url requires --content (iso|import|vztmpl)")
                    })?;
                    let cs = sha256.map(|h| ("sha256".to_string(), h));
                    (custom_url, fname, cs, cnt)
                }
                (None, None) => {
                    anyhow::bail!("specify --id <entry> or --url <custom-url>");
                }
            };

            let (algo, hex): (Option<&str>, Option<&str>) = match final_checksum.as_ref() {
                Some((a, h)) => (Some(a.as_str()), Some(h.as_str())),
                None => (None, None),
            };
            let upid = client
                .download_to_storage(
                    &node,
                    &storage,
                    &final_url,
                    &final_filename,
                    algo,
                    hex,
                    &final_content,
                )
                .await?;

            Ok((
                serde_json::json!({
                    "node": node,
                    "storage": storage,
                    "url": final_url,
                    "filename": final_filename,
                    "checksum": final_checksum,
                    "content": final_content,
                    "upid": upid,
                    "status": "queued"
                }),
                0,
            ))
        }
    }
}

/// Feature #6 CLI dispatch.
///
/// Note: the CLI takes the direct API path (no queue), unlike the TUI.
/// We hard-require `--yes` per op so non-interactive scripts can't
/// accidentally trash storage by piping stale arguments.
async fn execute_disk(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: DiskCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    // Locate the guest's node + type (bug #1 dispatch).
    async fn find_guest(
        client: &crate::api::PxClient,
        vmid: u32,
    ) -> Result<(String, crate::api::types::GuestType)> {
        let nodes = client.get_nodes().await?;
        for n in nodes {
            if let Ok(guests) = client.get_guests(&n.node).await {
                if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                    return Ok((n.node.clone(), g.guest_type));
                }
            }
        }
        anyhow::bail!("Guest {vmid} not found")
    }

    match action {
        DiskCommand::Move {
            vmid,
            disk,
            storage,
            delete_source,
            yes,
        } => {
            if !yes {
                anyhow::bail!("disk move is destructive — re-run with --yes");
            }
            let (node, gt) = find_guest(client, vmid).await?;
            let upid = client
                .move_disk(&node, vmid, gt, &disk, &storage, delete_source)
                .await?;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "disk": disk,
                    "target_storage": storage,
                    "delete_source": delete_source,
                    "node": node,
                    "upid": upid,
                    "status": "queued"
                }),
                0,
            ))
        }
        DiskCommand::Resize {
            vmid,
            disk,
            size,
            yes,
        } => {
            if !yes {
                anyhow::bail!("disk resize is destructive — re-run with --yes");
            }
            let (node, gt) = find_guest(client, vmid).await?;
            let upid = client.resize_disk(&node, vmid, gt, &disk, &size).await?;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "disk": disk,
                    "size": size,
                    "node": node,
                    "upid": upid,
                    "status": "queued"
                }),
                0,
            ))
        }
    }
}

/// Bug #3 fix: implement `proxxx snapshot create/delete` (was stub).
async fn execute_snapshot(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: SnapshotCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    let (vmid, name, is_create) = match action {
        SnapshotCommand::Create { vmid, name } => (vmid, name, true),
        SnapshotCommand::Delete { vmid, name } => (vmid, name, false),
    };

    // Locate the guest to get its node + type (bug #1 dispatch).
    let nodes = client.get_nodes().await?;
    let mut found: Option<(String, crate::api::types::GuestType)> = None;
    for n in nodes {
        if let Ok(guests) = client.get_guests(&n.node).await {
            if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                found = Some((n.node.clone(), g.guest_type));
                break;
            }
        }
    }
    let (node, gt) = found.ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;

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

/// Bug #6 fix: implement `proxxx delete <vmid>...` (was missing entirely).
/// Requires `--yes` from the caller; routes through `delete_guest` with
/// type-aware dispatch.
async fn execute_delete(
    client: &std::sync::Arc<crate::api::PxClient>,
    vmids: &[u32],
    strict: bool,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    use tracing::warn;

    // Build vmid → (node, type) map from a single cluster scan.
    let nodes = client.get_nodes().await?;
    let mut guest_map: std::collections::HashMap<u32, (String, crate::api::types::GuestType)> =
        std::collections::HashMap::new();
    for n in nodes {
        if let Ok(guests) = client.get_guests(&n.node).await {
            for g in guests {
                guest_map.insert(g.vmid, (n.node.clone(), g.guest_type));
            }
        }
    }

    if strict {
        let missing: Vec<u32> = vmids
            .iter()
            .copied()
            .filter(|v| !guest_map.contains_key(v))
            .collect();
        if !missing.is_empty() {
            anyhow::bail!("Strict mode: guests not found: {missing:?}");
        }
    }

    let mut results = Vec::new();
    let mut has_failure = false;
    for vmid in vmids {
        let Some((node, gt)) = guest_map.get(vmid).cloned() else {
            warn!("guest {vmid} not found");
            results.push(serde_json::json!({
                "vmid": vmid,
                "status": "error",
                "message": "guest not found"
            }));
            has_failure = true;
            continue;
        };
        match client.delete_guest(&node, *vmid, gt).await {
            Ok(upid) => results.push(serde_json::json!({
                "vmid": vmid,
                "status": "success",
                "node": node,
                "upid": upid,
            })),
            Err(e) => {
                has_failure = true;
                results.push(serde_json::json!({
                    "vmid": vmid,
                    "status": "error",
                    "message": e.to_string()
                }));
                if strict {
                    anyhow::bail!("Strict mode: delete failed for {vmid}: {e}");
                }
            }
        }
    }

    let exit = if has_failure { 1 } else { 0 };
    Ok((serde_json::Value::Array(results), exit))
}

async fn execute_patch(
    client: std::sync::Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    action: PatchCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    use crate::app::patch::{Orchestrator, PatchStrategy, Phase};
    use crate::ssh::{SshGateway, SshPool};
    use std::sync::Arc;

    let api: Arc<dyn ProxmoxGateway> = client;

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
            let exit = if applied
                .nodes
                .iter()
                .any(|n| matches!(n.status, Phase::Failed { .. }))
            {
                1
            } else {
                0
            };
            Ok((serde_json::to_value(applied)?, exit))
        }
    }
}

/// Trait object used by `patch plan` where SSH is never invoked. Panics
/// loudly if anyone tries to use it — that would be a programming error,
/// not a user-recoverable one.
struct NoSsh;

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

enum BatchOp {
    Start,
    Stop { force: bool },
    Restart,
}

async fn execute_batch_op(
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
        if let Ok((_node_name, Ok(guests))) = res {
            for g in guests {
                guest_map.insert(g.vmid, g);
            }
        }
    }

    let mut results = Vec::new();
    let mut has_failure = false;
    let mut hitl_pending = false;
    let mut op_join_set = tokio::task::JoinSet::new();
    // Vector 7 (Gemini audit) — bound concurrent in-flight HTTPS
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
    };

    let policies = config.policies.as_deref().unwrap_or_default();

    let tg_gateway = config
        .telegram
        .clone()
        .map(crate::hitl::telegram::TelegramGateway::new);

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
                BatchOp::Stop { force } => BatchOp::Stop { force },
                BatchOp::Restart => BatchOp::Restart,
            };

            if strict {
                // Bug #1+#2 fix: dispatch by guest_type, route force=false to shutdown.
                let res = match operation {
                    BatchOp::Start => client_c.start_guest(&node, v, gt).await,
                    BatchOp::Stop { force: true } => client_c.stop_guest(&node, v, gt, true).await,
                    BatchOp::Stop { force: false } => client_c.shutdown_guest(&node, v, gt).await,
                    BatchOp::Restart => client_c.restart_guest(&node, v, gt).await,
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
                        BatchOp::Stop { force: true } => {
                            client_c.stop_guest(&node, v, gt, true).await
                        }
                        BatchOp::Stop { force: false } => {
                            client_c.shutdown_guest(&node, v, gt).await
                        }
                        BatchOp::Restart => client_c.restart_guest(&node, v, gt).await,
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
            if let Ok((vmid, api_res)) = res {
                match api_res {
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
                        has_failure = true;
                    }
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

async fn hitl_serve(
    client: std::sync::Arc<crate::api::PxClient>,
    config: crate::config::ProfileConfig,
) -> Result<()> {
    use crate::api::ProxmoxGateway;
    use tracing::{error, info, warn};

    let tg_config = config
        .telegram
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Telegram not configured"))?;
    let tg_gateway = crate::hitl::telegram::TelegramGateway::new(tg_config);

    info!("Starting HITL daemon...");
    let mut offset = 0;
    // Vector 6 (Gemini audit) — exponential backoff on getUpdates
    // failure. Without this, sustained Telegram outage / DNS failure
    // would re-poll on a fixed cadence forever; with it we ramp from
    // 1 s to a 60 s ceiling so a multi-hour outage costs ~60 requests
    // per minute → ~1/min instead of 12/min.
    let mut backoff = std::time::Duration::from_secs(1);
    const BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(60);

    loop {
        // Vector 21 (macro audit) — graceful shutdown.
        //
        // Race the next getUpdates against SIGTERM/SIGINT so systemd
        // stops the daemon cleanly instead of escalating to SIGKILL
        // after the grace period. Long-poll has a 30 s window; the
        // signal handler resolves immediately when fired.
        let poll_fut = tg_gateway.poll_updates(offset, 30);
        let updates = tokio::select! {
            biased;
            () = crate::util::shutdown::wait_for_shutdown_signal() => {
                info!("HITL daemon: shutdown signal received, exiting cleanly");
                return Ok(());
            }
            res = poll_fut => res,
        };
        match updates {
            Ok(updates) => {
                // Reset backoff on success — the next failure starts fresh
                // at 1 s rather than carrying over the previous outage's
                // cap.
                backoff = std::time::Duration::from_secs(1);
                for update in updates {
                    offset = offset.max(update.update_id + 1);

                    if let Some(cb) = update.callback_query {
                        if let Some(data) = cb.data {
                            info!("Received HITL callback: {}", data);
                            let parts: Vec<&str> = data.split(':').collect();
                            if parts.len() >= 3 {
                                let decision = parts[0];
                                let action = parts[1];
                                let vmid: u32 = parts[2].parse().unwrap_or(0);

                                if decision == "approve" {
                                    // find node + guest_type (bug #1 fix: dispatch path)
                                    let mut target_node = None;
                                    let mut guest_type = None;
                                    if let Ok(nodes) = client.get_nodes().await {
                                        for n in nodes {
                                            if let Ok(guests) = client.get_guests(&n.node).await {
                                                if let Some(g) =
                                                    guests.iter().find(|g| g.vmid == vmid)
                                                {
                                                    target_node = Some(n.node.clone());
                                                    guest_type = Some(g.guest_type);
                                                    break;
                                                }
                                            }
                                        }
                                    }

                                    if let (Some(node), Some(gt)) = (target_node, guest_type) {
                                        // Bug #2 fix: HITL "stop" is graceful by default.
                                        let res = match action {
                                            "start" => client.start_guest(&node, vmid, gt).await,
                                            "stop" => client.shutdown_guest(&node, vmid, gt).await,
                                            "restart" => {
                                                client.restart_guest(&node, vmid, gt).await
                                            }
                                            _ => {
                                                warn!("Unknown action: {}", action);
                                                Err(anyhow::anyhow!("Unknown action"))
                                            }
                                        };

                                        match res {
                                            Ok(_) => {
                                                let _ = tg_gateway
                                                    .answer_callback(&cb.id, "✅ Executed")
                                                    .await;
                                            }
                                            Err(e) => {
                                                error!("Execution failed: {}", e);
                                                let _ = tg_gateway
                                                    .answer_callback(
                                                        &cb.id,
                                                        &format!("❌ Failed: {e}"),
                                                    )
                                                    .await;
                                            }
                                        }
                                    } else {
                                        let _ = tg_gateway
                                            .answer_callback(&cb.id, "❌ Node not found")
                                            .await;
                                    }
                                } else {
                                    let _ = tg_gateway.answer_callback(&cb.id, "🚫 Denied").await;
                                }
                            } else {
                                let _ = tg_gateway
                                    .answer_callback(&cb.id, "❌ Invalid transaction ID format")
                                    .await;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Polling error: {} — backing off {}s", e, backoff.as_secs());
                tokio::time::sleep(backoff).await;
                // Double until we hit the cap.
                backoff = (backoff * 2).min(BACKOFF_CAP);
            }
        }
    }
}
