//! Cluster-wide operations: pools (multi-tenant resource bags), global
//! options, resource aggregation, the cluster event log, PVE API
//! version, and Corosync bootstrap (node membership, join, qdevice).

use anyhow::Result;
use clap::Subcommand;
use serde_json::Value;
use std::sync::Arc;

/// Pool CRUD. Member changes (`add`/`remove`) split out so the operator
/// doesn't have to type `vms=` / `storage=` / `delete=1` form params
/// directly — typed flags compose into them.
#[derive(Debug, Subcommand)]
pub enum PoolCommand {
    /// List every pool in the cluster.
    List,
    /// Show one pool's full member list (mixed VMs/LXCs/storages).
    Show { poolid: String },
    /// Create a new (empty) pool.
    Create {
        #[arg(long)]
        poolid: String,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Add members (VMIDs and/or storage ids) to an existing pool.
    AddMembers {
        poolid: String,
        /// CSV of VMIDs to add (e.g. `100,200,300`).
        #[arg(long)]
        vms: Option<String>,
        /// CSV of storage ids to add (e.g. `local,pbs-main`).
        #[arg(long)]
        storage: Option<String>,
    },
    /// Remove members from a pool. Same shape as `add-members` but
    /// PVE-side it's the same PUT with `delete=1`.
    RemoveMembers {
        poolid: String,
        #[arg(long)]
        vms: Option<String>,
        #[arg(long)]
        storage: Option<String>,
    },
    /// Edit just the comment.
    SetComment {
        poolid: String,
        #[arg(long)]
        comment: String,
    },
    /// Delete an empty pool. PVE rejects with 400 if there are still
    /// members — `remove-members` first.
    Delete {
        poolid: String,
        #[arg(long)]
        yes: bool,
    },
}

/// Cluster-wide config. Just `get` + `set` — most operators read once,
/// edit a few fields, walk away. `--raw KEY=VAL` covers the long tail
/// of less-common knobs (crs, fencing, u2f schema).
#[derive(Debug, Subcommand)]
pub enum ClusterConfigCommand {
    Get,
    /// Update one or more cluster-wide options. Refuses no-op calls.
    Set {
        /// MAC prefix for auto-generated guest NICs (e.g. `BC:24:11`).
        #[arg(long)]
        mac_prefix: Option<String>,
        /// Default migration network/type (e.g.
        /// `type=insecure,network=10.0.0.0/24`).
        #[arg(long)]
        migration: Option<String>,
        #[arg(long)]
        description: Option<String>,
        /// Console viewer choice: `applet` | `vv` | `html5` | `xtermjs`.
        #[arg(long)]
        console: Option<String>,
        /// Default keyboard layout for VNC/console.
        #[arg(long)]
        keyboard: Option<String>,
        #[arg(long)]
        max_workers: Option<u32>,
        #[arg(long)]
        email_from: Option<String>,
        /// Allowed tags (semicolon-separated).
        #[arg(long)]
        registered_tags: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
}

/// Corosync cluster bootstrap. Four sub-trees: `nodes` (membership),
/// `join` (bootstrap a new node into an existing cluster), `qdevice`
/// (3rd-party tiebreaker for even-node clusters), `totem` (read-only
/// transport inspection).
#[derive(Debug, Subcommand)]
pub enum ClusterBootstrapCommand {
    #[command(subcommand)]
    Nodes(CorosyncNodesCommand),
    #[command(subcommand)]
    Join(ClusterJoinCommand),
    #[command(subcommand)]
    Qdevice(ClusterQdeviceCommand),
    /// Inspect corosync totem transport config (read-only — totem
    /// changes go through `/etc/pve/corosync.conf` editing).
    Totem,
}

#[derive(Debug, Subcommand)]
pub enum CorosyncNodesCommand {
    List,
    /// Add a node to corosync membership. Optional knobs let you pin
    /// the nodeid + ring addresses + vote count instead of letting
    /// PVE auto-assign.
    Add {
        node: String,
        /// Primary corosync ring address (hostname or IP).
        #[arg(long)]
        ring0_addr: Option<String>,
        /// Secondary corosync ring address (knet redundancy).
        #[arg(long)]
        ring1_addr: Option<String>,
        /// Pin the corosync nodeid (default: PVE auto-assigns).
        #[arg(long)]
        nodeid: Option<u32>,
        /// Quorum votes for this node (default 1).
        #[arg(long)]
        votes: Option<u32>,
        /// Skip safety checks (dangerous — only for recovery).
        #[arg(long, default_value_t = false)]
        force: bool,
        #[arg(long)]
        raw: Vec<String>,
    },
    /// Remove a node from corosync membership. Destructive — requires `--yes`.
    Remove {
        node: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ClusterJoinCommand {
    /// Fetch the join data + totem config + cert fingerprint a new
    /// node needs to join. PVE 8+ requires `--node` (the new node's
    /// intended name).
    Info {
        #[arg(long)]
        node: Option<String>,
    },
    /// Actually join an existing cluster from the new-node side.
    /// Needs the target cluster's hostname + a root password + the
    /// cert fingerprint (use `info` on the target side first).
    /// Returns a UPID — corosync restart involved.
    Join {
        /// Target cluster node hostname/IP.
        #[arg(long)]
        hostname: String,
        /// Root password on the target node.
        #[arg(long)]
        password: String,
        /// Cluster cert fingerprint (SHA-256, colon-separated).
        #[arg(long)]
        fingerprint: String,
        /// Override this new node's nodeid (default: auto-assigned).
        #[arg(long)]
        nodeid: Option<u32>,
        /// Override this node's vote count.
        #[arg(long)]
        votes: Option<u32>,
        /// Force-join despite safety check failures.
        #[arg(long, default_value_t = false)]
        force: bool,
        #[arg(long)]
        raw: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ClusterQdeviceCommand {
    /// Read the current quorum-device config (singleton per cluster).
    Get,
    /// Set up a new quorum device. Required: `--addr` (qdevice host).
    /// Returns a UPID (corosync restart).
    Setup {
        /// Quorum device host address.
        #[arg(long)]
        addr: String,
        /// Voting algorithm: `ffsplit` | `lms` (last-man-standing).
        #[arg(long)]
        algorithm: Option<String>,
        /// Tie-breaker mode: `lowest` | `highest` | `valid_quorum_policy`.
        #[arg(long)]
        tie_breaker: Option<String>,
        /// Operator name on the qdevice host (default `root`).
        #[arg(long)]
        net_username: Option<String>,
        /// Force-setup despite safety check failures.
        #[arg(long, default_value_t = false)]
        force: bool,
        #[arg(long)]
        raw: Vec<String>,
    },
    /// Update an existing qdevice config (no-op refused).
    Update {
        #[arg(long)]
        algorithm: Option<String>,
        #[arg(long)]
        tie_breaker: Option<String>,
        #[arg(long)]
        force: Option<bool>,
        #[arg(long)]
        raw: Vec<String>,
    },
    /// Remove the quorum device. Destructive — requires `--yes`.
    /// Returns a UPID.
    Delete {
        #[arg(long)]
        yes: bool,
    },
}

/// Pool dispatch. `add-members` / `remove-members` both compose into
/// the same PVE PUT (PVE uses `delete=1` to flip the operation), so
/// we route them through a single helper.
pub async fn execute_pool(
    client: &Arc<crate::api::PxClient>,
    action: PoolCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn member_params<'a>(
        vms: Option<&'a String>,
        storage: Option<&'a String>,
    ) -> Vec<(&'a str, &'a str)> {
        let mut p = vec![];
        if let Some(v) = vms {
            p.push(("vms", v.as_str()));
        }
        if let Some(s) = storage {
            p.push(("storage", s.as_str()));
        }
        p
    }

    match action {
        PoolCommand::List => {
            let pools = client.list_pools().await?;
            Ok((serde_json::to_value(pools)?, 0))
        }
        PoolCommand::Show { poolid } => {
            let p = client.get_pool(&poolid).await?;
            Ok((serde_json::to_value(p)?, 0))
        }
        PoolCommand::Create { poolid, comment } => {
            let mut params: Vec<(&str, &str)> = vec![("poolid", poolid.as_str())];
            if let Some(c) = comment.as_deref() {
                params.push(("comment", c));
            }
            client.create_pool(&params).await?;
            Ok((serde_json::json!({"created": poolid}), 0))
        }
        PoolCommand::AddMembers {
            poolid,
            vms,
            storage,
        } => {
            let params = member_params(vms.as_ref(), storage.as_ref());
            if params.is_empty() {
                anyhow::bail!("add-members needs at least one of --vms or --storage");
            }
            client.update_pool(&poolid, &params).await?;
            Ok((serde_json::json!({"added": true}), 0))
        }
        PoolCommand::RemoveMembers {
            poolid,
            vms,
            storage,
        } => {
            let mut params = member_params(vms.as_ref(), storage.as_ref());
            if params.is_empty() {
                anyhow::bail!("remove-members needs at least one of --vms or --storage");
            }
            params.push(("delete", "1"));
            client.update_pool(&poolid, &params).await?;
            Ok((serde_json::json!({"removed": true}), 0))
        }
        PoolCommand::SetComment { poolid, comment } => {
            client
                .update_pool(&poolid, &[("comment", comment.as_str())])
                .await?;
            Ok((serde_json::json!({"updated": poolid}), 0))
        }
        PoolCommand::Delete { poolid, yes } => {
            crate::cli::common::require_yes(yes, "pool delete")?;
            client.delete_pool(&poolid).await?;
            Ok((serde_json::json!({"deleted": poolid}), 0))
        }
    }
}

/// `proxxx cluster-resources [--kind ...]` — dump the single-shot
/// cluster-wide resource list. The PVE web UI's main dashboard query.
pub async fn execute_resources(
    client: &Arc<crate::api::PxClient>,
    kind: Option<String>,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    let resources = client.get_cluster_resources(kind.as_deref()).await?;
    Ok((
        serde_json::json!({"count": resources.len(), "resources": resources}),
        0,
    ))
}

/// `proxxx pve-version` — PVE API version + git rev. Output is the
/// typed shape so it's easy to grep with jq for compat-gating scripts.
/// (Distinct from `proxxx version` which reports proxxx's own binary
/// version + build metadata.)
pub async fn execute_pve_version(client: &Arc<crate::api::PxClient>) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    let v = client.get_api_version().await?;
    Ok((serde_json::to_value(v)?, 0))
}

/// `proxxx cluster-config {get|set}` — global cluster options.
pub async fn execute_config(
    client: &Arc<crate::api::PxClient>,
    action: ClusterConfigCommand,
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
        ClusterConfigCommand::Get => {
            let opts = client.get_cluster_options().await?;
            Ok((serde_json::to_value(opts)?, 0))
        }
        ClusterConfigCommand::Set {
            mac_prefix,
            migration,
            description,
            console,
            keyboard,
            max_workers,
            email_from,
            registered_tags,
            raw,
        } => {
            let mut typed: Vec<(&str, String)> = vec![];
            let push_opt =
                |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                    if let Some(s) = v {
                        t.push((k, s));
                    }
                };
            push_opt(&mut typed, "mac_prefix", mac_prefix);
            push_opt(&mut typed, "migration", migration);
            push_opt(&mut typed, "description", description);
            push_opt(&mut typed, "console", console);
            push_opt(&mut typed, "keyboard", keyboard);
            if let Some(n) = max_workers {
                typed.push(("max_workers", n.to_string()));
            }
            push_opt(&mut typed, "email_from", email_from);
            // Hyphenated wire field needs the literal hyphen, not the
            // snake_case CLI flag name.
            if let Some(t) = registered_tags {
                typed.push(("registered-tags", t));
            }
            if typed.is_empty() && raw.is_empty() {
                anyhow::bail!("set needs at least one field");
            }
            let owned = build_params(typed, &raw)?;
            client.update_cluster_options(&as_refs(&owned)).await?;
            Ok((serde_json::json!({"updated": true}), 0))
        }
    }
}

/// `proxxx cluster-log [--max N]` — recent cluster events. Newest
/// first. Useful for "what happened around 14:30 yesterday" diagnostics.
pub async fn execute_log(
    client: &Arc<crate::api::PxClient>,
    max: Option<u32>,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    let entries = client.get_cluster_log(max).await?;
    Ok((
        serde_json::json!({"count": entries.len(), "entries": entries}),
        0,
    ))
}

/// Corosync cluster bootstrap dispatch. Most mutations return UPIDs
/// (corosync restart on the cluster involves real reconfiguration).
#[allow(clippy::too_many_lines)]
pub async fn execute_bootstrap(
    client: &Arc<crate::api::PxClient>,
    action: ClusterBootstrapCommand,
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
        ClusterBootstrapCommand::Nodes(cmd) => match cmd {
            CorosyncNodesCommand::List => {
                let nodes = client.list_cluster_corosync_nodes().await?;
                Ok((serde_json::to_value(nodes)?, 0))
            }
            CorosyncNodesCommand::Add {
                node,
                ring0_addr,
                ring1_addr,
                nodeid,
                votes,
                force,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                let push_opt =
                    |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                        if let Some(s) = v {
                            t.push((k, s));
                        }
                    };
                push_opt(&mut typed, "ring0_addr", ring0_addr);
                push_opt(&mut typed, "ring1_addr", ring1_addr);
                if let Some(n) = nodeid {
                    typed.push(("nodeid", n.to_string()));
                }
                if let Some(v) = votes {
                    typed.push(("votes", v.to_string()));
                }
                if force {
                    typed.push(("force", "1".to_string()));
                }
                let owned = build_params(typed, &raw)?;
                client
                    .add_cluster_corosync_node(&node, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"added": node}), 0))
            }
            CorosyncNodesCommand::Remove { node, yes } => {
                crate::cli::common::require_yes(yes, "corosync node removal")?;
                client.remove_cluster_corosync_node(&node).await?;
                Ok((serde_json::json!({"removed": node}), 0))
            }
        },
        ClusterBootstrapCommand::Join(cmd) => match cmd {
            ClusterJoinCommand::Info { node } => {
                let info = client.get_cluster_join_info(node.as_deref()).await?;
                Ok((info, 0))
            }
            ClusterJoinCommand::Join {
                hostname,
                password,
                fingerprint,
                nodeid,
                votes,
                force,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![
                    ("hostname", hostname),
                    ("password", password),
                    ("fingerprint", fingerprint),
                ];
                if let Some(n) = nodeid {
                    typed.push(("nodeid", n.to_string()));
                }
                if let Some(v) = votes {
                    typed.push(("votes", v.to_string()));
                }
                if force {
                    typed.push(("force", "1".to_string()));
                }
                let owned = build_params(typed, &raw)?;
                let upid = client.join_cluster(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"upid": upid}), 0))
            }
        },
        ClusterBootstrapCommand::Qdevice(cmd) => match cmd {
            ClusterQdeviceCommand::Get => {
                let q = client.get_cluster_qdevice().await?;
                Ok((q, 0))
            }
            ClusterQdeviceCommand::Setup {
                addr,
                algorithm,
                tie_breaker,
                net_username,
                force,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("addr", addr)];
                let push_opt =
                    |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                        if let Some(s) = v {
                            t.push((k, s));
                        }
                    };
                push_opt(&mut typed, "algorithm", algorithm);
                push_opt(&mut typed, "tie_breaker", tie_breaker);
                push_opt(&mut typed, "net_username", net_username);
                if force {
                    typed.push(("force", "1".to_string()));
                }
                let owned = build_params(typed, &raw)?;
                let upid = client.setup_cluster_qdevice(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"upid": upid}), 0))
            }
            ClusterQdeviceCommand::Update {
                algorithm,
                tie_breaker,
                force,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                let push_opt =
                    |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                        if let Some(s) = v {
                            t.push((k, s));
                        }
                    };
                push_opt(&mut typed, "algorithm", algorithm);
                push_opt(&mut typed, "tie_breaker", tie_breaker);
                if let Some(f) = force {
                    typed.push(("force", if f { "1" } else { "0" }.to_string()));
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                let upid = client.update_cluster_qdevice(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"upid": upid}), 0))
            }
            ClusterQdeviceCommand::Delete { yes } => {
                crate::cli::common::require_yes(yes, "QDevice delete")?;
                let upid = client.remove_cluster_qdevice().await?;
                Ok((serde_json::json!({"upid": upid}), 0))
            }
        },
        ClusterBootstrapCommand::Totem => {
            let totem = client.get_cluster_totem().await?;
            Ok((totem, 0))
        }
    }
}
