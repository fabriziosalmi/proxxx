//! Per-node operations: lifecycle (start/stop all guests), shells, OS-level
//! system config (DNS, hosts, time, subscription, certs), and hardware
//! inventory (PCI/USB passthrough + conflict detection).

use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum NodeShellKind {
    /// Web-based xterm.js shell (POST /termproxy).
    Term,
    /// VNC framebuffer shell (POST /vncshell).
    Vnc,
    /// SPICE shell (POST /spiceshell).
    Spice,
}

#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    /// Start every auto-start guest on the node (`onboot=1` config).
    /// Returns one UPID for the whole batch — track via
    /// `proxxx tasks`. Sequenced PVE-side by `bootorder`.
    Startall {
        /// Target node name (e.g. `pve1`).
        node: String,
    },
    /// Graceful shutdown of every running guest on the node.
    Stopall { node: String },
    /// Suspend every running guest (PVE 8+). On older PVE versions the
    /// endpoint 404s and the call surfaces `ApiError::NotFound`.
    Suspendall { node: String },
    /// Mint a one-shot ticket for shell access to the NODE itself
    /// (not a guest). Three flavours: term (xterm.js), vnc, spice.
    /// proxxx prints the ticket as JSON for handoff to a viewer; it
    /// does NOT embed a graphical client.
    Shell {
        node: String,
        #[arg(long, value_enum, default_value_t = NodeShellKind::Term)]
        kind: NodeShellKind,
    },
}

/// System-level configuration per node. These endpoints land under
/// `/api2/json/nodes/{node}/...` rather than `/cluster/...` — the
/// scope is one host. Grouped under `node-system <node> ...` because
/// in practice a sysadmin walking into "this node is misbehaving"
/// reaches for several of them in the same maintenance window
/// (check NTP, peek the journal, reload pveproxy after cert upload).
#[derive(Debug, Subcommand)]
pub enum NodeSystemCommand {
    /// DNS resolver config (search domain + up to 3 nameservers).
    #[command(subcommand)]
    Dns(NodeDnsCommand),
    /// `/etc/hosts` content + digest-guarded atomic replace.
    #[command(subcommand)]
    Hosts(NodeHostsCommand),
    /// Tail systemd journal with PVE filters.
    Journal {
        /// ISO timestamp or relative (`-1h`, `yesterday`).
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        /// Cap on returned entries.
        #[arg(long)]
        lastentries: Option<u32>,
        /// Filter to one systemd unit (e.g. `ssh`, `corosync`).
        #[arg(long)]
        service: Option<String>,
    },
    /// Tail `/var/log/syslog` (line-numbered for paging).
    Syslog {
        /// 1-indexed start cursor — pass back the last `n` from the
        /// previous response to paginate forward.
        #[arg(long)]
        start: Option<u64>,
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(long)]
        service: Option<String>,
    },
    /// NTP / timezone — `get` reports clock + zone, `set` updates
    /// timezone (clock itself is NTP-driven).
    #[command(subcommand)]
    Time(NodeTimeCommand),
    /// Wake the node from S5/standby via cluster-network magic packet.
    Wol,
    /// Subscription state + key management.
    #[command(subcommand)]
    Subscription(NodeSubscriptionCommand),
    /// pveproxy TLS certificates — list, upload custom, delete custom,
    /// order ACME.
    #[command(subcommand)]
    Cert(NodeCertCommand),
    /// `pvereport` support bundle (plain text, many KB).
    Report,
}

#[derive(Debug, Subcommand)]
pub enum NodeDnsCommand {
    Get,
    Set {
        #[arg(long)]
        search: Option<String>,
        #[arg(long)]
        dns1: Option<String>,
        #[arg(long)]
        dns2: Option<String>,
        #[arg(long)]
        dns3: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum NodeHostsCommand {
    Get,
    /// Replace the entire `/etc/hosts` content. PVE rejects with 412
    /// if `--digest` doesn't match the current file (atomic update);
    /// pass `--no-check` to skip the digest guard.
    Set {
        /// Literal file content (use shell quoting for newlines).
        #[arg(long)]
        data: String,
        /// SHA-1 digest from a prior `get` — required unless
        /// `--no-check` is passed.
        #[arg(long)]
        digest: Option<String>,
        #[arg(long)]
        no_check: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum NodeTimeCommand {
    Get,
    Set {
        /// IANA timezone name (e.g. `Europe/Rome`, `UTC`).
        #[arg(long)]
        timezone: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum NodeSubscriptionCommand {
    /// Show current subscription state — status, level, due date.
    Get,
    /// Set the subscription key. PVE validates against the licensing
    /// server inline; failure surfaces as an API error.
    Set {
        #[arg(long)]
        key: String,
    },
    /// Force re-validate of the existing key (e.g. after a network blip).
    Refresh,
    /// Remove the subscription key. Destructive — requires `--yes`.
    Delete {
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum NodeCertCommand {
    /// List currently-served certs (filename, fingerprint, expiry, SAN).
    Info,
    /// Upload an operator-managed cert + key (writes to
    /// `pveproxy-ssl.{pem,key}`).
    Upload {
        /// PEM-encoded certificate (literal content).
        #[arg(long)]
        certificate: String,
        /// PEM-encoded private key (literal content).
        #[arg(long)]
        key: String,
        /// Reload pveproxy after writing.
        #[arg(long, default_value_t = false)]
        restart: bool,
    },
    /// Remove the operator-uploaded custom cert.
    Delete {
        #[arg(long, default_value_t = false)]
        restart: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Trigger ACME order/renewal. Returns a UPID (long task —
    /// DNS-01 / HTTP-01 round-trips with the CA).
    AcmeOrder {
        /// Renew even if the existing cert isn't near expiry.
        #[arg(long, default_value_t = false)]
        force: bool,
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

/// Hill B — bulk node power. Each subcommand is a single POST to PVE;
/// returns the batch UPID for `proxxx tasks` follow-up.
pub async fn execute_node(
    client: &Arc<crate::api::PxClient>,
    action: NodeCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        NodeCommand::Startall { node } => {
            let upid = client.startall_node(&node).await?;
            Ok((
                serde_json::json!({"action": "startall", "status": "submitted", "upid": upid}),
                0,
            ))
        }
        NodeCommand::Stopall { node } => {
            let upid = client.stopall_node(&node).await?;
            Ok((
                serde_json::json!({"action": "stopall", "status": "submitted", "upid": upid}),
                0,
            ))
        }
        NodeCommand::Suspendall { node } => {
            let upid = client.suspendall_node(&node).await?;
            Ok((
                serde_json::json!({"action": "suspendall", "status": "submitted", "upid": upid}),
                0,
            ))
        }
        NodeCommand::Shell { node, kind } => match kind {
            NodeShellKind::Term => {
                let t = client.get_node_termproxy(&node).await?;
                Ok((serde_json::to_value(t)?, 0))
            }
            NodeShellKind::Vnc => {
                let t = client.get_node_vncshell(&node).await?;
                Ok((serde_json::to_value(t)?, 0))
            }
            NodeShellKind::Spice => {
                let t = client.get_node_spiceshell(&node).await?;
                Ok((serde_json::to_value(t)?, 0))
            }
        },
    }
}

#[allow(clippy::too_many_lines)]
pub async fn execute_system(
    client: &Arc<crate::api::PxClient>,
    node: &str,
    action: NodeSystemCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn push_opt<'a>(v: &mut Vec<(&'a str, String)>, key: &'a str, val: Option<String>) {
        if let Some(s) = val {
            v.push((key, s));
        }
    }
    fn as_refs<'a>(v: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
        v.iter().map(|(k, s)| (*k, s.as_str())).collect()
    }

    match action {
        NodeSystemCommand::Dns(cmd) => match cmd {
            NodeDnsCommand::Get => {
                let dns = client.get_node_dns(node).await?;
                Ok((serde_json::to_value(dns)?, 0))
            }
            NodeDnsCommand::Set {
                search,
                dns1,
                dns2,
                dns3,
            } => {
                let mut params: Vec<(&str, String)> = vec![];
                push_opt(&mut params, "search", search);
                push_opt(&mut params, "dns1", dns1);
                push_opt(&mut params, "dns2", dns2);
                push_opt(&mut params, "dns3", dns3);
                if params.is_empty() {
                    anyhow::bail!("set needs at least one field");
                }
                client.update_node_dns(node, &as_refs(&params)).await?;
                Ok((serde_json::json!({"updated": true}), 0))
            }
        },
        NodeSystemCommand::Hosts(cmd) => match cmd {
            NodeHostsCommand::Get => {
                let h = client.get_node_hosts(node).await?;
                Ok((serde_json::to_value(h)?, 0))
            }
            NodeHostsCommand::Set {
                data,
                digest,
                no_check,
            } => {
                let resolved_digest = if no_check {
                    None
                } else {
                    match digest {
                        Some(d) => Some(d),
                        None => Some(client.get_node_hosts(node).await?.digest),
                    }
                };
                client
                    .update_node_hosts(node, &data, resolved_digest.as_deref())
                    .await?;
                Ok((serde_json::json!({"updated": true}), 0))
            }
        },
        NodeSystemCommand::Journal {
            since,
            until,
            lastentries,
            service,
        } => {
            let mut q: Vec<(&str, String)> = vec![];
            push_opt(&mut q, "since", since);
            push_opt(&mut q, "until", until);
            if let Some(n) = lastentries {
                q.push(("lastentries", n.to_string()));
            }
            push_opt(&mut q, "service", service);
            let lines = client.get_node_journal(node, &as_refs(&q)).await?;
            Ok((
                serde_json::json!({"node": node, "count": lines.len(), "lines": lines}),
                0,
            ))
        }
        NodeSystemCommand::Syslog {
            start,
            limit,
            since,
            until,
            service,
        } => {
            let mut q: Vec<(&str, String)> = vec![];
            if let Some(s) = start {
                q.push(("start", s.to_string()));
            }
            if let Some(l) = limit {
                q.push(("limit", l.to_string()));
            }
            push_opt(&mut q, "since", since);
            push_opt(&mut q, "until", until);
            push_opt(&mut q, "service", service);
            let lines = client.get_node_syslog(node, &as_refs(&q)).await?;
            Ok((serde_json::to_value(lines)?, 0))
        }
        NodeSystemCommand::Time(cmd) => match cmd {
            NodeTimeCommand::Get => {
                let t = client.get_node_time(node).await?;
                Ok((serde_json::to_value(t)?, 0))
            }
            NodeTimeCommand::Set { timezone } => {
                client.update_node_timezone(node, &timezone).await?;
                Ok((serde_json::json!({"timezone": timezone}), 0))
            }
        },
        NodeSystemCommand::Wol => {
            let mac = client.wakeonlan_node(node).await?;
            Ok((serde_json::json!({"node": node, "mac": mac}), 0))
        }
        NodeSystemCommand::Subscription(cmd) => match cmd {
            NodeSubscriptionCommand::Get => {
                let s = client.get_node_subscription(node).await?;
                Ok((serde_json::to_value(s)?, 0))
            }
            NodeSubscriptionCommand::Set { key } => {
                client.set_node_subscription_key(node, &key).await?;
                Ok((serde_json::json!({"set": true}), 0))
            }
            NodeSubscriptionCommand::Refresh => {
                client.refresh_node_subscription(node).await?;
                Ok((serde_json::json!({"refreshed": true}), 0))
            }
            NodeSubscriptionCommand::Delete { yes } => {
                crate::cli::common::require_yes(yes, "node subscription delete")?;
                client.delete_node_subscription(node).await?;
                Ok((serde_json::json!({"deleted": true}), 0))
            }
        },
        NodeSystemCommand::Cert(cmd) => match cmd {
            NodeCertCommand::Info => {
                let info = client.get_node_certificates_info(node).await?;
                Ok((serde_json::to_value(info)?, 0))
            }
            NodeCertCommand::Upload {
                certificate,
                key,
                restart,
            } => {
                let restart_str = if restart { "1" } else { "0" };
                let params: Vec<(&str, &str)> = vec![
                    ("certificates", certificate.as_str()),
                    ("key", key.as_str()),
                    ("restart", restart_str),
                ];
                client.upload_node_custom_certificate(node, &params).await?;
                Ok((
                    serde_json::json!({"uploaded": true, "restarted": restart}),
                    0,
                ))
            }
            NodeCertCommand::Delete { restart, yes } => {
                crate::cli::common::require_yes(yes, "node certificate delete")?;
                client.delete_node_custom_certificate(node, restart).await?;
                Ok((
                    serde_json::json!({"deleted": true, "restarted": restart}),
                    0,
                ))
            }
            NodeCertCommand::AcmeOrder { force } => {
                let upid = client.order_node_acme_certificate(node, force).await?;
                Ok((serde_json::json!({"upid": upid, "force": force}), 0))
            }
        },
        NodeSystemCommand::Report => {
            let txt = client.get_node_report(node).await?;
            Ok((
                serde_json::json!({"node": node, "bytes": txt.len(), "report": txt}),
                0,
            ))
        }
    }
}

pub async fn execute_hw(
    client: &Arc<crate::api::PxClient>,
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
            let mut configs: std::collections::HashMap<
                u32,
                std::collections::HashMap<String, String>,
            > = std::collections::HashMap::new();
            // Errors propagate: a dropped guest/config would hide a real PCI
            // passthrough conflict (silent partial detection is dangerous here).
            for g in client.get_all_guests().await? {
                let cfg = client
                    .get_guest_config(&g.node, g.vmid, &g.guest_type)
                    .await?;
                configs.insert(g.vmid, cfg);
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
            let exit = i32::from(!conflicts.is_empty());
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
