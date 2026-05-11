//! PVE firewall + cluster passthrough device mappings.
//!
//! `proxxx firewall --scope ...` is read-only across cluster/node/guest;
//! `firewall-cluster` and `firewall-guest` are CRUD on aliases, groups,
//! ipsets and per-scope options. `cluster-mapping {pci,usb}` manages the
//! stable-name passthrough table that survives live migration.

use anyhow::Result;
use clap::Subcommand;
use serde_json::Value;
use std::sync::Arc;

use crate::cli::common::find_guest;

/// Three firewall rule scopes, mirrored from PVE. Each scope is a
/// distinct iptables chain on the host; a packet may traverse rules
/// in all three depending on its path.
#[derive(Debug, Subcommand)]
pub enum FirewallScope {
    /// Datacenter-wide rules (apply to every node and guest).
    Cluster,
    /// Rules attached to a single node's host iptables.
    Node {
        /// Node name
        node: String,
    },
    /// Rules attached to a guest's NIC chain (resolved automatically
    /// from VMID — works for QEMU and LXC).
    Guest {
        /// Guest VMID
        vmid: u32,
    },
}

/// Cluster firewall CRUD: aliases (named CIDRs), security groups
/// (rule bundles), ipsets (CIDR collections), and the global options.
/// Splits into four sub-trees so the help text stays grokable — each
/// resource has its own list/create/delete plus resource-specific
/// extras (e.g. `ipset add-cidr`).
#[derive(Debug, Subcommand)]
pub enum FirewallClusterCommand {
    #[command(subcommand)]
    Alias(FirewallAliasCommand),
    #[command(subcommand)]
    Group(FirewallGroupCommand),
    #[command(subcommand)]
    Ipset(FirewallIpsetCommand),
    #[command(subcommand)]
    Options(FirewallOptionsCommand),
}

#[derive(Debug, Subcommand)]
pub enum FirewallAliasCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
        /// CIDR or single IP — e.g. `10.0.0.0/8` or `192.168.1.1`.
        #[arg(long)]
        cidr: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        name: String,
        #[arg(long)]
        cidr: Option<String>,
        #[arg(long)]
        comment: Option<String>,
        /// Rename the alias atomically (PVE PUT param `rename`).
        #[arg(long)]
        rename: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum FirewallGroupCommand {
    List,
    Create {
        /// Group name (operator-chosen, e.g. `web-allow`).
        #[arg(long)]
        group: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        group: String,
        #[arg(long)]
        yes: bool,
    },
    /// List the rules contained in a security group — same shape as
    /// `proxxx firewall --scope cluster`, but filtered to one group.
    Rules {
        group: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum FirewallIpsetCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        name: String,
        #[arg(long)]
        yes: bool,
    },
    /// List the CIDRs inside an ipset.
    Cidrs {
        name: String,
    },
    AddCidr {
        name: String,
        #[arg(long)]
        cidr: String,
        /// Invert membership for this CIDR (carves an exception out of
        /// a broader range — `nomatch=1` in PVE terms).
        #[arg(long, default_value_t = false)]
        nomatch: bool,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    RemoveCidr {
        name: String,
        cidr: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum FirewallOptionsCommand {
    /// Read the cluster-wide firewall options.
    Get,
    /// Update one or more cluster-wide firewall options. Refuses no-op
    /// calls (at least one field must change).
    Set {
        /// Master switch — `0` disables the entire cluster firewall.
        #[arg(long)]
        enable: Option<bool>,
        /// `ACCEPT` | `REJECT` | `DROP` (case-sensitive on PVE).
        #[arg(long)]
        policy_in: Option<String>,
        #[arg(long)]
        policy_out: Option<String>,
        #[arg(long)]
        ebtables: Option<bool>,
        /// e.g. `enable=1,burst=5,rate=1/second`.
        #[arg(long)]
        log_ratelimit: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
}

/// Per-guest firewall sub-tree. Same alias CRUD shape as cluster
/// firewall, plus the per-guest options surface (which adds NIC-level
/// knobs absent from the cluster scope: macfilter, ipfilter, dhcp/ndp
/// auto-allow, radv).
#[derive(Debug, Subcommand)]
pub enum FirewallGuestCommand {
    #[command(subcommand)]
    Alias(GuestFirewallAliasCommand),
    #[command(subcommand)]
    Options(GuestFirewallOptionsCommand),
}

#[derive(Debug, Subcommand)]
pub enum GuestFirewallAliasCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        cidr: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        name: String,
        #[arg(long)]
        cidr: Option<String>,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        rename: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum GuestFirewallOptionsCommand {
    Get,
    /// Update per-guest firewall options. Refuses no-op calls.
    Set {
        #[arg(long)]
        enable: Option<bool>,
        #[arg(long)]
        policy_in: Option<String>,
        #[arg(long)]
        policy_out: Option<String>,
        /// `emerg`..`debug` | `nolog`. Empty = inherit cluster default.
        #[arg(long)]
        log_level_in: Option<String>,
        #[arg(long)]
        log_level_out: Option<String>,
        /// Auto-allow DHCP request/reply.
        #[arg(long)]
        dhcp: Option<bool>,
        /// Auto-allow IPv6 NDP.
        #[arg(long)]
        ndp: Option<bool>,
        /// Drop frames whose source MAC ≠ NIC MAC.
        #[arg(long)]
        macfilter: Option<bool>,
        /// Drop frames whose source IP isn't in the per-VM ipset.
        #[arg(long)]
        ipfilter: Option<bool>,
        /// LXC-only: allow router advertisements.
        #[arg(long)]
        radv: Option<bool>,
        #[arg(long)]
        raw: Vec<String>,
    },
}

/// Cluster hardware mapping CRUD — split by device class because the
/// PCI shape carries the mediated-device flag (vGPU) that USB doesn't.
#[derive(Debug, Subcommand)]
pub enum ClusterMappingCommand {
    #[command(subcommand)]
    Pci(ClusterMappingPciCommand),
    #[command(subcommand)]
    Usb(ClusterMappingUsbCommand),
}

#[derive(Debug, Subcommand)]
pub enum ClusterMappingPciCommand {
    List,
    /// Create a new PCI mapping. The `--map` arg accepts the wire
    /// format PVE expects, e.g.
    /// `--map "node=pve1,path=0000:01:00.0,id=10de:2684,iommugroup=13"`.
    /// Repeat once per cluster node.
    Create {
        #[arg(long)]
        id: String,
        #[arg(long)]
        description: Option<String>,
        /// `1` if this is a mediated device (vGPU).
        #[arg(long)]
        mdev: Option<bool>,
        /// One or more `node=…,path=…,id=…[,iommugroup=…]` strings.
        #[arg(long, required = true)]
        map: Vec<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        id: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        mdev: Option<bool>,
        #[arg(long)]
        map: Vec<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        id: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ClusterMappingUsbCommand {
    List,
    Create {
        #[arg(long)]
        id: String,
        #[arg(long)]
        description: Option<String>,
        /// One or more `node=…,path=…,id=…` strings.
        #[arg(long, required = true)]
        map: Vec<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        id: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        map: Vec<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        id: String,
        #[arg(long)]
        yes: bool,
    },
}

pub async fn execute_firewall(
    client: &Arc<crate::api::PxClient>,
    scope: FirewallScope,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    let (rules, scope_label) = match scope {
        FirewallScope::Cluster => {
            let rules = client.list_cluster_firewall_rules().await?;
            (rules, serde_json::json!({"scope": "cluster"}))
        }
        FirewallScope::Node { node } => {
            let rules = client.list_node_firewall_rules(&node).await?;
            (rules, serde_json::json!({"scope": "node", "node": node}))
        }
        FirewallScope::Guest { vmid } => {
            let (node, gt) = find_guest(client, vmid).await?;
            let rules = client.list_guest_firewall_rules(&node, vmid, gt).await?;
            (
                rules,
                serde_json::json!({
                    "scope": "guest",
                    "node": node,
                    "vmid": vmid,
                    "guest_type": format!("{gt:?}").to_lowercase(),
                }),
            )
        }
    };
    Ok((
        serde_json::json!({
            "context": scope_label,
            "rules": rules,
            "count": rules.len(),
        }),
        0,
    ))
}

/// Cluster firewall CRUD dispatch. Reuses the same `build_params`
/// pattern as backup-jobs: typed flags merged with `--raw KEY=VAL`
/// overrides, with `Box::leak` providing the static lifetime needed
/// for the `&[(&str, &str)]` shape `PxClient` takes. Acceptable here
/// because the process exits immediately after dispatching one CLI
/// invocation — the leak is bounded.
#[allow(clippy::too_many_lines)]
pub async fn execute_firewall_cluster(
    client: &Arc<crate::api::PxClient>,
    action: FirewallClusterCommand,
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
        v.iter().map(|(k, v)| (*k, v.as_str())).collect()
    }

    match action {
        FirewallClusterCommand::Alias(cmd) => {
            match cmd {
                FirewallAliasCommand::List => {
                    let aliases = client.list_cluster_firewall_aliases().await?;
                    Ok((serde_json::to_value(aliases)?, 0))
                }
                FirewallAliasCommand::Create {
                    name,
                    cidr,
                    comment,
                    raw,
                } => {
                    let mut typed: Vec<(&str, String)> = vec![("name", name), ("cidr", cidr)];
                    if let Some(c) = comment {
                        typed.push(("comment", c));
                    }
                    let owned = build_params(typed, &raw)?;
                    client
                        .create_cluster_firewall_alias(&as_refs(&owned))
                        .await?;
                    Ok((serde_json::json!({"created": true}), 0))
                }
                FirewallAliasCommand::Update {
                    name,
                    cidr,
                    comment,
                    rename,
                    raw,
                } => {
                    let mut typed: Vec<(&str, String)> = vec![];
                    if let Some(c) = cidr {
                        typed.push(("cidr", c));
                    }
                    if let Some(c) = comment {
                        typed.push(("comment", c));
                    }
                    if let Some(r) = rename {
                        typed.push(("rename", r));
                    }
                    if typed.is_empty() && raw.is_empty() {
                        anyhow::bail!("update needs at least one field (--cidr, --comment, --rename, or --raw)");
                    }
                    let owned = build_params(typed, &raw)?;
                    client
                        .update_cluster_firewall_alias(&name, &as_refs(&owned))
                        .await?;
                    Ok((serde_json::json!({"updated": name}), 0))
                }
                FirewallAliasCommand::Delete { name, yes } => {
                    if !yes {
                        anyhow::bail!("destructive — pass --yes to confirm");
                    }
                    client.delete_cluster_firewall_alias(&name).await?;
                    Ok((serde_json::json!({"deleted": name}), 0))
                }
            }
        }
        FirewallClusterCommand::Group(cmd) => match cmd {
            FirewallGroupCommand::List => {
                let groups = client.list_cluster_firewall_groups().await?;
                Ok((serde_json::to_value(groups)?, 0))
            }
            FirewallGroupCommand::Create {
                group,
                comment,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("group", group)];
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                let owned = build_params(typed, &raw)?;
                client
                    .create_cluster_firewall_group(&as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            FirewallGroupCommand::Delete { group, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.delete_cluster_firewall_group(&group).await?;
                Ok((serde_json::json!({"deleted": group}), 0))
            }
            FirewallGroupCommand::Rules { group } => {
                let rules = client.list_cluster_firewall_group_rules(&group).await?;
                Ok((serde_json::to_value(rules)?, 0))
            }
        },
        FirewallClusterCommand::Ipset(cmd) => match cmd {
            FirewallIpsetCommand::List => {
                let ipsets = client.list_cluster_firewall_ipsets().await?;
                Ok((serde_json::to_value(ipsets)?, 0))
            }
            FirewallIpsetCommand::Create { name, comment, raw } => {
                let mut typed: Vec<(&str, String)> = vec![("name", name)];
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                let owned = build_params(typed, &raw)?;
                client
                    .create_cluster_firewall_ipset(&as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            FirewallIpsetCommand::Delete { name, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.delete_cluster_firewall_ipset(&name).await?;
                Ok((serde_json::json!({"deleted": name}), 0))
            }
            FirewallIpsetCommand::Cidrs { name } => {
                let cidrs = client.list_cluster_firewall_ipset_cidrs(&name).await?;
                Ok((serde_json::to_value(cidrs)?, 0))
            }
            FirewallIpsetCommand::AddCidr {
                name,
                cidr,
                nomatch,
                comment,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("cidr", cidr)];
                if nomatch {
                    typed.push(("nomatch", "1".to_string()));
                }
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                let owned = build_params(typed, &raw)?;
                client
                    .add_cluster_firewall_ipset_cidr(&name, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"added": true}), 0))
            }
            FirewallIpsetCommand::RemoveCidr { name, cidr, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client
                    .remove_cluster_firewall_ipset_cidr(&name, &cidr)
                    .await?;
                Ok((serde_json::json!({"removed": cidr}), 0))
            }
        },
        FirewallClusterCommand::Options(cmd) => match cmd {
            FirewallOptionsCommand::Get => {
                let opts = client.get_cluster_firewall_options().await?;
                Ok((serde_json::to_value(opts)?, 0))
            }
            FirewallOptionsCommand::Set {
                enable,
                policy_in,
                policy_out,
                ebtables,
                log_ratelimit,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                if let Some(e) = enable {
                    typed.push(("enable", if e { "1" } else { "0" }.to_string()));
                }
                if let Some(p) = policy_in {
                    typed.push(("policy_in", p));
                }
                if let Some(p) = policy_out {
                    typed.push(("policy_out", p));
                }
                if let Some(e) = ebtables {
                    typed.push(("ebtables", if e { "1" } else { "0" }.to_string()));
                }
                if let Some(l) = log_ratelimit {
                    typed.push(("log_ratelimit", l));
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("set needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_cluster_firewall_options(&as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": true}), 0))
            }
        },
    }
}

/// Per-guest firewall CRUD dispatch. VMID is auto-resolved to its
/// owning node + guest type via the same scan the read-only firewall
/// command uses, so operators don't have to remember which node holds
/// which guest. Same `Box::leak` raw-param pattern as cluster firewall.
#[allow(clippy::too_many_lines)]
pub async fn execute_firewall_guest(
    client: &Arc<crate::api::PxClient>,
    vmid: u32,
    action: FirewallGuestCommand,
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
        v.iter().map(|(k, v)| (*k, v.as_str())).collect()
    }

    let (node, gt) = find_guest(client, vmid).await?;

    match action {
        FirewallGuestCommand::Alias(cmd) => match cmd {
            GuestFirewallAliasCommand::List => {
                let aliases = client.list_guest_firewall_aliases(&node, vmid, gt).await?;
                Ok((serde_json::to_value(aliases)?, 0))
            }
            GuestFirewallAliasCommand::Create {
                name,
                cidr,
                comment,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("name", name), ("cidr", cidr)];
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                let owned = build_params(typed, &raw)?;
                client
                    .create_guest_firewall_alias(&node, vmid, gt, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            GuestFirewallAliasCommand::Update {
                name,
                cidr,
                comment,
                rename,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                if let Some(c) = cidr {
                    typed.push(("cidr", c));
                }
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                if let Some(r) = rename {
                    typed.push(("rename", r));
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_guest_firewall_alias(&node, vmid, gt, &name, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": name}), 0))
            }
            GuestFirewallAliasCommand::Delete { name, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client
                    .delete_guest_firewall_alias(&node, vmid, gt, &name)
                    .await?;
                Ok((serde_json::json!({"deleted": name}), 0))
            }
        },
        FirewallGuestCommand::Options(cmd) => match cmd {
            GuestFirewallOptionsCommand::Get => {
                let opts = client.get_guest_firewall_options(&node, vmid, gt).await?;
                Ok((serde_json::to_value(opts)?, 0))
            }
            GuestFirewallOptionsCommand::Set {
                enable,
                policy_in,
                policy_out,
                log_level_in,
                log_level_out,
                dhcp,
                ndp,
                macfilter,
                ipfilter,
                radv,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                let push_bool = |t: &mut Vec<(&'static str, String)>, k: &'static str, v: bool| {
                    t.push((k, if v { "1" } else { "0" }.to_string()));
                };
                if let Some(e) = enable {
                    push_bool(&mut typed, "enable", e);
                }
                if let Some(p) = policy_in {
                    typed.push(("policy_in", p));
                }
                if let Some(p) = policy_out {
                    typed.push(("policy_out", p));
                }
                if let Some(l) = log_level_in {
                    typed.push(("log_level_in", l));
                }
                if let Some(l) = log_level_out {
                    typed.push(("log_level_out", l));
                }
                if let Some(b) = dhcp {
                    push_bool(&mut typed, "dhcp", b);
                }
                if let Some(b) = ndp {
                    push_bool(&mut typed, "ndp", b);
                }
                if let Some(b) = macfilter {
                    push_bool(&mut typed, "macfilter", b);
                }
                if let Some(b) = ipfilter {
                    push_bool(&mut typed, "ipfilter", b);
                }
                if let Some(b) = radv {
                    push_bool(&mut typed, "radv", b);
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("set needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_guest_firewall_options(&node, vmid, gt, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": true, "vmid": vmid}), 0))
            }
        },
    }
}

/// Cluster hardware mapping dispatch (PCI + USB). Same operator
/// pattern as the firewall CRUD: typed flags + `--raw KEY=VAL`
/// escape hatch. The `--map` arg accepts repeats so multi-node
/// passthrough configs land in one CLI call.
#[allow(clippy::too_many_lines)]
pub async fn execute_cluster_mapping(
    client: &Arc<crate::api::PxClient>,
    action: ClusterMappingCommand,
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
        v.iter().map(|(k, v)| (*k, v.as_str())).collect()
    }
    // PVE accepts the `map` field as a repeated form param — each
    // value is one `node=...,path=...,id=...` string. clap's Vec<String>
    // gives us each one separately; we re-emit them all under the same
    // key so the urlencoded body has `map=...&map=...&map=...`.
    fn push_map(typed: &mut Vec<(&'static str, String)>, items: Vec<String>) {
        for m in items {
            typed.push(("map", m));
        }
    }

    match action {
        ClusterMappingCommand::Pci(cmd) => match cmd {
            ClusterMappingPciCommand::List => {
                let mappings = client.list_cluster_mapping_pci().await?;
                Ok((serde_json::to_value(mappings)?, 0))
            }
            ClusterMappingPciCommand::Create {
                id,
                description,
                mdev,
                map,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("id", id)];
                if let Some(d) = description {
                    typed.push(("description", d));
                }
                if let Some(m) = mdev {
                    typed.push(("mdev", if m { "1" } else { "0" }.to_string()));
                }
                push_map(&mut typed, map);
                let owned = build_params(typed, &raw)?;
                client.create_cluster_mapping_pci(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            ClusterMappingPciCommand::Update {
                id,
                description,
                mdev,
                map,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                if let Some(d) = description {
                    typed.push(("description", d));
                }
                if let Some(m) = mdev {
                    typed.push(("mdev", if m { "1" } else { "0" }.to_string()));
                }
                push_map(&mut typed, map);
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_cluster_mapping_pci(&id, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": id}), 0))
            }
            ClusterMappingPciCommand::Delete { id, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.delete_cluster_mapping_pci(&id).await?;
                Ok((serde_json::json!({"deleted": id}), 0))
            }
        },
        ClusterMappingCommand::Usb(cmd) => match cmd {
            ClusterMappingUsbCommand::List => {
                let mappings = client.list_cluster_mapping_usb().await?;
                Ok((serde_json::to_value(mappings)?, 0))
            }
            ClusterMappingUsbCommand::Create {
                id,
                description,
                map,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("id", id)];
                if let Some(d) = description {
                    typed.push(("description", d));
                }
                push_map(&mut typed, map);
                let owned = build_params(typed, &raw)?;
                client.create_cluster_mapping_usb(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            ClusterMappingUsbCommand::Update {
                id,
                description,
                map,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                if let Some(d) = description {
                    typed.push(("description", d));
                }
                push_map(&mut typed, map);
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_cluster_mapping_usb(&id, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": id}), 0))
            }
            ClusterMappingUsbCommand::Delete { id, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.delete_cluster_mapping_usb(&id).await?;
                Ok((serde_json::json!({"deleted": id}), 0))
            }
        },
    }
}
