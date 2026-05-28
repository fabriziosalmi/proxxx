use serde::{Deserialize, Serialize};

use super::deserialize_bool_from_int;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallRule {
    /// 0-indexed position in the chain (defines evaluation order).
    pub pos: i32,
    /// Direction: `"in"`, `"out"`, `"group"` (security-group ref),
    /// or `"forward"` (PVE 8+).
    #[serde(rename = "type")]
    pub direction: String,
    /// `"ACCEPT"`, `"REJECT"`, `"DROP"`, or — when `direction == "group"`
    /// — the name of the referenced security group.
    pub action: String,
    /// `1` = active, `0` = disabled-but-saved.
    pub enable: u8,
    /// Outgoing/incoming network interface (matches against host
    /// iptables-NIC name; empty = any).
    pub iface: String,
    /// Source — IP/CIDR, `+alias`, `+ipset`, or empty.
    pub source: String,
    /// Destination — same forms as `source`.
    pub dest: String,
    /// Protocol (`tcp`, `udp`, `icmp`, `icmpv6`, …).
    pub proto: String,
    /// Source port spec — single (`22`) or range (`1000:2000`).
    pub sport: String,
    /// Destination port spec.
    pub dport: String,
    /// Logging level (`info`, `alert`, `nolog`, …).
    pub log: String,
    pub comment: String,
    /// PVE firewall macro (predefined common-case rule set, e.g.
    /// `"SSH"` or `"Web"`). Empty for hand-rolled rules.
    #[serde(rename = "macro")]
    pub fw_macro: String,
    /// SHA1 of the rules file — used by PVE for atomic updates.
    pub digest: String,
}

/// One named CIDR alias from `GET /cluster/firewall/aliases`.
/// Aliases let operators write `+web-servers` in a rule's `source` /
/// `dest` field instead of repeating a CIDR — handy when the CIDR
/// changes (one edit, every rule updates).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallAlias {
    pub name: String,
    pub cidr: String,
    pub comment: String,
    /// 4 or 6 — PVE rejects mixing v4 + v6 in a single alias.
    pub ipversion: u8,
    pub digest: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallSecurityGroup {
    pub group: String,
    pub comment: String,
    pub digest: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallIpset {
    pub name: String,
    pub comment: String,
    pub digest: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallIpsetCidr {
    pub cidr: String,
    pub comment: String,
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub nomatch: bool,
    pub digest: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallOptions {
    /// Master switch — `0` disables the entire cluster firewall.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub enable: bool,
    /// Default action for inbound traffic with no matching rule:
    /// `ACCEPT` | `REJECT` | `DROP`.
    pub policy_in: String,
    pub policy_out: String,
    /// Whether ebtables (L2) hooks are wired in addition to iptables.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub ebtables: bool,
    /// Encoded sub-spec, e.g. `"enable=1,burst=5,rate=1/second"`.
    pub log_ratelimit: String,
    pub digest: String,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuestFirewallOptions {
    /// Per-guest master switch.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub enable: bool,
    pub policy_in: String,
    pub policy_out: String,
    /// `emerg` | `alert` | `crit` | `err` | `warning` | `notice` |
    /// `info` | `debug` | `nolog`. Empty = inherit cluster default.
    pub log_level_in: String,
    pub log_level_out: String,
    /// Auto-allow DHCP request/reply traffic.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub dhcp: bool,
    /// Auto-allow IPv6 NDP (neighbour discovery).
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub ndp: bool,
    /// Drop frames whose source MAC doesn't match the configured NIC MAC.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub macfilter: bool,
    /// Drop frames whose source IP isn't in the per-VM `ipfilter-net*` ipset.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub ipfilter: bool,
    /// LXC-only: allow IPv6 router-advertisements out of the container.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub radv: bool,
    pub digest: String,
}
