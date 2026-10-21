use serde::{Deserialize, Serialize};

use super::{deserialize_bool_from_int, deserialize_opt_bool_from_int};

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

/// `GET /cluster/firewall/options`. PVE returns only the keys that are set
/// (an untouched cluster returns just `digest`), so every option is an
/// `Option`: `None` means "unset, PVE's default applies", which for
/// `ebtables` is ON. Printing an absent key as `false` told the operator a
/// protection was off when it was on (#349). `None` is omitted from output.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallOptions {
    /// Master switch. PVE default when unset: off.
    #[serde(
        deserialize_with = "deserialize_opt_bool_from_int",
        skip_serializing_if = "Option::is_none"
    )]
    pub enable: Option<bool>,
    /// Default action for inbound traffic with no matching rule:
    /// `ACCEPT` | `REJECT` | `DROP`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_in: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_out: Option<String>,
    /// Forward policy (PVE 8.2+): `ACCEPT` | `DROP`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_forward: Option<String>,
    /// Whether ebtables (L2) hooks are wired in addition to iptables.
    /// PVE default when unset: on.
    #[serde(
        deserialize_with = "deserialize_opt_bool_from_int",
        skip_serializing_if = "Option::is_none"
    )]
    pub ebtables: Option<bool>,
    /// Encoded sub-spec, e.g. `"enable=1,burst=5,rate=1/second"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_ratelimit: Option<String>,
    pub digest: String,
}

/// `GET /nodes/{node}/{qemu|lxc}/{vmid}/firewall/options`. Same shape as
/// [`FirewallOptions`]: PVE returns only the keys that are set, and an
/// absent key is `None` (PVE default applies), not `false` (#349). PVE
/// defaults when unset: `enable` off, `dhcp` off, `macfilter` ON, `ndp` ON.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuestFirewallOptions {
    /// Per-guest master switch.
    #[serde(
        deserialize_with = "deserialize_opt_bool_from_int",
        skip_serializing_if = "Option::is_none"
    )]
    pub enable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_in: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_out: Option<String>,
    /// `emerg` | `alert` | `crit` | `err` | `warning` | `notice` |
    /// `info` | `debug` | `nolog`. Unset = inherit cluster default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level_in: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level_out: Option<String>,
    /// Auto-allow DHCP request/reply traffic.
    #[serde(
        deserialize_with = "deserialize_opt_bool_from_int",
        skip_serializing_if = "Option::is_none"
    )]
    pub dhcp: Option<bool>,
    /// Auto-allow IPv6 NDP (neighbour discovery).
    #[serde(
        deserialize_with = "deserialize_opt_bool_from_int",
        skip_serializing_if = "Option::is_none"
    )]
    pub ndp: Option<bool>,
    /// Drop frames whose source MAC doesn't match the configured NIC MAC.
    #[serde(
        deserialize_with = "deserialize_opt_bool_from_int",
        skip_serializing_if = "Option::is_none"
    )]
    pub macfilter: Option<bool>,
    /// Drop frames whose source IP isn't in the per-VM `ipfilter-net*` ipset.
    #[serde(
        deserialize_with = "deserialize_opt_bool_from_int",
        skip_serializing_if = "Option::is_none"
    )]
    pub ipfilter: Option<bool>,
    /// LXC-only: allow IPv6 router-advertisements out of the container.
    #[serde(
        deserialize_with = "deserialize_opt_bool_from_int",
        skip_serializing_if = "Option::is_none"
    )]
    pub radv: Option<bool>,
    pub digest: String,
}
