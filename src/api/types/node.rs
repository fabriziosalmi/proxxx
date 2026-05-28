use serde::{Deserialize, Serialize};

use super::deserialize_u32_from_str_or_num;

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Node {
    pub node: String,
    pub status: NodeStatus,
    pub cpu: f64,
    pub maxcpu: u32,
    pub mem: u64,
    pub maxmem: u64,
    pub disk: u64,
    pub maxdisk: u64,
    pub uptime: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum NodeStatus {
    Online,
    Offline,
    /// (audit) — `#[serde(other)]` makes this the catchall
    /// for any future PVE status string we don't model. Without
    /// this, a hypothetical `"maintenance"` from PVE 8.4 would
    /// fail deserialization of the entire `/nodes` response. With
    /// it, the unknown value lands in `Unknown` and the rest of
    /// the payload survives. We lose the original string — that's
    /// the cost; the alternative is shipping a parser that breaks
    /// on every PVE upgrade.
    #[default]
    #[serde(other)]
    Unknown,
}

/// `GET /nodes/{n}/dns` — resolver config (search domain + up to 3
/// nameservers). PUT takes the same shape (every field optional).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeDns {
    pub search: String,
    pub dns1: String,
    pub dns2: String,
    pub dns3: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeHosts {
    pub data: String,
    pub digest: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeTime {
    /// `Option` because PVE returns `null` when no timezone has been
    /// configured (default state on a fresh install). Live cluster
    /// regression: assuming `String` failed to parse `"timezone": null`.
    pub timezone: Option<String>,
    /// UTC unix epoch seconds.
    pub time: u64,
    /// Local-zone unix epoch (= `time + tz offset`). PVE returns both
    /// so a UI doesn't need to apply the offset itself.
    pub localtime: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeSyslogLine {
    /// 1-indexed line number (PVE field `n`).
    pub n: u64,
    /// Log line text (PVE field `t`).
    pub t: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeSubscription {
    /// `"active"` | `"inactive"` | `"notfound"` | `"new"` |
    /// `"expired"` | `"suspended"`.
    pub status: String,
    pub productname: String,
    /// Subscription level — `c` (community), `b` (basic), `s`
    /// (standard), `p` (premium). Empty when no key.
    pub level: String,
    /// Subscription key (echoed back on GET — partially redacted by
    /// PVE on some versions). Empty when none set.
    pub key: String,
    pub message: String,
    pub serverid: String,
    pub regdate: String,
    pub nextduedate: String,
    pub url: String,
    pub validdirectory: String,
    pub checktime: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeCertificateInfo {
    /// e.g. `pve-ssl.pem`, `pveproxy-ssl.pem`.
    pub filename: String,
    /// SHA-256 fingerprint, colon-separated.
    pub fingerprint: String,
    pub issuer: String,
    pub subject: String,
    pub notbefore: i64,
    pub notafter: i64,
    /// Subject alternative names (DNS + IP).
    pub san: Vec<String>,
    /// Public-key algorithm (e.g. `rsaEncryption`, `ecPublicKey`).
    #[serde(rename = "public-key-type")]
    pub public_key_type: String,
    #[serde(rename = "public-key-bits")]
    pub public_key_bits: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkInterface {
    pub iface: String,
    /// `"eth"`, `"bridge"`, `"vlan"`, `"bond"`, `"OVSBridge"`,
    /// `"alias"`, `"lo"`, …
    #[serde(rename = "type")]
    pub iface_type: String,
    /// 1 = currently up at the kernel level.
    pub active: u8,
    /// 1 = present in the kernel netns (false for stale config).
    pub exists: u8,
    /// 1 = brought up at boot.
    pub autostart: u8,
    /// IPv4 method: `"static"`, `"dhcp"`, `"manual"`.
    pub method: String,
    /// IPv6 method.
    pub method6: String,
    pub address: String,
    pub netmask: String,
    pub cidr: String,
    pub gateway: String,
    pub gateway6: String,
    /// Bridge: space-separated list of slave interfaces.
    pub bridge_ports: String,
    pub bridge_stp: String,
    pub bridge_fd: String,
    /// Bond: space-separated list of slave interfaces.
    pub slaves: String,
    pub bond_mode: String,
    /// VLAN: parent interface name (e.g. `"vmbr0"` for `"vmbr0.100"`).
    #[serde(rename = "vlan-raw-device")]
    pub vlan_raw_device: String,
    /// Predictable + MAC-derived alternative names for physical NICs.
    pub altnames: Vec<String>,
    /// Address families enabled on this interface (e.g. `["inet"]`).
    pub families: Vec<String>,
    /// PVE assigns a numeric load order so `vmbr0` comes up before
    /// dependent VLAN sub-interfaces.
    pub priority: i32,
    pub comments: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeStatusDetail {
    /// Uptime in seconds since last boot. Resets on reboot — that's how
    /// we detect "the node has come back".
    #[serde(default)]
    pub uptime: u64,
    /// Kernel version currently running. Compare before/after upgrade
    /// to confirm the new kernel actually loaded.
    #[serde(default)]
    pub kversion: String,
    /// PVE manager version (e.g. "8.2.4").
    #[serde(default)]
    pub pveversion: String,
}

/// One row of `GET /cluster/config/nodes` — corosync member node.
/// Fields are optional because PVE versions vary in what they emit
/// (older clusters omit `ring1_addr` when no second ring is configured).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CorosyncNode {
    pub node: String,
    /// Numeric corosync nodeid (1..N, monotonically assigned). PVE
    /// emits this as a JSON string (`"1"`), not a number — live-cluster
    /// regression on `/cluster/config/nodes`.
    #[serde(deserialize_with = "deserialize_u32_from_str_or_num", default)]
    pub nodeid: u32,
    /// Vote count for quorum math (default 1; bumped to 2+ for
    /// asymmetric topologies like single-node ha-clusters). PVE emits
    /// this as a JSON string (`"1"`) — same regression as `nodeid`.
    #[serde(deserialize_with = "deserialize_u32_from_str_or_num", default)]
    pub quorum_votes: u32,
    /// Primary corosync ring address (hostname or IP).
    pub ring0_addr: String,
    /// Optional secondary ring (knet redundancy). Empty when single-ring.
    pub ring1_addr: String,
}
