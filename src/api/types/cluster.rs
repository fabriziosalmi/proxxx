use serde::{Deserialize, Serialize};

use super::{
    deserialize_bool_from_int, deserialize_opt_bool_from_int, deserialize_u64_from_str_or_num,
};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterResource {
    /// e.g. `node/pve1`, `qemu/100`, `lxc/200`, `storage/pve1/local`,
    /// `pool/dev`, `sdn/zone-foo`.
    pub id: String,
    /// `node` | `qemu` | `lxc` | `storage` | `pool` | `sdn`.
    #[serde(rename = "type")]
    pub resource_type: String,
    pub node: String,
    pub status: String,
    pub vmid: u32,
    pub storage: String,
    pub pool: String,
    pub name: String,
    pub cpu: f64,
    pub maxcpu: u32,
    pub mem: u64,
    pub maxmem: u64,
    pub disk: u64,
    pub maxdisk: u64,
    pub uptime: u64,
    /// PVE 8+ adds tags (semicolon-separated) on guests.
    pub tags: String,
    pub template: u8,
    pub plugintype: String,
}

/// `GET /cluster/options` — global cluster config. Many fields; the
/// typed ones below are the operator-facing essentials (`mac_prefix`,
/// migration network, etc.). Less-common knobs (crs, fencing, u2f
/// schema) are reachable via `--raw KEY=VAL` on the CLI.
///
/// PVE returns only the keys that are set, so every field is an `Option`
/// and an unset one is omitted from output instead of shown as `0` / `""`
/// (#349: `max_workers` printed `0`, which PVE does not allow).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterOptions {
    /// MAC prefix for auto-generated guest NIC MACs (e.g. `BC:24:11`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_prefix: Option<String>,
    /// Per-traffic-type bandwidth caps (string-encoded sub-spec).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bwlimit: Option<String>,
    /// Console viewer choice: `applet` | `vv` | `html5` | `xtermjs`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console: Option<String>,
    /// Free-form cluster description shown in the web UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_proxy: Option<String>,
    /// Default keyboard layout for VNC/console (e.g. `en-us`, `it`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyboard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Default migration network/type (encoded sub-spec, e.g.
    /// `type=insecure` or `network=10.0.0.0/24`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migration: Option<String>,
    #[serde(
        deserialize_with = "deserialize_opt_bool_from_int",
        skip_serializing_if = "Option::is_none"
    )]
    pub migration_unsecure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_workers: Option<u32>,
    /// Tags allowed on guests. Kept as PVE sends it.
    #[serde(rename = "registered-tags", skip_serializing_if = "Option::is_none")]
    pub registered_tags: Option<serde_json::Value>,
    /// Tag-style policy. Kept as PVE sends it.
    #[serde(rename = "tag-style", skip_serializing_if = "Option::is_none")]
    pub tag_style: Option<serde_json::Value>,
    /// Tags a non-admin user may set. Kept as PVE sends it (a list on 9.1);
    /// it used to be dropped.
    #[serde(rename = "allowed-tags", skip_serializing_if = "Option::is_none")]
    pub allowed_tags: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterLogEntry {
    pub node: String,
    pub user: String,
    pub msg: String,
    /// Severity tag: `info` | `warn` | `error` | etc.
    pub tag: String,
    /// Monotonic event id within this log. PVE serializes this as a
    /// JSON string (`"2957"`), not a number — live-cluster regression.
    #[serde(deserialize_with = "deserialize_u64_from_str_or_num", default)]
    pub uid: u64,
    /// syslog-style priority (0–7; 0=emerg, 6=info, 7=debug).
    pub pri: u8,
    /// Unix epoch seconds.
    pub time: u64,
    pub pid: u32,
}

/// One PCI device mapping from `GET /cluster/mapping/pci`. The `map`
/// field is wire-shaped as a list of `node=…,path=…,id=…[,iommugroup=…]`
/// strings — preserved as-is here so operators can inspect the literal
/// PVE form without us imposing a lossy parsed shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterMappingPci {
    pub id: String,
    pub description: String,
    /// `1` = mediated-device variant (vGPU-style time-slicing).
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub mdev: bool,
    pub map: Vec<String>,
    pub digest: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterMappingUsb {
    pub id: String,
    pub description: String,
    pub map: Vec<String>,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterStatusEntry {
    #[serde(rename = "type", default)]
    pub entry_type: String,
    pub name: String,
    /// 1 if online (cluster member's pov), 0 if offline. Proxmox also
    /// returns `1`/`0` as integer.
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub online: bool,
    /// Quorum status — true if cluster has quorum.
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub quorate: bool,
    /// Number of currently online nodes (only meaningful on the
    /// `entry_type == "cluster"` summary entry).
    #[serde(default)]
    pub nodes: u32,
    /// Local node flag — true on the entry that represents the node
    /// proxxx is talking to.
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub local: bool,
}
