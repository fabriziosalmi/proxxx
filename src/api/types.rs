use serde::{Deserialize, Serialize};

// ── Node ────────────────────────────────────────────────
//
// Vector 25 (macro audit) — lax deserialization. PVE has historically
// renamed and removed fields between point releases (`cpu` shape
// changed in PVE 7, `tags` added in PVE 7.0, `vmstate` shifted from
// string to int). To avoid a single missing key panicking the entire
// API ingest, every API response struct in this module follows two
// rules:
//   1. Every field carries `#[serde(default)]` (or is `Option<T>`).
//   2. The struct derives `Default` so the struct-level helper has
//      something to fall back on.
// Concrete consequence: PVE 8.3 silently dropping `Node.uptime`
// surfaces as `uptime: 0` (cosmetic) instead of crashing the entire
// `get_nodes` deserialization.

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
    /// V29.2 (audit) — `#[serde(other)]` makes this the catchall
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

// ── Guest (VM + LXC unified) ────────────────────────────

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Guest {
    pub vmid: u32,
    pub name: String,
    pub status: GuestStatus,
    #[serde(rename = "type")]
    pub guest_type: GuestType,
    pub node: String,
    pub cpu: f64,
    pub cpus: u32,
    pub mem: u64,
    pub maxmem: u64,
    pub disk: u64,
    pub maxdisk: u64,
    pub uptime: u64,
    pub tags: String,
    /// V27.4 (audit) — PVE config `lock` field. When non-empty the
    /// guest has a sticky lock (`backup`, `clone`, `migrate`,
    /// `rollback`, `snapshot`, `snapshot-delete`, `suspending`).
    /// PVE rejects almost every mutation while a lock is held with
    /// `500 VM is locked`. proxxx reads this field and refuses
    /// destructive ops up-front instead of letting the user collide
    /// with PVE's lock and surface a confusing 500.
    pub lock: String,
    /// V27.1 (audit) — HA Cluster Resource Manager state for this
    /// guest. Empty when not HA-managed; otherwise one of `started`,
    /// `stopped`, `disabled`, `ignored`, `error`. Reading
    /// `/qemu/{vmid}/status/stop` while the CRM has the resource at
    /// `started` causes the CRM to immediately restart the guest in
    /// 5–30 s — or worse, fence the node it's running on.
    /// Destructive ops on HA-managed guests must go through the
    /// `/cluster/ha/resources/{id}/state` endpoint instead.
    pub hastate: String,
}

impl Guest {
    /// V27.1 — true if this guest is under HA-CRM management.
    /// Destructive raw `/status/*` calls must NOT be issued; route
    /// through `/cluster/ha/resources/<vmid>` state changes
    /// instead.
    #[must_use]
    pub fn is_ha_managed(&self) -> bool {
        !self.hastate.is_empty()
    }

    /// V27.4 — true if PVE has a sticky lock on this guest right
    /// now. Caller should refuse destructive ops with a clear
    /// "guest is locked: {lock_reason}" message rather than collide
    /// with PVE's 500.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        !self.lock.is_empty()
    }

    /// Parse semicolon-separated tags into a vec
    #[must_use]
    pub fn tag_list(&self) -> Vec<&str> {
        if self.tags.is_empty() {
            Vec::new()
        } else {
            self.tags.split(';').collect()
        }
    }

    /// Check if guest has a specific tag
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tag_list().contains(&tag)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum GuestStatus {
    Running,
    Stopped,
    Paused,
    Suspended,
    /// V29.2 (audit) — catchall for unknown PVE status strings
    /// (e.g. a hypothetical future `"hibernating"`). Without
    /// `#[serde(other)]` the whole `/qemu` or `/lxc` payload would
    /// fail deserialization and the guest list would blank.
    #[default]
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum GuestType {
    #[default]
    Qemu,
    Lxc,
}

// ── Storage ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StoragePool {
    pub storage: String,
    #[serde(rename = "type")]
    pub storage_type: String,
    pub used: u64,
    pub avail: u64,
    pub total: u64,
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub active: bool,
    pub content: String,
}

fn deserialize_bool_from_int<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct BoolOrInt;
    impl de::Visitor<'_> for BoolOrInt {
        type Value = bool;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a boolean or integer 0/1")
        }
        fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<bool, E> {
            Ok(v)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<bool, E> {
            Ok(v != 0)
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<bool, E> {
            Ok(v != 0)
        }
    }

    deserializer.deserialize_any(BoolOrInt)
}

// ── Task Log ────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskLog {
    pub total: usize,
    pub data: Vec<TaskLogLine>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskLogLine {
    pub n: usize,
    pub t: String,
}

// ── API Response Wrapper ────────────────────────────────
// Proxmox wraps all responses in { "data": ... }

#[derive(Debug, Deserialize)]
pub struct ApiResponse<T> {
    pub data: T,
}

// ── Entity ID (profile-scoped, collision-proof) ─────────
//
// Vector 20 (macro audit) — `vmid: u32` collision across profiles.
//
// proxxx is **single-profile-per-process** by architectural decision:
//   - `tui::run(profile, ...)` and CLI subcommands take exactly one
//     profile name.
//   - `PxClient` is built for that single profile; the entire AppState
//     is derived from one cluster's API responses.
//   - The SQLite cache file is `{profile}_state.db` — physically
//     separated by profile, never shared.
// So `vmid` IS unique within any process and there's no in-memory
// collision surface. Two terminal sessions running with `--profile A`
// and `--profile B` are independent processes that share no state.
//
// `EntityId` exists as forward-looking machinery: when / if a future
// version supports multi-profile views in a single process, the
// reducer's keyed maps must migrate from `HashMap<u32, _>` to
// `HashMap<EntityId, _>`. Until that day, EntityId is unused on the
// hot path — its existence is the contract that the day it IS used,
// the type system enforces collision-free composition.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EntityId {
    pub profile: String,
    pub vmid: u32,
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.profile, self.vmid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskInfo {
    pub upid: String,
    pub node: String,
    pub user: String,
    pub id: String,
    #[serde(rename = "type")]
    pub task_type: String,
    pub status: Option<String>,
    pub starttime: u64,
    pub endtime: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentExecResponse {
    pub pid: i32,
}

// ── APT inventory (Proxmox 7+) ──────────────────────────
//
// Returned by `GET /nodes/{node}/apt/update`. We model only the fields
// we actually use; Proxmox includes more (Description, Section, Origin,
// Priority, Arch). All fields default-empty so a stripped-down server
// response (or future-deprecated fields) won't fail deserialization.

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AptUpgradable {
    #[serde(rename = "Title", alias = "Package", default)]
    pub package: String,
    #[serde(rename = "OldVersion", default)]
    pub old_version: String,
    #[serde(rename = "Version", default)]
    pub new_version: String,
    #[serde(rename = "Section", default)]
    pub section: String,
    #[serde(rename = "Priority", default)]
    pub priority: String,
}

impl AptUpgradable {
    /// Heuristic: does upgrading this package require a reboot?
    /// True for kernel images, microcode, libc, systemd. We err on
    /// the side of "yes" because users would rather reboot once
    /// extra than leave a half-loaded kernel running.
    #[must_use]
    pub fn requires_reboot(&self) -> bool {
        let p = self.package.as_str();
        p.starts_with("pve-kernel")
            || p.starts_with("proxmox-kernel")
            || p.starts_with("linux-image")
            || p == "intel-microcode"
            || p == "amd64-microcode"
            || p == "libc6"
            || p == "systemd"
    }

    /// Heuristic for security category. Proxmox tags security packages
    /// in `Section` as `pve-no-subscription/security` or upstream
    /// origin = "Debian-Security".
    #[must_use]
    pub fn is_security(&self) -> bool {
        self.section.contains("security")
    }
}

// ── Node status detail ──────────────────────────────────
//
// Returned by `GET /nodes/{node}/status`. We use a tiny subset to detect
// "node is back online with quorum" after a reboot. The full struct has
// 50+ fields; we model the ones the orchestrator needs.

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

// ── Snapshot (feature #7) ───────────────────────────────
//
// Returned by `GET /nodes/{node}/{type}/{vmid}/snapshot`. Proxmox always
// includes a synthetic `current` entry representing the live state — its
// `parent` field points at whichever snapshot the running VM was taken
// from (or is empty if no snapshots exist). Each real snapshot has a
// `parent` field of "" or another snapshot's `name`.
//
// Branching is intentional: when you `rollback` to snapshot S and then
// take a new snapshot T, T's parent is S, so two snapshots can share the
// same parent. The web UI flattens this to a list; we render it as a tree.

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    /// Snapshot name (or `"current"` for the live VM state).
    pub name: String,
    /// Parent snapshot name, or empty string when this is a root.
    /// Proxmox returns `""` (not absent) when there's no parent.
    pub parent: String,
    /// User-supplied description (often empty).
    pub description: String,
    /// Unix timestamp the snapshot was taken (0 for the synthetic
    /// `current` entry).
    #[serde(default)]
    pub snaptime: u64,
    /// Whether this snapshot includes RAM (live snapshot).
    pub vmstate: u32,
}

impl Snapshot {
    /// True for the synthetic "current" entry that Proxmox adds to mark
    /// the live state. Treat it specially in the tree: it's the cursor,
    /// not a real snapshot.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self.name == "current"
    }
}

// ── SPICE handoff (feature #1c) ─────────────────────────
//
// `POST /nodes/{node}/qemu/{vmid}/spiceproxy` returns a flat object of
// connection parameters that map almost 1:1 to the keys virt-viewer
// expects in its `.vv` (ConfigFile) format. We model it as a free-form
// HashMap<String, String> rather than enumerating fields — Proxmox can
// add new keys (proxy auth, tls cipher prefs, etc.) and we want to
// pass them through verbatim to remote-viewer without parsing each one.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpiceConfig {
    /// All key/value pairs from the spiceproxy response. Examples:
    ///   host, port, tls-port, password, ca, host-subject, proxy,
    ///   title, release-cursor, secure-attention, delete-this-file.
    /// Stored as strings because the .vv file is INI-style.
    #[serde(flatten)]
    pub keys: std::collections::HashMap<String, String>,
}

impl SpiceConfig {
    /// Render to `.vv` (virt-viewer ConfigFile) format. Output starts
    /// with `[virt-viewer]\n` followed by `key=value` lines, sorted by
    /// key for deterministic test snapshots. Missing-but-required keys
    /// are NOT injected — Proxmox always includes them.
    #[must_use]
    pub fn to_vv_file(&self) -> String {
        let mut keys: Vec<&String> = self.keys.keys().collect();
        keys.sort();
        let mut out = String::from("[virt-viewer]\n");
        for k in keys {
            if let Some(v) = self.keys.get(k) {
                // Sanitise: strip CR/LF from values to avoid breaking
                // the INI grammar. Proxmox-supplied values shouldn't
                // contain newlines but the `ca` PEM does — `.vv` accepts
                // multi-line values via `\n` ESCAPE, NOT raw newlines.
                let escaped = v.replace('\n', "\\n");
                out.push_str(&format!("{k}={escaped}\n"));
            }
        }
        out
    }

    /// Helper for tests + UI: extract the `host` key (always present).
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.keys.get("host").map(String::as_str)
    }
}

// ── Termproxy serial console (feature #1b) ──────────────
//
// Returned by `POST /nodes/{node}/{type}/{vmid}/termproxy`. The ticket
// is one-shot and short-lived (~30s typical). The WebSocket follow-up
// connects to `wss://{host}:{api_port}/.../vncwebsocket?port={port}&vncticket=<X>`
// and authenticates by sending `<user>:<ticket>\n` as the first frame.

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TermproxyTicket {
    /// Backend port the websocket should connect to (e.g. 5900).
    pub port: u32,
    /// One-shot ticket — must be sent in the WS auth frame.
    pub ticket: String,
    /// User the ticket was issued to (echoed back so we know what to
    /// send in the auth frame).
    pub user: String,
    /// UPID of the spawned termproxy task on the node. Useful for
    /// observability — proxxx can poll it for liveness.
    #[serde(default)]
    pub upid: String,
}

// ── Access control (feature #10) ────────────────────────
//
// Read surface mirrors `/access/*`. Keep field names close to the
// Proxmox JSON; expose `Option`/`String` defaults so partial responses
// don't break parsing across PVE versions.

/// One ACL entry. Returned by `GET /access/acl`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AclEntry {
    /// ACL path, e.g. `"/"`, `"/vms/100"`, `"/storage/local"`.
    pub path: String,
    /// `"user"` | `"group"` | `"token"`.
    #[serde(rename = "type", default)]
    pub kind: String,
    /// User/group/token id.
    pub ugid: String,
    pub roleid: String,
    /// Whether the permission propagates to children.
    #[serde(
        default = "default_true_int",
        deserialize_with = "deserialize_bool_from_int"
    )]
    pub propagate: bool,
}

fn default_true_int() -> bool {
    true
}

/// One user. Returned by `GET /access/users`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct User {
    /// `<user>@<realm>` — Proxmox's canonical id.
    pub userid: String,
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub enable: bool,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub firstname: String,
    #[serde(default)]
    pub lastname: String,
    #[serde(default)]
    pub comment: String,
    /// Optional expiration (Unix seconds, 0 = never).
    #[serde(default)]
    pub expire: u64,
}

/// One API token. Returned by `GET /access/users/{userid}/token`.
/// Note: token VALUES (the secret) are returned ONLY on creation —
/// never on list. We model that with `secret` being `Option`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiToken {
    pub tokenid: String,
    /// Privilege separation: when true, ACL on the token is independent
    /// from the parent user's ACL (recommended for least-privilege).
    #[serde(
        default = "default_true_int",
        deserialize_with = "deserialize_bool_from_int"
    )]
    pub privsep: bool,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub expire: u64,
    /// Only set on creation responses. None on list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// One group. Returned by `GET /access/groups`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Group {
    pub groupid: String,
    #[serde(default)]
    pub comment: String,
    /// Comma-separated user list (Proxmox quirk).
    #[serde(default)]
    pub users: String,
}

/// One role. Returned by `GET /access/roles`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Role {
    pub roleid: String,
    /// Comma-separated privilege list (e.g. `"VM.Allocate,VM.Audit"`).
    #[serde(default)]
    pub privs: String,
    /// Built-in roles can't be deleted.
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub special: bool,
}

/// One auth realm. Returned by `GET /access/domains`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Realm {
    pub realm: String,
    /// `"pam"` | `"pve"` | `"ad"` | `"ldap"` | `"openid"`.
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub comment: String,
}

/// One TFA entry for a user. Returned by `GET /access/tfa/{userid}`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TfaEntry {
    /// Internal id (PVE assigns).
    pub id: String,
    /// `"totp"` | `"webauthn"` | `"recovery"` | `"yubico"`.
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub created: u64,
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub enable: bool,
}

// ── Hardware passthrough (feature #4) ───────────────────
//
// Proxmox returns `iommugroup` directly in the PCI list — no need for
// SSH/sysfs for the base case. SSH would only be needed for current
// VFIO binding driver, which we treat as Phase 2 (defer).

/// One PCI device on a node. Returned by `GET /nodes/{n}/hardware/pci`.
/// `iommugroup` is the kernel-assigned group id; devices sharing a group
/// must be assigned together to passthrough or none-of-them-can passthrough.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PciDevice {
    /// PCI address, e.g. `"0000:01:00.0"`.
    pub id: String,
    /// PCI class code, e.g. `"0x030000"` (display controller). Hex string.
    #[serde(default)]
    pub class: String,
    /// Vendor id (hex string), e.g. `"0x10de"` for NVIDIA.
    #[serde(default)]
    pub vendor: String,
    /// Device id (hex string).
    #[serde(default)]
    pub device: String,
    /// Human-readable vendor name when Proxmox could resolve it.
    #[serde(default)]
    pub vendor_name: String,
    /// Human-readable device name.
    #[serde(default)]
    pub device_name: String,
    /// IOMMU group id. -1 (or absent) means IOMMU is disabled / not
    /// reported. Devices with the SAME group share a fence boundary.
    #[serde(default = "default_iommu_group")]
    pub iommugroup: i32,
    /// True if mdev (mediated device, e.g. vGPU) is supported.
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub mdev: bool,
}

fn default_iommu_group() -> i32 {
    -1
}

impl PciDevice {
    /// True if this looks like a GPU (display class 0x03xxxx).
    /// We use the class prefix because vendor varies (NVIDIA, AMD, Intel).
    #[must_use]
    pub fn is_gpu(&self) -> bool {
        let stripped = self.class.trim_start_matches("0x");
        // PCI class 03 = Display controller (VGA, 3D, etc.).
        stripped.starts_with("03") || stripped.starts_with("0300") || stripped.starts_with("0302")
    }

    /// Short human-readable display, e.g. `"01:00.0  NVIDIA RTX 3070"`.
    /// Falls back to vendor:device hex if names are missing.
    #[must_use]
    pub fn short_label(&self) -> String {
        let addr = self.id.strip_prefix("0000:").unwrap_or(&self.id);
        let name = if !self.device_name.is_empty() {
            self.device_name.clone()
        } else {
            format!("{}:{}", self.vendor, self.device)
        };
        format!("{addr}  {name}")
    }
}

/// One USB device. Returned by `GET /nodes/{n}/hardware/usb`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UsbDevice {
    #[serde(default)]
    pub busnum: u32,
    #[serde(default)]
    pub devnum: u32,
    /// Vendor id (hex), e.g. `"0x046d"` for Logitech.
    #[serde(default)]
    pub vendid: String,
    /// Product id (hex).
    #[serde(default)]
    pub prodid: String,
    #[serde(default)]
    pub manufacturer: String,
    #[serde(default)]
    pub product: String,
    /// USB device class code (e.g. `9` = Hub, `8` = Mass storage, `2` = CDC).
    /// PVE returns this as a small integer (`"class": 9`), not a hex string.
    #[serde(default, rename = "class")]
    pub usb_class: u8,
}

impl UsbDevice {
    /// Format the bus:dev id Proxmox uses in guest config (`usbN`):
    /// `"<vendid>:<prodid>"` (e.g. `"046d:c52b"`) — that's the form
    /// `qm set --usbN <id>` expects when using vendor/product matching.
    #[must_use]
    pub fn proxmox_id(&self) -> String {
        let v = self.vendid.trim_start_matches("0x");
        let p = self.prodid.trim_start_matches("0x");
        format!("{v}:{p}")
    }
}

// ── HA + replication (feature #5) ───────────────────────

/// HA group definition. Returned by `GET /cluster/ha/groups`.
///
/// The `nodes` field is Proxmox-encoded as a comma-separated list with
/// optional `:priority` suffixes per node, e.g. `"pve1:2,pve2:1,pve3"`.
/// Higher priority = preferred. We parse it into structured form via
/// `parse_priority_list()`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HaGroup {
    #[serde(rename = "group")]
    pub name: String,
    #[serde(default)]
    pub nodes: String,
    /// If true, resources can only run on nodes in `nodes` list.
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub restricted: bool,
    /// If true, don't auto-fall-back when the preferred node returns.
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub nofailback: bool,
    #[serde(default)]
    pub comment: String,
}

impl HaGroup {
    /// Parse the `nodes` field into `(node_name, priority)` pairs.
    /// Default priority when the suffix is absent is 0 — same as Proxmox.
    /// Output is stable: sorted by descending priority then name.
    #[must_use]
    pub fn parse_priority_list(&self) -> Vec<(String, i32)> {
        let mut out: Vec<(String, i32)> = self
            .nodes
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|piece| {
                if let Some((n, p)) = piece.split_once(':') {
                    let prio = p.trim().parse::<i32>().unwrap_or(0);
                    (n.trim().to_string(), prio)
                } else {
                    (piece.to_string(), 0)
                }
            })
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }
}

/// One HA-managed resource (VM or CT). Returned by
/// `GET /cluster/ha/resources`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HaResource {
    /// Service ID, e.g. `"vm:100"` or `"ct:200"`.
    pub sid: String,
    #[serde(default)]
    pub group: String,
    /// Desired state: `"started"` or `"stopped"` or `"disabled"`.
    #[serde(default)]
    pub state: String,
    /// Max number of restart attempts before giving up.
    #[serde(default)]
    pub max_restart: u32,
    /// Max number of relocations to other nodes.
    #[serde(default)]
    pub max_relocate: u32,
    #[serde(default)]
    pub comment: String,
}

impl HaResource {
    /// Extract the VMID portion of the SID (`"vm:100"` → 100).
    /// Returns None for malformed SIDs.
    #[must_use]
    pub fn vmid(&self) -> Option<u32> {
        self.sid
            .split_once(':')
            .and_then(|(_, n)| n.parse::<u32>().ok())
    }

    /// `"vm"` or `"ct"` from the SID prefix.
    #[must_use]
    pub fn kind(&self) -> &str {
        self.sid.split_once(':').map_or("", |(k, _)| k)
    }
}

/// HA manager status. Returned by `GET /cluster/ha/status/manager_status`.
/// We model the few fields the inspector needs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HaManagerStatus {
    /// Active master node name (the one running pve-ha-manager).
    #[serde(default)]
    pub master: String,
    /// `"active"`, `"unsafe"`, etc. — `unsafe` means quorum lost.
    #[serde(default)]
    pub mode: String,
    /// Per-node service runtime states (key = node, value = state).
    /// Proxmox returns `node_status` as a map; we keep it flat here.
    #[serde(default)]
    pub node_status: std::collections::HashMap<String, String>,
}

/// Cluster status entry. Returned by `GET /cluster/status` (an array of
/// nodes + a single `cluster` summary entry). We model both via
/// `entry_type` discrimination.
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

/// Replication job definition. Returned by `GET /cluster/replication`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplicationJob {
    /// Job id, e.g. `"100-0"` (vmid + '-' + index).
    pub id: String,
    /// Job type — `"local"` for pve-zsync style, etc.
    #[serde(rename = "type", default)]
    pub job_type: String,
    /// Source node.
    #[serde(default)]
    pub source: String,
    /// Target node.
    #[serde(default)]
    pub target: String,
    /// Cron-like schedule, e.g. `"*/15"` for every 15 minutes.
    #[serde(default)]
    pub schedule: String,
    /// Disabled flag — Proxmox stores as `1`/`0` int.
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub disable: bool,
    #[serde(default)]
    pub comment: String,
}

impl ReplicationJob {
    /// Extract the VMID from the job id (`"100-0"` → 100).
    #[must_use]
    pub fn vmid(&self) -> Option<u32> {
        self.id
            .split_once('-')
            .and_then(|(v, _)| v.parse::<u32>().ok())
    }
}

/// Replication runtime status. Returned by `GET /nodes/{node}/replication`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplicationStatus {
    pub id: String,
    /// Last successful sync timestamp (Unix seconds). 0 if never ran.
    #[serde(default)]
    pub last_sync: u64,
    /// Duration of the last sync in seconds.
    #[serde(default)]
    pub duration: f64,
    /// Last reported error string. Empty if last run was OK.
    #[serde(default)]
    pub error: String,
    /// Consecutive failure count.
    #[serde(default)]
    pub fail_count: u32,
    /// Source node (often duplicated with the parent job).
    #[serde(default)]
    pub source: String,
    /// Target node.
    #[serde(default)]
    pub target: String,
}

impl ReplicationStatus {
    /// Recovery Point Objective lag in seconds — how stale is the
    /// replica? Returns u64::MAX if `last_sync` is 0 (never ran).
    /// `now` lets tests inject a deterministic clock.
    #[must_use]
    pub fn rpo_secs(&self, now: u64) -> u64 {
        if self.last_sync == 0 {
            return u64::MAX;
        }
        now.saturating_sub(self.last_sync)
    }

    /// Health: green if recent + no errors, yellow if stale, red if
    /// failing. `expected_period_secs` is the schedule's period for
    /// staleness comparison (e.g. 900 for `*/15`).
    #[must_use]
    pub fn health(&self, now: u64, expected_period_secs: u64) -> ReplicationHealth {
        if self.fail_count > 0 || !self.error.is_empty() {
            return ReplicationHealth::Failing;
        }
        let rpo = self.rpo_secs(now);
        // Yellow when RPO exceeds 2× the expected period — typical
        // "you missed one tick" threshold used in DR runbooks.
        if rpo > expected_period_secs.saturating_mul(2) {
            ReplicationHealth::Stale
        } else {
            ReplicationHealth::Healthy
        }
    }
}

/// Replication health classification. Drives UI colour cues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationHealth {
    Healthy,
    Stale,
    Failing,
}

// ── Storage content (feature #2) ────────────────────────
//
// Returned by `GET /nodes/{node}/storage/{storage}/content`. Each entry
// is a stored item: ISO, disk image, backup, etc. We use this to show
// the user what's already on a storage so the ISO library can mark
// "already downloaded".

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageContent {
    /// Volume identifier, e.g. `"local:iso/debian-12.iso"`.
    pub volid: String,
    /// Content type: `"iso"`, `"vztmpl"`, `"backup"`, `"images"`, `"import"`.
    #[serde(default)]
    pub content: String,
    /// Size in bytes.
    #[serde(default)]
    pub size: u64,
    /// File format for image entries (`"qcow2"`, `"raw"`, etc.); empty
    /// for ISOs.
    #[serde(default)]
    pub format: String,
}

impl StorageContent {
    /// Last URL path component or filename — useful for matching against
    /// what proxxx is about to download.
    #[must_use]
    pub fn filename(&self) -> &str {
        self.volid.rsplit('/').next().unwrap_or(&self.volid)
    }
}

#[cfg(test)]
mod forward_compat_tests {
    use super::*;

    /// V29.2 (audit) — PVE 8.4 hypothetically adds a `"hibernating"`
    /// guest status. Without `#[serde(other)]` the entire `/qemu`
    /// or `/lxc` payload would fail deserialization. With it, the
    /// unknown value lands in `Unknown` and the rest survives.
    #[test]
    fn guest_status_unknown_variant_falls_back_to_unknown() {
        let json = r#""hibernating""#;
        let parsed: GuestStatus =
            serde_json::from_str(json).expect("unknown variant must be tolerated");
        assert_eq!(parsed, GuestStatus::Unknown);
    }

    #[test]
    fn node_status_unknown_variant_falls_back_to_unknown() {
        let json = r#""maintenance""#;
        let parsed: NodeStatus =
            serde_json::from_str(json).expect("unknown variant must be tolerated");
        assert_eq!(parsed, NodeStatus::Unknown);
    }

    /// V29.2 — a Guest with an unknown status string MUST still
    /// deserialize as part of a list, with the bad field clamped to
    /// Unknown and every OTHER field intact. End-to-end proof.
    #[test]
    fn guest_with_unknown_status_does_not_break_list_parse() {
        let json = r#"[
            {"vmid": 100, "status": "running",  "type": "qemu"},
            {"vmid": 101, "status": "starborn", "type": "qemu"},
            {"vmid": 102, "status": "stopped",  "type": "qemu"}
        ]"#;
        let parsed: Vec<Guest> = serde_json::from_str(json).expect("list survives unknown variant");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].status, GuestStatus::Running);
        assert_eq!(parsed[1].status, GuestStatus::Unknown);
        assert_eq!(parsed[2].status, GuestStatus::Stopped);
    }
}

#[cfg(test)]
mod ha_tests {
    use super::*;

    #[test]
    fn ha_group_priority_list_parses_full_form() {
        let g = HaGroup {
            name: "g1".into(),
            nodes: "pve1:2,pve2:1,pve3".into(),
            restricted: false,
            nofailback: false,
            comment: String::new(),
        };
        let parsed = g.parse_priority_list();
        // Sorted descending priority: pve1(2), pve2(1), pve3(0)
        assert_eq!(parsed[0], ("pve1".to_string(), 2));
        assert_eq!(parsed[1], ("pve2".to_string(), 1));
        assert_eq!(parsed[2], ("pve3".to_string(), 0));
    }

    #[test]
    fn ha_group_priority_list_handles_whitespace_and_empty() {
        let g = HaGroup {
            name: "g".into(),
            nodes: " pve1:5 , , pve2 ".into(),
            restricted: true,
            nofailback: false,
            comment: String::new(),
        };
        let parsed = g.parse_priority_list();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "pve1");
        assert_eq!(parsed[0].1, 5);
        assert_eq!(parsed[1].0, "pve2");
    }

    #[test]
    fn ha_group_priority_list_empty_nodes() {
        let g = HaGroup {
            name: "g".into(),
            nodes: String::new(),
            restricted: false,
            nofailback: false,
            comment: String::new(),
        };
        assert!(g.parse_priority_list().is_empty());
    }

    #[test]
    fn ha_resource_parses_sid() {
        let r = HaResource {
            sid: "vm:100".into(),
            group: String::new(),
            state: "started".into(),
            max_restart: 1,
            max_relocate: 1,
            comment: String::new(),
        };
        assert_eq!(r.vmid(), Some(100));
        assert_eq!(r.kind(), "vm");

        let ct = HaResource {
            sid: "ct:200".into(),
            group: String::new(),
            state: "started".into(),
            max_restart: 1,
            max_relocate: 1,
            comment: String::new(),
        };
        assert_eq!(ct.vmid(), Some(200));
        assert_eq!(ct.kind(), "ct");

        let bad = HaResource {
            sid: "garbage".into(),
            group: String::new(),
            state: String::new(),
            max_restart: 0,
            max_relocate: 0,
            comment: String::new(),
        };
        assert_eq!(bad.vmid(), None);
        assert_eq!(bad.kind(), "");
    }

    #[test]
    fn replication_rpo_never_synced_is_stale() {
        let s = ReplicationStatus {
            id: "100-0".into(),
            last_sync: 0,
            ..Default::default()
        };
        assert_eq!(s.rpo_secs(1_700_000_000), u64::MAX);
        // Never-synced is Stale by current rule (rpo > 2× period
        // because rpo == u64::MAX). The UI should distinguish this
        // visually but the worst-case classification is appropriate
        // — a never-replicated job is exactly as useful for DR.
        assert_eq!(s.health(1_700_000_000, 900), ReplicationHealth::Stale);
    }

    #[test]
    fn replication_rpo_recent_synced() {
        let s = ReplicationStatus {
            id: "100-0".into(),
            last_sync: 1_700_000_000,
            ..Default::default()
        };
        assert_eq!(s.rpo_secs(1_700_000_300), 300);
        assert_eq!(s.health(1_700_000_300, 900), ReplicationHealth::Healthy);
    }

    #[test]
    fn replication_health_stale_after_2x_period() {
        let s = ReplicationStatus {
            id: "100-0".into(),
            last_sync: 1_700_000_000,
            ..Default::default()
        };
        // Period = 15 min (900s). 2× = 1800. 1801s elapsed → Stale.
        assert_eq!(s.health(1_700_001_801, 900), ReplicationHealth::Stale);
    }

    #[test]
    fn replication_health_failing_when_error_present() {
        let s = ReplicationStatus {
            id: "100-0".into(),
            last_sync: 1_700_000_000,
            error: "ssh: connect: Network is unreachable".into(),
            fail_count: 0,
            ..Default::default()
        };
        // Even if RPO is fresh, presence of error → failing.
        assert_eq!(s.health(1_700_000_60, 900), ReplicationHealth::Failing);
    }

    #[test]
    fn replication_health_failing_when_fail_count_nonzero() {
        let s = ReplicationStatus {
            id: "100-0".into(),
            last_sync: 1_700_000_000,
            fail_count: 3,
            ..Default::default()
        };
        assert_eq!(s.health(1_700_000_30, 900), ReplicationHealth::Failing);
    }

    #[test]
    fn replication_job_extracts_vmid_from_id() {
        let j = ReplicationJob {
            id: "100-0".into(),
            job_type: "local".into(),
            source: "pve1".into(),
            target: "pve2".into(),
            schedule: "*/15".into(),
            disable: false,
            comment: String::new(),
        };
        assert_eq!(j.vmid(), Some(100));

        let bad = ReplicationJob {
            id: "garbage".into(),
            job_type: "local".into(),
            source: String::new(),
            target: String::new(),
            schedule: String::new(),
            disable: false,
            comment: String::new(),
        };
        assert_eq!(bad.vmid(), None);
    }
}
