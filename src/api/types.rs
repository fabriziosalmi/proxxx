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
    /// PVE marks a guest as a template by setting `template: 1` in
    /// the list response. Templates cannot be started — the start
    /// endpoint rejects them with a 500 — so callers must check
    /// `is_template()` and route to `clone_guest` instead. Field
    /// is `bool` here; PVE serializes as 0/1 int and the custom
    /// deserializer accepts either.
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub template: bool,
    /// Cumulative bytes received on the guest's NICs since boot.
    /// Combined with `uptime` gives an average network rate the
    /// pre-flight risk framework uses to flag "this VM is probably
    /// serving real traffic — confirm before destroying".
    pub netin: u64,
    /// Cumulative bytes transmitted since boot. Same rationale.
    pub netout: u64,
}

impl Guest {
    /// V27.1 — true if this guest is under HA-CRM management.
    /// Destructive raw `/status/*` calls must NOT be issued; route
    /// through `/cluster/ha/resources/<vmid>` state changes
    /// instead.
    #[must_use]
    pub const fn is_ha_managed(&self) -> bool {
        !self.hastate.is_empty()
    }

    /// V27.4 — true if PVE has a sticky lock on this guest right
    /// now. Caller should refuse destructive ops with a clear
    /// "guest is locked: {`lock_reason`}" message rather than collide
    /// with PVE's 500.
    #[must_use]
    pub const fn is_locked(&self) -> bool {
        !self.lock.is_empty()
    }

    /// True if this guest is a template (cannot be started; only
    /// usable as the source for `clone_guest`). Set when PVE returns
    /// `template: 1` in the list response.
    #[must_use]
    pub const fn is_template(&self) -> bool {
        self.template
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

/// Tolerant u32 deserializer: accepts JSON number OR JSON string.
/// PVE serializes some numeric fields as strings depending on
/// version + endpoint (e.g. `port: "5900"` from termproxy/vncproxy
/// on PVE 9). Without this, deserialization fails with a confusing
/// "invalid type: string, expected u32" error.
fn deserialize_u32_from_str_or_num<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StrOrNum;
    impl de::Visitor<'_> for StrOrNum {
        type Value = u32;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a u32 number or a string containing a u32")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<u32, E> {
            u32::try_from(v).map_err(|_| E::custom(format!("u64 {v} doesn't fit in u32")))
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<u32, E> {
            u32::try_from(v).map_err(|_| E::custom(format!("i64 {v} doesn't fit in u32")))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<u32, E> {
            v.parse::<u32>()
                .map_err(|e| E::custom(format!("cannot parse {v:?} as u32: {e}")))
        }
        fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<u32, E> {
            self.visit_str(&v)
        }
    }
    deserializer.deserialize_any(StrOrNum)
}

/// Same as [`deserialize_u32_from_str_or_num`] but for `u64`. Used for
/// fields like `ClusterLogEntry::uid` where PVE serializes the row's
/// monotonic id as a JSON string (`"2957"`) rather than a number.
fn deserialize_u64_from_str_or_num<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StrOrNum;
    impl de::Visitor<'_> for StrOrNum {
        type Value = u64;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a u64 number or a string containing a u64")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<u64, E> {
            Ok(v)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<u64, E> {
            u64::try_from(v).map_err(|_| E::custom(format!("i64 {v} doesn't fit in u64")))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<u64, E> {
            v.parse::<u64>()
                .map_err(|e| E::custom(format!("cannot parse {v:?} as u64: {e}")))
        }
        fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<u64, E> {
            self.visit_str(&v)
        }
    }
    deserializer.deserialize_any(StrOrNum)
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

/// Response from `GET /nodes/{n}/tasks/{upid}/status`. Used by
/// `--wait` to poll a long-running operation until completion.
///
/// Wire shape:
/// ```json
/// {"data": {"status": "stopped", "exitstatus": "OK",
///           "type": "qmigrate", "id": "8888", "starttime": 123,
///           "user": "root@pam"}}
/// ```
///
/// `status` is `"running"` while the task is in progress, `"stopped"`
/// once finished. `exitstatus` is only meaningful when stopped:
/// `"OK"` for success, otherwise an error string lifted from PVE
/// (typically the last log line).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskStatus {
    pub upid: String,
    pub status: String,
    pub exitstatus: Option<String>,
    #[serde(rename = "type")]
    pub task_type: String,
    pub id: String,
    pub user: String,
    pub starttime: u64,
}

impl TaskStatus {
    /// True when PVE has finished running the task (status == "stopped").
    /// Polling can stop here; callers then check `is_success()` for
    /// the outcome.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.status == "stopped"
    }
    /// True only after `is_done() && exitstatus == Some("OK")`. Anything
    /// else — partial completion, error string, missing exitstatus —
    /// is a failure from the caller's perspective.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.is_done() && self.exitstatus.as_deref() == Some("OK")
    }
}

/// Response from `POST /nodes/{n}/qemu/{vmid}/agent/exec`. The agent
/// forks the command and immediately returns the PID — actual completion
/// must be polled via `agent/exec-status?pid=N`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentExecResponse {
    pub pid: i32,
}

/// Response from `GET /nodes/{n}/qemu/{vmid}/agent/exec-status?pid=N`.
/// Returned by QEMU Guest Agent when polling a previously-submitted
/// command. Fields use kebab-case on the wire and are renamed here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentExecStatusResponse {
    /// Whether the command has finished. PVE serializes this as 0/1
    /// rather than a JSON bool.
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub exited: bool,
    /// Exit code reported by the command. Only meaningful once
    /// `exited == true`.
    pub exitcode: i32,
    /// Captured stdout (may be truncated — see `out_truncated`).
    #[serde(rename = "out-data")]
    pub out_data: String,
    /// Captured stderr (may be truncated — see `err_truncated`).
    #[serde(rename = "err-data")]
    pub err_data: String,
    /// True if PVE truncated stdout (default cap is ~16 KiB).
    #[serde(
        rename = "out-truncated",
        deserialize_with = "deserialize_bool_from_int"
    )]
    pub out_truncated: bool,
    /// True if PVE truncated stderr.
    #[serde(
        rename = "err-truncated",
        deserialize_with = "deserialize_bool_from_int"
    )]
    pub err_truncated: bool,
    /// Signal that terminated the command, if any (POSIX signal number).
    pub signal: i32,
}

/// Aggregated result of running a command in a guest. Returned by
/// `execute_guest_command` for QEMU guests only — LXC has no REST
/// exec endpoint in PVE 9+ and the call bails for containers
/// (callers should use `proxxx serial` or SSH for LXCs).
///
/// All three fields are populated by polling the QEMU Guest Agent's
/// `exec-status` endpoint until the command finishes or
/// `QGA_EXEC_TIMEOUT` elapses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GuestExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

// ── QEMU Guest Agent file ops + network introspection ──
//
// QGA-only surface: requires `agent: 1` in the VM config and the
// guest-agent package installed inside the VM. LXC has no QGA — these
// trait methods are QEMU-only and the CLI bails if pointed at an LXC.

/// Result of `GET /nodes/{n}/qemu/{vmid}/agent/file-read?file=…`. PVE
/// caps file size at the QGA buffer (default ~16 KiB) and sets
/// `truncated=1` when the file was bigger — surfaced here so callers
/// can warn the operator instead of silently using a partial read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuestAgentFileContent {
    pub content: String,
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub truncated: bool,
}

/// One IP address attached to a guest network interface (from QGA's
/// `network-get-interfaces` reply).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuestAgentIpAddress {
    /// `"ipv4"` | `"ipv6"`. Some QGA versions also report `"ipv4-link-local"`.
    #[serde(rename = "ip-address-type")]
    pub ip_address_type: String,
    #[serde(rename = "ip-address")]
    pub ip_address: String,
    /// CIDR prefix length. 32 for IPv4 host routes, 128 for IPv6 host.
    pub prefix: u8,
}

/// One network interface as reported by the QEMU Guest Agent. Used
/// by operators to confirm a guest's actual IPs (not just what the
/// `qm config` cloud-init line claims) — e.g. after a DHCP renewal,
/// or to map a VMID to a reachable IP without SSHing in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuestAgentNetworkInterface {
    pub name: String,
    /// MAC address (kebab-case on the wire).
    #[serde(rename = "hardware-address")]
    pub hardware_address: String,
    /// Each interface can have multiple IPs (link-local + DHCP + static).
    #[serde(rename = "ip-addresses")]
    pub ip_addresses: Vec<GuestAgentIpAddress>,
}

// ── Node system layer (nodes.system.*) ────────────────
//
// Day-to-day "what does this node look like" plumbing: DNS resolvers,
// /etc/hosts, NTP, journal/syslog tail, subscription state, certs.
// The shapes are flat enough that one struct per resource is plenty;
// every field defaults so older PVE versions that omit newer fields
// (e.g. `nextduedate` arrived in PVE 7) still deserialize cleanly.

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

/// `GET /nodes/{n}/hosts` — the entire `/etc/hosts` content as a
/// single string + a digest token for atomic replace. PUT requires
/// the digest from a prior GET (PVE rejects mismatch with 412).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeHosts {
    pub data: String,
    pub digest: String,
}

/// `GET /nodes/{n}/time` — current node clock + timezone. PUT takes
/// `timezone` only (the clock is set by NTP, not the API).
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

/// One row of `GET /nodes/{n}/syslog` — log line + 1-indexed cursor
/// the next pagination call should pass back as `start`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeSyslogLine {
    /// 1-indexed line number (PVE field `n`).
    pub n: u64,
    /// Log line text (PVE field `t`).
    pub t: String,
}

/// `GET /nodes/{n}/subscription` — license key + activation state.
/// Lots of optional fields because the response shape varies by
/// subscription level + activation state (no key, key set but
/// inactive, active, expired, server-side error).
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

/// One certificate from `GET /nodes/{n}/certificates/info`. PVE
/// serves multiple — typically `pve-ssl.pem` (cluster CA-signed),
/// optional `pveproxy-ssl.pem` (operator-uploaded custom), and the
/// ACME-issued one when configured.
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

// ── Pools, cluster resources, version (foundationals) ──
//
// `/pools` is the multi-tenant grouping primitive — a pool is a named
// bag of guests + storages that ACL paths can target as `/pool/<name>`.
// `/cluster/resources` is the single-shot cluster-wide query that the
// PVE web UI's main dashboard uses. `/version` is what `pveversion -v`
// hits — useful for compat checks before invoking PVE-version-gated
// endpoints (e.g. forwarded firewall direction needs PVE 8+).

/// One row of `GET /pools`. Just the id + free-form comment — to see
/// which guests/storages are in a pool you need a separate
/// `GET /pools/{poolid}` call.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Pool {
    pub poolid: String,
    pub comment: String,
}

/// Detail view of one pool from `GET /pools/{poolid}`. Carries the
/// list of members (mixed VMs, containers, storages) with whatever
/// per-row fields PVE happens to emit for each kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PoolDetails {
    pub poolid: String,
    pub comment: String,
    pub members: Vec<PoolMember>,
}

/// One pool member. PVE returns a mixed shape (a VM has `vmid` + `node`,
/// a storage has `storage`); the typed fields here are the union, with
/// every field defaulting so heterogeneous rows deserialize cleanly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PoolMember {
    /// e.g. `qemu/100`, `lxc/200`, `storage/pve1/local`.
    pub id: String,
    /// `qemu` | `lxc` | `storage`.
    #[serde(rename = "type")]
    pub member_type: String,
    pub node: String,
    pub vmid: u32,
    pub storage: String,
    pub status: String,
    pub name: String,
}

/// One row from `GET /cluster/resources`. PVE's most useful single
/// query: nodes, guests, storages, sdn objects, and pools all
/// flattened into one list with a discriminator (`type`). Every field
/// is optional because the meaningful subset depends on `type`.
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

/// `GET /version` — what `pveversion -v` reports. Useful for
/// compat-gating PVE-version-dependent calls (e.g. `forward` direction
/// rules need PVE 8+, `suspendall` needs PVE 8+).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiVersion {
    /// e.g. `"9.1.9"`.
    pub version: String,
    /// e.g. `"9.1"`.
    pub release: String,
    /// Build identifier (git revision short).
    pub repoid: String,
}

// ── Cluster-wide config + log (cluster.core.{options,log}) ──
//
// `/cluster/options` is the global cluster config — mac_prefix for new
// VM NICs, default migration network, console viewer choice, HA
// fencing strategy, etc. `/cluster/log` is the rolling cluster event
// log (login/lockout/task-start/quorum events) — diagnostic surface.

/// `GET /cluster/options` — global cluster config. Many fields; the
/// typed ones below are the operator-facing essentials (mac_prefix,
/// migration network, etc.). Less-common knobs (crs, fencing, u2f
/// schema) are reachable via `--raw KEY=VAL` on the CLI.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterOptions {
    /// MAC prefix for auto-generated guest NIC MACs (e.g. `BC:24:11`).
    pub mac_prefix: String,
    /// Per-traffic-type bandwidth caps (string-encoded sub-spec).
    pub bwlimit: String,
    /// Console viewer choice: `applet` | `vv` | `html5` | `xtermjs`.
    pub console: String,
    /// Free-form cluster description shown in the web UI.
    pub description: String,
    pub email_from: String,
    pub http_proxy: String,
    /// Default keyboard layout for VNC/console (e.g. `en-us`, `it`).
    pub keyboard: String,
    pub language: String,
    /// Default migration network/type (encoded sub-spec, e.g.
    /// `type=insecure` or `network=10.0.0.0/24`).
    pub migration: String,
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub migration_unsecure: bool,
    pub max_workers: u32,
    /// Tags allowed on guests (semicolon-separated).
    #[serde(rename = "registered-tags", default)]
    pub registered_tags: String,
    /// Tag-style policy: `free` | `restricted` | `must-be-defined`.
    #[serde(rename = "tag-style", default)]
    pub tag_style: String,
}

/// One row of `GET /cluster/log` — the rolling cluster event stream.
/// Login attempts, task starts/completions, quorum changes all land
/// here. Useful for "what happened around 14:30 yesterday" diagnostics.
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

/// One firewall rule. Returned by:
///   - `GET /cluster/firewall/rules` — datacenter scope
///   - `GET /nodes/{n}/firewall/rules` — node scope
///   - `GET /nodes/{n}/{kind}/{vmid}/firewall/rules` — guest scope
///
/// All three endpoints share this exact shape. Fields not set on a
/// given rule come back missing from PVE's JSON; the struct-level
/// `#[serde(default)]` substitutes empty strings / zero ints. The
/// `digest` field is PVE's atomic-update token (SHA1 of the rules
/// file) — ignored on read but preserved for round-trip fidelity.
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

// ── Cluster firewall CRUD (cluster.firewall.{aliases,groups,ipset,options}) ──
//
// PVE's `/cluster/firewall/*` surface beyond the rules list. These four
// resources back the operator's day-to-day firewall hygiene work:
// reusable address aliases, security-group templates, IP sets, and the
// global enable/policy toggles. All four follow the same V25-audit
// pattern (every field defaults), so a half-populated PVE response still
// deserializes cleanly.

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

/// One security group from `GET /cluster/firewall/groups`. Groups are
/// reusable rule-bundles — `direction=group` rules in any chain
/// reference a group by name and inline its rules at evaluation time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallSecurityGroup {
    pub group: String,
    pub comment: String,
    pub digest: String,
}

/// One IP set from `GET /cluster/firewall/ipset`. An ipset is a named
/// collection of CIDRs (filled separately via `/cluster/firewall/ipset/{name}`),
/// referenced from rules as `+ipset-name`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallIpset {
    pub name: String,
    pub comment: String,
    pub digest: String,
}

/// One CIDR entry within an ipset, from
/// `GET /cluster/firewall/ipset/{name}`. The `nomatch` flag inverts
/// membership for that specific CIDR (lets you carve out an exception
/// from a broader range).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallIpsetCidr {
    pub cidr: String,
    pub comment: String,
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub nomatch: bool,
    pub digest: String,
}

/// Cluster-wide firewall options from `GET /cluster/firewall/options`.
/// This is the global enable/disable + default policy + ratelimit
/// surface. The bool-from-int + per-field default pattern means PVE
/// versions that omit newer fields (e.g. older clusters without
/// `ebtables`) still deserialize without losing the rest.
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

/// Per-guest firewall options from
/// `GET /nodes/{n}/{kind}/{vmid}/firewall/options`. Larger surface than
/// the cluster-scope counterpart because the per-guest hook touches
/// L2/L3 details (MAC filter, IP filter, DHCP/NDP auto-allow) that are
/// only meaningful at the guest NIC. Closes the operator-facing CRUD
/// half of `qemu.firewall.options` + `lxc.firewall.options` — the
/// rules-list endpoint was already covered.
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

// ── Cluster hardware mapping (cluster.mapping.{pci,usb}) ────
//
// Operators with GPU/USB passthrough need to refer to a piece of
// hardware by a stable logical name (e.g. `gpu-rtx`) rather than by
// its bus address — the address differs per node, and a guest that
// migrates would otherwise lose its passthrough. PVE solves this with
// /cluster/mapping/{pci,usb}: a logical `id`, a per-node `map`
// describing where that device lives on each cluster member.

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

/// One USB device mapping from `GET /cluster/mapping/usb`. Same shape
/// as PCI minus the mediated-device flag (USB has no vGPU equivalent).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterMappingUsb {
    pub id: String,
    pub description: String,
    pub map: Vec<String>,
    pub digest: String,
}

/// One network interface from `GET /nodes/{n}/network`. PVE merges
/// physical NICs, bridges, bonds, and VLAN devices into a single
/// flat list — the `iface_type` discriminator tells callers which
/// fields are meaningful for a given row.
///
/// Bridge rows populate `bridge_ports`/`bridge_stp`/`bridge_fd`.
/// Bond rows populate `slaves`/`bond_mode`. VLAN rows populate
/// `vlan_raw_device`. Physical (`eth`) rows usually only have
/// `iface`/`active`/`exists`/`altnames`.
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

/// One row from `GET /nodes/{n}/{kind}/{vmid}/pending`. Reports a
/// config key alongside its current value and any change queued to
/// apply on the next guest reboot.
///
/// PVE marks a row in three flavours (the fields are mutually
/// exclusive at the wire level — at most one of `pending`/`delete`
/// will be `Some`):
///   - **applied** (`pending = None && delete = None`): the value
///     is already in effect.
///   - **pending change** (`pending = Some(new)`): the change has
///     been written but waits for a reboot.
///   - **pending delete** (`delete = Some(1)`): the key is queued
///     for removal on next reboot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PendingConfigEntry {
    pub key: String,
    /// Current effective value (None for keys that only exist as
    /// pending additions). Kept as `serde_json::Value` because PVE
    /// emits a mix of strings and integers in the same array
    /// (`memory: 256` int, `ostype: "alpine"` string) — narrowing
    /// to a single typed field would fail the whole list parse on
    /// the first int-typed key.
    pub value: Option<serde_json::Value>,
    /// Value queued to take effect on next reboot. Same int-or-string
    /// rationale as `value`.
    pub pending: Option<serde_json::Value>,
    /// `1` if the key is queued for deletion on next reboot.
    pub delete: Option<u8>,
}

// ── PVE property strings (Bisturi Tier-0 foundation) ─────
//
// PVE config keys whose VALUES are themselves CSV-encoded sub-records.
// Examples:
//   ipconfig0 = "ip=10.0.0.5/24,gw=10.0.0.1,ip6=dhcp"
//   net0      = "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1"
//   scsi0     = "local-lvm:vm-100-disk-0,size=32G,iothread=1"
//
// Each gets a typed struct with `FromStr` (parse PVE → struct) and
// `Display` (struct → PVE) so:
//   1. CLI / TUI input is validated parse-time (typo `bridge=vmrb0`
//      would still pass — we don't validate the bridge name itself —
//      but `--ip notanip` is caught by `--ip` clap-typed parsing).
//   2. Round-trip is lossless: parse → Display → parse stays identical.
//   3. Future field additions (PVE 10's hypothetical `iothread2`) only
//      require adding a struct field; callers don't change.

/// Cloud-init `ipconfig{N}` property string. Used to set per-NIC IP
/// configuration on QEMU VMs running cloud-init. Each NIC gets its own
/// (`ipconfig0` for `net0`, `ipconfig1` for `net1`, …).
///
/// Format on the wire: comma-separated `key=value` pairs. All keys are
/// optional; an empty struct serialises to an empty string (which PVE
/// accepts as "remove all ipconfig for this NIC").
///
/// Recognised keys:
///   - `ip`  — IPv4 CIDR (e.g. `10.0.0.5/24`) or the literal `dhcp`.
///   - `gw`  — IPv4 gateway address.
///   - `ip6` — IPv6 CIDR or `dhcp` or `auto` (SLAAC).
///   - `gw6` — IPv6 gateway address.
///
/// Unknown keys are preserved on parse and re-emitted on Display so a
/// future PVE addition (`ip4mtu`?) round-trips through this struct
/// without loss — caller code that doesn't know about the key still
/// sees it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ipconfig {
    pub ip: Option<String>,
    pub gw: Option<String>,
    pub ip6: Option<String>,
    pub gw6: Option<String>,
    /// Unrecognised `key=value` pairs from a forward-compat parse.
    /// Re-emitted in original order on Display.
    pub extra: Vec<(String, String)>,
}

impl std::str::FromStr for Ipconfig {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut out = Self::default();
        if s.trim().is_empty() {
            return Ok(out);
        }
        for token in s.split(',') {
            let (k, v) = token.split_once('=').ok_or_else(|| {
                anyhow::anyhow!(
                    "ipconfig token '{token}' missing '=' separator (expected `key=value`)"
                )
            })?;
            let (k, v) = (k.trim(), v.trim());
            if k.is_empty() {
                anyhow::bail!("ipconfig token '{token}' has empty key");
            }
            match k {
                "ip" => out.ip = Some(v.to_string()),
                "gw" => out.gw = Some(v.to_string()),
                "ip6" => out.ip6 = Some(v.to_string()),
                "gw6" => out.gw6 = Some(v.to_string()),
                _ => out.extra.push((k.to_string(), v.to_string())),
            }
        }
        Ok(out)
    }
}

impl std::fmt::Display for Ipconfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        if let Some(v) = &self.ip {
            parts.push(format!("ip={v}"));
        }
        if let Some(v) = &self.gw {
            parts.push(format!("gw={v}"));
        }
        if let Some(v) = &self.ip6 {
            parts.push(format!("ip6={v}"));
        }
        if let Some(v) = &self.gw6 {
            parts.push(format!("gw6={v}"));
        }
        for (k, v) in &self.extra {
            parts.push(format!("{k}={v}"));
        }
        f.write_str(&parts.join(","))
    }
}

/// QEMU `net{N}` property string. Example wire form returned by PVE:
///
/// ```text
/// virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1
/// ```
///
/// **First-token quirk**: unlike most PVE property strings, the first
/// token's KEY is the NIC model (`virtio`, `e1000`, `rtl8139`,
/// `vmxnet3`, …) and its VALUE is the MAC address. There is no
/// separate `model=` key. If the first token has no `=`, the model
/// is the entire token and PVE will auto-assign the MAC.
///
/// All subsequent tokens are regular `key=value` pairs.
///
/// LXC has its own (different) net format using `name=eth0,...,hwaddr=...`
/// — that's `LxcNetSpec`'s job (not yet implemented).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct QemuNetSpec {
    /// NIC model: `virtio`, `e1000`, `rtl8139`, `vmxnet3`, `e1000e`, ...
    pub model: String,
    /// MAC address. None means PVE auto-assigns on guest start.
    pub mac: Option<String>,
    /// Bridge to attach to (e.g. `vmbr0`).
    pub bridge: Option<String>,
    /// Whether host firewall hooks attach to this NIC's chain.
    pub firewall: bool,
    /// Administratively down — kernel link is forced off.
    pub link_down: bool,
    /// MTU. None = inherit from bridge.
    pub mtu: Option<u32>,
    /// Multi-queue tx/rx rings.
    pub queues: Option<u32>,
    /// Rate limit in MB/s. None = unlimited.
    pub rate: Option<f64>,
    /// VLAN tag (single, untagged on bridge if None).
    pub tag: Option<u32>,
    /// VLAN trunk allowed list (semicolon-separated string per PVE).
    pub trunks: Option<String>,
    /// Unrecognised extras for forward-compat — round-trip via Display.
    pub extra: Vec<(String, String)>,
}

impl std::str::FromStr for QemuNetSpec {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            anyhow::bail!("empty QEMU net spec");
        }
        let tokens: Vec<&str> = s.split(',').collect();
        let mut spec = Self::default();
        // First token: <model>[=<mac>] — the model is mandatory, mac
        // is optional (PVE auto-assigns when absent). This is the
        // quirk that distinguishes QEMU net from every other PVE
        // property string.
        let first = tokens
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("empty QEMU net spec"))?
            .trim();
        if let Some((model, mac)) = first.split_once('=') {
            let model = model.trim();
            if model.is_empty() {
                anyhow::bail!("QEMU net spec first token has empty model");
            }
            spec.model = model.to_string();
            spec.mac = Some(mac.trim().to_string());
        } else {
            spec.model = first.to_string();
        }
        if spec.model.is_empty() {
            anyhow::bail!("QEMU net spec has no model (first token must be <model>[=<mac>])");
        }
        // Subsequent tokens: regular key=value.
        for tok in tokens.iter().skip(1) {
            let (k, v) = tok.split_once('=').ok_or_else(|| {
                anyhow::anyhow!("QEMU net token '{tok}' missing '=' separator after first token")
            })?;
            let (k, v) = (k.trim(), v.trim());
            if k.is_empty() {
                anyhow::bail!("QEMU net token '{tok}' has empty key");
            }
            match k {
                "bridge" => spec.bridge = Some(v.to_string()),
                "firewall" => spec.firewall = matches!(v, "1" | "true"),
                "link_down" => spec.link_down = matches!(v, "1" | "true"),
                "mtu" => {
                    spec.mtu = Some(
                        v.parse()
                            .map_err(|e| anyhow::anyhow!("invalid mtu '{v}': {e}"))?,
                    );
                }
                "queues" => {
                    spec.queues = Some(
                        v.parse()
                            .map_err(|e| anyhow::anyhow!("invalid queues '{v}': {e}"))?,
                    );
                }
                "rate" => {
                    spec.rate = Some(
                        v.parse()
                            .map_err(|e| anyhow::anyhow!("invalid rate '{v}': {e}"))?,
                    );
                }
                "tag" => {
                    spec.tag = Some(
                        v.parse()
                            .map_err(|e| anyhow::anyhow!("invalid tag '{v}': {e}"))?,
                    );
                }
                "trunks" => spec.trunks = Some(v.to_string()),
                _ => spec.extra.push((k.to_string(), v.to_string())),
            }
        }
        Ok(spec)
    }
}

impl std::fmt::Display for QemuNetSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        // First token: model[=mac]
        if let Some(mac) = &self.mac {
            parts.push(format!("{}={}", self.model, mac));
        } else {
            parts.push(self.model.clone());
        }
        if let Some(b) = &self.bridge {
            parts.push(format!("bridge={b}"));
        }
        if self.firewall {
            parts.push("firewall=1".into());
        }
        if self.link_down {
            parts.push("link_down=1".into());
        }
        if let Some(v) = self.mtu {
            parts.push(format!("mtu={v}"));
        }
        if let Some(v) = self.queues {
            parts.push(format!("queues={v}"));
        }
        if let Some(v) = self.rate {
            parts.push(format!("rate={v}"));
        }
        if let Some(v) = self.tag {
            parts.push(format!("tag={v}"));
        }
        if let Some(t) = &self.trunks {
            parts.push(format!("trunks={t}"));
        }
        for (k, v) in &self.extra {
            parts.push(format!("{k}={v}"));
        }
        f.write_str(&parts.join(","))
    }
}

/// QEMU disk property string for `scsi{N}` / `virtio{N}` / `ide{N}` /
/// `sata{N}`. Example wire forms PVE returns:
///
/// ```text
/// local-lvm:vm-100-disk-0,size=32G,iothread=1
/// local:iso/ubuntu-22.04.iso,media=cdrom
/// none,media=cdrom
/// ```
///
/// **First-token quirk**: like `QemuNetSpec`, the first token has
/// no `=` separator — it's the **source** (storage:volume reference,
/// ISO path, or the literal `none` for an empty CD-ROM).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QemuDiskSpec {
    /// `<storage>:<volume>` (e.g. `local-lvm:vm-100-disk-0`),
    /// `<storage>:iso/<file>` for an ISO mount, or the literal
    /// `none` for an empty CD-ROM.
    pub source: String,
    /// PVE-formatted size (e.g. `"32G"`, `"10240M"`). For existing
    /// volumes this is reported as-was on disk; for new disks it's
    /// the requested capacity.
    pub size: Option<String>,
    /// `"raw"`, `"qcow2"`, `"vmdk"`, ...
    pub format: Option<String>,
    /// Run the I/O on a dedicated thread (QEMU `iothread`).
    pub iothread: bool,
    /// Include in vzdump backups. PVE default is true (enabled).
    /// Stored as `Option<bool>` so we can distinguish "explicitly
    /// false" from "default" on round-trip.
    pub backup: Option<bool>,
    /// Pass TRIM commands through to the backend.
    pub discard: bool,
    /// Advertise the disk as an SSD to the guest.
    pub ssd: bool,
    /// `"writeback"`, `"none"`, `"writethrough"`, `"directsync"`,
    /// `"unsafe"`.
    pub cache: Option<String>,
    /// `"disk"` (default) or `"cdrom"`.
    pub media: Option<String>,
    /// Unrecognised extras for forward-compat.
    pub extra: Vec<(String, String)>,
}

impl std::str::FromStr for QemuDiskSpec {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            anyhow::bail!("empty QEMU disk spec");
        }
        let tokens: Vec<&str> = s.split(',').collect();
        let mut spec = Self::default();
        let first = tokens
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("empty QEMU disk spec"))?
            .trim();
        if first.is_empty() {
            anyhow::bail!("QEMU disk spec source token is empty");
        }
        spec.source = first.to_string();
        for tok in tokens.iter().skip(1) {
            let (k, v) = tok.split_once('=').ok_or_else(|| {
                anyhow::anyhow!("QEMU disk token '{tok}' missing '=' separator after source")
            })?;
            let (k, v) = (k.trim(), v.trim());
            if k.is_empty() {
                anyhow::bail!("QEMU disk token '{tok}' has empty key");
            }
            match k {
                "size" => spec.size = Some(v.to_string()),
                "format" => spec.format = Some(v.to_string()),
                "iothread" => spec.iothread = matches!(v, "1" | "true"),
                "backup" => spec.backup = Some(matches!(v, "1" | "true")),
                "discard" => spec.discard = matches!(v, "on" | "1" | "true"),
                "ssd" => spec.ssd = matches!(v, "1" | "true"),
                "cache" => spec.cache = Some(v.to_string()),
                "media" => spec.media = Some(v.to_string()),
                _ => spec.extra.push((k.to_string(), v.to_string())),
            }
        }
        Ok(spec)
    }
}

impl std::fmt::Display for QemuDiskSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<String> = vec![self.source.clone()];
        if let Some(v) = &self.size {
            parts.push(format!("size={v}"));
        }
        if let Some(v) = &self.format {
            parts.push(format!("format={v}"));
        }
        if self.iothread {
            parts.push("iothread=1".into());
        }
        if let Some(b) = self.backup {
            parts.push(format!("backup={}", if b { "1" } else { "0" }));
        }
        if self.discard {
            parts.push("discard=on".into());
        }
        if self.ssd {
            parts.push("ssd=1".into());
        }
        if let Some(v) = &self.cache {
            parts.push(format!("cache={v}"));
        }
        if let Some(v) = &self.media {
            parts.push(format!("media={v}"));
        }
        for (k, v) in &self.extra {
            parts.push(format!("{k}={v}"));
        }
        f.write_str(&parts.join(","))
    }
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
    /// Render to `.vv` (virt-viewer `ConfigFile`) format. Output starts
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
    /// PVE returns this as a JSON string on 9.x; the tolerant
    /// deserializer accepts both string and numeric forms.
    #[serde(deserialize_with = "deserialize_u32_from_str_or_num")]
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

// ── Scheduled backup jobs (cluster.backup_jobs) ────────────────────
//
// proxxx historically supports ON-DEMAND backups via `create_backup`
// (one-shot vzdump POST). PVE also stores RECURRING jobs at
// `/cluster/backup` — cron-like schedule + retention policy + email.
// These types model the recurring kind. Field set chosen pragmatically:
// the most-common knobs as typed fields, exotic ones (exclude paths,
// tmpdir, custom hooks) accessible via the raw-set CLI escape hatch
// or PVE web UI.

/// One scheduled vzdump job. `GET|POST|PUT|DELETE /cluster/backup`.
///
/// All fields default-empty. PVE 7+ uses `schedule` (systemd-time
/// format like `mon..fri 02:00`); pre-7 used `starttime` + `dow` —
/// not modeled, those clusters won't see the field populated.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupJob {
    /// Job id, autogenerated by PVE on POST (e.g. `backup-abc123`).
    /// Returned in list responses; required as URL segment for
    /// PUT/DELETE.
    pub id: String,

    /// systemd-time schedule expression. Example: `mon..fri 02:00`,
    /// `*-*-* 03:30`. The PVE web UI offers a builder; CLI users
    /// supply the literal string.
    pub schedule: String,

    /// Target storage id (e.g. `local`, `pbs-prod`).
    pub storage: String,

    /// `snapshot` (live, no downtime) | `stop` (full hard stop) |
    /// `suspend` (paused mid-backup). Default `snapshot`.
    pub mode: String,

    /// Whether the job is currently enabled (gets executed). PVE
    /// returns int 0/1; tolerant deserializer maps to bool.
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub enabled: bool,

    /// `true` = backup ALL guests cluster-wide (or all on `node`
    /// when set). When false, `vmid` field carries the explicit list.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub all: bool,

    /// CSV of VMIDs when `all` is false. Empty when `all` is true.
    pub vmid: String,

    /// Restrict to a single node by name. Empty = cluster-wide.
    pub node: String,

    /// Notify destination — single email address or empty.
    pub mailto: String,

    /// `always` | `failure` (default). Empty in some versions.
    pub mailnotification: String,

    /// `none` | `lzo` | `gzip` | `zstd`. Default `zstd` on PVE 7+.
    pub compress: String,

    /// Free-text job comment (shown in the web UI). Empty by default.
    pub comment: String,

    /// vzdump notes template — `{{guestname}}`, `{{cluster}}`, etc.
    /// PVE serializes the field name with a hyphen.
    #[serde(rename = "notes-template")]
    pub notes_template: String,

    /// Retention policy DSL: `keep-last=3,keep-daily=7,keep-monthly=12`.
    /// PVE serializes with hyphen.
    #[serde(rename = "prune-backups")]
    pub prune_backups: String,

    /// Next scheduled run, Unix epoch seconds. 0 / absent when the
    /// scheduler hasn't computed it yet OR job is disabled.
    #[serde(rename = "next-run", default)]
    pub next_run: u64,
}

/// VNC console connection ticket. Returned by
/// `POST /nodes/{node}/{kind}/{vmid}/vncproxy` (guest) or
/// `POST /nodes/{node}/vncshell` (node-level shell).
///
/// Same shape as `TermproxyTicket` plus an optional `cert` field —
/// VNC carries the TLS server certificate when verify_tls is on, so
/// downstream noVNC clients can pin against it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct VncTicket {
    /// Backend port the websocket should connect to (e.g. 5900).
    /// PVE 9 returns this as a JSON string; older versions used int.
    /// `deserialize_u32_from_str_or_num` accepts both transparently.
    #[serde(deserialize_with = "deserialize_u32_from_str_or_num")]
    pub port: u32,
    /// One-shot ticket — must be sent in the WS auth frame.
    pub ticket: String,
    /// User the ticket was issued to.
    pub user: String,
    /// UPID of the spawned vncproxy task on the node.
    #[serde(default)]
    pub upid: String,
    /// Server TLS certificate when `verify_tls=true` was negotiated.
    /// Empty when proxxx connected with `verify_tls=false`.
    #[serde(default)]
    pub cert: String,
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

const fn default_true_int() -> bool {
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
///
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

const fn default_iommu_group() -> i32 {
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
        let name = if self.device_name.is_empty() {
            format!("{}:{}", self.vendor, self.device)
        } else {
            self.device_name.clone()
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

/// One entry from `GET /cluster/ha/status/current` — the user-facing
/// live HA status. PVE returns a heterogeneous list mixing node-state
/// rows (`type: node`), per-service rows (`type: service`), and a
/// quorum/master summary row. Each row populates a different subset
/// of fields; #[serde(default)] on every field handles the variation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HaStatusEntry {
    /// `id` is the row key — `node/<name>`, `service:<sid>`, `master`.
    pub id: String,
    /// `node` | `service` | `master` | `quorum` (PVE-version-dependent).
    #[serde(rename = "type")]
    pub entry_type: String,
    /// Node name on `type=node` and `type=service` rows; absent on master/quorum.
    pub node: String,
    /// Service id (`vm:100`) on `type=service` rows.
    pub sid: String,
    /// Current state — for nodes: `online|offline|unknown|fence|maintenance`;
    /// for services: `started|stopped|error|fence|migrate|relocate|recovery`.
    pub status: String,
    /// Free-form status text from PVE (e.g. quorum messages).
    #[serde(rename = "crm_state")]
    pub crm_state: String,
    /// Quorate flag on the quorum/master row. PVE serializes 0/1.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub quorate: bool,
    /// On service rows, which group it belongs to.
    pub group: String,
    /// Free-form text — error message on failed services, etc.
    pub timestamp: u64,
}

// ── PVE 8+ notification system (cluster.notifications.*) ──
//
// PVE 8 introduced a typed notification routing system: `endpoints`
// are the delivery mechanisms (sendmail/smtp/gotify/webhook), `matchers`
// are routing rules ("send backup-failure events to gotify-on-call"),
// and `targets` is the read-only flat list of valid delivery names.
// Distinct from the Telegram/ntfy/webhook alerter proxxx ships in the
// `proxxx alerts` command — that's a proxxx-side rule engine; this is
// PVE-side native, used by tools like `vzdump` and the API itself.

/// One notification endpoint from `GET /cluster/notifications/endpoints`.
/// Heterogeneous shape — fields vary by `endpoint_type`. The typed
/// fields below cover the shared subset; type-specific knobs (smtp's
/// `server`, gotify's `server`, webhook's `url`) round-trip via
/// raw flow on PVE update — operators pass them via `--raw KEY=VAL`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationEndpoint {
    pub name: String,
    /// `sendmail` | `smtp` | `gotify` | `webhook`.
    #[serde(rename = "type")]
    pub endpoint_type: String,
    pub comment: String,
    /// `builtin` | `modified-builtin` | `user-created`. PVE-version-
    /// dependent — older clusters omit it.
    pub origin: String,
    /// 1 = disabled (kept for re-enable, not deleted).
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub disable: bool,
}

/// One notification matcher from `GET /cluster/notifications/matchers`.
/// Routes events to one or more endpoints based on field matches +
/// severity. PVE serializes match-fields/match-severity as repeated
/// form params on the wire; we expose them as `Vec<String>` here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationMatcher {
    pub name: String,
    pub comment: String,
    pub origin: String,
    /// CSV of endpoint/group names to deliver matching events to.
    pub target: Vec<String>,
    /// Per-field match patterns, e.g. `type=vzdump,hostname=pve1`.
    #[serde(rename = "match-field", default)]
    pub match_field: Vec<String>,
    /// Severity filters, e.g. `error,warning`.
    #[serde(rename = "match-severity", default)]
    pub match_severity: Vec<String>,
    /// `all` | `any` — how multi-clause matchers combine.
    #[serde(rename = "mode", default)]
    pub mode: String,
    /// 1 = invert the match decision.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub invert_match: bool,
    /// 1 = disabled.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub disable: bool,
}

/// One row from `GET /cluster/notifications/targets` — flat,
/// read-only list of all valid notification delivery names. Includes
/// individual endpoints + groups. Used by the matcher's `target` field
/// for autocomplete-style validation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationTarget {
    pub name: String,
    /// `sendmail` | `smtp` | `gotify` | `webhook` | `group`.
    #[serde(rename = "type")]
    pub target_type: String,
    pub comment: String,
    pub origin: String,
}

// ── Corosync cluster bootstrap (cluster.config.*) ──
//
// PVE clusters are corosync-backed. These endpoints handle the
// bootstrap lifecycle: list/add/remove corosync member nodes, fetch
// or apply join info, configure a quorum-device tiebreaker, and
// inspect totem (the corosync transport) settings. Rare day-to-day
// but high-stakes when invoked — getting nodes/qdevice wrong loses
// quorum and freezes HA.

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

/// One network interface from inside an LXC container, returned by
/// `GET /nodes/{n}/lxc/{vmid}/interfaces`. PVE shells out to
/// `lxc-info` / `ip addr` inside the container's netns and returns
/// the parsed result. Mirrors what QGA gives for QEMU
/// (`GuestAgentNetworkInterface`) but for LXC, where there's no agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LxcInterface {
    pub name: String,
    /// MAC address (kebab-renamed on the wire).
    #[serde(rename = "hwaddr", default)]
    pub hwaddr: String,
    /// IPv4 address with CIDR (e.g. `10.0.0.42/24`). Empty if none.
    pub inet: String,
    /// IPv6 address with CIDR.
    pub inet6: String,
}

/// Response from `GET /nodes/{n}/{kind}/{vmid}/rrd` — PNG graph
/// reference. PVE generates the image on the node's filesystem and
/// returns its path; the caller fetches it via separate transport
/// (storage download or SSH). Distinct from the typed `rrddata` flow
/// which returns numeric series — this is for UI consumers wanting
/// pre-rendered graphs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RrdImage {
    /// Server-side path (e.g. `/var/cache/pve-graphs/rrd-….png`).
    pub filename: String,
}

/// One row of `GET /cluster/metrics/server` — a configured external
/// metrics exporter (InfluxDB / Graphite). Heterogeneous shape
/// because `type` discriminates between protocol families with
/// different config knobs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricServer {
    pub id: String,
    /// `influxdb` | `graphite`.
    #[serde(rename = "type")]
    pub server_type: String,
    pub server: String,
    pub port: u16,
    pub comment: String,
    /// 1 = exporter is paused (no metrics shipped).
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub disable: bool,
    /// influxdb-specific: HTTP / UDP write API. `udp` | `http` | `https`.
    pub influxdbproto: String,
    /// graphite-specific: `tcp` | `udp`.
    pub proto: String,
    /// influxdb-specific: org name (cloud) or db name (OSS).
    pub organization: String,
    pub bucket: String,
    /// graphite-specific: top-level path prefix.
    pub path: String,
}

/// Response from `GET /nodes/{n}/{kind}/{vmid}/feature?feature=X`.
/// Pre-flight capability check — "can this guest do snapshot/clone/
/// migrate right now?". Used to gate destructive ops with a clear
/// "no" instead of letting them 500 on PVE-side rejection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuestFeatureCheck {
    /// 1 if the guest currently supports the queried feature.
    #[serde(
        rename = "hasFeature",
        deserialize_with = "deserialize_bool_from_int",
        default
    )]
    pub has_feature: bool,
    /// PVE 8+: list of nodes the guest could be migrated to without
    /// losing the feature (e.g. for `--feature snapshot`, nodes whose
    /// storage stack supports snapshots).
    pub nodes: Vec<String>,
}

/// One row of `GET /nodes/{n}/aplinfo` — an LXC template available
/// for download from PVE's curated catalog. Heterogeneous metadata —
/// fields vary by template type / source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AplTemplate {
    /// Template filename, e.g. `debian-12-standard_12.7-1_amd64.tar.zst`.
    pub template: String,
    /// `system` | `turnkeylinux` | `mailserver` | etc.
    pub section: String,
    /// `iso` | `vztmpl`.
    #[serde(rename = "type")]
    pub template_type: String,
    /// Where the template comes from (PVE | TurnKey | etc).
    pub source: String,
    pub headline: String,
    pub description: String,
    pub version: String,
    pub os: String,
    pub package: String,
    /// SHA-512 checksum (PVE 8+).
    pub sha512sum: String,
    /// Bytes — handy for "will this fit in /var/lib/vz" pre-checks.
    pub infopage: String,
    pub maintainer: String,
}

/// Response from `GET /nodes/{n}/query-url-metadata?url=…` — pre-flight
/// for `download_to_storage`: returns size + filename + mime so the
/// operator can size-check before kicking off the actual download.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UrlMetadata {
    /// Bytes (parsed from Content-Length). 0 when unknown.
    pub size: u64,
    /// Filename derived from URL or Content-Disposition.
    pub filename: String,
    pub mimetype: String,
}

// ── ACME (cluster.acme.{accounts,plugins,tos,directories,…}) ──
//
// PVE 8+ ships ACME (Let's Encrypt et al) integration for cluster-wide
// cert management. Accounts hold the ACME-CA registration; plugins
// configure DNS-01 / HTTP-01 challenge runners; the read-only tos /
// directories / challenge-schema endpoints back the wizard UI. proxxx
// already wired the per-node `/nodes/{n}/certificates/acme/certificate`
// order endpoint in the node-system region; this region adds the
// cluster-wide configuration the order endpoint depends on.

/// One row of `GET /cluster/acme/account`. Just the account `name`
/// (operator-chosen) — full registration details require the per-name
/// GET (returns `AcmeAccountDetails`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeAccount {
    pub name: String,
}

/// Full ACME account from `GET /cluster/acme/account/{name}`.
/// Wraps the registration response from the ACME CA — `account` is
/// the CA's RFC 8555 account object (status, contact, orders), `tos`
/// is the agreed-to ToS URL captured at registration, `directory` is
/// the CA endpoint, `location` is the per-account URL the CA assigned.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeAccountDetails {
    pub account: serde_json::Value,
    pub tos: String,
    pub directory: String,
    pub location: String,
}

/// One ACME challenge plugin from `GET /cluster/acme/plugins`.
/// Heterogeneous shape — each `plugin_type` populates a different
/// field subset (DNS-01 plugins need `api`, `data`; HTTP-01 has none).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmePlugin {
    /// Plugin id (operator-chosen name).
    pub plugin: String,
    /// `dns` | `standalone` (HTTP-01 default).
    #[serde(rename = "type")]
    pub plugin_type: String,
    /// DNS plugin name (e.g. `cloudflare`, `route53`, `gandi_livedns`).
    /// Empty for HTTP-01.
    pub api: String,
    /// DNS API credentials (encoded sub-spec, masked on read).
    pub data: String,
    /// Time the plugin gives DNS records to propagate before validating.
    pub validation_delay: u32,
    /// Disable without deleting.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub disable: bool,
    /// Comment / description.
    pub nodes: String,
}

/// One row of `GET /cluster/acme/directories` — name + URL of an
/// ACME-compatible CA (Let's Encrypt prod, Let's Encrypt staging,
/// custom). Used by the account-create wizard.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeDirectory {
    pub name: String,
    pub url: String,
}

/// One cluster-wide storage definition from `GET /storage`. PVE
/// supports many storage types (dir, lvm, lvmthin, zfspool, nfs, cifs,
/// iscsi, glusterfs, cephfs, rbd, pbs, btrfs, esxi, …) — the typed
/// fields below cover the common subset; type-specific knobs (smb_version,
/// monhost, krbd, prune-backups, encryption-key, …) round-trip via the
/// raw escape hatch on create/update — operators pass them via
/// `--raw KEY=VAL`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageDefinition {
    /// Storage id (the operator-chosen name).
    pub storage: String,
    /// Storage type: `dir` | `lvm` | `lvmthin` | `zfspool` | `nfs` |
    /// `cifs` | `iscsi` | `glusterfs` | `cephfs` | `rbd` | `pbs` |
    /// `btrfs` | `esxi`.
    #[serde(rename = "type")]
    pub storage_type: String,
    /// CSV of allowed content kinds, e.g.
    /// `"vztmpl,iso,backup,images,rootdir,snippets"`.
    pub content: String,
    /// CSV of nodes this storage is restricted to. Empty = all nodes.
    pub nodes: String,
    /// 1 = config kept but storage is inactive.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub disable: bool,
    /// 1 = visible to every node (e.g. NFS, PBS, CephFS).
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub shared: bool,
    pub digest: String,
    // ── Type-specific subset (most-common fields) ──
    /// `dir` / `btrfs`: filesystem path. Empty for non-fs types.
    pub path: String,
    /// `zfspool` / `rbd`: ZFS dataset / Ceph pool name.
    pub pool: String,
    /// `nfs` / `cifs` / `pbs` / `iscsi`: server hostname/IP.
    pub server: String,
    /// `nfs`: export path on the server.
    pub export: String,
    /// `pbs`: PBS datastore name.
    pub datastore: String,
    /// `pbs` / `cifs`: TLS fingerprint for verification.
    pub fingerprint: String,
    /// `cifs` / `pbs`: auth username (PBS uses `user@realm!tokenname`).
    pub username: String,
    /// `lvm` / `lvmthin`: volume group name.
    pub vgname: String,
    /// `lvmthin`: thin pool name within `vgname`.
    pub thinpool: String,
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
    /// replica? Returns `u64::MAX` if `last_sync` is 0 (never ran).
    /// `now` lets tests inject a deterministic clock.
    #[must_use]
    pub const fn rpo_secs(&self, now: u64) -> u64 {
        if self.last_sync == 0 {
            return u64::MAX;
        }
        now.saturating_sub(self.last_sync)
    }

    /// Health: green if recent + no errors, yellow if stale, red if
    /// failing. `expected_period_secs` is the schedule's period for
    /// staleness comparison (e.g. 900 for `*/15`).
    #[must_use]
    pub const fn health(&self, now: u64, expected_period_secs: u64) -> ReplicationHealth {
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
    /// Owning guest VMID (populated for `backup` and `images` entries
    /// — empty for ISOs and templates which don't belong to a guest).
    /// Used by the pre-flight backup-recency check to find the most
    /// recent backup for a given VMID.
    #[serde(default)]
    pub vmid: Option<u32>,
    /// Creation time in Unix epoch seconds (populated for `backup`
    /// entries — PVE writes the vzdump timestamp here). Used by
    /// pre-flight backup-recency to compute "hours since last
    /// backup".
    #[serde(default)]
    pub ctime: u64,
    /// Backup subtype: `"qemu"` or `"lxc"` (only set for `content == "backup"`).
    #[serde(default)]
    pub subtype: String,
}

impl StorageContent {
    /// Last URL path component or filename — useful for matching against
    /// what proxxx is about to download.
    #[must_use]
    pub fn filename(&self) -> &str {
        self.volid.rsplit('/').next().unwrap_or(&self.volid)
    }
}

// ── Storage health (mountain #1) ────────────────────────────────────
//
// Physical-disk + SMART + LVM/ZFS pool inventory. proxxx previously
// modelled the storage layer at the LOGICAL level only (`StoragePool`
// for `/nodes/{n}/storage`, `StorageContent` for the volumes inside).
// Operators were blind to the BLOCK layer underneath: which physical
// disk is failing, which ZFS pool degrading, which LVM VG out of
// extents. These types fill that gap by mapping
// `/nodes/{node}/disks/{list,smart,lvm,lvmthin,zfs}` to typed Rust.
//
// Same V25 lax-deserialization pattern as the rest of the file: every
// field defaults, every struct derives Default. PVE renames fields
// between point releases (`wearout` shape changed in 8.x) so a single
// missing key must not crash the entire response parse.

/// One physical disk on a Proxmox node. Returned by
/// `GET /nodes/{node}/disks/list`.
///
/// `Eq` is intentionally NOT derived: `wearout` is `serde_json::Value`
/// (PVE returns either u8 or u32 depending on version) which contains
/// f64 internally; floats break Eq.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Disk {
    /// Block device path, e.g. `/dev/sda`, `/dev/nvme0n1`.
    pub devpath: String,
    /// Vendor model string, e.g. `Samsung_SSD_860_EVO_500GB`.
    #[serde(default)]
    pub model: String,
    /// Vendor field as PVE reports it (often `ATA`/`NVME`/`USB`).
    #[serde(default)]
    pub vendor: String,
    /// Serial number — empty when udev couldn't read it.
    #[serde(default)]
    pub serial: String,
    /// Capacity in BYTES (not blocks).
    #[serde(default)]
    pub size: u64,
    /// Spindle speed (rpm). 0 for SSD/NVME. PVE returns **-1** (i32)
    /// when the kernel couldn't read the speed from the hardware
    /// (e.g. virtio block, USB-passthrough, missing smartmontools).
    /// Render `< 0` as "unknown" rather than the literal -1.
    #[serde(default)]
    pub rpm: i32,
    /// `"ssd"` | `"hdd"` | `"nvme"` | `"unknown"`.
    #[serde(rename = "type", default)]
    pub disk_type: String,
    /// SMART overall verdict: `"PASSED"` | `"FAILED"` | empty when
    /// SMART unavailable. Don't rely on this alone — fetch
    /// `get_disk_smart` for the per-attribute view.
    #[serde(default)]
    pub health: String,
    /// SSD wear indicator (0..100, 0 = new). Optional — HDD/USB/etc.
    /// don't report it. PVE's u8 ranges 0–100 OR PVE 8 returns u32
    /// for the same field; deserialize defensively.
    #[serde(default)]
    pub wearout: serde_json::Value,
    /// `"LVM"` | `"ZFS"` | `"partitions"` | `"mounted"` | empty (free).
    /// Indicates current usage so the operator knows whether wiping
    /// the disk is destructive.
    #[serde(default)]
    pub used: String,
    /// True when the disk has a GPT label (vs MBR or empty).
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub gpt: bool,
    /// World-Wide Name — stable hardware id, useful for udev rules.
    #[serde(default)]
    pub wwn: String,
}

/// SMART status of one disk. Returned by
/// `GET /nodes/{node}/disks/smart?disk={path}`.
///
/// PVE returns either an `attributes` array (ATA disks) or a `text`
/// blob (NVME, where smartctl returns key:value pairs not a table).
/// Both are kept so the renderer can pick whichever is non-empty.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DiskSmart {
    /// `"ata"` | `"sas"` | `"nvme"` | `""` (smartctl probe failed).
    #[serde(rename = "type", default)]
    pub smart_type: String,
    /// Overall health, `"PASSED"` / `"FAILED"`. Authoritative.
    #[serde(default)]
    pub health: String,
    /// Per-attribute table. Empty for NVME (see `text` instead).
    #[serde(default)]
    pub attributes: Vec<SmartAttribute>,
    /// Free-form smartctl output. Useful for NVME where the structured
    /// attribute table is empty but the raw text contains `Critical
    /// Warning`, `Available Spare`, `Percentage Used`, etc.
    #[serde(default)]
    pub text: String,
}

/// One row of an ATA/SAS SMART attribute table. PVE serializes most
/// fields as `String` even when the underlying value is numeric — keep
/// them String to round-trip cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SmartAttribute {
    /// SMART attribute id (e.g. `"5"` for Reallocated_Sector_Ct).
    pub id: String,
    /// Human name (e.g. `"Reallocated_Sector_Ct"`).
    pub name: String,
    /// Normalized current value (typically 0..253; higher is better).
    pub value: String,
    /// Normalized worst value over disk lifetime.
    pub worst: String,
    /// Failure threshold — once `value <= threshold`, disk fails the
    /// SMART check. 0 means "no threshold defined for this attribute".
    pub threshold: String,
    /// Raw value (vendor-specific encoding). For Reallocated_Sector_Ct
    /// this is the literal bad-sector count.
    #[serde(default)]
    pub raw: String,
    /// Vendor-defined flags, hex-encoded.
    #[serde(default)]
    pub flags: String,
    /// `"-"` | `"FAILING_NOW"` | `"In_the_past"`. Anything other than
    /// `"-"` means the disk has triggered this attribute at least once.
    #[serde(default)]
    pub fail: String,
}

/// One LVM Volume Group on a node. Returned (under a `children` tree)
/// by `GET /nodes/{node}/disks/lvm`. We flatten the tree at the call
/// site — this struct represents one VG entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LvmVolumeGroup {
    /// VG name, e.g. `"pve"`.
    pub name: String,
    /// Total size in BYTES.
    #[serde(default)]
    pub size: u64,
    /// Free space in BYTES.
    #[serde(default)]
    pub free: u64,
    /// Number of logical volumes inside this VG (0 when empty).
    #[serde(default, alias = "lvcount")]
    pub lv_count: u32,
}

/// One LVM-thin pool on a node. Returned by
/// `GET /nodes/{node}/disks/lvmthin`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LvmThinPool {
    /// LV name within the VG, e.g. `"data"`.
    pub lv: String,
    /// Parent volume group name.
    pub vg: String,
    /// Total pool size in BYTES.
    #[serde(default)]
    pub lv_size: u64,
    /// Allocated within the pool (data only; metadata reported
    /// separately below).
    #[serde(default)]
    pub used: u64,
    /// Metadata bytes consumed. `metadata_used / metadata_size` is
    /// the load-bearing metric — when this approaches 1.0 the thin
    /// pool stops accepting writes and EVERY VM on it freezes. PVE
    /// reports both as `u64` strings or u64 numbers depending on
    /// version; serde tolerates both via Value.
    #[serde(default)]
    pub metadata_used: u64,
    #[serde(default)]
    pub metadata_size: u64,
}

/// One ZFS pool on a node. Returned by `GET /nodes/{node}/disks/zfs`.
///
/// `Eq` is intentionally NOT derived: `dedup` is `f64` (ZFS dedup
/// ratio, e.g. 1.07x) and `frag` is `serde_json::Value` (PVE swings
/// between number and string across versions).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ZfsPool {
    /// Pool name, e.g. `"rpool"`.
    pub name: String,
    /// Total pool capacity in BYTES.
    #[serde(default)]
    pub size: u64,
    /// Allocated bytes (in-use).
    #[serde(default)]
    pub alloc: u64,
    /// Free bytes.
    #[serde(default)]
    pub free: u64,
    /// Fragmentation percentage (0..100). May come back as a number
    /// even when displayed as a string in pveweb — defensive `Value`.
    #[serde(default)]
    pub frag: serde_json::Value,
    /// Deduplication ratio (1.0 = no dedup).
    #[serde(default)]
    pub dedup: f64,
    /// `"ONLINE"` | `"DEGRADED"` | `"FAULTED"` | `"REMOVED"` | `"UNAVAIL"`.
    /// Anything other than `ONLINE` is operator-actionable.
    #[serde(default)]
    pub health: String,
}

// ── Time-series metrics (hill 3a) ──────────────────────────────────
//
// PVE serves historical metrics via RRDtool-backed endpoints:
//   GET /nodes/{node}/rrddata
//   GET /nodes/{node}/{qemu|lxc}/{vmid}/rrddata
//   GET /nodes/{node}/storage/{storage}/rrddata
//
// Each returns `Vec<RrdPoint>` — typically 60 points over the chosen
// timeframe (so ~1 minute resolution at `hour`, ~1 hour at `day`,
// etc.). Field set varies by SOURCE:
//   - guest:   cpu, mem, disk, net, PSI, memhost
//   - node:    same + loadavg, iowait, memtotal/used/available, swap*,
//              roottotal/used, arcsize
//   - storage: used, total
//
// We model with a flat all-`Option<f64>` struct: any field PVE doesn't
// emit for this source defaults to None. f64 covers byte counts up to
// ~9 PB exactly (mantissa precision) which is well beyond Proxmox
// scale, so we don't lose precision casting u64 byte sizes.

/// One time-bucketed sample of the PVE rrddata response. `time` is
/// epoch-seconds; every other field is `Option<f64>` because the
/// available metrics depend on the SOURCE (guest vs node vs storage).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RrdPoint {
    /// Bucket midpoint, Unix epoch seconds.
    pub time: u64,

    // Common — guest + node
    pub cpu: Option<f64>,
    pub maxcpu: Option<f64>,
    pub mem: Option<f64>,
    pub maxmem: Option<f64>,
    pub disk: Option<f64>,
    pub maxdisk: Option<f64>,
    pub diskread: Option<f64>,
    pub diskwrite: Option<f64>,
    pub netin: Option<f64>,
    pub netout: Option<f64>,

    // Node-only
    pub loadavg: Option<f64>,
    pub iowait: Option<f64>,
    pub memtotal: Option<f64>,
    pub memused: Option<f64>,
    pub memavailable: Option<f64>,
    pub swaptotal: Option<f64>,
    pub swapused: Option<f64>,
    pub roottotal: Option<f64>,
    pub rootused: Option<f64>,
    pub arcsize: Option<f64>,

    // Pressure stall info (PSI), Linux 5.2+. Both guest + node.
    pub pressurecpusome: Option<f64>,
    pub pressurecpufull: Option<f64>,
    pub pressurememorysome: Option<f64>,
    pub pressurememoryfull: Option<f64>,
    pub pressureiosome: Option<f64>,
    pub pressureiofull: Option<f64>,

    // QEMU-only
    pub memhost: Option<f64>,

    // Storage-only
    pub used: Option<f64>,
    pub total: Option<f64>,
}

/// Time window for an rrddata request. PVE accepts these literal
/// strings as `?timeframe=…`. Each maps to a different RRD bucket
/// resolution (hour ≈ 60s, day ≈ 30m, week ≈ 3h, month ≈ 1d, year ≈ 1w).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RrdTimeframe {
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl RrdTimeframe {
    /// PVE wire form (lowercase, matches `?timeframe=` URL param).
    #[must_use]
    pub const fn as_pve_str(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
            Self::Year => "year",
        }
    }
}

/// RRD consolidation function. PVE expects UPPERCASE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RrdCf {
    Average,
    Max,
}

impl RrdCf {
    #[must_use]
    pub const fn as_pve_str(self) -> &'static str {
        match self {
            Self::Average => "AVERAGE",
            Self::Max => "MAX",
        }
    }
}

/// One installed apt package on a node. Returned (per row) by
/// `GET /nodes/{node}/apt/versions`.
///
/// Distinct from `AptUpgradable` (which is the *delta* — what would
/// change on apt upgrade): this is the inventory of what's currently
/// installed, including kernel/manager metadata. PVE serializes the
/// fields in PascalCase (Debian apt convention); we map to snake_case.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AptInstalledPackage {
    #[serde(rename = "Package", default)]
    pub package: String,
    /// Currently-installed version.
    #[serde(rename = "Version", default)]
    pub version: String,
    /// Last installed-then-removed version (empty when first install).
    #[serde(rename = "OldVersion", default)]
    pub old_version: String,
    /// `Installed` | `ConfigFiles` | `NotInstalled`.
    #[serde(rename = "CurrentState", default)]
    pub current_state: String,
    #[serde(rename = "Section", default)]
    pub section: String,
    #[serde(rename = "Priority", default)]
    pub priority: String,
    #[serde(rename = "Origin", default)]
    pub origin: String,
    #[serde(rename = "Arch", default)]
    pub arch: String,
    /// Human-readable summary (Debian `Title:` field).
    #[serde(rename = "Title", default)]
    pub title: String,
    #[serde(rename = "Description", default)]
    pub description: String,
    /// Booted kernel version — only set on the `proxmox-ve` row.
    /// Useful to detect "kernel upgraded but reboot pending".
    #[serde(rename = "RunningKernel", default)]
    pub running_kernel: String,
    /// `pve-manager` reports its own version string here separately.
    #[serde(rename = "ManagerVersion", default)]
    pub manager_version: String,
}

#[cfg(test)]
mod qemu_net_spec_tests {
    use super::QemuNetSpec;
    use std::str::FromStr;

    #[test]
    fn parse_canonical_form() {
        let n = QemuNetSpec::from_str("virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1").unwrap();
        assert_eq!(n.model, "virtio");
        assert_eq!(n.mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(n.bridge.as_deref(), Some("vmbr0"));
        assert!(n.firewall);
    }

    #[test]
    fn parse_model_only_no_mac() {
        // PVE accepts a bare model (auto-generates MAC).
        let n = QemuNetSpec::from_str("e1000").unwrap();
        assert_eq!(n.model, "e1000");
        assert!(n.mac.is_none());
        assert!(n.bridge.is_none());
    }

    #[test]
    fn parse_with_vlan_tag_and_mtu() {
        let n = QemuNetSpec::from_str("virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=100,mtu=9000")
            .unwrap();
        assert_eq!(n.tag, Some(100));
        assert_eq!(n.mtu, Some(9000));
    }

    #[test]
    fn unknown_keys_round_trip_via_extra() {
        // Forward-compat: a hypothetical PVE 10 addition `tx_offload`
        // must NOT cause parse to fail.
        let n = QemuNetSpec::from_str("virtio=AA:BB,bridge=vmbr0,tx_offload=on").unwrap();
        assert_eq!(n.extra, vec![("tx_offload".into(), "on".into())]);
        assert_eq!(n.to_string(), "virtio=AA:BB,bridge=vmbr0,tx_offload=on");
    }

    #[test]
    fn empty_spec_errors() {
        assert!(QemuNetSpec::from_str("").is_err());
    }

    #[test]
    fn missing_separator_in_subsequent_token_errors() {
        // First token can be model-only; subsequent MUST be key=value.
        let err = QemuNetSpec::from_str("virtio,bareword").unwrap_err();
        assert!(err.to_string().contains("missing '=' separator"));
    }

    #[test]
    fn invalid_mtu_errors_with_context() {
        let err = QemuNetSpec::from_str("virtio,mtu=notanumber").unwrap_err();
        assert!(err.to_string().contains("mtu"));
    }

    #[test]
    fn round_trip_idempotent() {
        let inputs = [
            "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
            "virtio",
            "e1000=11:22:33:44:55:66,bridge=vmbr1,firewall=1,tag=42",
            "vmxnet3=AA:BB:CC:DD:EE:FF,bridge=vmbr0,mtu=1500,queues=4,rate=125",
        ];
        for input in inputs {
            let parsed = QemuNetSpec::from_str(input).unwrap();
            let displayed = parsed.to_string();
            let reparsed = QemuNetSpec::from_str(&displayed).unwrap();
            assert_eq!(parsed, reparsed, "round-trip failed for {input}");
        }
    }
}

#[cfg(test)]
mod qemu_disk_spec_tests {
    use super::QemuDiskSpec;
    use std::str::FromStr;

    #[test]
    fn parse_storage_volume_with_size() {
        let d = QemuDiskSpec::from_str("local-lvm:vm-100-disk-0,size=32G,iothread=1").unwrap();
        assert_eq!(d.source, "local-lvm:vm-100-disk-0");
        assert_eq!(d.size.as_deref(), Some("32G"));
        assert!(d.iothread);
    }

    #[test]
    fn parse_iso_cdrom() {
        let d = QemuDiskSpec::from_str("local:iso/ubuntu.iso,media=cdrom").unwrap();
        assert_eq!(d.source, "local:iso/ubuntu.iso");
        assert_eq!(d.media.as_deref(), Some("cdrom"));
    }

    #[test]
    fn parse_empty_cdrom_with_none_source() {
        let d = QemuDiskSpec::from_str("none,media=cdrom").unwrap();
        assert_eq!(d.source, "none");
        assert_eq!(d.media.as_deref(), Some("cdrom"));
    }

    #[test]
    fn discard_accepts_on_and_1_and_true() {
        for v in ["on", "1", "true"] {
            let d = QemuDiskSpec::from_str(&format!("local-lvm:0,discard={v}")).unwrap();
            assert!(d.discard, "discard={v} should parse as true");
        }
    }

    #[test]
    fn unknown_keys_round_trip_via_extra() {
        let d = QemuDiskSpec::from_str("local-lvm:0,size=10G,aio=native").unwrap();
        assert_eq!(d.extra, vec![("aio".into(), "native".into())]);
        assert_eq!(d.to_string(), "local-lvm:0,size=10G,aio=native");
    }

    #[test]
    fn empty_source_errors() {
        assert!(QemuDiskSpec::from_str("").is_err());
        assert!(QemuDiskSpec::from_str(",size=10G").is_err());
    }

    #[test]
    fn missing_separator_errors() {
        let err = QemuDiskSpec::from_str("local-lvm:0,bareword").unwrap_err();
        assert!(err.to_string().contains("missing '=' separator"));
    }

    #[test]
    fn round_trip_idempotent() {
        let inputs = [
            "local-lvm:vm-100-disk-0,size=32G",
            "local-lvm:0,size=10G,format=qcow2,iothread=1,ssd=1,discard=on",
            "local:iso/ubuntu.iso,media=cdrom",
            "none,media=cdrom",
            "local-lvm:vm-100-disk-1,backup=0,cache=writeback",
        ];
        for input in inputs {
            let parsed = QemuDiskSpec::from_str(input).unwrap();
            let displayed = parsed.to_string();
            let reparsed = QemuDiskSpec::from_str(&displayed).unwrap();
            assert_eq!(parsed, reparsed, "round-trip failed for {input}");
        }
    }
}

#[cfg(test)]
mod ipconfig_tests {
    use super::Ipconfig;
    use std::str::FromStr;

    #[test]
    fn parse_full_ipv4_plus_ipv6_dhcp() {
        let cfg = Ipconfig::from_str("ip=10.0.0.5/24,gw=10.0.0.1,ip6=dhcp").unwrap();
        assert_eq!(cfg.ip.as_deref(), Some("10.0.0.5/24"));
        assert_eq!(cfg.gw.as_deref(), Some("10.0.0.1"));
        assert_eq!(cfg.ip6.as_deref(), Some("dhcp"));
        assert_eq!(cfg.gw6, None);
        assert!(cfg.extra.is_empty());
    }

    #[test]
    fn parse_dhcp_minimal() {
        let cfg = Ipconfig::from_str("ip=dhcp").unwrap();
        assert_eq!(cfg.ip.as_deref(), Some("dhcp"));
        assert_eq!(cfg.gw, None);
    }

    #[test]
    fn parse_empty_input_yields_default() {
        let cfg = Ipconfig::from_str("").unwrap();
        assert_eq!(cfg, Ipconfig::default());
    }

    #[test]
    fn unknown_keys_round_trip_via_extra() {
        // Forward-compat: a hypothetical PVE 10 addition `mtu=9000`
        // must NOT cause parse to fail. The unknown key lives in
        // `extra` and re-emerges intact on Display.
        let original = "ip=10.0.0.5/24,mtu=9000,gw=10.0.0.1";
        let cfg = Ipconfig::from_str(original).unwrap();
        assert_eq!(cfg.extra, vec![("mtu".to_string(), "9000".to_string())]);
        // Display preserves `extra` (after the recognised fields).
        assert_eq!(cfg.to_string(), "ip=10.0.0.5/24,gw=10.0.0.1,mtu=9000");
    }

    #[test]
    fn missing_equals_separator_errors() {
        let err = Ipconfig::from_str("ip=10.0.0.5/24,bareword").unwrap_err();
        assert!(err.to_string().contains("missing '=' separator"));
    }

    #[test]
    fn empty_key_errors() {
        let err = Ipconfig::from_str("=value").unwrap_err();
        assert!(err.to_string().contains("empty key"));
    }

    #[test]
    fn round_trip_parse_display_parse_is_idempotent() {
        // Critical invariant: any valid PVE ipconfig string survives
        // a parse → Display → parse cycle unchanged.
        let inputs = [
            "ip=10.0.0.5/24,gw=10.0.0.1",
            "ip=dhcp",
            "ip6=2001:db8::1/64,gw6=2001:db8::ff",
            "ip=10.0.0.5/24,gw=10.0.0.1,ip6=dhcp,gw6=fe80::1",
            "",
        ];
        for input in inputs {
            let parsed = Ipconfig::from_str(input).unwrap();
            let displayed = parsed.to_string();
            let reparsed = Ipconfig::from_str(&displayed).unwrap();
            assert_eq!(parsed, reparsed, "round-trip failed for {input}");
        }
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
        assert_eq!(s.health(1_700_000_060, 900), ReplicationHealth::Failing);
    }

    #[test]
    fn replication_health_failing_when_fail_count_nonzero() {
        let s = ReplicationStatus {
            id: "100-0".into(),
            last_sync: 1_700_000_000,
            fail_count: 3,
            ..Default::default()
        };
        assert_eq!(s.health(1_700_000_030, 900), ReplicationHealth::Failing);
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
