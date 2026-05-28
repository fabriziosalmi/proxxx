use serde::{Deserialize, Serialize};

use super::deserialize_bool_from_int;

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
    /// (audit) — PVE config `lock` field. When non-empty the
    /// guest has a sticky lock (`backup`, `clone`, `migrate`,
    /// `rollback`, `snapshot`, `snapshot-delete`, `suspending`).
    /// PVE rejects almost every mutation while a lock is held with
    /// `500 VM is locked`. proxxx reads this field and refuses
    /// destructive ops up-front instead of letting the user collide
    /// with PVE's lock and surface a confusing 500.
    pub lock: String,
    /// (audit) — HA Cluster Resource Manager state for this
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
    /// — true if this guest is under HA-CRM management.
    /// Destructive raw `/status/*` calls must NOT be issued; route
    /// through `/cluster/ha/resources/<vmid>` state changes
    /// instead.
    #[must_use]
    pub const fn is_ha_managed(&self) -> bool {
        !self.hastate.is_empty()
    }

    /// — true if PVE has a sticky lock on this guest right
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
    /// (audit) — catchall for unknown PVE status strings
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
    use super::super::node::NodeStatus;
    use super::*;

    /// (audit) — PVE 8.4 hypothetically adds a `"hibernating"`
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

    /// — a Guest with an unknown status string MUST still
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
