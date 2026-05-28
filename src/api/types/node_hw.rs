use serde::{Deserialize, Serialize};

use super::deserialize_bool_from_int;

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

/// One physical disk on a Proxmox node. Returned by
/// `GET /nodes/{node}/disks/list`.
///
/// `Eq` is intentionally NOT derived: `wearout` is `serde_json::Value`
/// (PVE returns either u8 or u32 depending on version) which contains
/// f64 internally; floats break Eq.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SmartAttribute {
    /// SMART attribute id (e.g. `"5"` for `Reallocated_Sector_Ct`).
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
    /// Raw value (vendor-specific encoding). For `Reallocated_Sector_Ct`
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
