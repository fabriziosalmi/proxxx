//! Hardware passthrough inspector (feature #4).
//!
//! Honest scope cuts (per the draconian review):
//! - Read-only diagnostic. NO assignment writes from proxxx in this MVP.
//! - NO VFIO binding mutation (modprobe + initramfs + reboot). The
//!   driver-binding path is a separate phase requiring SSH (SSH layer).
//! - NO MIG / `MxGPU` partitioning, NO cluster-wide GPU pool scheduler.
//!   Both are vendor-specific multi-month projects on their own.
//!
//! What this module does:
//! 1. Parse guest configs to extract per-guest PCI / USB assignments.
//! 2. Detect direct conflicts (same device on two guests).
//! 3. Detect IOMMU-group conflicts (sibling devices spread across
//!    different guests — the kernel will refuse passthrough).
//! 4. Surface "unassigned" passthrough-capable devices for review.
//!
//! Pure logic — zero I/O, fully testable.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::api::types::{Guest, PciDevice};

/// One PCI assignment found in a guest config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PciAssignment {
    pub vmid: u32,
    /// Config key, e.g. `"hostpci0"`.
    pub key: String,
    /// PCI address, e.g. `"0000:01:00.0"`. We normalize to the full
    /// `0000:` prefix Proxmox API uses, even if the config omits it.
    pub address: String,
    /// Raw value from the config (post-`<address>,...` options preserved).
    pub raw: String,
}

/// One USB assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbAssignment {
    pub vmid: u32,
    pub key: String,
    /// Either `vendor:product` (e.g. `046d:c52b`) or `bus-port` form
    /// (`1-3`). We pass through whatever the config says.
    pub spec: String,
}

/// Parse a single hostpci value: `"0000:01:00.0,pcie=1,x-vga=1"` →
/// (`"0000:01:00.0"`, full raw string). The address is the first
/// comma-delimited segment, with any `0000:` prefix added if missing.
fn parse_pci_value(value: &str) -> (String, String) {
    let raw = value.to_string();
    let first_segment = value.split_once(',').map_or(value, |(a, _)| a);
    let trimmed = first_segment.trim();
    let normalized = if trimmed.split(':').count() == 2 {
        // PVE accepts short `01:00.0` form too. Pad with `0000:`.
        format!("0000:{trimmed}")
    } else {
        trimmed.to_string()
    };
    (normalized, raw)
}

/// Walk all guest configs and extract PCI/USB assignments.
///
/// `configs` is a map of `vmid → (raw config map)`. The raw config map
/// is what `ProxmoxGateway::get_guest_config` returns.
#[must_use]
pub fn scan_assignments(
    configs: &HashMap<u32, HashMap<String, String>>,
) -> (Vec<PciAssignment>, Vec<UsbAssignment>) {
    let mut pci = Vec::new();
    let mut usb = Vec::new();
    for (vmid, cfg) in configs {
        for (k, v) in cfg {
            if let Some(rest) = k.strip_prefix("hostpci") {
                if rest.chars().all(|c| c.is_ascii_digit()) {
                    let (addr, raw) = parse_pci_value(v);
                    pci.push(PciAssignment {
                        vmid: *vmid,
                        key: k.clone(),
                        address: addr,
                        raw,
                    });
                }
            } else if let Some(rest) = k.strip_prefix("usb") {
                if rest.chars().all(|c| c.is_ascii_digit()) {
                    usb.push(UsbAssignment {
                        vmid: *vmid,
                        key: k.clone(),
                        spec: v.clone(),
                    });
                }
            }
        }
    }
    pci.sort_by(|a, b| a.address.cmp(&b.address).then(a.vmid.cmp(&b.vmid)));
    usb.sort_by(|a, b| a.spec.cmp(&b.spec).then(a.vmid.cmp(&b.vmid)));
    (pci, usb)
}

/// Conflict report for a single PCI passthrough configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PciConflict {
    /// Same address claimed by multiple guests. The first start wins;
    /// every other guest fails to start with "device busy".
    DirectShared { address: String, vmids: Vec<u32> },
    /// Devices A and B are in the same IOMMU group but assigned to
    /// different guests. Kernel binds the whole group → neither guest
    /// gets a working passthrough.
    IommuGroupSplit {
        group: i32,
        /// Which (address, vmid) pairs are involved, sorted.
        members: Vec<(String, u32)>,
    },
}

/// Detect both classes of PCI conflicts. Operates purely on the
/// already-fetched data.
#[must_use]
pub fn detect_pci_conflicts(
    assignments: &[PciAssignment],
    devices: &[PciDevice],
) -> Vec<PciConflict> {
    let mut conflicts = Vec::new();

    // 1. Direct shared.
    let mut by_addr: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for a in assignments {
        by_addr.entry(a.address.clone()).or_default().push(a.vmid);
    }
    for (addr, mut vmids) in by_addr {
        // Dedup vmids: a single guest can have hostpci0 and hostpci1
        // both pointing at the same address — typical of a function-
        // split device — that's not a conflict.
        vmids.sort_unstable();
        vmids.dedup();
        if vmids.len() > 1 {
            conflicts.push(PciConflict::DirectShared {
                address: addr,
                vmids,
            });
        }
    }

    // 2. IOMMU group split. For every group containing devices assigned
    // to >1 distinct guest, surface a single conflict listing the members.
    let mut group_members: BTreeMap<i32, Vec<(String, u32)>> = BTreeMap::new();
    let dev_group: HashMap<String, i32> = devices
        .iter()
        .filter(|d| d.iommugroup >= 0)
        .map(|d| (d.id.clone(), d.iommugroup))
        .collect();
    for a in assignments {
        if let Some(g) = dev_group.get(&a.address) {
            group_members
                .entry(*g)
                .or_default()
                .push((a.address.clone(), a.vmid));
        }
    }
    for (group, mut members) in group_members {
        members.sort();
        members.dedup();
        let distinct_vmids: HashSet<u32> = members.iter().map(|(_, v)| *v).collect();
        let distinct_addrs: HashSet<&str> = members.iter().map(|(a, _)| a.as_str()).collect();
        // Only report a split when the group contains AT LEAST two
        // distinct addresses split across guests. A single-address
        // group with multiple vmids is already covered by DirectShared
        // — surfacing both would be noise.
        if distinct_vmids.len() > 1 && distinct_addrs.len() > 1 {
            conflicts.push(PciConflict::IommuGroupSplit { group, members });
        }
    }

    conflicts
}

/// Inventory entry for the UI: device + which guest (if any) claims it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PciInventoryRow {
    pub device: PciDevice,
    /// Set of vmids that have this exact address in their config.
    pub assigned_to: Vec<u32>,
    /// Other addresses in the same IOMMU group (excluding self).
    pub iommu_siblings: Vec<String>,
}

/// Build a unified inventory view: every device on the node, paired
/// with whatever guest config references it.
#[must_use]
pub fn pci_inventory(devices: &[PciDevice], assignments: &[PciAssignment]) -> Vec<PciInventoryRow> {
    let mut by_addr: HashMap<String, Vec<u32>> = HashMap::new();
    for a in assignments {
        by_addr.entry(a.address.clone()).or_default().push(a.vmid);
    }
    // Pre-compute group → addresses for sibling lookup.
    let mut by_group: HashMap<i32, Vec<String>> = HashMap::new();
    for d in devices {
        if d.iommugroup >= 0 {
            by_group.entry(d.iommugroup).or_default().push(d.id.clone());
        }
    }

    devices
        .iter()
        .map(|d| {
            let mut assigned_to = by_addr.get(&d.id).cloned().unwrap_or_default();
            assigned_to.sort_unstable();
            assigned_to.dedup();
            let siblings = by_group
                .get(&d.iommugroup)
                .map(|all| {
                    let mut s: Vec<String> = all.iter().filter(|a| **a != d.id).cloned().collect();
                    s.sort();
                    s
                })
                .unwrap_or_default();
            PciInventoryRow {
                device: d.clone(),
                assigned_to,
                iommu_siblings: siblings,
            }
        })
        .collect()
}

/// Look up a guest name from `state.guests` (returns vmid as fallback).
#[must_use]
pub fn label_for(guests: &[Guest], vmid: u32) -> String {
    guests
        .iter()
        .find(|g| g.vmid == vmid)
        .map(|g| {
            if g.name.is_empty() {
                vmid.to_string()
            } else {
                format!("{vmid} ({})", g.name)
            }
        })
        .unwrap_or_else(|| vmid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pci(id: &str, group: i32) -> PciDevice {
        PciDevice {
            id: id.into(),
            class: "0x030000".into(),
            vendor: "0x10de".into(),
            device: "0x2484".into(),
            vendor_name: "NVIDIA".into(),
            device_name: "RTX 3070".into(),
            iommugroup: group,
            mdev: false,
        }
    }

    fn cfg(items: &[(&str, &str)]) -> HashMap<String, String> {
        items
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    // ── Parser ──────────────────────────────────────────────

    #[test]
    fn parse_pci_value_full_address() {
        let (addr, _) = parse_pci_value("0000:01:00.0");
        assert_eq!(addr, "0000:01:00.0");
    }

    #[test]
    fn parse_pci_value_short_form_pads_prefix() {
        let (addr, _) = parse_pci_value("01:00.0");
        assert_eq!(addr, "0000:01:00.0");
    }

    #[test]
    fn parse_pci_value_strips_options() {
        let (addr, raw) = parse_pci_value("0000:01:00.0,pcie=1,x-vga=1");
        assert_eq!(addr, "0000:01:00.0");
        assert!(
            raw.contains("x-vga"),
            "raw must preserve options for display"
        );
    }

    // ── Assignment scan ─────────────────────────────────────

    #[test]
    fn scan_extracts_hostpci_keys_only() {
        let mut configs = HashMap::new();
        configs.insert(
            100,
            cfg(&[
                ("name", "vm-100"),
                ("hostpci0", "0000:01:00.0"),
                ("hostpci1", "0000:01:00.1,pcie=1"),
                // hostpcix2 — invalid (non-numeric suffix)
                ("hostpcix2", "0000:02:00.0"),
                ("usb0", "046d:c52b"),
                ("memory", "8192"),
            ]),
        );
        configs.insert(200, cfg(&[("hostpci0", "0000:03:00.0")]));
        let (pci, usb) = scan_assignments(&configs);
        assert_eq!(pci.len(), 3);
        assert_eq!(usb.len(), 1);
        // No hostpcix2 picked up.
        assert!(!pci.iter().any(|p| p.address == "0000:02:00.0"));
        // Sort by address then vmid.
        assert_eq!(pci[0].address, "0000:01:00.0");
        assert_eq!(pci[0].vmid, 100);
    }

    #[test]
    fn scan_extracts_usb_keys_only() {
        let mut configs = HashMap::new();
        configs.insert(
            100,
            cfg(&[("usb0", "046d:c52b"), ("usb1", "1-2"), ("usbx", "garbage")]),
        );
        let (_, usb) = scan_assignments(&configs);
        assert_eq!(usb.len(), 2);
    }

    // ── Conflict detection ──────────────────────────────────

    #[test]
    fn no_conflicts_when_distinct_devices() {
        let devices = vec![pci("0000:01:00.0", 1), pci("0000:02:00.0", 2)];
        let assignments = vec![
            PciAssignment {
                vmid: 100,
                key: "hostpci0".into(),
                address: "0000:01:00.0".into(),
                raw: "0000:01:00.0".into(),
            },
            PciAssignment {
                vmid: 200,
                key: "hostpci0".into(),
                address: "0000:02:00.0".into(),
                raw: "0000:02:00.0".into(),
            },
        ];
        let conflicts = detect_pci_conflicts(&assignments, &devices);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn detects_direct_shared() {
        let devices = vec![pci("0000:01:00.0", 1)];
        let assignments = vec![
            PciAssignment {
                vmid: 100,
                key: "hostpci0".into(),
                address: "0000:01:00.0".into(),
                raw: "0000:01:00.0".into(),
            },
            PciAssignment {
                vmid: 200,
                key: "hostpci0".into(),
                address: "0000:01:00.0".into(),
                raw: "0000:01:00.0".into(),
            },
        ];
        let conflicts = detect_pci_conflicts(&assignments, &devices);
        assert_eq!(conflicts.len(), 1);
        match &conflicts[0] {
            PciConflict::DirectShared { address, vmids } => {
                assert_eq!(address, "0000:01:00.0");
                assert_eq!(vmids, &vec![100, 200]);
            }
            other => panic!("expected DirectShared, got {other:?}"),
        }
    }

    #[test]
    fn no_conflict_when_same_guest_same_address_twice() {
        // A guest with hostpci0 and hostpci1 pointing at the same physical
        // device (function split) — NOT a conflict.
        let devices = vec![pci("0000:01:00.0", 1)];
        let assignments = vec![
            PciAssignment {
                vmid: 100,
                key: "hostpci0".into(),
                address: "0000:01:00.0".into(),
                raw: "0000:01:00.0".into(),
            },
            PciAssignment {
                vmid: 100,
                key: "hostpci1".into(),
                address: "0000:01:00.0".into(),
                raw: "0000:01:00.0,pcie=1".into(),
            },
        ];
        let conflicts = detect_pci_conflicts(&assignments, &devices);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn detects_iommu_group_split() {
        // GPU + audio on same card — same IOMMU group, assigned to
        // different guests → kernel won't isolate them.
        let devices = vec![
            pci("0000:01:00.0", 1), // GPU
            pci("0000:01:00.1", 1), // audio (same group)
        ];
        let assignments = vec![
            PciAssignment {
                vmid: 100,
                key: "hostpci0".into(),
                address: "0000:01:00.0".into(),
                raw: "0000:01:00.0".into(),
            },
            PciAssignment {
                vmid: 200,
                key: "hostpci0".into(),
                address: "0000:01:00.1".into(),
                raw: "0000:01:00.1".into(),
            },
        ];
        let conflicts = detect_pci_conflicts(&assignments, &devices);
        let split = conflicts
            .iter()
            .find(|c| matches!(c, PciConflict::IommuGroupSplit { .. }))
            .expect("split conflict surfaces");
        match split {
            PciConflict::IommuGroupSplit { group, members } => {
                assert_eq!(*group, 1);
                assert_eq!(members.len(), 2);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn no_iommu_split_when_same_group_same_guest() {
        let devices = vec![pci("0000:01:00.0", 1), pci("0000:01:00.1", 1)];
        let assignments = vec![
            PciAssignment {
                vmid: 100,
                key: "hostpci0".into(),
                address: "0000:01:00.0".into(),
                raw: "0000:01:00.0".into(),
            },
            PciAssignment {
                vmid: 100,
                key: "hostpci1".into(),
                address: "0000:01:00.1".into(),
                raw: "0000:01:00.1".into(),
            },
        ];
        let conflicts = detect_pci_conflicts(&assignments, &devices);
        assert!(
            conflicts.is_empty(),
            "same guest assigning the whole group is the correct passthrough setup"
        );
    }

    #[test]
    fn iommu_disabled_devices_dont_trigger_split() {
        // iommugroup = -1 means IOMMU info is missing or kernel doesn't
        // report it. Don't flag those as conflicts.
        let devices = vec![pci("0000:01:00.0", -1), pci("0000:01:00.1", -1)];
        let assignments = vec![
            PciAssignment {
                vmid: 100,
                key: "hostpci0".into(),
                address: "0000:01:00.0".into(),
                raw: "0000:01:00.0".into(),
            },
            PciAssignment {
                vmid: 200,
                key: "hostpci0".into(),
                address: "0000:01:00.1".into(),
                raw: "0000:01:00.1".into(),
            },
        ];
        let conflicts = detect_pci_conflicts(&assignments, &devices);
        // Direct shared = no (different addresses). IOMMU = N/A.
        assert!(conflicts.is_empty());
    }

    // ── Inventory ───────────────────────────────────────────

    #[test]
    fn inventory_links_devices_to_assignments() {
        let devices = vec![
            pci("0000:01:00.0", 1),
            pci("0000:01:00.1", 1),
            pci("0000:02:00.0", 2),
        ];
        let assignments = vec![PciAssignment {
            vmid: 100,
            key: "hostpci0".into(),
            address: "0000:01:00.0".into(),
            raw: "0000:01:00.0".into(),
        }];
        let inv = pci_inventory(&devices, &assignments);
        assert_eq!(inv.len(), 3);
        let gpu = inv.iter().find(|r| r.device.id == "0000:01:00.0").unwrap();
        assert_eq!(gpu.assigned_to, vec![100]);
        assert_eq!(gpu.iommu_siblings, vec!["0000:01:00.1"]);
        let audio = inv.iter().find(|r| r.device.id == "0000:01:00.1").unwrap();
        assert!(audio.assigned_to.is_empty());
        assert_eq!(audio.iommu_siblings, vec!["0000:01:00.0"]);
    }
}
