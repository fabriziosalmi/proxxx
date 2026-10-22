//! `proxxx gpu` — GPU / PCI passthrough orchestration (MVP).
//!
//! vfio-pci setup end-to-end is the white-whale Proxmox setup task:
//! IOMMU groups, kernel cmdline, blacklists, vfio binding, VM
//! config. Operators today wade through 4 wiki pages.
//!
//! ## MVP scope (per #57)
//!
//! - **`proxxx gpu inspect <node>`** — SSH-probe the node for
//!   IOMMU readiness: `dmesg | grep -i iommu`, `find /sys/kernel/
//!   iommu_groups`, current vfio bindings. Report per-device:
//!   vendor/device ID, IOMMU group, current driver, vfio-ready.
//! - **JSON output** for tooling; text for humans.
//!
//! ## Out of scope per #57 (deferred to follow-ups)
//!
//! - **`proxxx gpu bind <device>`** — actually editing
//!   /etc/modprobe.d, /etc/default/grub, regenerating initramfs.
//!   Per-distro / per-bootloader logic + reboot orchestration =
//!   substantial separate slice.
//! - **VM-side `qm set` integration** — once a device is bound,
//!   attaching to a guest is a single `qm set hostpci0 …`. Doing
//!   this safely (preventing double-binding) needs the bind flow
//!   to exist first.
//! - **NVIDIA vGPU-specific** flows — driver licensing + MIG.
//!   Lives entirely outside the open-source Proxmox path.
//!
//! ## Why MVP-inspect is still useful
//!
//! It's the first "you can or you can't" question every operator
//! asks. A clear `gpu inspect` output tells them immediately
//! whether IOMMU + vfio are configured at all, and what's blocking
//! them if not. The bind step (write configs + reboot) is
//! intrinsically risky — operators tend to want to do that
//! step manually anyway. Inspect is the safe automation; bind
//! lives in a follow-up with explicit operator confirmation.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, clap::ValueEnum, Default)]
pub enum GpuOutput {
    #[default]
    Text,
    Json,
}

#[derive(Debug, clap::Args)]
pub struct GpuInspectArgs {
    /// Cluster node to probe.
    #[arg(long)]
    pub node: String,

    #[arg(long, value_enum, default_value_t = GpuOutput::Text)]
    pub output: GpuOutput,
}

#[derive(Debug, Clone, Serialize)]
pub struct GpuInspectReport {
    pub node: String,
    pub iommu_enabled: bool,
    pub iommu_evidence: String,
    pub iommu_group_count: u32,
    pub vfio_loaded: bool,
    pub devices: Vec<PciDevice>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PciDevice {
    pub address: String,
    pub vendor: String,
    pub device: String,
    pub class: String,
    pub driver: String,
}

pub async fn execute_gpu_inspect(
    client: &std::sync::Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    args: GpuInspectArgs,
) -> Result<(Value, i32)> {
    use crate::ssh::exec::ExecOptions;

    let ssh_cfg = config.ssh.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "`proxxx gpu inspect` requires `[profiles.X.ssh]` (key_path) — \
             we SSH to the node and probe /sys + dmesg"
        )
    })?;
    let api: std::sync::Arc<dyn crate::api::ProxmoxGateway> =
        std::sync::Arc::clone(client) as std::sync::Arc<dyn crate::api::ProxmoxGateway>;
    let pool = crate::ssh::SshPool::new(ssh_cfg, None)?.with_api(&config.url, api);

    // Single multi-command probe — one round-trip instead of N.
    // The output is parsed line-by-line below.
    let cmd = "
        echo '== IOMMU ==';
        dmesg 2>/dev/null | grep -iE 'iommu|dmar|amd-vi' | head -5 || true;
        echo '== IOMMU_GROUPS ==';
        ls /sys/kernel/iommu_groups 2>/dev/null | wc -l || echo 0;
        echo '== VFIO ==';
        lsmod 2>/dev/null | grep -E '^vfio' | head -5 || echo none;
        echo '== LSPCI ==';
        lspci -nnk 2>/dev/null | head -200 || echo none
    ";
    let result = pool.exec(&args.node, cmd, ExecOptions::default()).await?;
    let stdout = result.stdout;

    let mut report = GpuInspectReport {
        node: args.node.clone(),
        iommu_enabled: false,
        iommu_evidence: String::new(),
        iommu_group_count: 0,
        vfio_loaded: false,
        devices: Vec::new(),
    };

    parse_inspect_output(&stdout, &mut report);

    match args.output {
        GpuOutput::Json => {
            // raw-output: JSON for machines; removing characters would change the data
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        GpuOutput::Text => {
            crate::outln!("== GPU/PCI passthrough probe — node {} ==\n", report.node);
            crate::outln!(
                "IOMMU enabled:   {} ({})",
                if report.iommu_enabled {
                    "✓ yes"
                } else {
                    "✗ NO"
                },
                if report.iommu_evidence.is_empty() {
                    "no dmesg evidence"
                } else {
                    &report.iommu_evidence
                }
            );
            crate::outln!("IOMMU groups:    {}", report.iommu_group_count);
            crate::outln!(
                "vfio module:     {}",
                if report.vfio_loaded {
                    "✓ loaded"
                } else {
                    "✗ NOT loaded"
                }
            );
            crate::outln!("\nDevices ({}):", report.devices.len());
            for d in &report.devices {
                crate::outln!(
                    "  {addr:<10}  {vendor:<8}:{device:<8}  {class:<24}  driver={driver}",
                    addr = d.address,
                    vendor = d.vendor,
                    device = d.device,
                    class = d.class,
                    driver = d.driver,
                );
            }
            crate::outln!();
            if !report.iommu_enabled {
                crate::outln!(
                    "✗ IOMMU is not enabled — passthrough will not work. \
                     Enable in BIOS (`VT-d` / `AMD-Vi`) and on the kernel cmdline \
                     (`intel_iommu=on iommu=pt` or `amd_iommu=on iommu=pt`)."
                );
            } else if !report.vfio_loaded {
                crate::outln!(
                    "! IOMMU on but vfio not loaded — pre-stage with \
                     `echo vfio-pci >> /etc/modules-load.d/vfio.conf`."
                );
            }
        }
    }

    let exit = i32::from(!report.iommu_enabled);
    Ok((Value::Null, exit))
}

/// Parse the multi-section probe output. Sections are
/// `== TAG ==` markers; we walk and dispatch.
pub fn parse_inspect_output(stdout: &str, report: &mut GpuInspectReport) {
    let mut section: &str = "";
    for line in stdout.lines() {
        // Keep the raw line for indentation-sensitive checks
        // (continuation lines in `lspci -nnk` output start with a
        // tab/space). `trimmed` is the convenience form used for
        // content matching everywhere else.
        let trimmed = line.trim();
        let is_continuation = line.starts_with(['\t', ' ']);
        if trimmed.starts_with("== ") && trimmed.ends_with(" ==") {
            section = trimmed.trim_start_matches("== ").trim_end_matches(" ==");
            continue;
        }
        match section {
            // dmesg lines are evidence only: "DMAR: IOMMU disabled" and
            // "iommu: Default domain type" also mention the IOMMU, so a
            // match proves nothing about it being on (audit #383). The
            // group count below decides.
            "IOMMU" if !trimmed.is_empty() && report.iommu_evidence.is_empty() => {
                report.iommu_evidence = trimmed.chars().take(80).collect();
            }
            "IOMMU_GROUPS" if let Ok(n) = trimmed.parse::<u32>() => {
                report.iommu_group_count = n;
                report.iommu_enabled = n > 0;
            }
            "VFIO" if trimmed.starts_with("vfio") => {
                report.vfio_loaded = true;
            }
            "LSPCI" => {
                // Format: `01:00.0 VGA compatible controller [0300]: NVIDIA [10de:1b06] (rev a1)\n\tKernel driver in use: nvidia`
                // The device header starts at column 0; continuation
                // lines (driver, kernel modules) are indented.
                if !is_continuation {
                    if let Some(device) = parse_lspci_line(trimmed) {
                        report.devices.push(device);
                    }
                } else if let Some(last) = report.devices.last_mut() {
                    if let Some(rest) = trimmed.strip_prefix("Kernel driver in use:") {
                        last.driver = rest.trim().to_string();
                    }
                }
            }
            _ => {}
        }
    }
}

/// Parse one `lspci -nnk` device header line:
/// `01:00.0 VGA compatible controller [0300]: NVIDIA Corporation GP106 [GeForce GTX 1060] [10de:1c03] (rev a1)`.
fn parse_lspci_line(line: &str) -> Option<PciDevice> {
    let (address, rest) = line.split_once(' ')?;
    if !address.contains(':') || !address.contains('.') {
        return None;
    }
    // The class name runs up to the class-code bracket; it is several
    // words ("VGA compatible controller"), so it cannot be taken as one
    // whitespace-separated token (audit #383).
    let class = rest.split(" [").next().unwrap_or("").trim().to_string();
    // The vendor:device pair is the last bracket holding `xxxx:yyyy` in
    // hex; the device name may carry brackets of its own.
    let (vendor, device) = rest
        .match_indices('[')
        .filter_map(|(start, _)| {
            let inner = &rest[start + 1..];
            let pair = &inner[..inner.find(']')?];
            let (v, d) = pair.split_once(':')?;
            let is_id = |s: &str| s.len() == 4 && s.bytes().all(|b| b.is_ascii_hexdigit());
            (is_id(v) && is_id(d)).then(|| (v.to_string(), d.to_string()))
        })
        .next_back()
        .unwrap_or_default();
    Some(PciDevice {
        address: address.to_string(),
        vendor,
        device,
        class,
        driver: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lspci_line_extracts_address_and_ids() {
        let line = "01:00.0 VGA compatible controller [0300]: NVIDIA [10de:1b06] (rev a1)";
        let d = parse_lspci_line(line).unwrap();
        assert_eq!(d.address, "01:00.0");
        // The vendor:device pair is the LAST [XXXX:YYYY] pair (the
        // class-code [0300] comes first; we use rfind to skip it).
        assert_eq!(d.vendor, "10de");
        assert_eq!(d.device, "1b06");
        assert_eq!(d.class, "VGA compatible controller");
    }

    #[test]
    fn parse_lspci_line_keeps_the_whole_class_and_skips_bracketed_names() {
        let line = "01:00.0 VGA compatible controller [0300]: NVIDIA Corporation GP106 \
                    [GeForce GTX 1060 6GB] [10de:1c03] (rev a1)";
        let d = parse_lspci_line(line).unwrap();
        assert_eq!(d.class, "VGA compatible controller");
        assert_eq!((d.vendor.as_str(), d.device.as_str()), ("10de", "1c03"));
    }

    fn empty_report() -> GpuInspectReport {
        GpuInspectReport {
            node: "n".into(),
            iommu_enabled: false,
            iommu_evidence: String::new(),
            iommu_group_count: 0,
            vfio_loaded: false,
            devices: Vec::new(),
        }
    }

    #[test]
    fn a_dmesg_line_mentioning_the_iommu_does_not_enable_it_without_groups() {
        let probe = "== IOMMU ==
[    0.000000] DMAR: IOMMU disabled
[    0.412000] iommu: Default domain type: Translated
== IOMMU_GROUPS ==
0
== VFIO ==
none
== LSPCI ==
";
        let mut r = empty_report();
        parse_inspect_output(probe, &mut r);
        assert!(!r.iommu_enabled, "0 groups must report IOMMU off");
        assert_eq!(r.iommu_group_count, 0);
        assert_eq!(r.iommu_evidence, "[    0.000000] DMAR: IOMMU disabled");
    }

    #[test]
    fn parse_inspect_output_detects_iommu_and_vfio() {
        let probe = "== IOMMU ==
[    1.234567] DMAR: IOMMU enabled
== IOMMU_GROUPS ==
14
== VFIO ==
vfio_pci               45056  0
vfio                   53248  2 vfio_iommu_type1,vfio_pci
== LSPCI ==
01:00.0 VGA compatible controller [0300]: NVIDIA [10de:1b06] (rev a1)
\tKernel driver in use: vfio-pci
";
        let mut r = GpuInspectReport {
            node: "n".into(),
            iommu_enabled: false,
            iommu_evidence: String::new(),
            iommu_group_count: 0,
            vfio_loaded: false,
            devices: Vec::new(),
        };
        parse_inspect_output(probe, &mut r);
        assert!(r.iommu_enabled);
        assert_eq!(r.iommu_group_count, 14);
        assert!(r.vfio_loaded);
        assert_eq!(r.devices.len(), 1);
        assert_eq!(r.devices[0].driver, "vfio-pci");
    }
}
