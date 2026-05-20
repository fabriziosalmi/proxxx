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
    let pool = crate::ssh::SshPool::new(ssh_cfg, None)?;

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
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        GpuOutput::Text => {
            println!("== GPU/PCI passthrough probe — node {} ==\n", report.node);
            println!(
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
            println!("IOMMU groups:    {}", report.iommu_group_count);
            println!(
                "vfio module:     {}",
                if report.vfio_loaded {
                    "✓ loaded"
                } else {
                    "✗ NOT loaded"
                }
            );
            println!("\nDevices ({}):", report.devices.len());
            for d in &report.devices {
                println!(
                    "  {addr:<10}  {vendor:<8}:{device:<8}  {class:<24}  driver={driver}",
                    addr = d.address,
                    vendor = d.vendor,
                    device = d.device,
                    class = d.class,
                    driver = d.driver,
                );
            }
            println!();
            if !report.iommu_enabled {
                println!(
                    "✗ IOMMU is not enabled — passthrough will not work. \
                     Enable in BIOS (`VT-d` / `AMD-Vi`) and on the kernel cmdline \
                     (`intel_iommu=on iommu=pt` or `amd_iommu=on iommu=pt`)."
                );
            } else if !report.vfio_loaded {
                println!(
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
        let is_continuation = line.starts_with(|c: char| c == '\t' || c == ' ');
        if trimmed.starts_with("== ") && trimmed.ends_with(" ==") {
            section = trimmed.trim_start_matches("== ").trim_end_matches(" ==");
            continue;
        }
        match section {
            "IOMMU" if !trimmed.is_empty() && trimmed.to_lowercase().contains("iommu") => {
                report.iommu_enabled = true;
                if report.iommu_evidence.is_empty() {
                    report.iommu_evidence = trimmed.chars().take(80).collect();
                }
            }
            "IOMMU_GROUPS" if let Ok(n) = trimmed.parse::<u32>() => {
                report.iommu_group_count = n;
                if n > 0 {
                    report.iommu_enabled = true;
                }
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

/// Parse one `lspci -nnk` device header line.
fn parse_lspci_line(line: &str) -> Option<PciDevice> {
    let mut parts = line.splitn(3, ' ');
    let address = parts.next()?.to_string();
    if !address.contains(':') || !address.contains('.') {
        return None;
    }
    let _ = parts.next()?; // class name (e.g. "VGA compatible controller")
    let rest = parts.next()?;
    // Find the LAST `[XXXX:YYYY]` vendor:device pair (the first
    // bracket holds the class code, which we want to skip).
    let (vendor, device) = match (rest.rfind('['), rest.rfind(']')) {
        (Some(s), Some(e)) if e > s => {
            let pair = &rest[s + 1..e];
            if let Some((v, d)) = pair.split_once(':') {
                (v.to_string(), d.to_string())
            } else {
                (String::new(), String::new())
            }
        }
        _ => (String::new(), String::new()),
    };
    Some(PciDevice {
        address,
        vendor,
        device,
        class: rest.split('[').next().unwrap_or("").trim().to_string(),
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
