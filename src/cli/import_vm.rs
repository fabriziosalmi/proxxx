//! `proxxx import` — unified VM image converter + import.
//!
//! Converts common upstream image formats (OVA / OVF / raw / qcow2)
//! to PVE-compatible qcow2 and stages them as ready-to-attach disk
//! images. Wraps `qemu-img convert` (which must be installed on the
//! host running proxxx) so operators get a single command instead
//! of a 4-step manual pipeline.
//!
//! ## MVP scope (per #66)
//!
//! - **Convert to qcow2** (the lowest-common-denominator PVE
//!   format). Supports the inputs `qemu-img convert` natively
//!   understands: raw, qcow2, vmdk, vdi, vhdx, vhd.
//! - **Inspect-only mode** (`--dry-run`): print what would happen
//!   (input format detection + output path) without writing.
//! - **No PVE-side upload yet** — v1 converts locally; the
//!   operator picks up the qcow2 and `qm importdisk`s it. Direct
//!   upload via PVE's storage API is the obvious next slice.
//! - **No OVA/OVF parsing** — those are tarballs of (ovf-xml +
//!   vmdk). Extracting the vmdk + parsing the ovf for hw config
//!   is a separate chunk of code per the issue's "out of scope"
//!   ladder. The `qemu-img` chain handles the *image*; OVF hw
//!   metadata import is the v2 follow-up.
//! - **No libvirt-XML / VMware-direct chains** — also v2.

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, clap::ValueEnum, Default)]
pub enum ImportOutput {
    #[default]
    Text,
    Json,
}

#[derive(Debug, clap::Args)]
pub struct ImportArgs {
    /// Source image path. Format auto-detected by extension /
    /// magic-bytes if `--format` is omitted.
    pub input: PathBuf,

    /// Override the detected source format (`raw`, `qcow2`,
    /// `vmdk`, `vdi`, `vhdx`, `vhd`). Mostly useful when the file
    /// has a misleading extension.
    #[arg(long)]
    pub format: Option<String>,

    /// Output path for the converted qcow2. Default: `<input>.qcow2`
    /// next to the source.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Inspect-only — print the planned conversion command + paths
    /// without invoking `qemu-img`.
    #[arg(long)]
    pub dry_run: bool,

    #[arg(long, value_enum, default_value_t = ImportOutput::Text)]
    pub print: ImportOutput,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    pub input: String,
    pub detected_format: String,
    pub output: String,
    pub output_format: &'static str,
    pub command: Vec<String>,
    pub dry_run: bool,
    pub exit_code: Option<i32>,
}

/// Detect the source format from the file extension. Falls back
/// to `raw` for unknown extensions — `qemu-img info` would be
/// more accurate but requires invoking the tool; v1 uses the
/// extension heuristic and the caller can override with
/// `--format` when needed.
#[must_use]
pub fn detect_format(path: &std::path::Path) -> String {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match ext.as_str() {
        "qcow2" => "qcow2".into(),
        "vmdk" => "vmdk".into(),
        "vdi" => "vdi".into(),
        "vhdx" => "vhdx".into(),
        "vhd" => "vhd".into(),
        "img" | "raw" | "" => "raw".into(),
        other => other.to_string(),
    }
}

pub fn execute_import(args: &ImportArgs) -> Result<(Value, i32)> {
    if !args.input.exists() {
        anyhow::bail!("input file does not exist: {}", args.input.display());
    }
    let detected = args
        .format
        .clone()
        .unwrap_or_else(|| detect_format(&args.input));
    let output_path = args.output.clone().unwrap_or_else(|| {
        let mut p = args.input.clone();
        p.set_extension("qcow2");
        p
    });

    let cmd: Vec<String> = vec![
        "qemu-img".into(),
        "convert".into(),
        "-f".into(),
        detected.clone(),
        "-O".into(),
        "qcow2".into(),
        args.input.to_string_lossy().into_owned(),
        output_path.to_string_lossy().into_owned(),
    ];

    let mut report = ImportReport {
        input: args.input.to_string_lossy().into_owned(),
        detected_format: detected,
        output: output_path.to_string_lossy().into_owned(),
        output_format: "qcow2",
        command: cmd.clone(),
        dry_run: args.dry_run,
        exit_code: None,
    };

    if !args.dry_run {
        let status = std::process::Command::new(&cmd[0])
            .args(&cmd[1..])
            .status()
            .with_context(|| {
                "spawn `qemu-img` — is it installed on this host? \
                 (apt install qemu-utils on Debian/PVE)"
            })?;
        report.exit_code = status.code();
    }

    match args.print {
        ImportOutput::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ImportOutput::Text => {
            println!("input:    {}", report.input);
            println!("detected: {}", report.detected_format);
            println!("output:   {} ({})", report.output, report.output_format);
            println!("command:  {}", report.command.join(" "));
            if args.dry_run {
                println!("(dry-run — not executed)");
            } else if let Some(code) = report.exit_code {
                if code == 0 {
                    println!("✓ converted successfully");
                } else {
                    println!("✗ qemu-img exited {code}");
                }
            }
        }
    }

    let exit = report.exit_code.unwrap_or(0);
    Ok((Value::Null, exit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detect_format_recognises_common_extensions() {
        assert_eq!(detect_format(&PathBuf::from("vm.qcow2")), "qcow2");
        assert_eq!(detect_format(&PathBuf::from("vm.vmdk")), "vmdk");
        assert_eq!(detect_format(&PathBuf::from("vm.vdi")), "vdi");
        assert_eq!(detect_format(&PathBuf::from("vm.vhdx")), "vhdx");
        assert_eq!(detect_format(&PathBuf::from("vm.vhd")), "vhd");
        assert_eq!(detect_format(&PathBuf::from("vm.img")), "raw");
        assert_eq!(detect_format(&PathBuf::from("vm.raw")), "raw");
        assert_eq!(detect_format(&PathBuf::from("vm")), "raw");
    }

    #[test]
    fn detect_format_is_case_insensitive_on_extension() {
        assert_eq!(detect_format(&PathBuf::from("vm.QCOW2")), "qcow2");
        assert_eq!(detect_format(&PathBuf::from("vm.VMDK")), "vmdk");
    }
}
