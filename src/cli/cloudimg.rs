//! `proxxx cloud-img …` — cloud-image template provisioner.
//!
//! Why it exists: setting up a cloud-init template VM today is a
//! ~10-step manual process per distro per cluster, and the community
//! helper-scripts (tteck) do it without supply-chain verification.
//! proxxx already enforces SHA-256 pinning for ISOs via
//! `app::iso_library::LIBRARY`; this module extends the same
//! discipline to cloud images.
//!
//! ## What this module covers (per #65)
//!
//! - **Bundled registry** of cloud-image manifests. Checksum-pinned
//!   per release (SHA-256 for Ubuntu/Fedora, SHA-512 for Debian/Alpine
//!   — each distro's native sidecar), pinned to dated immutable build
//!   dirs, append-only. v1 ships:
//!     * Ubuntu 24.04 (noble) cloud, amd64
//!     * Debian 13 (trixie) genericcloud, amd64
//!     * Alpine 3.20 generic cloud, `x86_64`
//!     * Fedora 41 cloud, `x86_64`
//! - **`proxxx cloud-img list`** — print the registry as a table
//!   (id / distro / version / arch / size / algo:checksum prefix).
//! - **`proxxx cloud-img download <id> --node <n> --storage <s>`** —
//!   issue PVE's `download-url` (server-side checksum-verified). The
//!   bytes never transit through proxxx; PVE downloads + verifies
//!   in one atomic step and rejects on hash mismatch. `.img` images
//!   deposit as `iso` content, `.qcow2` as `import` (PVE 8.2+).
//! - **`proxxx cloud-img provision <id> --node <n> --storage <s>`** —
//!   the full template orchestration (#65): (optionally download →)
//!   `qm create` with the image imported as the boot disk
//!   (`import-from`), a cloud-init drive on `ide2`, serial console +
//!   guest agent, cloud-init config (`ciuser`/`sshkeys`/`ipconfig0`),
//!   an optional disk grow, then `qm template`. One verified command
//!   in place of the ~5-step manual dance. `--no-template` / `--start`
//!   stop short of templating for boot-testing.
//!
//! ## Updating the registry
//!
//! **Bumping an existing entry to a new point release is automated** —
//! `scripts/repin-cloudimg.py` (run weekly by
//! `.github/workflows/cloudimg-repin.yml`) fetches each distro's latest
//! dated build + official checksum and opens a PR. You don't hand-edit
//! `url` / `checksum` / `checksum_algorithm` / `version`.
//!
//! Adding a NEW distro (a new `id`, which is append-only) is still
//! manual:
//! 1. Find the official upstream **dated/immutable** URL (never a
//!    `current`/`latest` symlink) + its checksum from the distro's
//!    SHA256SUMS / SHA512SUMS / CHECKSUM sidecar.
//! 2. Append a new [`CloudImg`] to [`REGISTRY`] below.
//! 3. Update [`registry_has_entry_per_supported_distro`] in the
//!    test module, and add a discovery fn + `DISCOVERERS` entry in
//!    `scripts/repin-cloudimg.py` so the new id stays fresh too.

use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Serialize;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;

use crate::api::types::GuestType;
use crate::api::{ProxmoxGateway, PxClient};
use crate::cli::common::poll_task_until_done;

/// One cloud-image entry in the bundled registry. All `'static`
/// — the registry is a compile-time constant.
#[derive(Debug, Clone, Serialize)]
pub struct CloudImg {
    /// Stable kebab-case identifier the operator types. Embeds
    /// distro + version + arch so disambiguation is built in.
    pub id: &'static str,
    pub distro: &'static str,
    pub version: &'static str,
    pub arch: &'static str,
    /// Official upstream download URL (HTTPS).
    pub url: &'static str,
    /// Checksum of the upstream file (lowercase hex). 64 chars for
    /// `sha256`, 128 for `sha512` — see `checksum_algorithm`. PVE's
    /// `download-url` verifies this server-side and rejects the
    /// download on mismatch.
    pub checksum: &'static str,
    /// Checksum algorithm: `"sha256"` or `"sha512"`. Distros differ —
    /// Ubuntu/Fedora publish SHA-256 sidecars, Debian/Alpine publish
    /// SHA-512 — so the algorithm is pinned per entry and forwarded to
    /// PVE's `download-url` `checksum-algorithm` parameter.
    pub checksum_algorithm: &'static str,
    /// Human-readable size estimate.
    pub size_human: &'static str,
    /// Filename to write into the storage. Conventionally
    /// `<distro>-<version>-<arch>.<ext>`.
    pub filename: &'static str,
    /// PVE storage `content` type — `"iso"` or `"import"`. The choice
    /// is forced by PVE's per-content filename-extension validation:
    /// `iso` accepts `.iso`/`.img` only, `import` accepts
    /// `.qcow2`/`.raw`/`.vmdk`/`.vhdx` only. So a `.img` cloud image
    /// (Ubuntu) deposits as `iso`; a `.qcow2` (Debian/Alpine/Fedora)
    /// MUST deposit as `import` — PVE 8.2+ — or `download-url` rejects
    /// it with "wrong file extension". The operator then imports the
    /// disk with `qm importdisk` / `qm set --scsi0 …,import-from=…`.
    pub content: &'static str,
}

/// The bundled registry. Append-only — never remove or mutate an
/// entry once shipped, because operators may rely on the id being
/// stable. Bump versions by adding new entries with new ids.
///
/// All URLs + checksums verified against the official upstream at
/// registry-edit time (2026-05-21). URLs point at **dated, immutable**
/// build directories — never `current`/`latest` symlinks — so the
/// pinned checksum stays valid. When a distro ships a new point
/// release, bump the entry (new dated URL + fresh checksum from the
/// official SHA256SUMS / SHA512SUMS); a stale entry keeps working until
/// then. The supply-chain discipline matches `app::iso_library::LIBRARY`.
pub const REGISTRY: &[CloudImg] = &[
    CloudImg {
        id: "ubuntu-24.04-noble-amd64",
        distro: "Ubuntu",
        version: "24.04 LTS (noble, build 20260321)",
        arch: "amd64",
        // Dated immutable build dir (not noble/current/, which rotates
        // daily). Checksum from this dir's SHA256SUMS.
        url: "https://cloud-images.ubuntu.com/releases/noble/release-20260321/ubuntu-24.04-server-cloudimg-amd64.img",
        checksum: "5c3ddb00f60bc455dac0862fabe9d8bacec46c33ac1751143c5c3683404b110d",
        checksum_algorithm: "sha256",
        size_human: "~580 MiB",
        filename: "ubuntu-24.04-noble-amd64.img",
        content: "iso",
    },
    CloudImg {
        id: "debian-13-trixie-amd64",
        distro: "Debian",
        version: "13 (trixie) genericcloud, build 20260518-2482",
        arch: "amd64",
        // Debian publishes SHA512SUMS only (no SHA256). Dated build dir.
        url: "https://cloud.debian.org/images/cloud/trixie/20260518-2482/debian-13-genericcloud-amd64-20260518-2482.qcow2",
        checksum: "7752ad2adce1bc49dd964dae8300ed7a239d0bf3c13112f55953b111447fe642d2cc01afeead234aa6ebe3605513f2e7c0e7c56785d675c38ff40110d5c8332b",
        checksum_algorithm: "sha512",
        size_human: "~400 MiB",
        filename: "debian-13-trixie-amd64.qcow2",
        content: "import",
    },
    CloudImg {
        id: "alpine-3.20-virt-x86_64",
        distro: "Alpine",
        version: "3.20.10 generic (bios cloudinit)",
        arch: "x86_64",
        // Alpine's generic cloud qcow2 (the registry previously named a
        // non-existent `nocloud_` artifact). Per-file .sha512 sidecar;
        // no .sha256 is published.
        url: "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/generic_alpine-3.20.10-x86_64-bios-cloudinit-r0.qcow2",
        checksum: "dbf008c5910e22d2c9c2268ea9ce2dfef8b12e6f5e303c7515bdc1c4540d1b01cc7452fd351910b349162af6364f183af41ff01acdc2f6cb38a3652ee7f7e56e",
        checksum_algorithm: "sha512",
        size_human: "~190 MiB",
        filename: "alpine-3.20-virt-x86_64.qcow2",
        content: "import",
    },
    CloudImg {
        id: "fedora-41-cloud-x86_64",
        distro: "Fedora",
        version: "41 cloud (Generic Base 1.4)",
        arch: "x86_64",
        // Fedora release path is already immutable (versioned 41-1.4).
        // Checksum from the Fedora-Cloud-41-1.4-x86_64-CHECKSUM file.
        url: "https://download.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2",
        checksum: "6205ae0c524b4d1816dbd3573ce29b5c44ed26c9fbc874fbe48c41c89dd0bac2",
        checksum_algorithm: "sha256",
        size_human: "~470 MiB",
        filename: "fedora-41-cloud-x86_64.qcow2",
        content: "import",
    },
];

/// Look up an entry by id. Case-sensitive (ids are already
/// kebab-case) — typos surface clearly.
#[must_use]
pub fn by_id(id: &str) -> Option<&'static CloudImg> {
    REGISTRY.iter().find(|e| e.id == id)
}

/// Sanitize a registry id into a PVE-legal VM name: `.` and `_` → `-`
/// (PVE guest names are DNS-ish and reject dots/underscores).
fn sanitize_template_name(id: &str) -> String {
    id.replace(['.', '_'], "-")
}

/// PVE volid of a downloaded registry image on `storage`. `.qcow2`
/// images land under `import/` (content=import, PVE 8.2+), `.img`
/// under `iso/` (content=iso) — keyed off the entry's `content`.
fn source_volid(storage: &str, entry: &CloudImg) -> String {
    let dir = if entry.content == "import" {
        "import"
    } else {
        "iso"
    };
    format!("{storage}:{dir}/{}", entry.filename)
}

/// Inputs to [`build_create_params`]. Grouped into a struct so the
/// param builder stays a pure, unit-testable function.
struct CreateSpec {
    vmid: u32,
    name: String,
    cores: u32,
    memory: u32,
    bridge: String,
    storage: String,
    source_volid: String,
    ciuser: Option<String>,
    sshkeys: Option<String>,
    ipconfig: String,
}

/// Build the `POST /nodes/{node}/qemu` body for a cloud-init template:
/// boot disk imported from `source_volid` (PVE 8.2+ `import-from`), a
/// cloud-init drive on `ide2`, a serial console + `serial0` VGA (cloud
/// images expect a serial console — without it boot output is invisible
/// and some images hang), and the guest agent. cloud-init config
/// (`ciuser` / `sshkeys` / `ipconfig0`) is applied when supplied.
fn build_create_params(spec: &CreateSpec) -> Vec<(String, String)> {
    let mut p: Vec<(String, String)> = vec![
        ("vmid".into(), spec.vmid.to_string()),
        ("name".into(), spec.name.clone()),
        ("cores".into(), spec.cores.to_string()),
        ("memory".into(), spec.memory.to_string()),
        ("ostype".into(), "l26".into()),
        ("scsihw".into(), "virtio-scsi-single".into()),
        ("net0".into(), format!("virtio,bridge={}", spec.bridge)),
        (
            "scsi0".into(),
            format!("{}:0,import-from={}", spec.storage, spec.source_volid),
        ),
        ("ide2".into(), format!("{}:cloudinit", spec.storage)),
        ("boot".into(), "order=scsi0".into()),
        ("serial0".into(), "socket".into()),
        ("vga".into(), "serial0".into()),
        ("agent".into(), "1".into()),
        ("ipconfig0".into(), spec.ipconfig.clone()),
    ];
    if let Some(u) = &spec.ciuser {
        p.push(("ciuser".into(), u.clone()));
    }
    if let Some(k) = &spec.sshkeys {
        // Raw key — reqwest URL-encodes form bodies, matching the
        // existing `proxxx vm` cloud-init path (src/cli/vm.rs).
        p.push(("sshkeys".into(), k.clone()));
    }
    p
}

#[derive(Debug, Subcommand)]
pub enum CloudImgCommand {
    /// Print the bundled cloud-image registry (id / distro / version /
    /// arch / size / SHA-256 prefix). All entries are pinned by
    /// SHA-256 — PVE verifies the download server-side and rejects
    /// on mismatch.
    List {
        /// Output format. `text` (default) for humans, `json` for
        /// tooling consumers.
        #[arg(long, value_enum, default_value_t = CloudImgOutput::Text)]
        output: CloudImgOutput,
    },

    /// Download a cloud image into a PVE storage via PVE's
    /// `download-url` (server-side SHA-256 verified). The bytes
    /// never transit through proxxx — PVE talks directly to the
    /// upstream over HTTPS.
    ///
    /// Returns the task UPID. Use `proxxx tasks --node <node>` to
    /// follow progress; the typical 500 MiB image takes 30 s to a
    /// few minutes depending on upstream bandwidth.
    Download {
        /// Registry id (run `proxxx cloud-img list` for the catalog).
        id: String,
        /// Target PVE node.
        #[arg(long)]
        node: String,
        /// Target PVE storage. Must accept `content = iso`.
        #[arg(long)]
        storage: String,
    },

    /// Provision a cloud-init **template** from a registry image in one
    /// command: (optionally download →) create the VM with the image
    /// imported as its boot disk, attach a cloud-init drive, wire the
    /// serial console + guest agent, apply cloud-init config, optionally
    /// grow the disk, then convert to a template.
    ///
    /// Collapses the manual `qm create` / `qm set --scsiN import-from`
    /// / `qm set --ide2 cloudinit` / `qm set --ciuser/--sshkeys` /
    /// `qm template` dance into a single verified step. Requires PVE
    /// 8.2+ for the `import-from` disk syntax (the cluster is 9.x).
    ///
    /// The image must already be on `--storage` (run `cloud-img
    /// download` first), unless `--download` is passed to fetch it
    /// inline. Returns once the template exists.
    Provision {
        /// Registry id (run `proxxx cloud-img list` for the catalog).
        id: String,
        /// Target PVE node.
        #[arg(long)]
        node: String,
        /// Target PVE storage for the image, cloud-init drive, and the
        /// VM's imported disk. Must accept disk images + `import`/`iso`.
        #[arg(long)]
        storage: String,
        /// VMID for the new template. Default: next free id from the
        /// cluster (`/cluster/nextid`).
        #[arg(long)]
        vmid: Option<u32>,
        /// Template name. Default: the registry id with `.`/`_` → `-`
        /// (PVE names can't contain dots).
        #[arg(long)]
        name: Option<String>,
        /// vCPU cores.
        #[arg(long, default_value_t = 2)]
        cores: u32,
        /// Memory in MiB.
        #[arg(long, default_value_t = 2048)]
        memory: u32,
        /// Network bridge for net0 (virtio).
        #[arg(long, default_value = "vmbr0")]
        bridge: String,
        /// Grow the imported boot disk to this size, e.g. `20G` or
        /// `+10G`. Cloud images ship small (~2-4 GiB); most operators
        /// want headroom. Omit to keep the image's native size.
        #[arg(long)]
        disk_size: Option<String>,
        /// File with SSH public key(s) to inject via cloud-init
        /// (`sshkeys`). One key per line.
        #[arg(long)]
        ssh_key_file: Option<PathBuf>,
        /// cloud-init default username (`ciuser`).
        #[arg(long)]
        ciuser: Option<String>,
        /// cloud-init `ipconfig0` for net0, e.g. `ip=dhcp` or
        /// `ip=10.0.0.50/24,gw=10.0.0.1`.
        #[arg(long, default_value = "ip=dhcp")]
        ipconfig: String,
        /// Download the image first (waits for completion) instead of
        /// requiring it already on `--storage`.
        #[arg(long)]
        download: bool,
        /// Leave the result as a stopped VM instead of converting it to
        /// a template (e.g. to boot-test the image before templating).
        #[arg(long)]
        no_template: bool,
        /// Start the VM at the end instead of templating it. Implies
        /// `--no-template`. Useful for a smoke boot.
        #[arg(long)]
        start: bool,
        /// Output format.
        #[arg(long, value_enum, default_value_t = CloudImgOutput::Text)]
        output: CloudImgOutput,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, Default)]
pub enum CloudImgOutput {
    #[default]
    Text,
    Json,
}

pub async fn execute_cloudimg(
    client: &Arc<PxClient>,
    action: CloudImgCommand,
) -> Result<(Value, i32)> {
    match action {
        CloudImgCommand::List { output } => {
            if matches!(output, CloudImgOutput::Json) {
                let v: Vec<&CloudImg> = REGISTRY.iter().collect();
                let s = serde_json::to_string_pretty(&v)?;
                println!("{s}");
                return Ok((Value::Null, 0));
            }
            println!(
                "{id:<32}  {distro:<8}  {version:<40}  {arch:<8}  {size:<10}  checksum",
                id = "id",
                distro = "distro",
                version = "version",
                arch = "arch",
                size = "size"
            );
            let sep = "─".repeat(130);
            println!("{sep}");
            for e in REGISTRY {
                // Char-boundary safe (checksums are ASCII hex, but use
                // the shared helper for consistency).
                let sum_short = crate::util::sanitize::truncate_ellipsis(e.checksum, 16);
                println!(
                    "{id:<32}  {distro:<8}  {version:<40}  {arch:<8}  {size:<10}  {algo}:{sum}",
                    id = e.id,
                    distro = e.distro,
                    version = e.version,
                    arch = e.arch,
                    size = e.size_human,
                    algo = e.checksum_algorithm,
                    sum = sum_short,
                );
            }
            Ok((Value::Null, 0))
        }
        CloudImgCommand::Download { id, node, storage } => {
            let entry = by_id(&id).with_context(|| {
                format!("unknown template id `{id}` — run `proxxx template list` for the catalog")
            })?;
            // Always forward the pinned checksum + algorithm so PVE
            // verifies server-side and rejects on mismatch (or on a
            // tampered upstream). The algorithm is per-entry: Ubuntu/
            // Fedora are sha256, Debian/Alpine sha512.
            let upid = client
                .download_to_storage(
                    &node,
                    &storage,
                    entry.url,
                    entry.filename,
                    Some(entry.checksum_algorithm),
                    Some(entry.checksum),
                    entry.content,
                )
                .await?;
            Ok((
                serde_json::json!({
                    "id": entry.id,
                    "node": node,
                    "storage": storage,
                    "url": entry.url,
                    "filename": entry.filename,
                    "checksum": entry.checksum,
                    "checksum_algorithm": entry.checksum_algorithm,
                    "task": upid,
                    "note": "Use `proxxx tasks --node <node>` to follow progress. \
                             PVE verifies the checksum server-side and rejects on mismatch.",
                }),
                0,
            ))
        }

        CloudImgCommand::Provision {
            id,
            node,
            storage,
            vmid,
            name,
            cores,
            memory,
            bridge,
            disk_size,
            ssh_key_file,
            ciuser,
            ipconfig,
            download,
            no_template,
            start,
            output,
        } => {
            let entry = by_id(&id).with_context(|| {
                format!("unknown template id `{id}` — run `proxxx cloud-img list` for the catalog")
            })?;

            // Read the SSH key file up front so a bad path fails before
            // we mutate the cluster.
            let sshkeys = match &ssh_key_file {
                Some(p) => Some(
                    std::fs::read_to_string(p)
                        .with_context(|| format!("reading SSH key file {}", p.display()))?
                        .trim()
                        .to_string(),
                ),
                None => None,
            };

            let vmid = match vmid {
                Some(v) => v,
                None => client
                    .get_next_vmid()
                    .await
                    .context("allocating next VMID from /cluster/nextid")?,
            };
            let name = name.unwrap_or_else(|| sanitize_template_name(entry.id));

            // 1. Optionally download the image first (and wait for it).
            if download {
                eprintln!(
                    "→ downloading {} to {storage} (PVE verifies checksum)…",
                    entry.id
                );
                let upid = client
                    .download_to_storage(
                        &node,
                        &storage,
                        entry.url,
                        entry.filename,
                        Some(entry.checksum_algorithm),
                        Some(entry.checksum),
                        entry.content,
                    )
                    .await
                    .context("starting image download")?;
                let st = poll_task_until_done(client, &node, &upid, 0)
                    .await
                    .context("waiting for image download")?;
                if !st.is_success() {
                    anyhow::bail!(
                        "image download task failed (status: {}) — check `proxxx tasks --node {node}`",
                        st.status
                    );
                }
            }

            // 2. Create the VM with the image imported as its boot disk.
            let spec = CreateSpec {
                vmid,
                name: name.clone(),
                cores,
                memory,
                bridge,
                storage: storage.clone(),
                source_volid: source_volid(&storage, entry),
                ciuser,
                sshkeys,
                ipconfig,
            };
            let params = build_create_params(&spec);
            let borrowed: Vec<(&str, &str)> = params
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            eprintln!(
                "→ creating VM {vmid} ({name}) — importing disk from {}…",
                spec.source_volid
            );
            let create_upid = client
                .create_qemu(&node, &borrowed)
                .await
                .context("creating VM")?;
            let st = poll_task_until_done(client, &node, &create_upid, 0)
                .await
                .context("waiting for VM create + disk import")?;
            if !st.is_success() {
                anyhow::bail!(
                    "VM create task failed (status: {}) — check `proxxx tasks --node {node}`",
                    st.status
                );
            }

            // 3. Optionally grow the imported boot disk.
            if let Some(size) = &disk_size {
                eprintln!("→ resizing scsi0 to {size}…");
                let rupid = client
                    .resize_disk(&node, vmid, GuestType::Qemu, "scsi0", size)
                    .await
                    .context("resizing boot disk")?;
                if !rupid.is_empty() {
                    poll_task_until_done(client, &node, &rupid, 0)
                        .await
                        .context("waiting for disk resize")?;
                }
            }

            // 4. Terminal action: template (default), leave as VM, or start.
            let final_state = if start {
                eprintln!("→ starting VM {vmid}…");
                let supid = client
                    .start_guest(&node, vmid, GuestType::Qemu)
                    .await
                    .context("starting VM")?;
                if !supid.is_empty() {
                    poll_task_until_done(client, &node, &supid, 0)
                        .await
                        .context("waiting for VM start")?;
                }
                "started"
            } else if no_template {
                "vm"
            } else {
                eprintln!("→ converting VM {vmid} to template…");
                client
                    .convert_to_template(&node, vmid, GuestType::Qemu)
                    .await
                    .context("converting to template")?;
                "template"
            };

            let summary = serde_json::json!({
                "id": entry.id,
                "node": node,
                "vmid": vmid,
                "name": name,
                "storage": storage,
                "source": spec.source_volid,
                "disk_size": disk_size,
                "state": final_state,
            });
            if matches!(output, CloudImgOutput::Json) {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                let what = match final_state {
                    "template" => format!("template {vmid} ({name})"),
                    "started" => format!("running VM {vmid} ({name})"),
                    _ => format!("VM {vmid} ({name})"),
                };
                println!("✓ provisioned {what} on {node} from {}", entry.id);
                if final_state == "template" {
                    println!("  clone it: proxxx clone {vmid} <new-vmid> --name <name>");
                }
            }
            // Self-printed above (text or JSON), so return Null to avoid a
            // double-render by the caller — same convention as `List`.
            Ok((Value::Null, 0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_ids_are_unique_and_kebab_case() {
        let mut seen = std::collections::HashSet::new();
        for e in REGISTRY {
            assert!(seen.insert(e.id), "duplicate template id `{}`", e.id);
            assert!(
                e.id.chars().all(|c| c.is_ascii_lowercase()
                    || c.is_ascii_digit()
                    || c == '-'
                    || c == '.'
                    || c == '_'),
                "id `{}` is not kebab-case (allowed: a-z 0-9 - . _)",
                e.id,
            );
            assert!(!e.distro.is_empty(), "empty distro for {}", e.id);
            assert!(!e.version.is_empty(), "empty version for {}", e.id);
            assert!(!e.url.is_empty(), "empty url for {}", e.id);
            assert!(
                e.url.starts_with("https://"),
                "url for `{}` is not HTTPS",
                e.id
            );
            // Checksum length must match the declared algorithm, be all
            // lowercase hex, and NOT be a placeholder (all-zero). The
            // all-zero guard is the regression pin against the v0.3.0
            // shipped state where every entry was unusable.
            let (algo_ok, want_len) = match e.checksum_algorithm {
                "sha256" => (true, 64),
                "sha512" => (true, 128),
                _ => (false, 0),
            };
            assert!(
                algo_ok,
                "checksum_algorithm for `{}` must be sha256 or sha512, got `{}`",
                e.id, e.checksum_algorithm,
            );
            assert_eq!(
                e.checksum.len(),
                want_len,
                "checksum for `{}` ({}) must be {want_len} hex chars",
                e.id,
                e.checksum_algorithm,
            );
            assert!(
                e.checksum
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "checksum for `{}` must be lowercase hex",
                e.id,
            );
            assert!(
                e.checksum.chars().any(|c| c != '0'),
                "checksum for `{}` is an all-zero placeholder — repin from upstream",
                e.id,
            );
            // Dated/immutable URL discipline: no `current`/`latest`
            // symlinks (their content rotates, invalidating the pin).
            assert!(
                !e.url.contains("/current/") && !e.url.contains("/latest/"),
                "url for `{}` uses a rotating symlink path; pin a dated build dir",
                e.id,
            );
            assert!(!e.filename.is_empty(), "empty filename for {}", e.id);
            assert!(
                e.content == "iso" || e.content == "import",
                "unsupported content `{}`",
                e.content
            );
        }
    }

    #[test]
    fn registry_has_entry_per_supported_distro() {
        // Pinned coverage: any future PR that drops one of these
        // ids fails the test, so the catalog regression is loud.
        let expected: &[&str] = &[
            "ubuntu-24.04-noble-amd64",
            "debian-13-trixie-amd64",
            "alpine-3.20-virt-x86_64",
            "fedora-41-cloud-x86_64",
        ];
        for id in expected {
            assert!(
                by_id(id).is_some(),
                "registry missing pinned template id `{id}`",
            );
        }
    }

    #[test]
    fn by_id_returns_none_for_unknown() {
        assert!(by_id("totally-fake-distro").is_none());
        assert!(by_id("").is_none());
    }

    // ── provision helpers ─────────────────────────────────

    #[test]
    fn sanitize_template_name_strips_dots_and_underscores() {
        // PVE guest names reject `.`/`_`; the registry ids carry both.
        assert_eq!(
            sanitize_template_name("ubuntu-24.04-noble-amd64"),
            "ubuntu-24-04-noble-amd64"
        );
        assert_eq!(sanitize_template_name("alpine_3.20_x86"), "alpine-3-20-x86");
        assert_eq!(sanitize_template_name("plain-id"), "plain-id");
    }

    #[test]
    fn source_volid_picks_dir_from_content_type() {
        let import_entry = REGISTRY
            .iter()
            .find(|e| e.content == "import")
            .expect("registry has an import-content entry");
        assert_eq!(
            source_volid("local", import_entry),
            format!("local:import/{}", import_entry.filename)
        );
        if let Some(iso_entry) = REGISTRY.iter().find(|e| e.content == "iso") {
            assert_eq!(
                source_volid("nvme", iso_entry),
                format!("nvme:iso/{}", iso_entry.filename)
            );
        }
    }

    #[test]
    fn build_create_params_wires_import_cloudinit_serial_agent() {
        let spec = CreateSpec {
            vmid: 9001,
            name: "ubuntu-tmpl".into(),
            cores: 2,
            memory: 2048,
            bridge: "vmbr0".into(),
            storage: "local-lvm".into(),
            source_volid: "local:import/x.qcow2".into(),
            ciuser: Some("admin".into()),
            sshkeys: Some("ssh-ed25519 AAAAExample".into()),
            ipconfig: "ip=dhcp".into(),
        };
        let p = build_create_params(&spec);
        let get = |k: &str| p.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.as_str());
        assert_eq!(get("vmid"), Some("9001"));
        assert_eq!(get("name"), Some("ubuntu-tmpl"));
        // The load-bearing bit: boot disk imported from the source volid.
        assert_eq!(
            get("scsi0"),
            Some("local-lvm:0,import-from=local:import/x.qcow2")
        );
        assert_eq!(get("ide2"), Some("local-lvm:cloudinit"));
        assert_eq!(get("boot"), Some("order=scsi0"));
        // Cloud images need a serial console or boot output is invisible.
        assert_eq!(get("serial0"), Some("socket"));
        assert_eq!(get("vga"), Some("serial0"));
        assert_eq!(get("agent"), Some("1"));
        assert_eq!(get("net0"), Some("virtio,bridge=vmbr0"));
        assert_eq!(get("ciuser"), Some("admin"));
        assert_eq!(get("sshkeys"), Some("ssh-ed25519 AAAAExample"));
        assert_eq!(get("ipconfig0"), Some("ip=dhcp"));
    }

    #[test]
    fn build_create_params_omits_absent_cloudinit_fields() {
        let spec = CreateSpec {
            vmid: 9001,
            name: "t".into(),
            cores: 1,
            memory: 512,
            bridge: "vmbr0".into(),
            storage: "local".into(),
            source_volid: "local:iso/x.img".into(),
            ciuser: None,
            sshkeys: None,
            ipconfig: "ip=dhcp".into(),
        };
        let p = build_create_params(&spec);
        assert!(
            !p.iter().any(|(k, _)| k == "ciuser"),
            "no ciuser when unset"
        );
        assert!(
            !p.iter().any(|(k, _)| k == "sshkeys"),
            "no sshkeys when unset"
        );
        // ipconfig0 always present (the CLI arg defaults to ip=dhcp).
        assert!(p.iter().any(|(k, _)| k == "ipconfig0"));
    }
}
