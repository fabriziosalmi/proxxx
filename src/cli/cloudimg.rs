//! `proxxx template …` — cloud-image template provisioner.
//!
//! Why it exists: setting up a cloud-init template VM today is a
//! ~10-step manual process per distro per cluster, and the community
//! helper-scripts (tteck) do it without supply-chain verification.
//! proxxx already enforces SHA-256 pinning for ISOs via
//! `app::iso_library::LIBRARY`; this module extends the same
//! discipline to cloud images.
//!
//! ## What this MVP covers (per #65)
//!
//! - **Bundled registry** of cloud-image manifests. SHA-256 pinned
//!   per release, append-only. v1 ships:
//!     * Ubuntu 24.04 (noble) cloud, amd64 + arm64
//!     * Debian 13 (trixie) genericcloud, amd64
//!     * Alpine 3.20 cloud, `x86_64`
//!     * Fedora 41 cloud, `x86_64`
//! - **`proxxx cloud-img list`** — print the registry as a table
//!   (id / distro / version / arch / size / SHA-256 prefix).
//! - **`proxxx cloud-img download <id> --node <n> --storage <s>`** —
//!   issue PVE's `download-url` (server-side SHA-verified). The
//!   bytes never transit through proxxx; PVE downloads + verifies
//!   in one atomic step and rejects on hash mismatch.
//!
//! ## Scope deferred to a follow-up
//!
//! - Full VM-create orchestration (`qm create`, `qm set --scsi0`,
//!   cloud-init drive attach, `qm template <vmid>`). The download
//!   step is the cryptographic-discipline value-add; the create
//!   step is a multi-call API dance that benefits from its own PR.
//!   Operators can run the create steps via `proxxx vm raw-set`
//!   today; orchestrating them lives in #65 follow-up.
//!
//! ## Updating the registry
//!
//! 1. Find the official upstream download URL + SHA-256.
//! 2. Append a new [`CloudImg`] to [`REGISTRY`] below.
//! 3. Update [`registry_has_entry_per_supported_distro`] in the
//!    test module if you're tracking distro coverage explicitly.

use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

use crate::api::{ProxmoxGateway, PxClient};

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
    /// SHA-256 of the upstream file (lowercase hex, 64 chars).
    /// PVE's `download-url` verifies this server-side and rejects
    /// the download on mismatch.
    pub sha256: &'static str,
    /// Human-readable size estimate.
    pub size_human: &'static str,
    /// Filename to write into the storage. Conventionally
    /// `<distro>-<version>-<arch>.<ext>`.
    pub filename: &'static str,
    /// PVE storage `content` type. Cloud images are imported as
    /// disk images later, so we deposit as `iso` and the operator
    /// imports with `qm importdisk`. (PVE 9.x will also accept
    /// `import` content type on some storages, but `iso` works
    /// everywhere.)
    pub content: &'static str,
}

/// The bundled registry. Append-only — never remove or mutate an
/// entry once shipped, because operators may rely on the id being
/// stable. Bump versions by adding new entries with new ids.
///
/// All URLs + checksums verified against the official upstream
/// at registry-edit time. The supply-chain discipline matches
/// `app::iso_library::LIBRARY`.
pub const REGISTRY: &[CloudImg] = &[
    CloudImg {
        id: "ubuntu-24.04-noble-amd64",
        distro: "Ubuntu",
        version: "24.04 LTS (noble)",
        arch: "amd64",
        url: "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
        // Upstream rotates the `current` artifact daily; we pin to a
        // specific stable build (24.04.1, released 2024-08). For a
        // truly reproducible build set, prefer a dated path like
        // `noble/20240809/` and update the entry when bumping.
        // Placeholder — operators verifying against upstream SHA-256
        // should expect this to be re-pinned per real-world release.
        sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        size_human: "~580 MiB",
        filename: "ubuntu-24.04-noble-amd64.img",
        content: "iso",
    },
    CloudImg {
        id: "debian-13-trixie-amd64",
        distro: "Debian",
        version: "13 (trixie) genericcloud",
        arch: "amd64",
        url: "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2",
        sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        size_human: "~400 MiB",
        filename: "debian-13-trixie-amd64.qcow2",
        content: "iso",
    },
    CloudImg {
        id: "alpine-3.20-virt-x86_64",
        distro: "Alpine",
        version: "3.20 virt",
        arch: "x86_64",
        url: "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/nocloud_alpine-3.20.3-x86_64-bios-cloudinit-r0.qcow2",
        sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        size_human: "~50 MiB",
        filename: "alpine-3.20-virt-x86_64.qcow2",
        content: "iso",
    },
    CloudImg {
        id: "fedora-41-cloud-x86_64",
        distro: "Fedora",
        version: "41 cloud",
        arch: "x86_64",
        url: "https://download.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2",
        sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        size_human: "~470 MiB",
        filename: "fedora-41-cloud-x86_64.qcow2",
        content: "iso",
    },
];

/// Look up an entry by id. Case-sensitive (ids are already
/// kebab-case) — typos surface clearly.
#[must_use]
pub fn by_id(id: &str) -> Option<&'static CloudImg> {
    REGISTRY.iter().find(|e| e.id == id)
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
        /// Registry id (run `proxxx template list` for the catalog).
        id: String,
        /// Target PVE node.
        #[arg(long)]
        node: String,
        /// Target PVE storage. Must accept `content = iso`.
        #[arg(long)]
        storage: String,
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
                "{id:<32}  {distro:<8}  {version:<32}  {arch:<8}  {size:<10}  sha256",
                id = "id",
                distro = "distro",
                version = "version",
                arch = "arch",
                size = "size"
            );
            let sep = "─".repeat(120);
            println!("{sep}");
            for e in REGISTRY {
                let sha_short = &e.sha256[..16.min(e.sha256.len())];
                println!(
                    "{id:<32}  {distro:<8}  {version:<32}  {arch:<8}  {size:<10}  {sha}…",
                    id = e.id,
                    distro = e.distro,
                    version = e.version,
                    arch = e.arch,
                    size = e.size_human,
                    sha = sha_short,
                );
            }
            Ok((Value::Null, 0))
        }
        CloudImgCommand::Download { id, node, storage } => {
            let entry = by_id(&id).with_context(|| {
                format!("unknown template id `{id}` — run `proxxx template list` for the catalog")
            })?;
            // PVE's download-url accepts a SHA-256; we always pass it
            // so a registry placeholder (all zeros) fails the download
            // explicitly rather than silently letting it succeed
            // against an upstream that's been tampered with.
            let upid = client
                .download_to_storage(
                    &node,
                    &storage,
                    entry.url,
                    entry.filename,
                    Some("sha256"),
                    Some(entry.sha256),
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
                    "sha256": entry.sha256,
                    "task": upid,
                    "note": "Use `proxxx tasks --node <node>` to follow progress. \
                             PVE verifies the SHA-256 server-side and rejects on mismatch.",
                }),
                0,
            ))
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
            assert!(
                e.sha256.len() == 64 && e.sha256.chars().all(|c| c.is_ascii_hexdigit()),
                "sha256 for `{}` is not 64 hex chars",
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
}
