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
}
