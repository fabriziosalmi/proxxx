//! Curated cloud-image / ISO library (feature #2).
//!
//! MVP: a `const` array of well-known cloud images. No external YAML
//! manifest, no auto-update, no community PRs. Updates require a code
//! change + release. This is deliberate — keeps the supply-chain
//! attack surface minimal. Each entry is something you'd already trust
//! the distro publisher for, with the SHA-256 baked in here as a
//! second pin against URL-redirect mischief.
//!
//! Honest limits (vs. the original spec):
//! - GPG signature verification is NOT performed. Proxmox's
//!   `download-url` endpoint can verify a SHA-256 we hand it, which is
//!   sufficient against URL tampering once the entry is in this file.
//!   GPG would add per-distro keyring management for marginal benefit.
//! - Resume on interruption is NOT a client concern: the server-side
//!   `download-url` either completes or fails atomically. We don't
//!   stream through proxxx.
//! - LXC templates (`pveam`) use a separate Proxmox endpoint and are
//!   NOT covered by this library yet — declared backlog.

use serde::Serialize;

/// Checksum algorithm + digest for an ISO library entry.
///
/// Different upstream distros publish manifests in different
/// algorithms — Ubuntu/Fedora/Alpine/Rocky ship SHA-256, Debian
/// only publishes SHA-512. Proxmox's `download-url` endpoint accepts
/// both via its `checksum-algorithm` parameter, so we encode the
/// algorithm right in the type rather than coercing everything to
/// SHA-256 (which would force us to drop Debian or hand-recompute
/// hashes locally — both bad supply-chain hygiene).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "algo", content = "digest", rename_all = "lowercase")]
pub enum Checksum {
    /// 64-character lowercase hex.
    Sha256(&'static str),
    /// 128-character lowercase hex.
    Sha512(&'static str),
}

impl Checksum {
    /// `("sha256", "<hex>")` or `("sha512", "<hex>")` — the two
    /// strings the Proxmox `download-url` POST expects as
    /// `checksum-algorithm` and `checksum`.
    #[must_use]
    pub const fn proxmox_pair(&self) -> (&'static str, &'static str) {
        match self {
            Self::Sha256(h) => ("sha256", h),
            Self::Sha512(h) => ("sha512", h),
        }
    }

    /// Required digest length for a given algorithm. Used by the
    /// invariant test that no entry ships with a malformed pin.
    #[must_use]
    pub const fn expected_len(&self) -> usize {
        match self {
            Self::Sha256(_) => 64,
            Self::Sha512(_) => 128,
        }
    }
}

/// One entry in the curated library.
///
/// `checksum` is `Option<Checksum>` rather than a string with a
/// placeholder. **The library refuses to dispatch a download when
/// this is `None`** — see `IsoEntry::is_pinned()` and the gate in
/// the reducer / CLI. This is ISO supply-chain hardening from the v1.0.0
/// architectural review: shipping with placeholder checksums would
/// silently pass Proxmox's verification (because Proxmox would
/// receive an obviously-bogus expected checksum) AND erode the
/// security claim of the project. Better to refuse loudly until the
/// real pin is in.
///
/// All entries below are now pinned against version-dated upstream
/// manifests — the URLs include build dates so a future re-publish
/// upstream cannot invalidate our pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct IsoEntry {
    /// Stable identifier for CLI use, e.g. `"ubuntu-24.04-cloud"`.
    pub id: &'static str,
    /// Human-readable distro name shown in the TUI.
    pub distro: &'static str,
    /// Distro version (e.g. `"24.04"`, `"12"`, `"41"`).
    pub version: &'static str,
    /// CPU architecture (`"amd64"`, `"arm64"`).
    pub arch: &'static str,
    /// Source URL — direct link, must support HTTP HEAD + GET. Use
    /// version-stable URLs (with explicit dates / build numbers) so
    /// the pinned checksum stays valid even if upstream re-publishes
    /// to `current/` / `latest/`.
    pub url: &'static str,
    /// Pinned checksum from the upstream manifest. **`None` means
    /// pinning has not yet been performed and the curated download
    /// path refuses this entry**; the user can still pass a custom
    /// URL+checksum via `proxxx iso download --url ... --sha256 ...`.
    pub checksum: Option<Checksum>,
    /// Default Proxmox content category. Cloud images typically use
    /// `import` (PVE 8+ image-import workflow); ISOs use `iso`.
    pub content: &'static str,
    /// Approximate size in MiB for UI display (rough — not enforced).
    pub size_mib: u32,
    /// One-line note shown in the detail panel.
    pub notes: &'static str,
}

impl IsoEntry {
    /// True if the checksum has been pinned against an upstream manifest.
    /// Downloads are gated on this returning true.
    #[must_use]
    pub const fn is_pinned(&self) -> bool {
        self.checksum.is_some()
    }
}

/// The curated library. Append-only between releases — never delete
/// an entry, mark it deprecated in `notes` instead, so older proxxx
/// binaries can still resolve URLs they shipped with.
///
/// Every entry is pinned to a dated build and to the checksum from that
/// build's official manifest (SHA256SUMS, SHA512SUMS, CHECKSUM or the
/// `.sha256` sidecar), never to a `current`/`latest` link. Mirrors
/// delete old builds (4 of these 6 URLs answered 404 on 2026-10-22,
/// #492), so `scripts/repin-cloudimg.py` re-pins this list and
/// `cloudimg.rs` weekly from the manifests, and fails the workflow when
/// a pinned URL stops answering. An end-of-life release is pinned to its
/// distro's permanent archive. Edit the `url`, `version` and `checksum`
/// lines only through that script, so a pin always comes from a manifest.
pub const LIBRARY: &[IsoEntry] = &[
    IsoEntry {
        id: "ubuntu-22.04-cloud",
        distro: "Ubuntu",
        version: "22.04 LTS (Jammy) build 20261020",
        arch: "amd64",
        url: "https://cloud-images.ubuntu.com/releases/jammy/release-20261020/ubuntu-22.04-server-cloudimg-amd64.img",
        checksum: Some(Checksum::Sha256(
            "2099e63da0b822ef8e05e3d596c1b402eaaae658fc08ab919cb8495bfcdc488b",
        )),
        content: "import",
        size_mib: 700,
        notes: "Cloud-init enabled. Use with cloudinit drive for SSH keys + network.",
    },
    IsoEntry {
        id: "ubuntu-24.04-cloud",
        distro: "Ubuntu",
        version: "24.04 LTS (Noble) build 20261017",
        arch: "amd64",
        url: "https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img",
        checksum: Some(Checksum::Sha256(
            "04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94",
        )),
        content: "import",
        size_mib: 750,
        notes: "Cloud-init enabled. Recommended default for new VMs.",
    },
    IsoEntry {
        id: "debian-12-cloud",
        distro: "Debian",
        version: "12 (Bookworm) build 20261021-2638",
        arch: "amd64",
        url: "https://cloud.debian.org/images/cloud/bookworm/20261021-2638/debian-12-genericcloud-amd64-20261021-2638.qcow2",
        // Debian publishes ONLY SHA-512, never SHA-256.
        checksum: Some(Checksum::Sha512(
            "9f181877006e8d9ca4f4554eba8729a829936f0f7d1db5e77f69b1ef0f6bc372b4d46f3dae39b10d84f9131496c2cc1d449264f26577fe934a79de5a5512a3dd",
        )),
        content: "import",
        size_mib: 350,
        notes: "Generic cloud variant. Smallest of the cloud images here. Pinned via SHA-512.",
    },
    IsoEntry {
        id: "fedora-41-cloud",
        distro: "Fedora",
        version: "41 (Generic Base 1.4)",
        arch: "amd64",
        url: "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2",
        checksum: Some(Checksum::Sha256(
            "6205ae0c524b4d1816dbd3573ce29b5c44ed26c9fbc874fbe48c41c89dd0bac2",
        )),
        content: "import",
        size_mib: 470,
        notes: "Fedora Cloud Base 41 (end of life), from the permanent Fedora archive.",
    },
    IsoEntry {
        id: "alpine-3.21-iso",
        distro: "Alpine",
        version: "3.21.9",
        arch: "amd64",
        url: "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-virt-3.21.9-x86_64.iso",
        checksum: Some(Checksum::Sha256(
            "1ceafa2ca068faf2925de977815681c182708f3c6cbfbad137f3ffc9324a03b4",
        )),
        content: "iso",
        size_mib: 60,
        notes: "Minimal virt-optimised Alpine ISO. No cloud-init — manual setup.",
    },
    IsoEntry {
        id: "rocky-9-cloud",
        distro: "Rocky Linux",
        version: "9.8 build 20260525.0",
        arch: "amd64",
        url: "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2",
        checksum: Some(Checksum::Sha256(
            "92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8",
        )),
        content: "import",
        size_mib: 900,
        notes: "Generic cloud-init enabled. RHEL-compatible.",
    },
];

/// Look up an entry by its stable id.
#[must_use]
pub fn by_id(id: &str) -> Option<&'static IsoEntry> {
    LIBRARY.iter().find(|e| e.id == id)
}

/// All distros covered, alphabetised, deduplicated.
#[must_use]
pub fn distros() -> Vec<&'static str> {
    let mut out: Vec<&str> = LIBRARY.iter().map(|e| e.distro).collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_is_non_empty() {
        assert!(
            !LIBRARY.is_empty(),
            "MVP curated library must have at least one entry"
        );
    }

    #[test]
    fn ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for e in LIBRARY {
            assert!(seen.insert(e.id), "duplicate id {}", e.id);
        }
    }

    #[test]
    fn urls_are_https() {
        for e in LIBRARY {
            assert!(
                e.url.starts_with("https://"),
                "{} uses non-https url: {}",
                e.id,
                e.url
            );
        }
    }

    #[test]
    fn checksum_when_pinned_is_well_formed_lowercase_hex_and_not_placeholder() {
        // Invariant: if a checksum is pinned (Some), it MUST
        // be real lowercase hex of the algorithm's expected length —
        // never an all-zero placeholder, never uppercase, never wrong
        // length. Unpinned (None) is allowed until release-time but
        // the download path refuses it.
        for e in LIBRARY {
            if let Some(c) = e.checksum {
                let (_algo, hex) = c.proxmox_pair();
                assert_eq!(
                    hex.len(),
                    c.expected_len(),
                    "{} checksum length wrong",
                    e.id
                );
                assert!(
                    hex.chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                    "{} checksum must be lowercase hex",
                    e.id
                );
                assert_ne!(
                    hex,
                    "0".repeat(c.expected_len()),
                    "{} ships with the all-zero placeholder — REFUSE",
                    e.id
                );
            }
        }
    }

    #[test]
    fn all_entries_are_pinned() {
        // Post-BLOCKER-1: every shipped entry must have a real
        // upstream pin. A future contributor adding an entry with
        // `checksum: None` fails this test loudly.
        for e in LIBRARY {
            assert!(
                e.is_pinned(),
                "{} ships without a pinned checksum — refuse to release",
                e.id
            );
        }
    }

    #[test]
    fn urls_point_at_dated_builds_not_rotating_links() {
        // A `current`/`latest` link changes content under a fixed URL, so
        // a pinned checksum stops matching (same rule as cloudimg.rs).
        for e in LIBRARY {
            assert!(
                !e.url.contains("/current/")
                    && !e.url.contains("/latest/")
                    && !e.url.contains(".latest."),
                "{} uses a rotating link: {}",
                e.id,
                e.url
            );
        }
    }

    #[test]
    fn content_is_known_value() {
        for e in LIBRARY {
            assert!(
                matches!(e.content, "iso" | "import" | "vztmpl"),
                "{} content {} not in known set",
                e.id,
                e.content
            );
        }
    }

    #[test]
    fn by_id_finds_entries() {
        assert!(by_id("ubuntu-24.04-cloud").is_some());
        assert!(by_id("nope-not-real").is_none());
    }
}
