//! Durable rename: make a renamed file survive a power loss.
//!
//! Audit 2026-09-09 (#268). Every atomic write in proxxx follows the
//! same discipline — write a sibling temp file, `sync_all()` it, chmod
//! it, then `rename` over the target — and that is correct for the
//! property it was reaching for: a reader sees either the old file or
//! the complete new one, never a half-written one.
//!
//! What it did not do is make the *rename* durable. `rename(2)` updates
//! the parent directory, and POSIX does not guarantee that update has
//! reached stable storage until the directory itself is fsynced. Between
//! the rename returning and that flush, the process has already told the
//! operator the write succeeded — `proxxx incident freeze` prints that
//! the fleet is frozen, `proxxx init` reports the config written. After a
//! power loss the directory may still show the pre-rename state: the
//! freeze lock absent and the kill-switch off, or a newly generated HITL
//! HMAC key gone, which makes every audit row signed with it
//! unverifiable.
//!
//! On ext4 with `data=ordered` a rename-over-existing gets an implicit
//! data flush, so the practical exposure is narrower than the POSIX
//! guarantee implies — but the directory entry itself is still not
//! covered, and proxxx also runs on APFS, XFS and ZFS.
//!
//! There were four hand-rolled copies of the same pattern; this is the
//! shared helper they now call.

use anyhow::{Context, Result};
use std::path::Path;

/// `rename` `from` over `to`, then fsync the parent directory so the
/// rename itself survives a crash.
///
/// # Errors
/// When the rename fails, or when the parent directory cannot be opened
/// or synced. A failure to sync is reported rather than swallowed: the
/// caller asked for a durable write and did not get one.
pub fn rename_durable(from: &Path, to: &Path) -> Result<()> {
    std::fs::rename(from, to)
        .with_context(|| format!("rename {} → {}", from.display(), to.display()))?;
    sync_parent_dir(to)
}

/// fsync the directory containing `path`.
///
/// Opening a directory read-only and syncing it is the portable way to
/// flush its entries. On platforms where a directory cannot be opened
/// this way the call is a no-op rather than an error — the rename has
/// already happened, and failing the operation over an unsupported
/// durability primitive would be worse than the exposure it closes.
///
/// # Errors
/// When the directory exists and can be opened but the sync fails.
pub fn sync_parent_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    // An empty parent means a bare filename in the cwd.
    let dir = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    match std::fs::File::open(dir) {
        Ok(handle) => handle
            .sync_all()
            .with_context(|| format!("fsync directory {}", dir.display())),
        // Windows cannot open a directory as a file. Nothing to do.
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{rename_durable, sync_parent_dir};

    #[test]
    fn rename_durable_moves_the_file_and_syncs() {
        let dir = tempfile::tempdir().expect("tmp");
        let tmp = dir.path().join("x.tmp");
        let target = dir.path().join("x");
        std::fs::write(&tmp, b"payload").expect("write");

        rename_durable(&tmp, &target).expect("durable rename");

        assert!(!tmp.exists(), "the temp file must be gone");
        assert_eq!(
            std::fs::read(&target).expect("read back"),
            b"payload",
            "the target must hold the new content"
        );
    }

    #[test]
    fn rename_durable_overwrites_an_existing_target() {
        let dir = tempfile::tempdir().expect("tmp");
        let tmp = dir.path().join("x.tmp");
        let target = dir.path().join("x");
        std::fs::write(&target, b"old").expect("seed");
        std::fs::write(&tmp, b"new").expect("write");

        rename_durable(&tmp, &target).expect("durable rename");
        assert_eq!(std::fs::read(&target).expect("read"), b"new");
    }

    #[test]
    fn syncing_a_bare_filename_does_not_error() {
        sync_parent_dir(std::path::Path::new("no-directory-component"))
            .expect("a bare filename resolves to the cwd, which is syncable");
    }
}

#[cfg(test)]
mod call_site_tests {
    /// #268 — every atomic write must go through the durable helper.
    ///
    /// There were six hand-rolled `fs::rename` sites, each fsyncing the
    /// temp file and none the directory. A seventh added later would
    /// inherit the same gap silently, so this asserts the helper is the
    /// only way a write reaches its final name.
    #[test]
    fn no_atomic_write_site_uses_a_bare_rename() {
        const SITES: &[(&str, &str)] = &[
            ("cli/init.rs", include_str!("../cli/init.rs")),
            ("cli/init_wizard.rs", include_str!("../cli/init_wizard.rs")),
            ("cli/schedule.rs", include_str!("../cli/schedule.rs")),
            ("config/mod.rs", include_str!("../config/mod.rs")),
            ("hitl/hmac_key.rs", include_str!("../hitl/hmac_key.rs")),
            ("incident/mod.rs", include_str!("../incident/mod.rs")),
        ];
        for (name, src) in SITES {
            assert!(
                !src.contains("std::fs::rename("),
                "{name} uses a bare std::fs::rename — use util::durable::rename_durable \
                 so the rename itself survives a power loss (#268)"
            );
            assert!(
                src.contains("rename_durable("),
                "{name} should reach its final filename through rename_durable"
            );
        }
    }
}
