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
                src.contains("rename_durable(") || src.contains("write_private_atomic("),
                "{name} should reach its final filename through rename_durable \
                 (directly or via write_private_atomic)"
            );
        }
    }
}

/// A tag for a temp file name, `<pid>.<n>`, where `n` comes from a
/// process-wide counter. The pid alone (or pid plus a clock reading) is not
/// unique: two threads of one process writing the same target picked the
/// same temp name, and one removed or failed on the other's file.
#[must_use]
pub fn unique_temp_tag() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!(
        "{}.{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

/// Write `bytes` to `path` without ever exposing them with wider permissions
/// or half written (`#376`).
///
/// - The parent directory is created with mode 0700 if it is missing (an
///   existing directory is left as it is).
/// - The bytes go to a temp file in the same directory, created with mode
///   0600 from the first byte (`create_new`, so no other file is reused):
///   there is no window in which the content sits in a 0644 file waiting for
///   a `chmod`.
/// - The temp file is fsync-ed, then renamed over `path` with
///   [`rename_durable`], which also fsyncs the directory.
///
/// # Errors
/// When the directory, the temp file, the write, the fsync or the rename
/// fails. The temp file is removed on failure.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .with_context(|| format!("create directory {}", dir.display()))?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create directory {}", dir.display()))?;
    }
    let name = path
        .file_name()
        .map_or_else(|| "proxxx".into(), |n| n.to_string_lossy().into_owned());
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", unique_temp_tag()));
    let _ = std::fs::remove_file(&tmp);
    let written = (|| -> Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("create temp file {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("write temp file {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync temp file {}", tmp.display()))?;
        rename_durable(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

#[cfg(test)]
mod private_write_tests {
    use super::write_private_atomic;

    /// Threads of one process writing the same file must not share a temp
    /// file: every write succeeds, the result is one complete payload, and no
    /// temp file is left behind.
    #[test]
    fn concurrent_writers_in_one_process_each_use_their_own_temp_file() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("secret");
        let payloads: Vec<Vec<u8>> = (0..16u8).map(|i| vec![b'a' + i; 4096]).collect();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(payloads.len()));
        let handles: Vec<_> = payloads
            .iter()
            .cloned()
            .map(|p| {
                let path = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    write_private_atomic(&path, &p)
                })
            })
            .collect();
        for h in handles {
            h.join()
                .expect("join")
                .expect("every concurrent write succeeds");
        }
        let got = std::fs::read(&path).expect("read");
        assert!(
            payloads.contains(&got),
            "the file must hold one complete payload"
        );
        let names: Vec<_> = std::fs::read_dir(root.path())
            .expect("ls")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["secret".to_string()], "no temp file may remain");
    }

    #[test]
    fn creates_a_0600_file_in_a_new_0700_directory_and_replaces_atomically() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("nested").join("secret");
        write_private_atomic(&path, b"first").expect("write");
        write_private_atomic(&path, b"second").expect("overwrite");
        assert_eq!(std::fs::read(&path).expect("read"), b"second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let file_mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
            let dir_mode = std::fs::metadata(path.parent().expect("dir"))
                .expect("stat dir")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600);
            assert_eq!(dir_mode, 0o700);
        }
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().expect("dir"))
            .expect("ls")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "secret")
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp file may remain: {leftovers:?}"
        );
    }

    /// `#376` regression guard: no production code writes a file and then
    /// tightens it to 0600 afterwards; private files go through
    /// `write_private_atomic` (or open with `mode(0o600)` from the start).
    #[test]
    fn no_production_code_chmods_a_file_to_0600_after_writing_it() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir)
                .expect("read src")
                .filter_map(Result::ok)
            {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&root, &mut files);
        // Sites that set 0600 at open(2) time or only tighten files they did
        // not just write (SQLite databases and their sidecars, legacy files):
        // not the write-then-chmod pattern.
        const ALLOWED: &[(&str, &str)] = &[
            (
                "src/handoff/spice.rs",
                "tempfile::Builder::permissions sets the mode in open(2)",
            ),
            (
                "src/hitl/pending.rs",
                "file created with mode(0o600); chmod only tightens a legacy file",
            ),
            (
                "src/app/cache.rs",
                "tightens the SQLite db and -wal/-shm sidecars SQLite created",
            ),
        ];
        let mut hits = Vec::new();
        for f in files {
            let rel = f
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or(&f)
                .to_string_lossy()
                .trim_start_matches('/')
                .to_string();
            if ALLOWED.iter().any(|(p, _)| *p == rel) {
                continue;
            }
            let src = std::fs::read_to_string(&f).expect("read");
            let prod = src.split("#[cfg(test)]").next().unwrap_or(&src);
            for (i, line) in prod.lines().enumerate() {
                let l = line.trim_start();
                if l.starts_with("//") {
                    continue;
                }
                if l.contains("from_mode(0o600)") || l.contains("set_mode(0o600)") {
                    hits.push(format!("{}:{}", f.display(), i + 1));
                }
            }
        }
        assert!(
            hits.is_empty(),
            "write-then-chmod found; use util::durable::write_private_atomic: {hits:?}"
        );
    }
}
