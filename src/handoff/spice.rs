//! SPICE handoff — write a `.vv` file and launch virt-viewer (#1c).
//!
//! `.vv` is virt-viewer's `ConfigFile` format (INI-like). Proxmox's
//! `/spiceproxy` response keys map almost 1:1 to the `[virt-viewer]`
//! section, which is why we keep the response as a flat `HashMap` rather
//! than enumerating fields — forward-compat with Proxmox additions.
//!
//! Vector 2 audit (TOCTOU): the `.vv` file contains the SPICE password
//! in plaintext. We use `tempfile::Builder` which:
//!   1. Picks a path with a 16-byte crypto-random suffix (unguessable).
//!   2. Opens with `O_EXCL | O_CREAT` (refuses to follow a pre-placed
//!      symlink — the kernel rejects the call if the target exists).
//!   3. Sets mode 0o600 ATOMICALLY at creation time, before any data
//!      is written, so there is no window where the file exists with
//!      world-readable permissions.
//! These three together close the TOCTOU race: an attacker cannot
//! predict the path AND cannot win the symlink race even if they could.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::api::types::SpiceConfig;

/// Write the `.vv` body to a caller-supplied path with `O_EXCL` + 0o600
/// semantics. Used when the user passes `proxxx spice --write-vv
/// <path>` and we don't get to pick the filename.
///
/// `O_EXCL` here is the critical guarantee — if the path already
/// exists OR is a symlink, the call fails with `EEXIST`. The caller
/// must pick an unused path; we will not silently overwrite or
/// follow a pre-placed symlink.
pub fn write_vv_at(path: &Path, cfg: &SpiceConfig) -> Result<()> {
    let body = cfg.to_vv_file();
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true); // O_EXCL | O_CREAT
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating {} (O_EXCL)", path.display()))?;
    f.write_all(body.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Atomically write a `.vv` file in the system temp directory and
/// return its absolute path.
///
/// `delete-this-file=1` in the SPICE response (which proxmox always
/// sets) tells virt-viewer to unlink the file after reading, so cleanup
/// is delegated to the consumer. If virt-viewer fails to launch, the
/// file is left in `$TMPDIR` and gets reaped by the OS's tmp cleanup
/// (systemd-tmpfiles / launchd's /private/tmp policy).
pub fn write_vv_file(vmid: u32, cfg: &SpiceConfig) -> Result<PathBuf> {
    let body = cfg.to_vv_file();
    let prefix = format!("proxxx-spice-{vmid}-");
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix.as_str()).suffix(".vv").rand_bytes(16); // 128 bits of entropy in the filename

    // Permissions are set in the OS-level open(2) call on Unix, so the
    // file is 0600 from the very first byte — no chmod-after-create
    // window. On non-Unix platforms `permissions` is a no-op.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o600));
    }

    let temp = builder
        .tempfile()
        .with_context(|| "creating SPICE temp file")?;
    {
        use std::io::Write;
        let mut handle = temp.as_file();
        handle
            .write_all(body.as_bytes())
            .with_context(|| "writing SPICE config")?;
    }
    // `keep` consumes the NamedTempFile and returns the persistent
    // path so virt-viewer can find it after our handle drops.
    let (_file, path) = temp.keep().with_context(|| "persisting SPICE temp file")?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_cfg() -> SpiceConfig {
        let mut k = HashMap::new();
        k.insert("type".into(), "spice".into());
        k.insert("host".into(), "192.168.1.10".into());
        k.insert("port".into(), "5900".into());
        k.insert("tls-port".into(), "5901".into());
        k.insert("password".into(), "PVESPICE:secret".into());
        k.insert("delete-this-file".into(), "1".into());
        k.insert("title".into(), "VM 100".into());
        SpiceConfig { keys: k }
    }

    #[test]
    fn vv_file_starts_with_section_header() {
        let body = sample_cfg().to_vv_file();
        assert!(body.starts_with("[virt-viewer]\n"));
    }

    #[test]
    fn vv_file_contains_all_keys_sorted() {
        let body = sample_cfg().to_vv_file();
        // Sorted alphabetically: delete-this-file < host < password <
        // port < title < tls-port < type.
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines[0], "[virt-viewer]");
        assert!(lines[1].starts_with("delete-this-file="));
        assert!(lines.contains(&"host=192.168.1.10"));
        assert!(lines.contains(&"password=PVESPICE:secret"));
        assert!(lines.contains(&"type=spice"));
    }

    #[test]
    fn newlines_in_values_are_escaped() {
        // `ca` PEM contains real newlines — these MUST be encoded as
        // `\n` literal so the .vv INI parser doesn't see them as
        // record separators.
        let mut k = HashMap::new();
        k.insert("ca".into(), "-----BEGIN-----\nABCD\n-----END-----".into());
        let cfg = SpiceConfig { keys: k };
        let body = cfg.to_vv_file();
        assert!(
            body.contains("ca=-----BEGIN-----\\nABCD\\n-----END-----"),
            "raw newlines must be escaped: {body}"
        );
        // Sanity: the rendered body itself only has line breaks at
        // record boundaries (after [virt-viewer] and after ca=...).
        let actual_lines = body.matches('\n').count();
        assert_eq!(actual_lines, 2, "exactly 2 record-separating newlines");
    }

    #[test]
    fn host_helper_returns_value() {
        assert_eq!(sample_cfg().host(), Some("192.168.1.10"));
    }

    #[test]
    fn write_vv_file_creates_file_with_content() {
        let path = write_vv_file(999, &sample_cfg()).expect("write");
        let s = path.to_string_lossy();
        assert!(s.contains("999"), "filename embeds vmid: {s}");
        assert!(s.ends_with(".vv"));
        let content = std::fs::read_to_string(&path).expect("read");
        assert!(content.starts_with("[virt-viewer]"));
        assert!(content.contains("password=PVESPICE:secret"));
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn write_vv_file_sets_0600_perms_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let path = write_vv_file(888, &sample_cfg()).expect("write");
        let meta = std::fs::metadata(&path).expect("meta");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "password lives in plaintext — must be 0600");
        let _ = std::fs::remove_file(&path);
    }

    /// Vector 2 regression: each call must produce a UNIQUE path. With
    /// the predictable nano-timestamp scheme an attacker who could see
    /// the launch time within ~1 µs could pre-place a symlink. The
    /// 16-byte random suffix from tempfile makes the path unguessable
    /// (2^128 search space) and `O_EXCL` makes any pre-placed file or
    /// symlink an error rather than a target.
    #[test]
    fn write_vv_file_uses_unique_path_per_call() {
        let p1 = write_vv_file(7, &sample_cfg()).expect("write 1");
        let p2 = write_vv_file(7, &sample_cfg()).expect("write 2");
        assert_ne!(p1, p2, "tempfile must produce unique paths");
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }

    /// Vector 2 regression: confirm the temp file lives in the system
    /// temp directory, not in some predictable path the attacker can
    /// walk to.
    #[test]
    fn write_vv_file_lives_under_temp_dir() {
        let path = write_vv_file(11, &sample_cfg()).expect("write");
        let temp = std::env::temp_dir();
        // Some platforms canonicalise temp_dir() to a different path
        // than what tempfile uses (macOS /var vs /private/var). Compare
        // suffixes rather than full prefixes.
        assert!(
            path.starts_with(&temp)
                || path.canonicalize().ok().is_some_and(|p| {
                    p.starts_with(temp.canonicalize().unwrap_or(temp.clone()))
                }),
            "expected temp-dir path, got {}",
            path.display()
        );
        let _ = std::fs::remove_file(&path);
    }
}
