//! PBS restore via `proxmox-backup-client` shell-out.
//!
//! MVP scope (per the draconian review's honest cuts):
//! - Full archive restore only. Single-file extraction needs FUSE mount,
//!   which is platform-fragile (macFUSE blocked on Apple Silicon, Windows
//!   needs `WinFsp`). We'd rather refuse than ship a broken half-feature.
//! - Restore target is a local path. The user pulls the archive to disk,
//!   then uses normal tools to extract individual files.
//! - No re-injection into a live guest via qemu-guest-agent — the
//!   `guest-file-write` API only handles small files and can't recreate
//!   directory trees or permissions safely.
//!
//! Auth is via two env vars passed to the child:
//!   `PBS_REPOSITORY` — `user@realm!tokenid@host:store`
//!   `PBS_PASSWORD`   — the token secret
//! These are documented in `proxmox-backup-client` man page.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{info, warn};

use crate::config::PbsConfig;

#[derive(Debug, Clone)]
pub struct RestoreRequest {
    /// Snapshot reference: e.g. `"vm/100/2024-01-15T10:00:00Z"`.
    pub snapshot: String,
    /// Archive file to extract: e.g. `"root.pxar.didx"`.
    pub archive: String,
    /// Local directory or file to restore into.
    pub target: PathBuf,
    /// Datastore to read from.
    pub store: String,
}

/// Outcome of a restore attempt.
#[derive(Debug, Clone)]
pub struct RestoreResult {
    pub exit_code: Option<i32>,
    pub last_lines: Vec<String>,
}

/// Detect whether `proxmox-backup-client` is available on PATH.
/// Returns the resolved absolute path so the caller can show a clear
/// "configure your $PATH" hint when missing.
#[must_use]
pub fn detect_client_binary() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("proxmox-backup-client");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Build the `PBS_REPOSITORY` env var value. Expected format:
///   `user@realm!tokenid@host:store`
/// where `host` is the URL host (without scheme/port), and `store` is
/// the datastore name.
#[must_use]
pub fn build_repository(cfg: &PbsConfig, store: &str) -> Option<String> {
    let host = pbs_host(&cfg.url)?;
    Some(format!(
        "{user}!{token}@{host}:{store}",
        user = cfg.user,
        token = cfg.token_id,
    ))
}

fn pbs_host(url: &str) -> Option<String> {
    // Strip scheme.
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    // Strip path.
    let host_port = after_scheme
        .split_once('/')
        .map_or(after_scheme, |(h, _)| h);
    if host_port.is_empty() {
        return None;
    }
    Some(host_port.to_string())
}

/// Run `proxmox-backup-client restore` and stream its output line-by-line.
///
/// The `on_line` callback fires for each stdout/stderr line so the TUI
/// (or CLI) can surface progress. We retain only the last 50 lines for
/// the final result — enough to capture the relevant error tail without
/// memory bloat on a successful 100GB restore.
pub async fn run_restore<F>(
    cfg: &PbsConfig,
    cli_secret: Option<&str>,
    req: RestoreRequest,
    mut on_line: F,
) -> Result<RestoreResult>
where
    F: FnMut(&str) + Send,
{
    let bin = detect_client_binary().ok_or_else(|| {
        anyhow::anyhow!(
            "proxmox-backup-client not found in PATH. Install the PBS client \
             (e.g. apt install proxmox-backup-client) and retry. \
             Note: macOS / Windows clients aren't packaged upstream — use a Linux host."
        )
    })?;

    let repository = build_repository(cfg, &req.store)
        .ok_or_else(|| anyhow::anyhow!("cannot extract host from PBS url '{}'", cfg.url))?;
    let secret = cfg.resolve_token_secret(cli_secret).await?;

    info!(
        "pbs restore: {} → {} (target {})",
        req.snapshot,
        req.archive,
        req.target.display()
    );

    // — `cmd.env(...)` clones into the Command's internal
    // env map. The secret leaves our zeroizing envelope at that
    // boundary (also enters the child process's env via execve).
    // Our `secret` Zeroizing<String> still zeros its own heap copy
    // when this scope ends.
    let secret_ref: &str = &secret;
    let mut cmd = Command::new(&bin);
    cmd.arg("restore")
        .arg(&req.snapshot)
        .arg(&req.archive)
        .arg(req.target.as_os_str())
        .env("PBS_REPOSITORY", repository)
        .env("PBS_PASSWORD", secret_ref)
        // proxmox-backup-client needs PBS_FINGERPRINT only when verify_tls
        // is off and the cert is self-signed. We surface this as a future
        // enhancement; for now if the cert isn't trusted the user gets
        // a clear error from the client itself.
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // PBS restore subprocess: if the parent dies abnormally (panic, OOM, etc.),
        // tokio sends SIGKILL to the child via this flag. Without it,
        // a 40-min restore continues running orphaned and the user has
        // no way to discover or stop it. Defence in depth on top of the
        // explicit Ctrl+C handler below.
        .kill_on_drop(true);

    if !cfg.verify_tls {
        // The client honours this env var to skip TLS verification.
        // We reuse the same opt-in the user already set in PbsConfig.
        cmd.env("PBS_FINGERPRINT", "");
    }

    let mut child = cmd.spawn().context("spawning proxmox-backup-client")?;

    // SAFETY note: we configured `.stdout(Stdio::piped())` /
    // `.stderr(Stdio::piped())` above, so `take()` returns Some on the
    // first call. The .ok_or_else dance keeps the unwrap_used lint
    // clean and produces a useful error if the invariant ever breaks.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("child stdout pipe missing — internal bug"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("child stderr pipe missing — internal bug"))?;

    let mut last_lines: Vec<String> = Vec::with_capacity(50);

    let mut so = BufReader::new(stdout).lines();
    let mut se = BufReader::new(stderr).lines();
    let mut cancelled = false;

    loop {
        // PBS restore subprocess: graceful Ctrl+C handling. `tokio::signal::ctrl_c()`
        // resolves on SIGINT; we kill the child and return early. Without
        // this, the user pressing Ctrl+C exits proxxx but leaves the
        // child process running orphaned — a 40-minute zombie restore
        // is exactly the failure mode the architectural review called out.
        tokio::select! {
            biased; // prefer signals over output reads
            sig = tokio::signal::ctrl_c() => {
                if sig.is_ok() {
                    on_line("(received Ctrl+C — killing proxmox-backup-client)");
                    push_capped(
                        &mut last_lines,
                        "(received Ctrl+C — killing proxmox-backup-client)".into(),
                        50,
                    );
                    let _ = child.kill().await;
                    cancelled = true;
                }
                break;
            }
            line = so.next_line() => {
                match line {
                    Ok(Some(l)) => {
                        on_line(&l);
                        push_capped(&mut last_lines, l, 50);
                    }
                    Ok(None) => break,
                    Err(e) => {
                        // SPOF 4.2 (Category 4 audit): on read error
                        // (e.g. invalid UTF-8 in a backup file path) we
                        // MUST keep draining or the child blocks writing
                        // to a full 64KB pipe — and `child.wait().await`
                        // below would then deadlock forever. tokio's
                        // `Lines` advances past the offending bytes, so
                        // continuing eventually reaches Ok(None)/EOF.
                        warn!("restore stdout read error: {e:#} — continuing to drain");
                    }
                }
            }
            line = se.next_line() => {
                match line {
                    Ok(Some(l)) => {
                        on_line(&l);
                        push_capped(&mut last_lines, l, 50);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        // Same drain-or-deadlock invariant as stdout.
                        warn!("restore stderr read error: {e:#} — continuing to drain");
                    }
                }
            }
        }
    }

    let status = child.wait().await.context("waiting on restore process")?;
    if cancelled {
        // Surface the cancellation explicitly — exit code from a killed
        // child is platform-dependent and easy to misread as a normal
        // failure. Caller can match on error message.
        anyhow::bail!(
            "restore cancelled by Ctrl+C (last exit: {:?})",
            status.code()
        );
    }
    Ok(RestoreResult {
        exit_code: status.code(),
        last_lines,
    })
}

fn push_capped(buf: &mut Vec<String>, line: String, cap: usize) {
    buf.push(line);
    let len = buf.len();
    if len > cap {
        buf.drain(..len - cap);
    }
}

/// Validate the restore target: must exist and be a directory, OR its
/// parent must exist (so a single-file restore can create the file).
pub fn validate_target(p: &Path) -> Result<()> {
    if p.exists() {
        if !p.is_dir() {
            anyhow::bail!(
                "restore target {} exists but is not a directory",
                p.display()
            );
        }
        return Ok(());
    }
    if let Some(parent) = p.parent() {
        if parent.as_os_str().is_empty() || parent.exists() {
            return Ok(());
        }
    }
    anyhow::bail!("restore target parent does not exist: {}", p.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PbsConfig {
        PbsConfig {
            url: "https://pbs.lan:8007".into(),
            user: "proxxx@pbs".into(),
            token_id: "reader".into(),
            token_secret: Some(zeroize::Zeroizing::new("test".into())),
            token_secret_file: None,
            verify_tls: true,
            rate_limit: None,
        }
    }

    #[test]
    fn pbs_host_extracts_from_https_url_with_port() {
        assert_eq!(
            pbs_host("https://pbs.lan:8007"),
            Some("pbs.lan:8007".into())
        );
    }

    #[test]
    fn pbs_host_extracts_from_url_with_path() {
        assert_eq!(
            pbs_host("https://pbs.lan:8007/api2/json/something"),
            Some("pbs.lan:8007".into())
        );
    }

    #[test]
    fn pbs_host_handles_no_scheme() {
        assert_eq!(pbs_host("pbs.lan"), Some("pbs.lan".into()));
    }

    #[test]
    fn build_repository_full_form() {
        let r = build_repository(&cfg(), "store-1").expect("repo");
        assert_eq!(r, "proxxx@pbs!reader@pbs.lan:8007:store-1");
    }

    #[test]
    fn validate_target_rejects_non_dir_existing() {
        // The Cargo.toml file exists and isn't a directory — must reject.
        let p = std::path::Path::new("Cargo.toml");
        assert!(validate_target(p).is_err());
    }

    #[test]
    fn validate_target_accepts_existing_dir() {
        let p = std::path::Path::new("src");
        assert!(validate_target(p).is_ok());
    }

    #[test]
    fn validate_target_accepts_nonexistent_with_existing_parent() {
        let p = std::path::Path::new("src/not-yet-here.bin");
        assert!(validate_target(p).is_ok());
    }

    #[test]
    fn detect_client_binary_returns_none_when_path_unset() {
        // Snapshot the env, scrub PATH, restore.
        let saved = std::env::var_os("PATH");
        std::env::remove_var("PATH");
        let detected = detect_client_binary();
        if let Some(p) = saved {
            std::env::set_var("PATH", p);
        }
        assert!(detected.is_none());
    }

    #[test]
    fn push_capped_caps_at_n() {
        let mut buf = Vec::new();
        for i in 0..100 {
            push_capped(&mut buf, format!("{i}"), 10);
        }
        assert_eq!(buf.len(), 10);
        assert_eq!(buf.first().map(String::as_str), Some("90"));
        assert_eq!(buf.last().map(String::as_str), Some("99"));
    }

    // PBS restore subprocess: kill_on_drop smoke test. Spawn `sleep` directly via
    // tokio Command with kill_on_drop, then drop the handle and assert
    // the process is no longer alive. Validates that our config flag
    // actually does what tokio's docs claim.
    #[tokio::test]
    #[cfg(unix)]
    async fn kill_on_drop_terminates_child_when_handle_dropped() {
        use std::time::Duration;
        use tokio::process::Command;

        // Skip on systems without /bin/sleep (almost never).
        if !std::path::Path::new("/bin/sleep").exists() {
            return;
        }

        let pid = {
            let mut cmd = Command::new("/bin/sleep");
            cmd.arg("60");
            cmd.kill_on_drop(true);
            let child = cmd.spawn().expect("spawn sleep");
            let pid = child.id().expect("pid");
            // Drop the handle here. kill_on_drop should SIGKILL.
            drop(child);
            pid
        };

        // Wait briefly for the kernel to clean up.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Probe: kill -0 returns 0 if the process exists, ESRCH if not.
        // We use the `kill` command since libc isn't a current dep.
        let status = std::process::Command::new("/bin/kill")
            .arg("-0")
            .arg(pid.to_string())
            .status();
        match status {
            Ok(s) if !s.success() => { /* expected — child gone */ }
            Ok(_) => panic!("child {pid} still alive after kill_on_drop — orphan zombie risk"),
            Err(_) => { /* /bin/kill missing? skip rather than fail */ }
        }
    }
}
