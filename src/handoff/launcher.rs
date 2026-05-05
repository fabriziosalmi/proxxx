//! Cross-platform "open this with the system default" launcher (#1c).
//!
//! Per the architectural review, we don't pull in the `opener` crate —
//! ~50KB binary delta for what's literally a 3-line `Command::new`
//! per platform. Direct shell-out is also more obvious to audit.
//!
//! Linux/BSD use `xdg-open`; macOS uses `open`; Windows shells through
//! `cmd /C start "" <path>` (the empty string is the title argument
//! that `start` expects when the path itself contains spaces).

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

/// Open a path or URL with the system default handler. Spawns and
/// returns immediately — does NOT wait. The handler runs detached so
/// closing proxxx doesn't kill the launched viewer.
pub fn open_with_default(target: &str) -> Result<()> {
    let mut cmd = build_command(target);
    cmd.spawn()
        .with_context(|| format!("spawning system handler for {target}"))?;
    Ok(())
}

/// Try `remote-viewer` first (preferred for `.vv` SPICE files); fall
/// back to the system default. Returns the launcher name actually used.
pub fn open_spice_vv(vv_path: &Path) -> Result<&'static str> {
    let path_str = vv_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 path"))?;

    // Probe `remote-viewer` on PATH. Two reasons to prefer it:
    // 1. It's the canonical SPICE client and handles all .vv keys.
    // 2. The system default for .vv on macOS/Windows is unreliable
    //    unless virt-viewer was installed AND associated.
    if which("remote-viewer").is_some() {
        Command::new("remote-viewer")
            .arg(path_str)
            .spawn()
            .context("spawning remote-viewer")?;
        return Ok("remote-viewer");
    }
    if which("virt-viewer").is_some() {
        Command::new("virt-viewer")
            .arg(path_str)
            .spawn()
            .context("spawning virt-viewer")?;
        return Ok("virt-viewer");
    }
    open_with_default(path_str)?;
    Ok("system-default")
}

/// Locate an executable on `$PATH`. Returns its absolute path or None.
///
/// Cheaper than spawning `which(1)` and works on Windows too (without
/// any reliance on PATHEXT — we only need to know if a Unix-style
/// binary exists).
#[must_use]
pub fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
        // Windows: check .exe sibling.
        #[cfg(windows)]
        {
            let with_ext = dir.join(format!("{bin}.exe"));
            if with_ext.is_file() {
                return Some(with_ext);
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn build_command(target: &str) -> Command {
    let mut cmd = Command::new("open");
    cmd.arg(target);
    cmd
}

#[cfg(target_os = "linux")]
fn build_command(target: &str) -> Command {
    let mut cmd = Command::new("xdg-open");
    cmd.arg(target);
    cmd
}

#[cfg(target_os = "windows")]
fn build_command(target: &str) -> Command {
    let mut cmd = Command::new("cmd");
    // The empty "" is the window title — required by `start` when the
    // first quoted argument might be misread as a title.
    cmd.args(["/C", "start", "", target]);
    cmd
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn build_command(target: &str) -> Command {
    // BSDs typically have xdg-open via xdg-utils; fall back to that.
    let mut cmd = Command::new("xdg-open");
    cmd.arg(target);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_finds_path_components() {
        // /bin/sh exists on every Unix the test suite runs on.
        #[cfg(unix)]
        {
            assert!(which("sh").is_some(), "sh on PATH");
        }
        // Sentinel: clearly nonexistent.
        assert!(which("definitely-not-a-real-binary-xyz123").is_none());
    }

    #[test]
    fn which_returns_none_when_path_unset() {
        let saved = std::env::var_os("PATH");
        std::env::remove_var("PATH");
        let result = which("ls");
        if let Some(p) = saved {
            std::env::set_var("PATH", p);
        }
        assert!(result.is_none());
    }
}
