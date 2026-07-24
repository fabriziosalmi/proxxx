//! End-to-end proof that the SIGHUP config hot-reload actually works
//! against a real on-disk config and a real signal — the path AR-1's
//! `mcp_token` rotation mitigation depends on, previously untested.
//!
//! ONE combined test on purpose: `PROXXX_CONFIG` and Unix signals are
//! process-global, and cargo runs `#[test]`s in a file on parallel
//! threads of a single process — a second test here would race the env
//! var and the SIGHUP handler. Unix-only (no SIGHUP on Windows).

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use proxxx::config::watcher::{new_handle, spawn_reload_on_sighup};

fn write(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).expect("write config");
}

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("{}-{}", prefix, std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self { path: dir }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[tokio::test]
async fn sighup_hot_reloads_and_a_bad_edit_keeps_last_known_good() {
    // Isolated temp config; PROXXX_CONFIG makes load_config read it.
    let dir = TempDir::new("proxxx-reload-e2e");
    let cfg_path = dir.path().join("config.toml");
    std::env::set_var("PROXXX_CONFIG", &cfg_path);

    // v1 on disk → build the live handle and start the watcher.
    write(
        &cfg_path,
        "url = \"https://pve:8006\"\nuser = \"root@pam\"\nmcp_token = \"v1-token\"\n",
    );
    let initial = proxxx::config::load_config(None).expect("v1 loads");
    assert_eq!(
        initial.mcp_token.as_ref().map(|s| s.as_str()),
        Some("v1-token")
    );
    let handle = new_handle(initial);
    spawn_reload_on_sighup(std::sync::Arc::clone(&handle), None);
    // Let the async task register its SIGHUP handler before we raise.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Rotate the token on disk, then SIGHUP until the live handle picks it
    // up (raising in the poll loop absorbs any handler-registration race).
    write(
        &cfg_path,
        "url = \"https://pve:8006\"\nuser = \"root@pam\"\nmcp_token = \"v2-rotated\"\n",
    );
    let mut reloaded = false;
    for _ in 0..20 {
        unsafe { libc::raise(libc::SIGHUP) };
        tokio::time::sleep(Duration::from_millis(100)).await;
        if handle.read().await.mcp_token.as_ref().map(|s| s.as_str()) == Some("v2-rotated") {
            reloaded = true;
            break;
        }
    }
    assert!(
        reloaded,
        "SIGHUP did not hot-reload the rotated mcp_token within 2s"
    );

    // A bad edit + SIGHUP must NOT tear down the running config: the
    // watcher keeps the last-known-good (v2) instead of clearing auth.
    write(&cfg_path, "this is = not valid toml = [[[");
    for _ in 0..5 {
        unsafe { libc::raise(libc::SIGHUP) };
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        handle.read().await.mcp_token.as_ref().map(|s| s.as_str()),
        Some("v2-rotated"),
        "a failed reload must keep the last-known-good token, not clear it"
    );

    std::env::remove_var("PROXXX_CONFIG");
    // dir is dropped automatically, cleaning up the temp dir
}
