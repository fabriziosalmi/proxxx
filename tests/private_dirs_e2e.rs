#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #384: the log directory, which by default is also the audit directory,
//! is owner-only. `tracing-appender` cannot set a file mode, so the 0700
//! directory is what keeps the log files and `audit.db` from other users.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const CONFIG: &str = "url = \"https://127.0.0.1:1\"\nuser = \"root@pam\"\n\
    token_id = \"x\"\ntoken_secret = \"00000000-0000-0000-0000-000000000000\"\n\
    verify_tls = false\n";

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// Run a command that starts logging and then fails on the network.
fn run(home: &Path, log_dir: Option<&Path>) {
    let cfg = home.join("config.toml");
    std::fs::write(&cfg, CONFIG).unwrap();
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"));
    cmd.args(["ls", "nodes"])
        .env("HOME", home)
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_CACHE_DIR", home.join("cache"))
        .env_remove("XDG_DATA_HOME")
        .env_remove("PROXXX_LOG_DIR")
        .env_remove("PROXXX_AUDIT_DIR");
    if let Some(d) = log_dir {
        cmd.env("PROXXX_LOG_DIR", d);
    }
    let out = cmd.output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn default_data_dir(home: &Path) -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/dev.proxxx.proxxx")
    } else {
        home.join(".local/share/proxxx")
    }
}

#[test]
fn a_log_dir_proxxx_creates_is_owner_only() {
    let home = tempfile::tempdir().unwrap();
    let logs = home.path().join("new/logs");
    run(home.path(), Some(&logs));
    assert_eq!(mode(&logs), 0o700);

    let home = tempfile::tempdir().unwrap();
    run(home.path(), None);
    assert_eq!(mode(&default_data_dir(home.path())), 0o700);
}

#[test]
fn the_default_data_dir_is_narrowed_and_an_operator_dir_is_left_alone() {
    let home = tempfile::tempdir().unwrap();
    let data = default_data_dir(home.path());
    std::fs::create_dir_all(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
    run(home.path(), None);
    assert_eq!(mode(&data), 0o700, "the default dir is proxxx's own");

    let home = tempfile::tempdir().unwrap();
    let logs = home.path().join("var-log");
    std::fs::create_dir(&logs).unwrap();
    std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(0o755)).unwrap();
    run(home.path(), Some(&logs));
    assert_eq!(mode(&logs), 0o755, "a PROXXX_LOG_DIR the operator made");
}
