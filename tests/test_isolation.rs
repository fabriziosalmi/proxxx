#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #386: test runs must not write into the developer's real directories.
//! The audit directory is set per test (#406; `PROXXX_AUDIT_DIR` for spawned
//! binaries). The state cache honours
//! `PROXXX_CACHE_DIR` and the log files `PROXXX_LOG_DIR`, which
//! `.cargo/config.toml` sets for every process cargo starts; these tests fail
//! if that wiring is lost.

use std::path::Path;
use std::process::Command;

fn build_tree() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("target")
}

#[test]
fn the_state_cache_of_a_test_run_lives_under_the_build_tree() {
    let dir = std::env::var("PROXXX_CACHE_DIR")
        .expect("PROXXX_CACHE_DIR must be set for test runs (see .cargo/config.toml)");
    let db = proxxx::app::cache::get_db_path("isolation_probe");
    assert!(
        db.starts_with(&dir),
        "the cache path {} must be under PROXXX_CACHE_DIR {dir}",
        db.display()
    );
    assert!(
        Path::new(&dir).starts_with(build_tree()),
        "the test cache {dir} must be inside the build tree, not a user directory"
    );
}

#[test]
fn the_binary_spawned_by_a_test_logs_under_the_build_tree() {
    let dir = std::env::var("PROXXX_LOG_DIR")
        .expect("PROXXX_LOG_DIR must be set for test runs (see .cargo/config.toml)");
    assert!(
        Path::new(&dir).starts_with(build_tree()),
        "the test log dir {dir} must be inside the build tree, not a user directory"
    );
}

/// #420: the startup line names the file the appender really writes,
/// `proxxx.<date>.log`, and `PROXXX_LOG_DIR` relocates it.
#[test]
fn the_startup_line_names_the_log_file_that_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(["completions", "bash"])
        .env("PROXXX_LOG_DIR", tmp.path())
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let named = tmp.path().join("proxxx.<date>.log");
    assert!(
        stderr.contains(&format!("(log file: {})", named.display())),
        "startup line must name {}; stderr was:\n{stderr}",
        named.display()
    );
    let files: Vec<String> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(files.len(), 1, "one log file expected, found {files:?}");
    let f = &files[0];
    let date = f
        .strip_prefix("proxxx.")
        .and_then(|r| r.strip_suffix(".log"))
        .unwrap_or_else(|| panic!("log file {f} is not proxxx.<date>.log"));
    assert_eq!(date.len(), 10, "date part of {f} should be YYYY-MM-DD");
    assert!(
        date.chars().all(|c| c.is_ascii_digit() || c == '-'),
        "date part of {f} should be YYYY-MM-DD"
    );
}
