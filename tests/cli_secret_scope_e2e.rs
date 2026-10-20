#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #374: the global `--token-secret` / `--token-secret-file` belong to ONE
//! profile. Fan-out commands (`ls --all-profiles`, `find`, `fleet`) contact
//! every profile, so they refuse the flag (exit 3) instead of sending one
//! cluster's secret to all of them.

use std::process::Command;

fn two_profile_config(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("config.toml");
    std::fs::write(
        &p,
        "default = \"a\"\n[profiles.a]\nurl = \"https://127.0.0.1:1\"\nuser = \"root@pam\"\ntoken_id = \"x\"\nverify_tls = false\n[profiles.b]\nurl = \"https://127.0.0.1:2\"\nuser = \"root@pam\"\ntoken_id = \"y\"\nverify_tls = false\n",
    )
    .unwrap();
    p
}

fn run(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .env("PROXXX_CONFIG", two_profile_config(dir))
        .env("PROXXX_AUDIT_DIR", dir.join("audit"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn fanout_commands_refuse_the_cli_secret_with_exit_3() {
    let dir = tempfile::tempdir().unwrap();
    let secret = "00000000-0000-0000-0000-00000000c4a7";
    for (args, name) in [
        (
            vec!["--token-secret", secret, "ls", "nodes", "--all-profiles"],
            "ls --all-profiles",
        ),
        (vec!["--token-secret", secret, "find", "100"], "find"),
        (vec!["--token-secret", secret, "fleet"], "fleet"),
    ] {
        let out = run(dir.path(), &args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(3), "{name}: {stderr}");
        assert!(
            stderr.contains("apply to a single profile"),
            "{name}: {stderr}"
        );
        assert!(
            !stderr.contains(secret),
            "{name}: the secret must not be echoed"
        );
    }
}

#[test]
fn fanout_without_the_flag_still_runs_per_profile() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), &["ls", "nodes", "--all-profiles"]);
    // Both profiles fail on their own (no secret configured, closed ports):
    // exit 1 per #322, not the exit-3 refusal.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
