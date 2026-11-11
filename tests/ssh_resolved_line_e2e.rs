#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `proxxx ssh <vmid>` prints `[ssh] resolved user@host:port (source: ...)`
//! on stderr before it hands the terminal to the system `ssh`. On a pipe,
//! a file or a CI log that line is plain text: no escape sequence.
//!
//! The system `ssh` is replaced by a stub on `PATH` that records its
//! arguments and exits 0, so no connection is attempted.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

fn run_ssh(extra_env: &[(&str, &str)]) -> (std::process::Output, String) {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let argv_log = dir.path().join("ssh-argv");
    let stub = bin.join("ssh");
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nexit 0\n",
            argv_log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();

    let key = dir.path().join("id_test");
    std::fs::write(&key, "not a real key: the stub never reads it\n").unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "url = \"https://127.0.0.1:1\"\nuser = \"root@pam\"\ntoken_id = \"x\"\n\
             token_secret = \"00000000-0000-0000-0000-000000000000\"\nverify_tls = false\n\
             \n[ssh]\nuser = \"root\"\nkey_path = \"{}\"\n\
             \n[ssh.guests.\"200\"]\nhost = \"192.0.2.10\"\n",
            key.display()
        ),
    )
    .unwrap();

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"));
    cmd.args(["ssh", "200"])
        .env("PATH", path)
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
        .env_remove("NO_COLOR");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    let argv = std::fs::read_to_string(&argv_log).unwrap_or_default();
    (out, argv)
}

/// stderr here is a pipe: the resolved line reaches it as plain text even
/// with a colour-capable `TERM`, and the stub `ssh` got the target.
#[test]
fn the_resolved_line_on_a_pipe_has_no_escape_sequence() {
    let (out, argv) = run_ssh(&[("TERM", "xterm-256color")]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {stderr}");
    assert!(
        argv.lines().any(|l| l == "root@192.0.2.10"),
        "the stub ssh was not called with the guest target: {argv:?}"
    );
    let line = stderr
        .lines()
        .find(|l| l.contains("[ssh] resolved"))
        .unwrap_or_else(|| panic!("no resolved line on stderr: {stderr:?}"));
    assert_eq!(
        line, "[ssh] resolved root@192.0.2.10:22 (source: config.toml)",
        "{stderr:?}"
    );
    assert!(!stderr.contains('\u{1b}'), "{stderr:?}");
}
