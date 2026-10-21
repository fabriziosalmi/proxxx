#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #440: in a config made only of `[profiles.<name>]` tables (no top-level
//! `url`), a top-level key other than `default`, `profiles` and `defaults`
//! is read by no profile. It used to be dropped silently (a top-level
//! `[[alerts]]` gave "no [[alerts]] rules configured", a misspelled key
//! was accepted); it is now a configuration error, exit 3.

use std::path::Path;
use std::process::Output;

/// Connection settings that point nowhere: a config that loads fails on
/// the network (exit 1), one that does not load fails with exit 3.
const PROFILE: &str = "url = \"https://127.0.0.1:1\"\nuser = \"root@pam\"\n\
    token_id = \"x\"\ntoken_secret = \"00000000-0000-0000-0000-000000000000\"\n\
    verify_tls = false\n";

const ALERT: &str =
    "name = \"node_down\"\ntrigger = \"node_offline\"\nfor_secs = 60\nroute = [\"ntfy:t\"]\n";

fn run(dir: &Path, config: &str, args: &[&str]) -> Output {
    let cfg = dir.join("config.toml");
    std::fs::write(&cfg, config).unwrap();
    std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(args)
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_AUDIT_DIR", dir.join("audit"))
        .output()
        .unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn a_top_level_alerts_table_in_a_profile_only_config_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = format!("default = \"lab\"\n\n[[alerts]]\n{ALERT}\n[profiles.lab]\n{PROFILE}");
    let out = run(dir.path(), &config, &["alerts", "eval"]);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(3), "{err}");
    assert!(
        err.contains("`alerts`") && err.contains("[[defaults.alerts]]"),
        "{err}"
    );
}

#[test]
fn a_misspelled_top_level_key_is_refused_and_named() {
    let dir = tempfile::tempdir().unwrap();
    for (name, config) in [
        (
            "default key",
            format!("default = \"lab\"\nverfy_tls = false\n\n[profiles.lab]\n{PROFILE}"),
        ),
        (
            "single profile",
            format!(
                "verfy_tls = false\n[telegram]\nbot_token = \"x\"\n\n[profiles.lab]\n{PROFILE}"
            ),
        ),
    ] {
        let out = run(dir.path(), &config, &["ls", "nodes"]);
        let err = stderr(&out);
        assert_eq!(out.status.code(), Some(3), "{name}: {err}");
        assert!(err.contains("`verfy_tls`"), "{name}: {err}");
    }
    // --profile goes through the same check.
    let config =
        format!("[ssh]\nuser = \"root\"\n\n[profiles.a]\n{PROFILE}\n[profiles.b]\n{PROFILE}");
    let out = run(dir.path(), &config, &["--profile", "a", "ls", "nodes"]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(stderr(&out).contains("`ssh`"), "{}", stderr(&out));
}

/// Shared settings under `[defaults]` and per-profile tables still load.
#[test]
fn defaults_and_profile_tables_still_load() {
    let dir = tempfile::tempdir().unwrap();
    let config = format!(
        "default = \"lab\"\n\n[[defaults.alerts]]\n{ALERT}\n[profiles.lab]\n{PROFILE}\n\
         [[profiles.lab.alerts]]\n{}",
        ALERT.replace("node_down", "node_down_2")
    );
    let out = run(dir.path(), &config, &["ls", "nodes"]);
    let err = stderr(&out);
    assert_ne!(out.status.code(), Some(3), "{err}");
    assert!(!err.contains("would be ignored"), "{err}");
}

/// A config with a top-level `url` is a flat profile plus named ones; its
/// top-level keys belong to the flat profile and are not refused when a
/// named profile is selected.
#[test]
fn a_flat_profile_next_to_named_ones_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let config = format!("{PROFILE}\n[telegram]\nbot_token = \"x\"\n\n[profiles.lab]\n{PROFILE}");
    let out = run(dir.path(), &config, &["--profile", "lab", "ls", "nodes"]);
    let err = stderr(&out);
    assert_ne!(out.status.code(), Some(3), "{err}");
    assert!(!err.contains("would be ignored"), "{err}");
}
