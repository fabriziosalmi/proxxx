//! Integration and binary E2E tests for Step 18 (`fix/keychain-backend`:
//! issues `#319`, `#329`, `#332`).
//!
//! Resolver tests that use the `#[cfg(test)]` keychain hook (Tests 2, 3a, 3b, 5)
//! live in `src/config/mod.rs` (`mod keychain_and_secret_resolution_tests`).
//! Never touches the developer's real macOS login keychain.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

use std::process::Command;

use proxxx::config::keychain_store_info;
use serde_json::Value;

const fn proxxx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_proxxx")
}

/// Test 1 (`#319`, macOS-only): the compiled default credential builder reports
/// a persistent store (`UntilDelete` -> `compiled: true, store: "macos-keychain"`).
/// Fails on the base where `keyring` lacked `apple-native` and used its
/// `EntryOnly` mock builder.
#[cfg(all(feature = "keychain", target_os = "macos"))]
#[test]
fn test_1_macos_default_credential_builder_reports_persistent_store() {
    let info = keychain_store_info();
    assert!(
        info.compiled,
        "macOS build must compile a persistent keychain store (apple-native), got: {info:?}"
    );
    assert_eq!(info.store, "macos-keychain");
}

/// Test 1b (`#319`, non-macOS): on targets without a persistent keychain store
/// compiled in, `keychain_store_info()` reports `compiled: false, store: "none"`.
#[cfg(not(all(feature = "keychain", target_os = "macos")))]
#[test]
fn test_1b_non_macos_reports_no_keychain_store() {
    let info = keychain_store_info();
    assert!(!info.compiled, "non-macOS build must report compiled=false");
    assert_eq!(info.store, "none");
}

/// Test 4 (`#332`, binary E2E):
/// - `proxxx version --json` includes `"features"` and `"keychain": {"compiled": ..., "store": ...}`.
/// - `proxxx --format json doctor` includes the `"keychain"` check.
#[test]
fn test_4_version_json_and_doctor_json_report_features_and_keychain_store() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_dir = tmp.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");

    // 4a. `proxxx version --json`
    let ver_out = Command::new(proxxx_bin())
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["version", "--json"])
        .output()
        .expect("run proxxx version --json");
    assert_eq!(ver_out.status.code(), Some(0));
    let ver_json: Value =
        serde_json::from_slice(&ver_out.stdout).expect("parse version --json output");

    let features = ver_json["features"]
        .as_array()
        .expect("version --json must include a features array");
    if cfg!(feature = "keychain") {
        assert!(
            features.iter().any(|f| f == "keychain"),
            "features array must contain 'keychain', got: {features:?}"
        );
    }

    let kc = &ver_json["keychain"];
    assert!(
        kc.is_object(),
        "version --json must include keychain object: {ver_json:?}"
    );
    if cfg!(all(feature = "keychain", target_os = "macos")) {
        assert_eq!(kc["compiled"], Value::Bool(true));
        assert_eq!(kc["store"], "macos-keychain");
    } else {
        assert_eq!(kc["compiled"], Value::Bool(false));
        assert_eq!(kc["store"], "none");
    }

    // 4b. `proxxx --format json doctor`
    let cfg_path = tmp.path().join("doctor_kc.toml");
    std::fs::write(
        &cfg_path,
        r#"
default = "lab"

[profiles.lab]
url = "https://127.0.0.1:1"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false
"#,
    )
    .expect("write doctor_kc.toml");

    let doc_out = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_path)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "doctor"])
        .output()
        .expect("run proxxx --format json doctor");
    let checks: Value =
        serde_json::from_slice(&doc_out.stdout).expect("parse doctor --format json output");
    let arr = checks.as_array().expect("doctor checks array");
    let kc_check = arr
        .iter()
        .find(|c| c["check"] == "keychain")
        .expect("doctor output must contain a 'keychain' check");

    if cfg!(all(feature = "keychain", target_os = "macos")) {
        assert_eq!(kc_check["status"], "ok");
        assert!(
            kc_check["message"]
                .as_str()
                .unwrap_or_default()
                .contains("macos-keychain"),
            "unexpected doctor keychain message: {kc_check:?}"
        );
    } else {
        assert_eq!(kc_check["status"], "warn");
        assert!(
            kc_check["message"]
                .as_str()
                .unwrap_or_default()
                .contains("no keychain store in this build"),
            "unexpected doctor keychain message: {kc_check:?}"
        );
    }
}
