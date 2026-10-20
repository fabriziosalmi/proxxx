//! Integration and binary E2E tests for Step 18 (`fix/keychain-backend`:
//! issues `#319`, `#329`, `#332`).
//!
//! Never touches the developer's real macOS login keychain: all resolver tests
//! install [`proxxx::config::TestKeychainGuard`], and binary E2E tests use an
//! inline `token_secret` in a temporary config file.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

use std::collections::HashMap;
use std::process::Command;

use proxxx::cli::doctor::check_keychain_for_store;
use proxxx::config::{
    keychain_store_info, load_config_from_path, KeychainEntryOutcome, KeychainStoreInfo,
    ProfileConfig, TestKeychainGuard, TestKeychainMode,
};
use proxxx::util::secret::SecretString;
use serde_json::Value;

const fn proxxx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_proxxx")
}

fn clear_secret_env_vars() {
    std::env::remove_var("PROXXX_TOKEN_SECRET");
    std::env::remove_var("PROXXX_PASSWORD");
    std::env::remove_var("PROXXX_PBS_TOKEN_SECRET");
    std::env::remove_var("PROXXX_TELEGRAM_BOT_TOKEN");
}

/// Test 1 (`#319`, macOS-only): the compiled default credential builder reports
/// a persistent store (`UntilDelete` -> `compiled: true, store: "macos-keychain"`).
/// Fails on the base where `keyring` lacked `apple-native` and used its
/// `EntryOnly` mock builder.
#[cfg(target_os = "macos")]
#[test]
fn test_1_macos_default_credential_builder_reports_persistent_store() {
    let info = keychain_store_info();
    assert!(
        info.compiled,
        "macOS build must compile a persistent keychain store (apple-native), got: {info:?}"
    );
    assert_eq!(info.store, "macos-keychain");
}

/// Test 2 (`#319` + consistent keychain account names):
/// With an injected keychain (`TestKeychainGuard`), `load_config_from_path`
/// stamps `profile_name` on `ProfileConfig`, `PbsConfig`, and `TelegramConfig`,
/// and all four resolvers (`token_secret`, `password`, `pbs_token_secret`,
/// `telegram_bot_token`) resolve `<profile>/<item>` first, then fall back to
/// the flat `<item>` name.
#[tokio::test]
#[serial_test::serial]
async fn test_2_injected_keychain_resolves_profile_scoped_then_flat_names() {
    clear_secret_env_vars();

    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_path = tmp.path().join("config.toml");
    std::fs::write(
        &cfg_path,
        r#"
default = "pve-test"

[profiles.pve-test]
url = "https://127.0.0.1:8006"
user = "root@pam"
token_id = "proxxx"

[profiles.pve-test.pbs]
url = "https://127.0.0.1:8007"
user = "backup@pbs"
token_id = "reader"

[profiles.pve-test.telegram]
chat_id = "12345"
"#,
    )
    .expect("write config.toml");

    let cfg = load_config_from_path(&cfg_path, None).expect("load config");
    assert_eq!(cfg.profile_name.as_deref(), Some("pve-test"));
    assert_eq!(
        cfg.pbs.as_ref().unwrap().profile_name.as_deref(),
        Some("pve-test")
    );
    assert_eq!(
        cfg.telegram.as_ref().unwrap().profile_name.as_deref(),
        Some("pve-test")
    );

    // 2a. Both `<profile>/<item>` and flat `<item>` present -> `<profile>/<item>` wins.
    let mut scoped_and_flat = HashMap::new();
    for (item, scoped_val, flat_val) in [
        ("token_secret", "pve-scoped-val", "pve-flat-val"),
        ("password", "pw-scoped-val", "pw-flat-val"),
        ("pbs_token_secret", "pbs-scoped-val", "pbs-flat-val"),
        ("telegram_bot_token", "tg-scoped-val", "tg-flat-val"),
    ] {
        scoped_and_flat.insert(
            ("proxxx".to_string(), format!("pve-test/{item}")),
            KeychainEntryOutcome::Found(SecretString::from(scoped_val)),
        );
        scoped_and_flat.insert(
            ("proxxx".to_string(), item.to_string()),
            KeychainEntryOutcome::Found(SecretString::from(flat_val)),
        );
    }
    {
        let guard = TestKeychainGuard::install(TestKeychainMode::Entries(scoped_and_flat));
        assert_eq!(
            cfg.resolve_token_secret(None).await.unwrap().expose(),
            "pve-scoped-val"
        );
        assert_eq!(
            cfg.resolve_password().await.unwrap().expose(),
            "pw-scoped-val"
        );
        assert_eq!(
            cfg.pbs
                .as_ref()
                .unwrap()
                .resolve_token_secret(None)
                .await
                .unwrap()
                .expose(),
            "pbs-scoped-val"
        );
        assert_eq!(
            cfg.telegram
                .as_ref()
                .unwrap()
                .resolve_bot_token()
                .await
                .unwrap()
                .expose(),
            "tg-scoped-val"
        );
        assert_eq!(
            guard.consult_count(),
            4,
            "each resolver must stop after the first hit on <profile>/<item>"
        );
    }

    // 2b. Only flat `<item>` present -> falls back to flat `<item>`.
    let mut flat_only = HashMap::new();
    for (item, flat_val) in [
        ("token_secret", "pve-flat-only"),
        ("password", "pw-flat-only"),
        ("pbs_token_secret", "pbs-flat-only"),
        ("telegram_bot_token", "tg-flat-only"),
    ] {
        flat_only.insert(
            ("proxxx".to_string(), item.to_string()),
            KeychainEntryOutcome::Found(SecretString::from(flat_val)),
        );
    }
    {
        let guard = TestKeychainGuard::install(TestKeychainMode::Entries(flat_only));
        assert_eq!(
            cfg.resolve_token_secret(None).await.unwrap().expose(),
            "pve-flat-only"
        );
        assert_eq!(
            cfg.resolve_password().await.unwrap().expose(),
            "pw-flat-only"
        );
        assert_eq!(
            cfg.pbs
                .as_ref()
                .unwrap()
                .resolve_token_secret(None)
                .await
                .unwrap()
                .expose(),
            "pbs-flat-only"
        );
        assert_eq!(
            cfg.telegram
                .as_ref()
                .unwrap()
                .resolve_bot_token()
                .await
                .unwrap()
                .expose(),
            "tg-flat-only"
        );
        assert_eq!(
            guard.consult_count(),
            8,
            "each resolver queries <profile>/<item> (miss) then <item> (hit)"
        );
    }
}

/// Test 3a (`#329`):
/// With no source available, `ProfileConfig::resolve_token_secret`,
/// `ProfileConfig::resolve_password`, `PbsConfig::resolve_token_secret`, and
/// `TelegramConfig::resolve_bot_token` list every source tried in order,
/// name every keychain account queried, and never print any secret value
/// (verified with canary secrets in a decoy profile's keychain accounts).
#[tokio::test]
#[serial_test::serial]
async fn test_3a_secret_not_found_lists_all_sources_in_order_and_leaks_no_canary() {
    clear_secret_env_vars();

    let canary_pve = "CANARY-PVE-SECRET-329-DO-NOT-PRINT";
    let canary_pw = "CANARY-PW-SECRET-329-DO-NOT-PRINT";
    let canary_pbs = "CANARY-PBS-SECRET-329-DO-NOT-PRINT";
    let canary_tg = "CANARY-TG-SECRET-329-DO-NOT-PRINT";

    let mut decoy_entries = HashMap::new();
    decoy_entries.insert(
        (
            "proxxx".to_string(),
            "other-profile/token_secret".to_string(),
        ),
        KeychainEntryOutcome::Found(SecretString::from(canary_pve)),
    );
    decoy_entries.insert(
        ("proxxx".to_string(), "other-profile/password".to_string()),
        KeychainEntryOutcome::Found(SecretString::from(canary_pw)),
    );
    decoy_entries.insert(
        (
            "proxxx".to_string(),
            "other-profile/pbs_token_secret".to_string(),
        ),
        KeychainEntryOutcome::Found(SecretString::from(canary_pbs)),
    );
    decoy_entries.insert(
        (
            "proxxx".to_string(),
            "other-profile/telegram_bot_token".to_string(),
        ),
        KeychainEntryOutcome::Found(SecretString::from(canary_tg)),
    );
    let _guard = TestKeychainGuard::install(TestKeychainMode::Entries(decoy_entries));

    let mut cfg: ProfileConfig = toml::from_str(
        r#"
url = "https://127.0.0.1:8006"
user = "root@pam"
token_id = "proxxx"

[pbs]
url = "https://127.0.0.1:8007"
user = "backup@pbs"
token_id = "reader"

[telegram]
chat_id = "12345"
"#,
    )
    .expect("parse profile");
    cfg.profile_name = Some("pve-test".to_string());
    cfg.pbs.as_mut().unwrap().profile_name = Some("pve-test".to_string());
    cfg.telegram.as_mut().unwrap().profile_name = Some("pve-test".to_string());

    // 1. PVE token_secret
    let pve_msg = format!("{:#}", cfg.resolve_token_secret(None).await.unwrap_err());
    let i_cli = pve_msg
        .find("1. CLI flag --token-secret (not given)")
        .expect(&pve_msg);
    let i_env = pve_msg
        .find("2. env var PROXXX_TOKEN_SECRET (unset)")
        .expect(&pve_msg);
    let i_inl = pve_msg
        .find("3. inline token_secret (absent)")
        .expect(&pve_msg);
    let i_fil = pve_msg
        .find("4. token_secret_file (not configured)")
        .expect(&pve_msg);
    let i_kc = pve_msg
        .find("5. keychain (service `proxxx`, accounts [`pve-test/token_secret` (not found), `token_secret` (not found)])")
        .expect(&pve_msg);
    assert!(i_cli < i_env && i_env < i_inl && i_inl < i_fil && i_fil < i_kc);
    assert!(!pve_msg.contains(canary_pve) && !pve_msg.contains("CANARY-"));

    // 2. PVE password
    let pw_msg = format!("{:#}", cfg.resolve_password().await.unwrap_err());
    assert!(
        pw_msg.contains("1. env var PROXXX_PASSWORD (unset)"),
        "{pw_msg}"
    );
    assert!(pw_msg.contains("2. inline password (absent)"), "{pw_msg}");
    assert!(
        pw_msg.contains("3. keychain (service `proxxx`, accounts [`pve-test/password` (not found), `password` (not found)])"),
        "{pw_msg}"
    );
    assert!(!pw_msg.contains(canary_pw) && !pw_msg.contains("CANARY-"));

    // 3. PBS token_secret
    let pbs_msg = format!(
        "{:#}",
        cfg.pbs
            .as_ref()
            .unwrap()
            .resolve_token_secret(None)
            .await
            .unwrap_err()
    );
    assert!(
        pbs_msg.contains("1. CLI flag --pbs-token-secret (not given)"),
        "{pbs_msg}"
    );
    assert!(
        pbs_msg.contains("2. env var PROXXX_PBS_TOKEN_SECRET (unset)"),
        "{pbs_msg}"
    );
    assert!(
        pbs_msg.contains("3. inline pbs.token_secret (absent)"),
        "{pbs_msg}"
    );
    assert!(
        pbs_msg.contains("4. pbs.token_secret_file (not configured)"),
        "{pbs_msg}"
    );
    assert!(
        pbs_msg.contains("5. keychain (service `proxxx`, accounts [`pve-test/pbs_token_secret` (not found), `pbs_token_secret` (not found)])"),
        "{pbs_msg}"
    );
    assert!(!pbs_msg.contains(canary_pbs) && !pbs_msg.contains("CANARY-"));

    // 4. Telegram bot_token
    let tg_msg = format!(
        "{:#}",
        cfg.telegram
            .as_ref()
            .unwrap()
            .resolve_bot_token()
            .await
            .unwrap_err()
    );
    assert!(
        tg_msg.contains("1. env var PROXXX_TELEGRAM_BOT_TOKEN (unset)"),
        "{tg_msg}"
    );
    assert!(
        tg_msg.contains("2. telegram.bot_token_file (not configured)"),
        "{tg_msg}"
    );
    assert!(
        tg_msg.contains("3. inline telegram.bot_token (absent)"),
        "{tg_msg}"
    );
    assert!(
        tg_msg.contains("4. keychain (service `proxxx`, accounts [`pve-test/telegram_bot_token` (not found), `telegram_bot_token` (not found)])"),
        "{tg_msg}"
    );
    assert!(!tg_msg.contains(canary_tg) && !tg_msg.contains("CANARY-"));
}

/// Test 3b (`#329`):
/// Exercises `token_secret_file` diagnostics (`missing`, `bad permissions`,
/// `empty`) and keychain `access denied` without leaking any file content.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn test_3b_secret_file_states_and_keychain_access_denied_diagnostics() {
    use std::os::unix::fs::PermissionsExt;

    clear_secret_env_vars();
    let tmp = tempfile::tempdir().expect("tempdir");

    let mut entries = HashMap::new();
    entries.insert(
        ("proxxx".to_string(), "pve-test/token_secret".to_string()),
        KeychainEntryOutcome::AccessDenied("User interaction is not allowed".to_string()),
    );
    let _guard = TestKeychainGuard::install(TestKeychainMode::Entries(entries));

    // 1. Missing file
    let missing_path = tmp.path().join("missing.token");
    let mut cfg: ProfileConfig = toml::from_str(&format!(
        "url = \"https://127.0.0.1:8006\"\nuser = \"root@pam\"\ntoken_secret_file = \"{}\"\n",
        missing_path.display()
    ))
    .unwrap();
    cfg.profile_name = Some("pve-test".to_string());
    let msg_missing = format!("{:#}", cfg.resolve_token_secret(None).await.unwrap_err());
    assert!(
        msg_missing.contains(": missing)")
            && msg_missing.contains(
                "`pve-test/token_secret` (access denied: User interaction is not allowed)"
            )
            && msg_missing.contains("`token_secret` (not found)"),
        "unexpected missing-file diagnostic: {msg_missing}"
    );

    // 2. Bad permissions (0644) with a canary secret inside the file
    let lax_path = tmp.path().join("lax.token");
    let file_canary = "CANARY-LAX-FILE-SECRET-329";
    std::fs::write(&lax_path, file_canary).unwrap();
    std::fs::set_permissions(&lax_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    cfg.token_secret_file = Some(lax_path.display().to_string());
    let msg_lax = format!("{:#}", cfg.resolve_token_secret(None).await.unwrap_err());
    assert!(
        msg_lax.contains("bad permissions 0644") && msg_lax.contains("Must be 0600"),
        "unexpected bad-permissions diagnostic: {msg_lax}"
    );
    assert!(
        !msg_lax.contains(file_canary),
        "bad-permissions error must never print file contents: {msg_lax}"
    );

    // 3. Empty file (0600)
    let empty_path = tmp.path().join("empty.token");
    std::fs::write(&empty_path, "   \n").unwrap();
    std::fs::set_permissions(&empty_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    cfg.token_secret_file = Some(empty_path.display().to_string());
    let msg_empty = format!("{:#}", cfg.resolve_token_secret(None).await.unwrap_err());
    assert!(
        msg_empty.contains(": empty)"),
        "unexpected empty-file diagnostic: {msg_empty}"
    );
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

/// Test 5 (`#319`, `#329`, `#332` Linux / no-store behaviour):
/// - `check_keychain_for_store` with `compiled: false, store: "none"` reports
///   `warn` with `"no keychain store in this build (Linux): use token_secret_file or env"`.
/// - When no store is compiled in (`TestKeychainMode::NoStoreCompiled`), none
///   of the four secret resolvers ever consults a store (`consult_count() == 0`)
///   and each reports `"no keychain store in this build"`.
#[tokio::test]
#[serial_test::serial]
async fn test_5_linux_no_store_doctor_warn_and_resolvers_never_consult_store() {
    clear_secret_env_vars();

    let linux_check = check_keychain_for_store(
        KeychainStoreInfo {
            compiled: false,
            store: "none",
        },
        "Linux",
    );
    assert_eq!(linux_check["check"], "keychain");
    assert_eq!(linux_check["status"], "warn");
    assert_eq!(
        linux_check["message"],
        "no keychain store in this build (Linux): use token_secret_file or env"
    );

    let guard = TestKeychainGuard::install(TestKeychainMode::NoStoreCompiled);
    let mut cfg: ProfileConfig = toml::from_str(
        r#"
url = "https://127.0.0.1:8006"
user = "root@pam"
token_id = "proxxx"

[pbs]
url = "https://127.0.0.1:8007"
user = "backup@pbs"
token_id = "reader"

[telegram]
chat_id = "12345"
"#,
    )
    .expect("parse profile");
    cfg.profile_name = Some("pve-test".to_string());
    cfg.pbs.as_mut().unwrap().profile_name = Some("pve-test".to_string());
    cfg.telegram.as_mut().unwrap().profile_name = Some("pve-test".to_string());

    let pve_err = format!("{:#}", cfg.resolve_token_secret(None).await.unwrap_err());
    let pw_err = format!("{:#}", cfg.resolve_password().await.unwrap_err());
    let pbs_err = format!(
        "{:#}",
        cfg.pbs
            .as_ref()
            .unwrap()
            .resolve_token_secret(None)
            .await
            .unwrap_err()
    );
    let tg_err = format!(
        "{:#}",
        cfg.telegram
            .as_ref()
            .unwrap()
            .resolve_bot_token()
            .await
            .unwrap_err()
    );

    assert_eq!(
        guard.consult_count(),
        0,
        "resolver must never consult a keychain store when no store is compiled in"
    );
    for msg in [&pve_err, &pw_err, &pbs_err, &tg_err] {
        assert!(
            msg.contains("no keychain store in this build"),
            "expected 'no keychain store in this build', got: {msg}"
        );
    }
}
