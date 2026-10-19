#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]
//! End-to-end and static-guard tests for issue #346:
//! resolved profile label (`ProfileConfig::profile_label`) instead of
//! literal `"default"` fallback when `--profile` is omitted, plus
//! `[meta] profile` mismatch protection on `state` and `reconcile`.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use proxxx::api::types::GuestType;
use proxxx::api::{ProxmoxGateway, PxClient};
use proxxx::app::cache::get_db_path;
use proxxx::config::{load_config_from_path, ConfigError, ProfileConfig};
use proxxx::state::converge::converge_with_mismatch_policy;
use proxxx::state::model::ClusterState;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const fn proxxx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_proxxx")
}

/// Write `toml_body` to a temporary `config.toml` (0600 on Unix) and load it
/// via `load_config_from_path(path, profile)`.
fn load_temp_config(toml_body: &str, profile: Option<&str>) -> ProfileConfig {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_path = tmp.path().join("config.toml");
    std::fs::write(&cfg_path, toml_body).expect("write config.toml");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 config.toml");
    }
    load_config_from_path(&cfg_path, profile).expect("load_config_from_path")
}

/// Mount minimal read-only PVE endpoints required by `export_state` for an
/// empty cluster so `state export`, `state diff`, and `state apply --dry-run`
/// can complete against a local `wiremock::MockServer`.
async fn mount_empty_cluster_export_mocks(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api2/json/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "version": "8.2.2", "release": "8.2", "repoid": "deadbeef" }
        })))
        .mount(server)
        .await;

    for endpoint in [
        "/api2/json/pools",
        "/api2/json/access/acl",
        "/api2/json/storage",
        "/api2/json/cluster/backup",
        "/api2/json/cluster/firewall/aliases",
        "/api2/json/cluster/firewall/ipset",
        "/api2/json/cluster/firewall/groups",
        "/api2/json/cluster/notifications/matchers",
        "/api2/json/cluster/ha/resources",
        "/api2/json/cluster/ha/rules",
        "/api2/json/cluster/mapping/pci",
        "/api2/json/cluster/mapping/usb",
    ] {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": [] })))
            .mount(server)
            .await;
    }

    Mock::given(method("GET"))
        .and(path("/api2/json/cluster/firewall/options"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": {} })))
        .mount(server)
        .await;
}

/// Write a temporary `config.toml` with `default = "pve-test"` and
/// `[profiles.pve-test]` pointing at `server_uri`.
fn write_default_named_profile_config(dir: &Path, server_uri: &str) -> std::path::PathBuf {
    let cfg_path = dir.join("config.toml");
    let body = format!(
        r#"default = "pve-test"

[profiles.pve-test]
url = "{server_uri}"
user = "root@pam"
auth = "token"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000000"
verify_tls = false
"#
    );
    std::fs::write(&cfg_path, body).expect("write config.toml");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 config.toml");
    }
    cfg_path
}

// ── Test 1: Cache path resolution (`pve-test_state.db` vs `default_state.db`) ──

#[test]
fn test_1_cache_path_uses_resolved_profile_instead_of_literal_default() {
    // 1a. Multi-profile config with `default = "pve-test"` and NO `--profile`:
    //     resolved profile label is `"pve-test"` and cache DB ends in `pve-test_state.db`.
    let named_default_toml = r#"
default = "pve-test"

[profiles.pve-test]
url = "https://10.0.0.1:8006"
user = "root@pam"
auth = "token"
token_id = "t"
token_secret = "s"

[profiles.prod]
url = "https://10.0.0.2:8006"
user = "root@pam"
auth = "token"
token_id = "t"
token_secret = "s"
"#;
    let cfg = load_temp_config(named_default_toml, None);
    assert_eq!(cfg.profile_label(), "pve-test");
    let db_path = get_db_path(cfg.profile_label());
    assert_eq!(
        db_path.file_name().and_then(|s| s.to_str()),
        Some("pve-test_state.db"),
        "config with `default = \"pve-test\"` and no `--profile` must use pve-test_state.db, got {}",
        db_path.display()
    );
    assert!(
        !db_path.to_string_lossy().ends_with("default_state.db"),
        "named default profile must never resolve to default_state.db"
    );

    // 1b. Single `[profiles.pve-test]` section without `default` key and no `--profile`:
    //     also resolves to `"pve-test"` and `pve-test_state.db`.
    let single_named_toml = r#"
[profiles.pve-test]
url = "https://10.0.0.1:8006"
user = "root@pam"
auth = "token"
token_id = "t"
token_secret = "s"
"#;
    let single_cfg = load_temp_config(single_named_toml, None);
    assert_eq!(single_cfg.profile_label(), "pve-test");
    assert_eq!(
        get_db_path(single_cfg.profile_label())
            .file_name()
            .and_then(|s| s.to_str()),
        Some("pve-test_state.db")
    );

    // 1c. Flat top-level config (no `[profiles]`): resolves to `"default"` and `default_state.db`.
    let flat_toml = r#"
url = "https://10.0.0.1:8006"
user = "root@pam"
auth = "token"
token_id = "t"
token_secret = "s"
"#;
    let flat_cfg = load_temp_config(flat_toml, None);
    assert_eq!(flat_cfg.profile_name, None);
    assert_eq!(flat_cfg.profile_label(), "default");
    assert_eq!(
        get_db_path(flat_cfg.profile_label())
            .file_name()
            .and_then(|s| s.to_str()),
        Some("default_state.db")
    );
}

// ── Test 2: `state export` `[meta] profile` and audit `params_json` ──

#[tokio::test]
async fn test_2_state_export_and_audit_log_record_resolved_profile_pve_test() {
    let server = MockServer::start().await;
    mount_empty_cluster_export_mocks(&server).await;

    Mock::given(method("POST"))
        .and(path("/api2/json/nodes/pve1/qemu/100/status/start"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "data": "UPID:pve1:00000100:00000000:00000000:qmstart:100:root@pam:" }),
        ))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_dir = tmp.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");

    let cfg_path = write_default_named_profile_config(tmp.path(), &server.uri());

    // 2a. `proxxx state export` with `default = "pve-test"` and no `--profile`
    //     writes `profile = "pve-test"` in `[meta]` on stdout.
    let out = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_path)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["state", "export"])
        .output()
        .expect("spawn proxxx state export");
    assert_eq!(
        out.status.code(),
        Some(0),
        "state export must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let exported_raw = String::from_utf8(out.stdout).expect("state export stdout utf8");
    assert!(
        exported_raw.contains("profile = \"pve-test\""),
        "exported TOML must record `profile = \"pve-test\"` in [meta], got:\n{exported_raw}"
    );
    let parsed_state = ClusterState::from_toml_str(&exported_raw).expect("parse exported state");
    assert_eq!(
        parsed_state.meta.as_ref().map(|m| m.profile.as_str()),
        Some("pve-test")
    );

    // 2b. A mutation through PxClient with that config records `"profile":"pve-test"` in audit.db.
    let cfg = load_config_from_path(&cfg_path, None).expect("load_config_from_path");
    assert_eq!(cfg.profile_label(), "pve-test");
    let client = Arc::new(
        PxClient::new(cfg, None)
            .await
            .expect("PxClient::new")
            .with_audit_dir(&audit_dir),
    );
    let upid = client
        .start_guest("pve1", 100, GuestType::Qemu)
        .await
        .expect("start_guest");
    assert!(upid.starts_with("UPID:pve1:"));

    let conn = rusqlite::Connection::open(audit_dir.join("audit.db")).expect("open audit.db");
    let mut stmt = conn
        .prepare("SELECT action, params_json, result FROM audit_log ORDER BY id ASC")
        .expect("prepare");
    let rows: Vec<(String, String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("query_map")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect rows");
    assert_eq!(rows.len(), 2, "expected write-ahead + outcome rows");
    for (action, params_json, _result) in &rows {
        assert_eq!(action, "POST /nodes/pve1/qemu/100/status/start");
        let parsed: serde_json::Value =
            serde_json::from_str(params_json).expect("params_json must be valid JSON");
        assert_eq!(
            parsed["profile"], "pve-test",
            "audit params_json must record resolved profile \"pve-test\", got: {params_json}"
        );
    }
}

// ── Test 3: Profile mismatch guard on `state` and `reconcile` ──

#[tokio::test]
async fn test_3_state_apply_and_reconcile_refuse_profile_mismatch_with_exit_3_and_zero_requests() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_dir = tmp.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");

    let cfg_path = write_default_named_profile_config(tmp.path(), &server.uri());

    // Declared state file authored for `"prod"`, while target config resolves to `"pve-test"`.
    let prod_state_path = tmp.path().join("prod-state.toml");
    std::fs::write(
        &prod_state_path,
        r#"[meta]
schema_version = 1
profile = "prod"
exported_at = "2026-01-01T00:00:00Z"
exported_from_proxxx = "0.14.0"
"#,
    )
    .expect("write prod-state.toml");

    // 3a. `proxxx state apply prod-state.toml --dry-run` (no `--profile`, no `--allow-profile-mismatch`)
    //     MUST exit 3 and send ZERO requests to wiremock.
    let out = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_path)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args([
            "state",
            "apply",
            prod_state_path.to_str().unwrap(),
            "--dry-run",
        ])
        .output()
        .expect("spawn proxxx state apply");
    assert_eq!(
        out.status.code(),
        Some(ConfigError::EXIT_CODE),
        "state apply on mismatched profile must exit 3, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("declares profile 'prod'")
            && stderr.contains("target profile is 'pve-test'")
            && stderr.contains("--allow-profile-mismatch"),
        "stderr must explain profile mismatch and flag hint, got: {stderr}"
    );
    let received = server
        .received_requests()
        .await
        .expect("wiremock received_requests");
    assert!(
        received.is_empty(),
        "state apply must refuse BEFORE contacting PVE (expected 0 requests, got {})",
        received.len()
    );

    // 3b. `reconcile converge` without `--allow-profile-mismatch` also refuses with ConfigError::ProfileMismatch
    //     (exit 3) and sends 0 requests.
    let out_reconcile = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_path)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args([
            "reconcile",
            "converge",
            "--source",
            prod_state_path.to_str().unwrap(),
            "--dry-run",
        ])
        .output()
        .expect("spawn proxxx reconcile converge");
    assert_eq!(
        out_reconcile.status.code(),
        Some(ConfigError::EXIT_CODE),
        "reconcile converge on mismatched profile must exit 3, stderr: {}",
        String::from_utf8_lossy(&out_reconcile.stderr)
    );
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "reconcile converge must refuse BEFORE contacting PVE"
    );

    // Also verify `converge_with_mismatch_policy` directly downcasts to `ConfigError::ProfileMismatch`.
    let cfg = load_config_from_path(&cfg_path, None).expect("load cfg");
    let client = Arc::new(
        PxClient::new(cfg, None)
            .await
            .expect("PxClient::new")
            .with_audit_dir(&audit_dir),
    );
    let err = converge_with_mismatch_policy(
        &client,
        "pve-test",
        prod_state_path.to_str().unwrap(),
        Path::new("state.toml"),
        proxxx::state::apply::ApplyOptions {
            dry_run: true,
            prune: false,
            continue_on_error: false,
        },
        false,
        false,
        "root@pam",
    )
    .await
    .expect_err("converge_with_mismatch_policy must refuse mismatched profile");
    assert!(
        matches!(
            err.downcast_ref::<ConfigError>(),
            Some(ConfigError::ProfileMismatch {
                declared,
                target,
                ..
            }) if declared == "prod" && target == "pve-test"
        ),
        "expected ConfigError::ProfileMismatch(prod vs pve-test), got: {err:#}"
    );
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "converge_with_mismatch_policy must refuse BEFORE contacting PVE"
    );

    // Now mount the cluster export mocks so `--allow-profile-mismatch` and `state diff` can proceed.
    mount_empty_cluster_export_mocks(&server).await;

    // 3c. With `--allow-profile-mismatch`, `state apply` warns and proceeds (exit 0 on dry-run).
    let out_allowed = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_path)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args([
            "state",
            "apply",
            prod_state_path.to_str().unwrap(),
            "--dry-run",
            "--allow-profile-mismatch",
        ])
        .output()
        .expect("spawn proxxx state apply --allow-profile-mismatch");
    assert_eq!(
        out_allowed.status.code(),
        Some(0),
        "state apply --allow-profile-mismatch must succeed, stderr: {}",
        String::from_utf8_lossy(&out_allowed.stderr)
    );
    let stderr_allowed = String::from_utf8_lossy(&out_allowed.stderr);
    assert!(
        stderr_allowed.contains("declares [meta] profile = \"prod\", which differs from target profile \"pve-test\""),
        "state apply --allow-profile-mismatch must still emit a warning on stderr, got: {stderr_allowed}"
    );
    assert!(
        !server.received_requests().await.unwrap().is_empty(),
        "state apply --allow-profile-mismatch must contact PVE to export live state"
    );

    // 3d. `state diff` on a mismatched profile warns on stderr and exits as before (0 when in sync).
    let out_diff = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_path)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["state", "diff", prod_state_path.to_str().unwrap()])
        .output()
        .expect("spawn proxxx state diff");
    assert_eq!(
        out_diff.status.code(),
        Some(0),
        "state diff on in-sync empty cluster must exit 0 even with profile mismatch, stderr: {}",
        String::from_utf8_lossy(&out_diff.stderr)
    );
    let stderr_diff = String::from_utf8_lossy(&out_diff.stderr);
    assert!(
        stderr_diff.contains(
            "declares [meta] profile = \"prod\", which differs from target profile \"pve-test\""
        ),
        "state diff must warn on stderr when profile mismatches, got: {stderr_diff}"
    );
}

// ── Test 4: Static guard against literal `"default"` profile fallback in `src/` ──

/// Strip `//` line comments so doc comments explaining the historical bug do
/// not trip the static guard, while any executable `.unwrap_or("default")` or
/// `.unwrap_or_else(|| "default")` in `src/` is caught.
fn find_literal_default_fallbacks(source: &str) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.contains("unwrap_or(\"default\")")
            || compact.contains("unwrap_or_else(||\"default\"")
            || compact.contains("unwrap_or_else(|_|\"default\"")
        {
            hits.push((idx + 1, line.trim().to_string()));
        }
    }
    hits
}

fn collect_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let entries = std::fs::read_dir(dir).expect("read_dir");
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn test_4_no_source_file_uses_literal_default_unwrap_or_fallback() {
    // Self-check the detector so a broken guard cannot pass vacuously.
    assert_eq!(
        find_literal_default_fallbacks("let p = profile.unwrap_or(\"default\");").len(),
        1
    );
    assert_eq!(
        find_literal_default_fallbacks("let p = profile.unwrap_or_else(|| \"default\".into());")
            .len(),
        1
    );
    assert!(find_literal_default_fallbacks(
        "let p = config.profile_label(); // no unwrap_or(\"default\")"
    )
    .is_empty());

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    files.sort();
    assert!(!files.is_empty(), "must scan at least one .rs file in src/");

    let mut violations = Vec::new();
    for file in files {
        let content = std::fs::read_to_string(&file).expect("read source file");
        for (line_no, snippet) in find_literal_default_fallbacks(&content) {
            let rel = file.strip_prefix(manifest_dir).unwrap_or(&file);
            violations.push(format!("{}:{}: {}", rel.display(), line_no, snippet));
        }
    }

    assert!(
        violations.is_empty(),
        "Found forbidden literal `\"default\"` fallback in src/ (use `ProfileConfig::profile_label()` instead):\n{}",
        violations.join("\n")
    );
}
