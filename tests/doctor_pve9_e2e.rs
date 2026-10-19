//! End-to-end and `wiremock` integration tests for Step 15 (`fix/doctor-pve9-probe`):
//!
//! - `#321`: `proxxx doctor` probes PVE connectivity and authentication through
//!   [`proxxx::api::PxClient`] (`GET /api2/json/version` + `GET /api2/json/nodes`)
//!   rather than an unauthenticated JSON probe that fails on PVE 8+/9 (`401`).
//! - `#410`: `proxxx doctor` routes its Telegram probe through
//!   [`proxxx::hitl::telegram::TelegramGateway`] (`without_url()` + secret
//!   redaction) and never leaks the bot token on stdout or stderr in JSON or
//!   table output.
//! - `#411`: `proxxx doctor` reports `telegram` as `ok` only when `getMe`
//!   returns HTTP `2xx` **and** `"ok": true`; otherwise `warn` with the HTTP
//!   status code and Telegram's `"description"`.
//! - PBS probe: `proxxx doctor` uses [`proxxx::pbs::PbsClient`] + `version()`
//!   with the same three-way mapping (`ok` / reachable with rejected
//!   credentials / unreachable).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

use std::net::TcpListener;
use std::process::Command;

use serde_json::{json, Value};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const fn proxxx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_proxxx")
}

/// Bind an ephemeral local port, immediately drop the listener, and return the
/// closed port number.
fn allocate_closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

fn find_check<'a>(checks: &'a [Value], name: &str) -> &'a Value {
    checks
        .iter()
        .find(|c| c["check"] == name)
        .unwrap_or_else(|| panic!("check '{name}' not found in doctor output: {checks:?}"))
}

/// Test 1 (#321):
/// E2E with the built binary, temp `PROXXX_CONFIG`, wiremock PVE where
/// anonymous `/api2/json/version` returns `401` and authenticated
/// (`Authorization: PVEAPIToken=root@pam!test=00000000-0000-0000-0000-000000000001`)
/// `/api2/json/version` and `/api2/json/nodes` return `200`:
/// `proxxx doctor` reports `connectivity` `ok` AND `auth` `ok`, and exits `0`.
#[tokio::test]
async fn test_1_pve9_anon_401_authenticated_200_connectivity_and_auth_ok() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_dir = tmp.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");

    let pve = MockServer::start().await;
    let expected_auth = "PVEAPIToken=root@pam!test=00000000-0000-0000-0000-000000000001";

    // Authenticated `/api2/json/version` (higher priority than the fallback 401).
    Mock::given(method("GET"))
        .and(path("/api2/json/version"))
        .and(header("Authorization", expected_auth))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "version": "9.0.3",
                "release": "9.0",
                "repoid": "deadbeef"
            }
        })))
        .with_priority(1)
        .mount(&pve)
        .await;

    // Fallback: any unauthenticated or wrong-token `/api2/json/version` gets 401
    // with an empty/non-JSON body (exact PVE 8+/9 behaviour).
    Mock::given(method("GET"))
        .and(path("/api2/json/version"))
        .respond_with(ResponseTemplate::new(401).set_body_string(""))
        .with_priority(10)
        .mount(&pve)
        .await;

    // Authenticated `/api2/json/nodes` returns 2 nodes.
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes"))
        .and(header("Authorization", expected_auth))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"node": "pve1", "status": "online", "cpu": 0.1, "maxcpu": 8, "mem": 1024, "maxmem": 8192, "disk": 0, "maxdisk": 0, "uptime": 100},
                {"node": "pve2", "status": "online", "cpu": 0.2, "maxcpu": 8, "mem": 2048, "maxmem": 8192, "disk": 0, "maxdisk": 0, "uptime": 200}
            ]
        })))
        .mount(&pve)
        .await;

    let cfg_path = tmp.path().join("config.toml");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
default = "pve9"

[profiles.pve9]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false
"#,
            pve.uri()
        ),
    )
    .expect("write config.toml");

    let out = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_path)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "doctor"])
        .output()
        .expect("run proxxx doctor");

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let stderr_str = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "doctor must exit 0 when PVE 9 accepts authenticated /version and /nodes.\nstdout: {stdout_str}\nstderr: {stderr_str}"
    );

    let parsed: Value = serde_json::from_slice(&out.stdout).expect("parse doctor json");
    let checks = parsed.as_array().expect("checks array");

    let conn = find_check(checks, "connectivity");
    assert_eq!(conn["status"], "ok", "connectivity check: {conn:?}");
    let conn_msg = conn["message"].as_str().unwrap_or_default();
    assert!(
        conn_msg.contains("9.0.3"),
        "connectivity message must include version 9.0.3, got: {conn_msg}"
    );

    let auth = find_check(checks, "auth");
    assert_eq!(auth["status"], "ok", "auth check: {auth:?}");
    let auth_msg = auth["message"].as_str().unwrap_or_default();
    assert!(
        auth_msg.contains("2 node(s) visible"),
        "auth message must report 2 visible nodes, got: {auth_msg}"
    );
}

/// Test 2 (#321):
/// E2E with the built binary, temp `PROXXX_CONFIG`, wiremock rejecting the
/// token (`401` on everything): `connectivity` is `ok` (`PVE reachable (HTTP 401)`),
/// `auth` is `fail`, and exit code is `1`.
/// Also verifies the `PxClient::new` failure path (missing `token_secret_file`)
/// falls back to the anonymous probe (treating `401` as reachable) while
/// reporting `auth` `fail` (`client init failed: ...`).
#[tokio::test]
async fn test_2_pve9_rejected_token_connectivity_ok_auth_fail_exit_1() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_dir = tmp.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");

    let pve = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/version"))
        .respond_with(ResponseTemplate::new(401).set_body_string("authentication failure"))
        .mount(&pve)
        .await;

    let cfg_path = tmp.path().join("config_bad_token.toml");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
default = "pve9"

[profiles.pve9]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret = "wrong-token-secret"
verify_tls = false
"#,
            pve.uri()
        ),
    )
    .expect("write config_bad_token.toml");

    let out = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_path)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "doctor"])
        .output()
        .expect("run proxxx doctor");

    assert_eq!(
        out.status.code(),
        Some(1),
        "doctor must exit 1 when token is rejected with 401"
    );

    let parsed: Value = serde_json::from_slice(&out.stdout).expect("parse doctor json");
    let checks = parsed.as_array().expect("checks array");

    let conn = find_check(checks, "connectivity");
    assert_eq!(
        conn["status"], "ok",
        "401 proves PVE is reachable: {conn:?}"
    );
    let conn_msg = conn["message"].as_str().unwrap_or_default();
    assert!(
        conn_msg.contains("PVE reachable (HTTP 401)"),
        "expected 'PVE reachable (HTTP 401)', got: {conn_msg}"
    );

    let auth = find_check(checks, "auth");
    assert_eq!(
        auth["status"], "fail",
        "auth must fail on 401, got: {auth:?}"
    );

    // Sub-case: `PxClient::new` itself fails (missing `token_secret_file`) while
    // PVE answers 401 to the anonymous fallback probe.
    let cfg_init_fail = tmp.path().join("config_missing_secret.toml");
    let nonexistent_secret = tmp.path().join("does-not-exist.secret");
    std::fs::write(
        &cfg_init_fail,
        format!(
            r#"
default = "pve9"

[profiles.pve9]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret_file = "{}"
verify_tls = false
"#,
            pve.uri(),
            nonexistent_secret.display()
        ),
    )
    .expect("write config_missing_secret.toml");

    let out_init_fail = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_init_fail)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "doctor"])
        .output()
        .expect("run proxxx doctor with missing secret file");

    assert_eq!(out_init_fail.status.code(), Some(1));
    let parsed_init: Value =
        serde_json::from_slice(&out_init_fail.stdout).expect("parse doctor json");
    let checks_init = parsed_init.as_array().expect("checks array");

    let conn_init = find_check(checks_init, "connectivity");
    assert_eq!(
        conn_init["status"], "ok",
        "anonymous fallback probe must treat HTTP 401 as reachable: {conn_init:?}"
    );
    let auth_init = find_check(checks_init, "auth");
    assert_eq!(auth_init["status"], "fail");
    assert!(
        auth_init["message"]
            .as_str()
            .unwrap_or_default()
            .contains("client init failed:"),
        "expected 'client init failed: ...', got: {:?}",
        auth_init["message"]
    );
}

/// Test 3 (#321):
/// Closed port: `connectivity` is `fail`, `auth` is `warn` (`skipped`), and
/// exit code is `1`.
#[tokio::test]
async fn test_3_closed_port_connectivity_fail_auth_skipped_exit_1() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_dir = tmp.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");

    let closed_port = allocate_closed_port();
    let cfg_path = tmp.path().join("config_closed.toml");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
default = "dead"

[profiles.dead]
url = "https://127.0.0.1:{closed_port}"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false
"#
        ),
    )
    .expect("write config_closed.toml");

    let out = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_path)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "doctor"])
        .output()
        .expect("run proxxx doctor against closed port");

    assert_eq!(
        out.status.code(),
        Some(1),
        "doctor must exit 1 when PVE is unreachable"
    );

    let parsed: Value = serde_json::from_slice(&out.stdout).expect("parse doctor json");
    let checks = parsed.as_array().expect("checks array");

    let conn = find_check(checks, "connectivity");
    assert_eq!(conn["status"], "fail", "connectivity check: {conn:?}");

    let auth = find_check(checks, "auth");
    assert_eq!(auth["status"], "warn", "auth check: {auth:?}");
    assert!(
        auth["message"]
            .as_str()
            .unwrap_or_default()
            .contains("skipped"),
        "auth message must state it was skipped, got: {:?}",
        auth["message"]
    );
}

/// Test 4 (#410):
/// E2E with a canary bot token and `HTTPS_PROXY` / `https_proxy` pointing at a
/// closed local port: `proxxx doctor` stdout AND stderr must NOT contain the
/// canary token string in either `--format json` or default table mode, and the
/// JSON `telegram` check message must start with `Telegram probe failed:`.
#[tokio::test]
async fn test_4_t1_telegram_canary_token_never_leaks_in_json_or_table() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_dir = tmp.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");

    let pve = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"version": "9.0.1", "release": "9.0"}
        })))
        .mount(&pve)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"node": "pve1", "status": "online"}]
        })))
        .mount(&pve)
        .await;

    let canary = "FAKE0000:canary-token-xyz-secret-410";
    let dead_proxy_port = allocate_closed_port();
    let dead_proxy = format!("http://127.0.0.1:{dead_proxy_port}");

    let cfg_path = tmp.path().join("config_t1.toml");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
default = "lab"

[profiles.lab]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false

[profiles.lab.telegram]
bot_token = "{canary}"
chat_id = "12345"
"#,
            pve.uri()
        ),
    )
    .expect("write config_t1.toml");

    // 1. `--format json`
    let out_json = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_path)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .env("HTTPS_PROXY", &dead_proxy)
        .env("https_proxy", &dead_proxy)
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .args(["--format", "json", "doctor"])
        .output()
        .expect("run proxxx doctor --format json");

    let json_stdout = String::from_utf8_lossy(&out_json.stdout);
    let json_stderr = String::from_utf8_lossy(&out_json.stderr);
    assert!(
        !json_stdout.contains(canary) && !json_stdout.contains("canary-token-xyz"),
        "#410 violation: canary bot token leaked in JSON stdout:\n{json_stdout}"
    );
    assert!(
        !json_stderr.contains(canary) && !json_stderr.contains("canary-token-xyz"),
        "#410 violation: canary bot token leaked in JSON stderr:\n{json_stderr}"
    );

    let parsed: Value = serde_json::from_slice(&out_json.stdout).expect("parse doctor json");
    let checks = parsed.as_array().expect("checks array");
    let tg = find_check(checks, "telegram");
    assert_eq!(
        tg["status"], "warn",
        "failed Telegram probe via dead proxy must warn, got: {tg:?}"
    );
    let tg_msg = tg["message"].as_str().unwrap_or_default();
    assert!(
        tg_msg.starts_with("Telegram probe failed:"),
        "telegram check message must start with 'Telegram probe failed:' (not a config/token error), got: {tg_msg:?}"
    );

    // 2. Default table output
    let out_table = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_path)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .env("HTTPS_PROXY", &dead_proxy)
        .env("https_proxy", &dead_proxy)
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .arg("doctor")
        .output()
        .expect("run proxxx doctor (table)");

    let table_stdout = String::from_utf8_lossy(&out_table.stdout);
    let table_stderr = String::from_utf8_lossy(&out_table.stderr);
    assert!(
        !table_stdout.contains(canary) && !table_stdout.contains("canary-token-xyz"),
        "#410 violation: canary bot token leaked in table stdout:\n{table_stdout}"
    );
    assert!(
        !table_stderr.contains(canary) && !table_stderr.contains("canary-token-xyz"),
        "#410 violation: canary bot token leaked in table stderr:\n{table_stderr}"
    );
}

/// Test 5 (#411):
/// `wiremock` Telegram returning `401 {"ok":false,"error_code":401,"description":"Unauthorized"}`
/// -> `telegram` check is NOT `ok` (`warn` with HTTP status and description, never the URL/token);
/// `200 {"ok":true,"result":{...}}` -> `ok`.
#[tokio::test]
async fn test_5_t2_telegram_get_me_checks_http_status_and_ok_field() {
    use proxxx::cli::doctor::check_telegram_with_gateway;
    use proxxx::hitl::telegram::TelegramGateway;

    // 1. 401 {"ok":false,"error_code":401,"description":"Unauthorized"} -> warn (NOT ok)
    let tg_401 = MockServer::start().await;
    let canary = "FAKE0000:canary-t2-token";
    Mock::given(method("GET"))
        .and(path(format!("/bot{canary}/getMe")))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "ok": false,
            "error_code": 401,
            "description": "Unauthorized"
        })))
        .mount(&tg_401)
        .await;

    let gw_401 = TelegramGateway::with_base_url(
        canary,
        "98765".to_string(),
        format!("{}/bot", tg_401.uri()),
    );
    let res_401 = check_telegram_with_gateway(&gw_401).await;
    assert_eq!(
        res_401["status"], "warn",
        "401 Unauthorized from Telegram getMe must NOT report ok: {res_401:?}"
    );
    let msg_401 = res_401["message"].as_str().unwrap_or_default();
    assert!(
        msg_401.contains("401") && msg_401.contains("Unauthorized"),
        "warn message must include HTTP status 401 and Telegram description 'Unauthorized', got: {msg_401}"
    );
    assert!(
        !msg_401.contains(canary) && !msg_401.contains(&tg_401.uri()),
        "warn message must never include the bot token or request URL, got: {msg_401}"
    );

    // 2. 200 {"ok":false,"description":"Bot token revoked"} -> warn (NOT ok)
    let tg_200_false = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/bot{canary}/getMe")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "description": "Bot token revoked"
        })))
        .mount(&tg_200_false)
        .await;

    let gw_200_false = TelegramGateway::with_base_url(
        canary,
        "98765".to_string(),
        format!("{}/bot", tg_200_false.uri()),
    );
    let res_200_false = check_telegram_with_gateway(&gw_200_false).await;
    assert_eq!(
        res_200_false["status"], "warn",
        "200 with ok=false must NOT report ok: {res_200_false:?}"
    );
    assert!(
        res_200_false["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Bot token revoked"),
        "expected description in message, got: {res_200_false:?}"
    );

    // 3. 200 {"ok":true,"result":{"id":42,"first_name":"proxxx_bot"}} -> ok
    let tg_200_ok = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/bot{canary}/getMe")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "id": 42,
                "is_bot": true,
                "first_name": "proxxx_bot",
                "username": "proxxx_bot"
            }
        })))
        .mount(&tg_200_ok)
        .await;

    let gw_200_ok = TelegramGateway::with_base_url(
        canary,
        "98765".to_string(),
        format!("{}/bot", tg_200_ok.uri()),
    );
    let res_200_ok = check_telegram_with_gateway(&gw_200_ok).await;
    assert_eq!(
        res_200_ok["status"], "ok",
        "200 with ok=true must report ok: {res_200_ok:?}"
    );
    assert!(
        res_200_ok["message"]
            .as_str()
            .unwrap_or_default()
            .contains("chat_id = 98765"),
        "expected chat_id in ok message, got: {res_200_ok:?}"
    );
}

/// Test 6 (PBS):
/// `wiremock` PBS with a `401` on anonymous `/api2/json/version` and a valid
/// token (`Authorization: PBSAPIToken=backup@pbs!reader:pbs-secret-1`) ->
/// `pbs` `ok`; token rejected (`401` on all `/api2/json/version`) -> `pbs`
/// `warn` mentioning `credentials rejected` and `HTTP 401`.
#[tokio::test]
async fn test_6_pbs_authenticated_version_probe_ok_and_rejected_credentials_warn() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_dir = tmp.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");

    let pve = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"version": "9.0.1", "release": "9.0"}
        })))
        .mount(&pve)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"node": "pve1", "status": "online"}]
        })))
        .mount(&pve)
        .await;

    let pbs = MockServer::start().await;
    let valid_pbs_auth = "PBSAPIToken=backup@pbs!reader:pbs-secret-1";

    // Authenticated PBS `/api2/json/version` -> 200
    Mock::given(method("GET"))
        .and(path("/api2/json/version"))
        .and(header("Authorization", valid_pbs_auth))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"version": "3.2", "release": "3", "repoid": "abc1234"}
        })))
        .with_priority(1)
        .mount(&pbs)
        .await;

    // Anonymous or bad-token PBS `/api2/json/version` -> 401 non-JSON body
    Mock::given(method("GET"))
        .and(path("/api2/json/version"))
        .respond_with(ResponseTemplate::new(401).set_body_string("authentication failed"))
        .with_priority(10)
        .mount(&pbs)
        .await;

    // 1. Valid PBS token -> `pbs` check is `ok`
    let cfg_ok = tmp.path().join("config_pbs_ok.toml");
    std::fs::write(
        &cfg_ok,
        format!(
            r#"
default = "lab"

[profiles.lab]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false

[profiles.lab.pbs]
url = "{}"
user = "backup@pbs"
token_id = "reader"
token_secret = "pbs-secret-1"
verify_tls = false
"#,
            pve.uri(),
            pbs.uri()
        ),
    )
    .expect("write config_pbs_ok.toml");

    let out_ok = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_ok)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "doctor"])
        .output()
        .expect("run proxxx doctor with valid pbs token");

    assert_eq!(out_ok.status.code(), Some(0));
    let parsed_ok: Value = serde_json::from_slice(&out_ok.stdout).expect("parse doctor json");
    let checks_ok = parsed_ok.as_array().expect("checks array");
    let pbs_ok = find_check(checks_ok, "pbs");
    assert_eq!(
        pbs_ok["status"], "ok",
        "PBS with valid token and 401 on anonymous /version must be ok: {pbs_ok:?}"
    );
    assert!(
        pbs_ok["message"]
            .as_str()
            .unwrap_or_default()
            .contains("version 3.2"),
        "expected PBS version 3.2 in message, got: {:?}",
        pbs_ok["message"]
    );

    // 2. Rejected PBS token -> `pbs` check is `warn` mentioning credentials
    let cfg_bad = tmp.path().join("config_pbs_bad.toml");
    std::fs::write(
        &cfg_bad,
        format!(
            r#"
default = "lab"

[profiles.lab]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false

[profiles.lab.pbs]
url = "{}"
user = "backup@pbs"
token_id = "reader"
token_secret = "wrong-pbs-secret"
verify_tls = false
"#,
            pve.uri(),
            pbs.uri()
        ),
    )
    .expect("write config_pbs_bad.toml");

    let out_bad = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_bad)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "doctor"])
        .output()
        .expect("run proxxx doctor with invalid pbs token");

    // PBS is optional (Warn severity), so overall doctor still exits 0 when PVE is healthy.
    assert_eq!(out_bad.status.code(), Some(0));
    let parsed_bad: Value = serde_json::from_slice(&out_bad.stdout).expect("parse doctor json");
    let checks_bad = parsed_bad.as_array().expect("checks array");
    let pbs_bad = find_check(checks_bad, "pbs");
    assert_eq!(
        pbs_bad["status"], "warn",
        "PBS with rejected token must be warn: {pbs_bad:?}"
    );
    let pbs_bad_msg = pbs_bad["message"].as_str().unwrap_or_default();
    assert!(
        pbs_bad_msg.contains("credentials rejected") && pbs_bad_msg.contains("HTTP 401"),
        "PBS warn message on 401 must contain 'credentials rejected' and 'HTTP 401', got: {pbs_bad_msg}"
    );
}
