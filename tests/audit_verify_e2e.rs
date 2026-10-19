#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]
//! Audit-chain verifiability — the ADMIN-facing contract.
//!
//! The audit chain is only useful to an auditor if they can *run something* that
//! proves the log wasn't tampered with, and that thing must fail loudly when it
//! was. This drives the real `proxxx audit verify` binary end-to-end:
//!
//!   * a clean chain → exit 0 (`proxxx audit verify && echo trusted`)
//!   * one tampered row → exit 1 (scriptable / monitorable alarm)
//!
//! The logger-level mutation detection is exhaustively proptested in
//! `src/audit/mod.rs`; this pins the CLI exit-code contract an operator's cron
//! job actually depends on.
//!
//! Each test injects its own temporary `audit_dir` via `PxClient::with_audit_dir`,
//! `AuditLogger::open_in`, or `MutationAuditCtx::write_ahead_at` (and passes
//! `PROXXX_AUDIT_DIR` only to child processes via `Command::env`), so the
//! process-global environment is never mutated.

use std::path::Path;
use std::process::Command;

use proxxx::api::types::GuestType;
use proxxx::api::{ProxmoxGateway, PxClient};
use proxxx::audit::{AuditLogger, AuditWriteRefusal};
use proxxx::config::ProfileConfig;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const fn proxxx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_proxxx")
}

/// Serialises tests in this binary so the process-wide verify call-count
/// metrics (`full_verify_call_count` / `tail_verify_call_count`) are not
/// incremented concurrently by sibling tests.
static AUDIT_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn mock_client_with_profile(
    server: &MockServer,
    profile_name: Option<&str>,
    audit_dir: &Path,
) -> PxClient {
    let cfg = ProfileConfig {
        url: server.uri(),
        user: "root@pam".into(),
        auth: "token".into(),
        token_id: Some("test".into()),
        token_secret: None,
        token_secret_file: None,
        password: None,
        verify_tls: false,
        tls_pin_mode: None,
        read_only: false,
        rate_limit: Some(100),
        policies: None,
        telegram: None,
        ssh: None,
        pbs: None,
        alerts: None,
        mcp_token: None,
        reconcile: None,
        profile_name: profile_name.map(str::to_string),
    };
    PxClient::new(cfg, Some("fake-secret"))
        .await
        .expect("client builds")
        .with_audit_dir(audit_dir)
}

#[tokio::test]
async fn audit_verify_exit_code_reflects_tampering() {
    let _guard = AUDIT_TEST_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("temp dir");
    let audit_dir = dir.path().to_str().unwrap().to_string();

    // Write a short chain via the real logger in `dir`.
    {
        let mut logger = AuditLogger::open_in(dir.path()).expect("open audit logger");
        logger
            .log(
                "delete",
                "alice",
                Some(100),
                Some("pve1"),
                Some("{\"k\":1}"),
                "ok",
            )
            .unwrap();
        logger
            .log("stop", "bob", Some(101), Some("pve1"), None, "ok")
            .unwrap();
        logger
            .log("migrate", "carol", Some(102), Some("pve2"), None, "ok")
            .unwrap();
    }

    // (1) Clean chain → `audit verify` exits 0.
    let clean = Command::new(proxxx_bin())
        .args(["audit", "verify"])
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .env_remove("PROXXX_AUDIT_KEY")
        .output()
        .expect("run audit verify");
    assert!(
        clean.status.success(),
        "clean chain must verify (exit 0). stdout={} stderr={}",
        String::from_utf8_lossy(&clean.stdout),
        String::from_utf8_lossy(&clean.stderr),
    );

    // Tamper: rewrite the actor of the first row directly in SQLite — exactly
    // the "rewrite who ran the delete" attack the chain exists to catch.
    {
        let db = dir.path().join("audit.db");
        let conn = rusqlite::Connection::open(&db).expect("open audit db");
        let n = conn
            .execute("UPDATE audit_log SET user = 'mallory' WHERE id = 1", [])
            .expect("tamper");
        assert_eq!(n, 1, "expected to rewrite exactly one row");
    }

    // (2) Tampered chain → `audit verify` exits non-zero.
    let tampered = Command::new(proxxx_bin())
        .args(["audit", "verify"])
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .env_remove("PROXXX_AUDIT_KEY")
        .output()
        .expect("run audit verify");
    assert!(
        !tampered.status.success(),
        "tampered chain MUST fail verification (non-zero exit). stdout={} stderr={}",
        String::from_utf8_lossy(&tampered.stdout),
        String::from_utf8_lossy(&tampered.stderr),
    );
}

/// Step 11 (`#344`), Test 1:
/// With a temp audit dir injected on `PxClient` and a wiremock PVE: a
/// `delete_guest` produces two entries (`sent`, then `ok 200`) with the right
/// `action`, `node`, `vmid`, `user`; `audit verify` reports the chain intact.
#[tokio::test]
async fn delete_guest_writes_sent_and_ok_200_and_verifies_clean() {
    let _guard = AUDIT_TEST_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("temp dir");

    let server = MockServer::start().await;
    // Pre-flight status check inside `delete_guest` (GET — must not log).
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/qemu/100/status/current"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "vmid": 100,
                "name": "vm100",
                "status": "stopped"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;
    // Actual DELETE call.
    Mock::given(method("DELETE"))
        .and(path("/api2/json/nodes/pve1/qemu/100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": "UPID:pve1:00000001:00000001:qmestroy:100:root@pam:"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client_with_profile(&server, Some("prod"), dir.path()).await;
    let upid = client
        .delete_guest("pve1", 100, GuestType::Qemu)
        .await
        .expect("delete_guest succeeds");
    assert!(upid.starts_with("UPID:pve1:"));

    let logger = AuditLogger::open_in(dir.path()).expect("open audit logger");
    // `query` returns DESC order by `id`; reverse for chronological (`id=1`, `id=2`).
    let mut entries = logger.query(10, None).expect("query entries");
    entries.reverse();
    assert_eq!(
        entries.len(),
        2,
        "delete_guest must write exactly two entries (sent + ok 200); got: {entries:?}"
    );

    let expected_user = proxxx::incident::operator_label();
    for entry in &entries {
        assert_eq!(entry.action, "DELETE /nodes/pve1/qemu/100");
        assert_eq!(entry.node.as_deref(), Some("pve1"));
        assert_eq!(entry.vmid, Some(100));
        assert_eq!(entry.user, expected_user);
        let params: serde_json::Value =
            serde_json::from_str(entry.params_json.as_deref().expect("params_json")).unwrap();
        assert_eq!(params["profile"], "prod");
    }
    assert_eq!(entries[0].result, "sent");
    assert_eq!(entries[1].result, "ok 200");

    assert_eq!(logger.verify().expect("verify"), (2, 0));

    let verify_cmd = Command::new(proxxx_bin())
        .args(["audit", "verify"])
        .env("PROXXX_AUDIT_DIR", dir.path())
        .env_remove("PROXXX_AUDIT_KEY")
        .output()
        .expect("run proxxx audit verify");
    assert!(
        verify_cmd.status.success(),
        "CLI `proxxx audit verify` must exit 0 on intact chain: stdout={} stderr={}",
        String::from_utf8_lossy(&verify_cmd.stdout),
        String::from_utf8_lossy(&verify_cmd.stderr)
    );
}

/// Step 11 (`#344`), Test 2:
/// A failing PVE call (500) produces `sent` then `error 500`.
#[tokio::test]
async fn failing_pve_call_500_writes_sent_then_error_500() {
    let _guard = AUDIT_TEST_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("temp dir");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api2/json/nodes/pve1/qemu/100/status/stop"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client_with_profile(&server, Some("prod"), dir.path()).await;
    let _err = client
        .stop_guest("pve1", 100, GuestType::Qemu, false)
        .await
        .expect_err("HTTP 500 must fail");

    let logger = AuditLogger::open_in(dir.path()).expect("open audit logger");
    let mut entries = logger.query(10, None).expect("query entries");
    entries.reverse();
    assert_eq!(entries.len(), 2, "expected sent + error 500");
    assert_eq!(entries[0].action, "POST /nodes/pve1/qemu/100/status/stop");
    assert_eq!(entries[0].node.as_deref(), Some("pve1"));
    assert_eq!(entries[0].vmid, Some(100));
    assert_eq!(entries[0].result, "sent");

    assert_eq!(entries[1].action, "POST /nodes/pve1/qemu/100/status/stop");
    assert_eq!(entries[1].node.as_deref(), Some("pve1"));
    assert_eq!(entries[1].vmid, Some(100));
    assert_eq!(entries[1].result, "error 500");
    assert_eq!(logger.verify().expect("verify"), (2, 0));
}

/// Step 11 (`#344`), Test 3:
/// Redaction: a POST with `password=hunter2` (e.g. user create) stores
/// `"[REDACTED]"` and `"hunter2"` appears nowhere in the DB file bytes.
#[tokio::test]
async fn post_with_secret_params_redacts_values_and_never_writes_plaintext_to_db_bytes() {
    let _guard = AUDIT_TEST_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("temp dir");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api2/json/access/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client_with_profile(&server, Some("prod"), dir.path()).await;
    client
        .create_user(
            "alice@pve",
            Some("hunter2"),
            Some("Alice Operator"),
            None,
            None,
            None,
            Some(true),
            None,
            None,
        )
        .await
        .expect("create_user succeeds");

    let logger = AuditLogger::open_in(dir.path()).expect("open audit logger");
    let mut entries = logger.query(10, None).expect("query entries");
    entries.reverse();
    assert_eq!(entries.len(), 2);
    for entry in &entries {
        assert_eq!(entry.action, "POST /access/users");
        let params: serde_json::Value =
            serde_json::from_str(entry.params_json.as_deref().expect("params_json")).unwrap();
        assert_eq!(params["userid"], "alice@pve");
        assert_eq!(params["password"], "[REDACTED]");
        assert_eq!(params["profile"], "prod");
    }
    assert_eq!(entries[0].result, "sent");
    assert_eq!(entries[1].result, "ok 200");
    assert_eq!(logger.verify().expect("verify"), (2, 0));

    // Inspect raw bytes of every file in the audit directory to guarantee
    // the secret plaintext never reached disk.
    for dir_entry in std::fs::read_dir(dir.path()).expect("read audit dir") {
        let path = dir_entry.expect("entry").path();
        let bytes = std::fs::read(&path).expect("read file bytes");
        assert!(
            !bytes.windows(b"hunter2".len()).any(|w| w == b"hunter2"),
            "plaintext password `hunter2` must never appear in {}",
            path.display()
        );
    }
}

/// Step 11 (`#344`), Test 4:
/// Fail-closed: audit dir unwritable (or broken chain) -> the mutation is
/// refused (exit 8) and wiremock receives **no request**.
#[cfg(unix)]
#[tokio::test]
async fn fail_closed_unwritable_audit_dir_or_broken_chain_refuses_mutation_with_exit_8_and_sends_no_request(
) {
    use std::os::unix::fs::PermissionsExt;

    let _guard = AUDIT_TEST_LOCK.lock().await;
    let outer = tempfile::tempdir().expect("temp dir");
    let readonly_parent = outer.path().join("readonly");
    std::fs::create_dir_all(&readonly_parent).unwrap();
    std::fs::set_permissions(&readonly_parent, std::fs::Permissions::from_mode(0o500)).unwrap();
    let unwritable_audit_dir = readonly_parent.join("cannot_create");

    let server = MockServer::start().await;
    let client = mock_client_with_profile(&server, Some("prod"), &unwritable_audit_dir).await;
    let err = client
        .start_guest("pve1", 100, GuestType::Qemu)
        .await
        .expect_err("unwritable audit dir must refuse mutation");

    let refusal = err
        .chain()
        .find_map(|c| c.downcast_ref::<AuditWriteRefusal>())
        .expect("error must downcast to AuditWriteRefusal");
    assert_eq!(AuditWriteRefusal::EXIT_CODE, 8);
    assert_eq!(refusal.action, "POST /nodes/pve1/qemu/100/status/start");
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "wiremock must receive NO request when write-ahead audit fails"
    );

    // Also verify the CLI binary maps AuditWriteRefusal to exit code 8.
    let cfg_dir = outer.path().join("cfg");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    let cfg_path = cfg_dir.join("config.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "url = \"{}\"\nuser = \"root@pam\"\nauth = \"token\"\ntoken_id = \"test\"\nverify_tls = false\n",
            server.uri()
        ),
    )
    .unwrap();
    let cli_out = Command::new(proxxx_bin())
        .args([
            "--token-secret",
            "fake-secret",
            "access",
            "user-delete",
            "alice@pve",
            "--yes",
        ])
        .env("PROXXX_CONFIG", &cfg_path)
        .env("PROXXX_AUDIT_DIR", &unwritable_audit_dir)
        .env_remove("PROXXX_AUDIT_KEY")
        .output()
        .expect("run proxxx access user delete");
    assert_eq!(
        cli_out.status.code(),
        Some(8),
        "CLI must exit 8 on AuditWriteRefusal: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_out.stdout),
        String::from_utf8_lossy(&cli_out.stderr),
    );
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "wiremock must still have received 0 requests after CLI refusal"
    );

    // Restore permissions on `readonly_parent` so TempDir cleanup succeeds.
    std::fs::set_permissions(&readonly_parent, std::fs::Permissions::from_mode(0o700)).unwrap();

    // Part B: Broken HMAC chain in an otherwise writable audit directory must
    // also fail closed (AuditWriteRefusal / exit 8) and send NO request.
    let broken_dir = outer.path().join("broken_chain");
    std::fs::create_dir_all(&broken_dir).unwrap();
    let mut logger = AuditLogger::open_in(&broken_dir).expect("open broken_dir logger");
    logger
        .log(
            "POST /nodes/pve1/qemu/100/status/start",
            "root@pam",
            Some(100),
            Some("pve1"),
            None,
            "ok 200",
        )
        .expect("seed entry");
    drop(logger);
    let conn = rusqlite::Connection::open(broken_dir.join("audit.db")).unwrap();
    conn.execute("UPDATE audit_log SET result = 'tampered' WHERE id = 1", [])
        .unwrap();
    drop(conn);

    let broken_client = mock_client_with_profile(&server, Some("prod"), &broken_dir).await;
    let broken_err = broken_client
        .start_guest("pve1", 100, GuestType::Qemu)
        .await
        .expect_err("broken audit chain must refuse mutation");
    let broken_refusal = broken_err
        .chain()
        .find_map(|c| c.downcast_ref::<AuditWriteRefusal>())
        .expect("broken chain error must downcast to AuditWriteRefusal");
    assert!(
        broken_refusal.reason.contains("tampered"),
        "expected tampered chain refusal reason, got: {}",
        broken_refusal.reason
    );
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "wiremock must still have received 0 requests after broken-chain refusal"
    );
}

/// Step 11 (`#344`), Test 5:
/// GET requests write nothing.
#[tokio::test]
async fn get_requests_write_nothing_to_audit_log() {
    let _guard = AUDIT_TEST_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("temp dir");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/cluster/resources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client_with_profile(&server, Some("prod"), dir.path()).await;
    let nodes = client.get_nodes().await.expect("get_nodes");
    assert!(nodes.is_empty());
    let resources = client
        .get_cluster_resources(None)
        .await
        .expect("get_cluster_resources");
    assert!(resources.is_empty());

    assert!(
        !dir.path().join("audit.db").exists(),
        "GET requests must not even open/create audit.db"
    );
}

/// Step 11 (`#344` Rev. 16), Test 6:
/// With N = 2000 rows already in `audit.db`, opening the process-wide logger
/// runs full `verify()` once, and N = 2000 subsequent mutations do NOT call
/// the full verifier again (only the O(1) tail-link check runs per write).
#[tokio::test]
async fn write_ahead_verifies_full_chain_once_and_only_tail_link_across_2000_mutations() {
    const N: usize = 2000;

    let _guard = AUDIT_TEST_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("temp dir");

    // Seed N = 2000 valid chained rows before the process-wide logger opens
    // this directory.
    {
        let mut seed_logger = AuditLogger::open_in(dir.path()).expect("open seed logger");
        for i in 0..N {
            seed_logger
                .log(
                    "POST /nodes/pve1/qemu/100/status/start",
                    "root@pam",
                    Some(100),
                    Some("pve1"),
                    Some("{\"profile\":\"prod\"}"),
                    if i % 2 == 0 { "sent" } else { "ok 200" },
                )
                .expect("seed row");
        }
    }

    let full_before = proxxx::audit::full_verify_call_count();
    let tail_before = proxxx::audit::tail_verify_call_count();

    // Perform N = 2000 subsequent mutations through the write-ahead gate.
    for i in 0..N {
        let ctx = proxxx::audit::MutationAuditCtx::write_ahead_at(
            "POST",
            "/nodes/pve1/qemu/100/status/start",
            &[],
            "prod",
            Some(dir.path()),
        )
        .expect("write_ahead_at must succeed");
        if i == 0 {
            assert_eq!(
                proxxx::audit::full_verify_call_count(),
                full_before + 1,
                "first mutation must run full verify() exactly once when opening the process logger"
            );
        }
        ctx.record_outcome("ok 200");
    }

    assert_eq!(
        proxxx::audit::full_verify_call_count(),
        full_before + 1,
        "2000 subsequent mutations must NOT call full verify() again after initial open"
    );
    assert_eq!(
        proxxx::audit::tail_verify_call_count(),
        tail_before + N,
        "each of the 2000 mutations must check the tail link once"
    );

    // Confirm all 6000 rows (2000 seeded + 2000 * 2 mutation rows) form an
    // intact chain.
    let verifier = AuditLogger::open_in(dir.path()).expect("open verifier");
    assert_eq!(verifier.verify().expect("full verify"), (N + 2 * N, 0));
    drop(verifier);

    // Tamper with the tail row (id = 6000) while the process logger is still
    // open: the next mutation must fail closed via `verify_tail()` without
    // calling full `verify()`.
    let full_before_tamper = proxxx::audit::full_verify_call_count();
    let conn = rusqlite::Connection::open(dir.path().join("audit.db")).unwrap();
    let updated = conn
        .execute(
            "UPDATE audit_log SET result = 'tampered-tail' WHERE id = ?1",
            rusqlite::params![(N + 2 * N) as i64],
        )
        .unwrap();
    assert_eq!(updated, 1);
    drop(conn);

    let err = proxxx::audit::MutationAuditCtx::write_ahead_at(
        "POST",
        "/nodes/pve1/qemu/100/status/start",
        &[],
        "prod",
        Some(dir.path()),
    )
    .expect_err("tampered tail row must be caught by O(1) verify_tail");
    let refusal = err
        .chain()
        .find_map(|c| c.downcast_ref::<AuditWriteRefusal>())
        .expect("must downcast to AuditWriteRefusal");
    assert!(refusal.reason.contains("tampered"));
    assert_eq!(
        proxxx::audit::full_verify_call_count(),
        full_before_tamper,
        "catching a tampered tail row must use verify_tail(), not full verify()"
    );
}
