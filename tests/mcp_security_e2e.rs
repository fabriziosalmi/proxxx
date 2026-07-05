#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]
//! MCP security invariants — fail-closed gating of the network-reachable
//! MCP transport.
//!
//! Threat: the MCP HTTP server can be exposed on the network and (if
//! `mcp_token` is unset) served without auth. Combined with the legacy
//! "no matching policy = execute immediately" behaviour, an unauthenticated
//! caller could drive a destructive tool (`delete_guest`, …) with the
//! profile's PVE credentials. These tests pin the two fail-closed defences:
//!
//! 1. dispatch: a destructive tool with NO governing HITL policy is REFUSED
//!    (never reaches the gateway) — `mcp_destructive_without_policy_is_refused`.
//! 2. startup: the HTTP server REFUSES to bind a non-loopback interface
//!    without auth — `mcp_http_nonloopback_without_token_refuses_start`.
//!
//! A positive control proves the sanctioned path still works: a matching
//! policy routes the op to HITL approval (intercepted, not executed inline).

use std::sync::Arc;

use proxxx::api::PxClient;
use proxxx::config::ProfileConfig;
use proxxx::hitl::policy::Policy;
use serde_json::json;

/// Build an offline token-auth client. Token auth resolves locally, so
/// `PxClient::new` performs no network I/O — the URL is never dialled unless
/// a tool actually executes, which is exactly what these tests assert does
/// NOT happen on the refused paths.
async fn offline_client() -> Arc<PxClient> {
    let cfg = base_cfg(None);
    Arc::new(
        PxClient::new(cfg, Some("fake-secret"))
            .await
            .expect("token-auth client builds offline"),
    )
}

fn base_cfg(policies: Option<Vec<Policy>>) -> ProfileConfig {
    ProfileConfig {
        // 127.0.0.1:1 is effectively unroutable — if any of these tests ever
        // reaches execution, the connect fails loudly instead of silently
        // hitting a real host.
        url: "https://127.0.0.1:1".into(),
        user: "root@pam".into(),
        auth: "token".into(),
        token_id: Some("mcp-sec-test".into()),
        token_secret: None,
        token_secret_file: None,
        password: None,
        verify_tls: false,
        tls_pin_mode: None,
        read_only: false,
        rate_limit: Some(100),
        policies,
        telegram: None,
        ssh: None,
        pbs: None,
        alerts: None,
        mcp_token: None,
        reconcile: None,
        profile_name: None,
    }
}

#[tokio::test]
async fn mcp_destructive_without_policy_is_refused() {
    let client = offline_client().await;
    let cfg = base_cfg(None); // no policies at all

    let out = proxxx::mcp::dispatch::handle_tool_call(
        &client,
        &cfg,
        "delete_guest",
        &json!({ "guest_id": 100 }),
    )
    .await
    .expect("dispatch returns a controlled envelope, not a transport error");

    // Fail-closed: the call is refused with an error envelope, and — because
    // it returned before touching the gateway — no network op occurred.
    assert_eq!(
        out.get("isError").and_then(serde_json::Value::as_bool),
        Some(true),
        "destructive tool without policy must return isError=true, got: {out}"
    );
    let text = out["content"][0]["text"]
        .as_str()
        .expect("content text present");
    assert!(
        text.contains("Refused") && text.to_lowercase().contains("destructive"),
        "refusal message should explain the destructive-op denial, got: {text}"
    );
}

#[tokio::test]
async fn mcp_destructive_with_matching_policy_routes_to_approval_not_execution() {
    // Positive control: a wildcard policy governs the op → it is INTERCEPTED
    // for HITL approval, not executed inline. Telegram is unconfigured, so the
    // approval request is skipped but the intercept envelope is still returned;
    // the op never reaches PVE.
    let client = offline_client().await;
    let cfg = base_cfg(Some(vec![Policy {
        action: "*".into(),
        target: "*".into(),
        channel: "telegram".into(),
        require: 1,
    }]));

    let out = proxxx::mcp::dispatch::handle_tool_call(
        &client,
        &cfg,
        "delete_guest",
        &json!({ "guest_id": 100 }),
    )
    .await
    .expect("dispatch returns the intercept envelope");

    let text = out["content"][0]["text"]
        .as_str()
        .expect("content text present");
    assert!(
        text.contains("intercepted by HITL policy"),
        "matching policy must intercept for approval, got: {text}"
    );
    // Not flagged as an error — it's a pending approval, a legitimate outcome.
    assert_ne!(
        out.get("isError").and_then(serde_json::Value::as_bool),
        Some(true),
        "intercept is not an error envelope"
    );
}

#[tokio::test]
async fn mcp_http_nonloopback_without_token_refuses_start() {
    let client = offline_client().await;
    let handle = proxxx::config::watcher::new_handle(base_cfg(None)); // mcp_token: None

    // bind 0.0.0.0, no token, insecure_bind=false → must refuse BEFORE binding.
    let res = proxxx::mcp::http_server::run_http_server(
        client, handle, "0.0.0.0", 0, // port never reached — preflight bails first
        false,
    )
    .await;

    let err = res.expect_err("server must refuse to start on exposed bind without auth");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Refusing to start") && msg.contains("non-loopback"),
        "error must name the fail-closed reason, got: {msg}"
    );
}

/// Registry contract: the destructive-tool set is an explicit whitelist. Every
/// entry here is fail-closed (policy-gated) on the MCP path, so a silent flag
/// flip in either direction changes the security posture — this test forces the
/// change to be conscious. `suspend_guest` is included (it pauses a running VM).
#[test]
fn destructive_tool_set_matches_expected_whitelist() {
    let mut got: Vec<&str> = proxxx::mcp::tools::TOOLS
        .iter()
        .filter(|t| t.destructive)
        .map(|t| t.name)
        .collect();
    got.sort_unstable();
    let mut want = vec![
        "clone_guest",
        "clone_with_cloudinit",
        "create_guest",
        "create_snapshot",
        "delete_guest",
        "delete_snapshot",
        "migrate_guest",
        "restart_guest",
        "stop_guest",
        "suspend_guest",
    ];
    want.sort_unstable();
    assert_eq!(
        got, want,
        "destructive-tool set changed — update the whitelist consciously (each entry is \
         policy-gated / fail-closed on MCP)"
    );
}

/// The fail-closed gate is uniform (`tool_def.destructive`), not delete-specific.
/// Prove it for representatives spanning the required-param shapes; the registry
/// contract above covers the multi-param remainder (create/clone) that share the
/// identical gate branch.
#[tokio::test]
async fn every_destructive_tool_refuses_without_policy() {
    let client = offline_client().await;
    let cfg = base_cfg(None); // no policies → the gate must refuse

    let cases: &[(&str, serde_json::Value)] = &[
        ("stop_guest", json!({ "guest_id": 100 })),
        ("restart_guest", json!({ "guest_id": 100 })),
        ("delete_guest", json!({ "guest_id": 100 })),
        ("suspend_guest", json!({ "guest_id": 100 })),
        (
            "migrate_guest",
            json!({ "guest_id": 100, "target_node": "pve2" }),
        ),
        (
            "delete_snapshot",
            json!({ "guest_id": 100, "name": "snap1" }),
        ),
        (
            "create_snapshot",
            json!({ "guest_id": 100, "name": "snap1" }),
        ),
        // Highest-blast multi-param tools — proven behaviorally, not just via
        // the registry flag. create_guest has no guest_id (it mints one), so it
        // exercises the vmid-absent gate path.
        ("create_guest", json!({ "node": "pve1", "type": "lxc" })),
        ("clone_guest", json!({ "guest_id": 100 })),
        ("clone_with_cloudinit", json!({ "guest_id": 100 })),
    ];

    for (tool, args) in cases {
        let out = proxxx::mcp::dispatch::handle_tool_call(&client, &cfg, tool, args)
            .await
            .unwrap_or_else(|e| panic!("{tool}: dispatch should return an envelope, got err: {e}"));
        assert_eq!(
            out.get("isError").and_then(serde_json::Value::as_bool),
            Some(true),
            "{tool}: a destructive tool with no policy MUST refuse (isError=true), got: {out}"
        );
    }
}
