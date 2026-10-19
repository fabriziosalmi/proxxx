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

/// Send a raw HTTP/1.1 request over a TCP stream and return `(status_code, headers_lower, body)`.
///
/// Used to exercise wire-level cases (including a missing `Host` header, which
/// HTTP client libraries otherwise auto-populate from the URL) against the real
/// `axum::serve` stack.
async fn raw_http_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String, String) {
    use std::fmt::Write as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to test MCP server");
    let mut raw = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in headers {
        let _ = write!(raw, "{k}: {v}\r\n");
    }
    if !body.is_empty() {
        let _ = write!(
            raw,
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
    }
    raw.push_str("Connection: close\r\n\r\n");
    raw.push_str(body);

    stream
        .write_all(raw.as_bytes())
        .await
        .expect("write raw HTTP request");

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut chunk))
            .await
            .unwrap_or(Ok(0))
            .expect("read raw HTTP response");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        // For SSE 200 responses, stop as soon as we have the full header block.
        if path == "/mcp"
            && method == "GET"
            && buf.windows(4).any(|w| w == b"\r\n\r\n")
            && buf.starts_with(b"HTTP/1.1 200")
        {
            break;
        }
    }

    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, resp_body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status_line = head.lines().next().expect("HTTP status line");
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code token")
        .parse()
        .expect("numeric status code");
    (code, head.to_ascii_lowercase(), resp_body.to_owned())
}

#[tokio::test]
async fn cli_token_survives_config_reload_on_loopback_and_exposed_binds() {
    use proxxx::util::secret::SecretString;

    let ping_body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;

    // 1. Loopback bind started with a CLI `--token` and NO `mcp_token` in config.
    let client = offline_client().await;
    let handle = proxxx::config::watcher::new_handle(base_cfg(None));
    assert!(
        handle.read().await.mcp_token.is_none(),
        "CLI token must never be written into the reloadable ConfigHandle"
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let port = addr.port();
    let host_hdr = format!("127.0.0.1:{port}");

    let app = proxxx::mcp::http_server::build_http_router(
        Arc::clone(&client),
        Arc::clone(&handle),
        "127.0.0.1",
        port,
        false,
        Some(SecretString::from("cli-loopback-secret")),
        &[],
    );
    let srv = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Reload swaps in a fresh config WITHOUT `mcp_token`.
    let reloaded = proxxx::config::watcher::reload_once(&handle, || Ok(base_cfg(None))).await;
    assert!(reloaded, "reload_once must succeed");
    assert!(handle.read().await.mcp_token.is_none());

    // Request with the CLI bearer is still accepted (200).
    let (code, _, _) = raw_http_request(
        addr,
        "POST",
        "/mcp",
        &[
            ("Host", &host_hdr),
            ("Authorization", "Bearer cli-loopback-secret"),
        ],
        ping_body,
    )
    .await;
    assert_eq!(
        code, 200,
        "CLI bearer must still be accepted after config reload"
    );

    // Request without bearer is still refused (401) — reload did NOT drop the CLI token.
    let (code, _, _) =
        raw_http_request(addr, "POST", "/mcp", &[("Host", &host_hdr)], ping_body).await;
    assert_eq!(
        code, 401,
        "missing bearer must still be refused after config reload"
    );

    srv.abort();

    // 2. Exposed bind (`0.0.0.0`, `allow_insecure_bind = false`) started with a CLI `--token`.
    let handle_exp = proxxx::config::watcher::new_handle(base_cfg(None));
    let listener_exp = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr_exp = listener_exp.local_addr().expect("local_addr");
    let port_exp = addr_exp.port();
    let host_exp = format!("0.0.0.0:{port_exp}");

    let app_exp = proxxx::mcp::http_server::build_http_router(
        client,
        Arc::clone(&handle_exp),
        "0.0.0.0",
        port_exp,
        false,
        Some(SecretString::from("cli-exposed-secret")),
        &[],
    );
    let srv_exp = tokio::spawn(async move {
        let _ = axum::serve(listener_exp, app_exp).await;
    });

    // Reload swaps in a config WITHOUT `mcp_token`.
    let reloaded_exp =
        proxxx::config::watcher::reload_once(&handle_exp, || Ok(base_cfg(None))).await;
    assert!(reloaded_exp, "reload_once on exposed server must succeed");

    // Must NOT become 401-for-everyone: the CLI bearer still authorizes (200).
    let (code, _, _) = raw_http_request(
        addr_exp,
        "POST",
        "/mcp",
        &[
            ("Host", &host_exp),
            ("Authorization", "Bearer cli-exposed-secret"),
        ],
        ping_body,
    )
    .await;
    assert_eq!(
        code, 200,
        "exposed server with CLI token must still accept the CLI bearer after reload"
    );

    // Unauthenticated request is still refused (401).
    let (code, _, _) =
        raw_http_request(addr_exp, "POST", "/mcp", &[("Host", &host_exp)], ping_body).await;
    assert_eq!(
        code, 401,
        "exposed server must still refuse unauthenticated requests after reload"
    );

    srv_exp.abort();
}

#[tokio::test]
async fn dns_rebinding_middleware_enforces_host_and_origin_across_all_routes() {
    use proxxx::util::secret::SecretString;

    let ping_body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let client = offline_client().await;
    let handle = proxxx::config::watcher::new_handle(base_cfg(None));

    // 1. Loopback bind (`127.0.0.1:<port>`, no auth token).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let port = addr.port();
    let localhost_hdr = format!("localhost:{port}");
    let ipv4_hdr = format!("127.0.0.1:{port}");
    let ipv6_hdr = format!("[::1]:{port}");

    let app = proxxx::mcp::http_server::build_http_router(
        Arc::clone(&client),
        Arc::clone(&handle),
        "127.0.0.1",
        port,
        false,
        None,
        &[],
    );
    let srv = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Host: evil.example -> 403 on POST /mcp, GET /mcp (SSE), and GET /health.
    for (method, path, body) in [
        ("POST", "/mcp", ping_body),
        ("GET", "/mcp", ""),
        ("GET", "/health", ""),
    ] {
        let (code, _, resp_body) =
            raw_http_request(addr, method, path, &[("Host", "evil.example")], body).await;
        assert_eq!(
            code, 403,
            "{method} {path} with Host: evil.example must return 403"
        );
        assert!(
            resp_body.contains("evil.example"),
            "403 body on {method} {path} must name the rejected host, got: {resp_body}"
        );
    }

    // Host: localhost:<port>, 127.0.0.1:<port>, [::1]:<port> -> pass middleware (200).
    for allowed_host in [&localhost_hdr, &ipv4_hdr, &ipv6_hdr] {
        let (code, headers_lower, _) = raw_http_request(
            addr,
            "POST",
            "/mcp",
            &[("Host", allowed_host.as_str())],
            ping_body,
        )
        .await;
        assert_eq!(code, 200, "Host {allowed_host} must be accepted");
        assert!(
            !headers_lower.contains("access-control-allow-origin"),
            "no CORS headers may be emitted"
        );
    }
    let (sse_code, _, _) =
        raw_http_request(addr, "GET", "/mcp", &[("Host", &localhost_hdr)], "").await;
    assert_eq!(
        sse_code, 200,
        "SSE GET /mcp with Host: localhost:<port> must pass"
    );
    let (health_code, _, _) =
        raw_http_request(addr, "GET", "/health", &[("Host", &localhost_hdr)], "").await;
    assert_eq!(
        health_code, 200,
        "GET /health with Host: localhost:<port> must pass"
    );

    // Origin: http://evil.example -> 403 across routes even when Host is valid.
    for (method, path, body) in [
        ("POST", "/mcp", ping_body),
        ("GET", "/mcp", ""),
        ("GET", "/health", ""),
    ] {
        let (code, _, resp_body) = raw_http_request(
            addr,
            method,
            path,
            &[("Host", &localhost_hdr), ("Origin", "http://evil.example")],
            body,
        )
        .await;
        assert_eq!(
            code, 403,
            "{method} {path} with Origin: http://evil.example must return 403"
        );
        assert!(
            resp_body.contains("http://evil.example"),
            "403 body must name the rejected Origin, got: {resp_body}"
        );
    }

    // Matching http:// or https:// Origin -> 200; no Origin -> 200.
    let ok_origin = format!("http://{localhost_hdr}");
    let (code, headers_lower, _) = raw_http_request(
        addr,
        "POST",
        "/mcp",
        &[("Host", &localhost_hdr), ("Origin", &ok_origin)],
        ping_body,
    )
    .await;
    assert_eq!(code, 200, "matching Origin must be allowed");
    assert!(!headers_lower.contains("access-control-allow-origin"));

    // Missing Host header -> 400 Bad Request across routes.
    for (method, path, body) in [
        ("POST", "/mcp", ping_body),
        ("GET", "/mcp", ""),
        ("GET", "/health", ""),
    ] {
        let (code, _, _) = raw_http_request(addr, method, path, &[], body).await;
        assert_eq!(
            code, 400,
            "{method} {path} without Host header must return 400 Bad Request"
        );
    }

    srv.abort();

    // 2. Exposed bind (`0.0.0.0:3000`) with `--allowed-host mcp.lan:3000`.
    let listener_exp = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr_exp = listener_exp.local_addr().expect("local_addr");
    let app_exp = proxxx::mcp::http_server::build_http_router(
        client,
        handle,
        "0.0.0.0",
        3000,
        true,
        Some(SecretString::from("lan-token")),
        &["mcp.lan:3000".to_string()],
    );
    let srv_exp = tokio::spawn(async move {
        let _ = axum::serve(listener_exp, app_exp).await;
    });

    // Accepted: Host: mcp.lan:3000
    let (code, _, _) = raw_http_request(
        addr_exp,
        "POST",
        "/mcp",
        &[
            ("Host", "mcp.lan:3000"),
            ("Authorization", "Bearer lan-token"),
        ],
        ping_body,
    )
    .await;
    assert_eq!(
        code, 200,
        "exposed bind with --allowed-host mcp.lan:3000 must accept that host"
    );

    // Rejected: other hosts (including localhost:3000 and other.lan:3000) -> 403.
    for rejected in ["localhost:3000", "other.lan:3000", "evil.example"] {
        let (code, _, body_txt) = raw_http_request(
            addr_exp,
            "POST",
            "/mcp",
            &[("Host", rejected), ("Authorization", "Bearer lan-token")],
            ping_body,
        )
        .await;
        assert_eq!(
            code, 403,
            "exposed bind must reject non-allowed Host {rejected}"
        );
        assert!(body_txt.contains(rejected));
    }

    srv_exp.abort();
}

#[tokio::test]
async fn host_and_origin_check_runs_before_bearer_auth() {
    use proxxx::util::secret::SecretString;

    let ping_body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let client = offline_client().await;
    let handle = proxxx::config::watcher::new_handle(base_cfg(None));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let port = addr.port();

    let app = proxxx::mcp::http_server::build_http_router(
        client,
        handle,
        "127.0.0.1",
        port,
        false,
        Some(SecretString::from("valid-token")),
        &[],
    );
    let srv = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // 1. Bad Host + valid Bearer token -> 403 Forbidden (not 200).
    let (code_with_token, _, body_with_token) = raw_http_request(
        addr,
        "POST",
        "/mcp",
        &[
            ("Host", "evil.example"),
            ("Authorization", "Bearer valid-token"),
        ],
        ping_body,
    )
    .await;
    assert_eq!(
        code_with_token, 403,
        "bad Host must be refused with 403 even when a valid bearer token is presented"
    );
    assert!(body_with_token.contains("evil.example"));

    // 2. Bad Host + NO Bearer token -> 403 Forbidden (NOT 401 Unauthorized),
    // proving the Host/Origin middleware runs before `require_authorized`.
    let (code_without_token, _, _) =
        raw_http_request(addr, "POST", "/mcp", &[("Host", "evil.example")], ping_body).await;
    assert_eq!(
        code_without_token, 403,
        "Host check must execute before Bearer auth (expected 403, not 401)"
    );

    srv.abort();
}
