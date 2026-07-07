// MCP Streamable HTTP transport — spec 2025-03-26
//
// Endpoints:
//   POST /mcp   — JSON-RPC request → JSON response
//   GET  /mcp   — SSE keep-alive stream (notifications channel)
//   GET  /health — liveness probe (no auth required)
//
// Auth: if `mcp_token` is set in the profile, every POST /mcp and GET /mcp
// request must carry `Authorization: Bearer <token>`. Requests without or
// with a wrong token get HTTP 401. The health endpoint is always open.
//
// Session: stateless. The spec's Mcp-Session-Id header is not inspected —
// each request is independently authenticated and dispatched. Session
// affinity is not required for the current tool set (all ops are idempotent
// read-or-dispatch; no streaming continuations yet).

use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio_stream::StreamExt as _;

use crate::api::PxClient;
use crate::config::ConfigHandle;
use crate::mcp::dispatch;

/// Server state shared across handlers.
#[derive(Clone)]
struct McpState {
    client: Arc<PxClient>,
    config: ConfigHandle,
    /// Server-sent notification broker. Cheap to clone (it holds
    /// only the broadcast sender). Cloned per `GET /mcp` SSE
    /// connection to derive a fresh receiver.
    notifications: crate::mcp::notifications::Broker,
    /// True when the server is bound to a non-loopback interface WITHOUT an
    /// explicit `--insecure-bind` opt-in. In that mode a missing `mcp_token`
    /// means FAIL CLOSED (deny every request) — not open. Computed once at
    /// start; it closes the SIGHUP hole where clearing `mcp_token` on a live
    /// exposed server would otherwise silently drop all auth (the start-time
    /// bind preflight does not re-run on reload).
    require_token: bool,
}

impl McpState {
    const fn new(
        client: Arc<PxClient>,
        config: ConfigHandle,
        notifications: crate::mcp::notifications::Broker,
        require_token: bool,
    ) -> Self {
        Self {
            client,
            config,
            notifications,
            require_token,
        }
    }

    /// Returns `true` if the request is authorized. Reads `mcp_token` from the
    /// live config so a SIGHUP token rotation takes effect on the next request.
    /// When `require_token` is set (exposed bind, no `--insecure-bind`), a
    /// missing token denies every request instead of opening — see
    /// [`token_gate`].
    async fn auth_ok(&self, headers: &HeaderMap) -> bool {
        let expected = self.config.read().await.mcp_token.clone();
        let bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        token_gate(
            expected
                .as_ref()
                .map(crate::util::secret::SecretString::as_str),
            bearer,
            self.require_token,
        )
    }
}

/// Pure authorization decision, split out so the fail-closed logic is unit-
/// testable without spinning a server.
///
/// * `expected = Some(tok)` → constant-time compare of the presented bearer
///   (XOR fold over SHA-256, no length/prefix timing leak).
/// * `expected = None` → OPEN only when `require_token` is false (loopback bind
///   or explicit `--insecure-bind`). When `require_token` is true the server is
///   network-exposed and an absent token FAILS CLOSED — this is what prevents a
///   SIGHUP that clears `mcp_token` from silently unauthenticating the server.
fn token_gate(expected: Option<&str>, bearer: &str, require_token: bool) -> bool {
    // An empty / whitespace-only token counts as ABSENT — mirrors the
    // `!is_empty()` guards on token_secret/password (config/mod.rs) and closes
    // the bypass where `--token ""` (an unset env var) or a SIGHUP that sets
    // `mcp_token = ""` would otherwise be a real `Some("")` that authorizes a
    // header-less request on an exposed bind (sha256("") == sha256("")).
    let effective = expected.filter(|t| !t.trim().is_empty());
    match effective {
        None => !require_token,
        Some(tok) => {
            let expected_hash = sha256_bytes(tok);
            let got_hash = sha256_bytes(bearer);
            let diff: u8 = expected_hash
                .iter()
                .zip(got_hash.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b));
            diff == 0
        }
    }
}

fn sha256_bytes(s: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hasher.finalize().into()
}

/// `POST /mcp` — JSON-RPC 2.0 request handler.
async fn post_mcp(
    State(state): State<McpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !state.auth_ok(&headers).await {
        return (
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Bearer realm=\"proxxx-mcp\"")],
            Json(json!({"error": "Unauthorized"})),
        )
            .into_response();
    }

    // Batch requests: the spec allows an array of requests.
    if let Some(arr) = body.as_array() {
        let mut responses = Vec::with_capacity(arr.len());
        for req in arr {
            let r = handle_single(&state, req).await;
            // Notifications return Value::Null — omit from batch response (JSON-RPC §4).
            if !r.is_null() {
                responses.push(r);
            }
        }
        // If every item was a notification, return HTTP 204 No Content.
        if responses.is_empty() {
            return StatusCode::NO_CONTENT.into_response();
        }
        return Json(Value::Array(responses)).into_response();
    }

    let r = handle_single(&state, &body).await;
    // Single notification → 204 No Content (no body to send).
    if r.is_null() {
        return StatusCode::NO_CONTENT.into_response();
    }
    Json(r).into_response()
}

async fn handle_single(state: &McpState, req: &Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = match req.get("method").and_then(|v| v.as_str()) {
        Some(m) => m.to_owned(),
        None => {
            return dispatch::err_result(&id, -32600, "Invalid Request: missing method");
        }
    };
    let params = req.get("params").cloned();

    dispatch::dispatch_rpc(
        Arc::clone(&state.client),
        Arc::clone(&state.config),
        &method,
        id,
        params,
    )
    .await
}

/// `GET /mcp` — SSE notifications channel.
///
/// Each connection gets a fresh broker receiver and a `BroadcastStream`
/// adapter that yields one `Event` per [`McpNotification`]. The stream
/// emits `event: notifications/cluster-event` with the JSON-RPC 2.0
/// envelope from [`crate::mcp::notifications::rpc_envelope`] in the
/// SSE `data:` field — same shape the future stdio writer will emit.
///
/// Slow consumers experience the broadcast channel's lossy semantics:
/// `RecvError::Lagged(n)` collapses to a single advisory event so
/// the client knows it missed `n` events. `RecvError::Closed` ends
/// the stream — the broker outlives the server, so this only fires
/// when the server itself is shutting down.
async fn get_mcp_sse(State(state): State<McpState>, headers: HeaderMap) -> Response {
    use tokio_stream::wrappers::BroadcastStream;

    if !state.auth_ok(&headers).await {
        return (
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Bearer realm=\"proxxx-mcp\"")],
            "Unauthorized",
        )
            .into_response();
    }

    let rx = state.notifications.subscribe();
    let stream = BroadcastStream::new(rx).map(|res| {
        Ok::<Event, Infallible>(match res {
            Ok(n) => {
                let envelope = crate::mcp::notifications::rpc_envelope(&n);
                Event::default()
                    .event("notifications/cluster-event")
                    .data(envelope.to_string())
            }
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                // Don't pretend nothing happened — tell the client.
                Event::default()
                    .event("notifications/lagged")
                    .data(json!({"missed": n}).to_string())
            }
        })
    });

    Sse::new(stream)
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response()
}

/// `GET /health` — liveness probe. No auth. Returns 200 + version JSON.
async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "server": "proxxx-mcp",
        "version": env!("CARGO_PKG_VERSION"),
        "transport": "http"
    }))
}

/// Returns `true` if `bind` targets only the loopback interface.
///
/// Anything that is not a parseable loopback IP — `0.0.0.0`, `::`, a LAN
/// address, a hostname, or the empty string — is treated as network-exposed,
/// i.e. NOT loopback. Fail-closed: when in doubt, assume exposed.
fn is_loopback_bind(bind: &str) -> bool {
    if bind.eq_ignore_ascii_case("localhost") {
        return true;
    }
    bind.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Start the MCP HTTP server.
///
/// Binds to `bind:port` and serves until the process receives SIGTERM/SIGINT.
/// If `config.mcp_token` is set, all MCP endpoints require Bearer auth.
///
/// SECURITY preflight (fail-closed): refuses to start on a non-loopback bind
/// when no `mcp_token` is configured, unless `allow_insecure_bind` is set. An
/// unauthenticated MCP endpoint reachable from the network hands any caller
/// the profile's PVE credentials — the `--insecure-bind` flag is the explicit,
/// conscious opt-out for a trusted network / reverse-proxy-authenticated setup.
pub async fn run_http_server(
    client: Arc<PxClient>,
    config: ConfigHandle,
    bind: &str,
    port: u16,
    allow_insecure_bind: bool,
) -> Result<()> {
    // Exposed = network-reachable without a conscious --insecure-bind opt-in.
    // Drives BOTH the start-time refusal below AND the per-request fail-closed
    // gate in `auth_ok` (so a later SIGHUP that clears the token can't reopen).
    let require_token = !is_loopback_bind(bind) && !allow_insecure_bind;
    if require_token {
        // Non-empty, mirroring token_gate: `--token ""` must NOT be treated as
        // "authenticated" and start an exposed, effectively-open server.
        let has_token = config
            .read()
            .await
            .mcp_token
            .as_ref()
            .is_some_and(|t| !t.trim().is_empty());
        if !has_token {
            anyhow::bail!(
                "Refusing to start the MCP HTTP server on non-loopback bind '{bind}' without auth. \
                 Set `mcp_token` (or pass --token), bind to 127.0.0.1, or pass --insecure-bind to \
                 override consciously."
            );
        }
    }

    // Spin up the notification broker + pollers BEFORE the HTTP
    // server starts. The pollers run for the process lifetime;
    // when no SSE clients are connected the broker drops messages
    // silently, so the cost of the pollers is just two periodic
    // PVE polls (2 s tasks, 5 s incident).
    let notifications = crate::mcp::notifications::Broker::new();
    let _task_poller =
        crate::mcp::notifications::spawn_task_poller(Arc::clone(&client), notifications.clone());
    let _incident_watcher =
        crate::mcp::notifications::spawn_incident_watcher(notifications.clone());
    let _reconcile_watcher = crate::mcp::notifications::spawn_reconcile_watcher(
        client.profile_config().profile_name.clone(),
        notifications.clone(),
    );

    let state = McpState::new(client, config, notifications, require_token);
    let addr = format!("{bind}:{port}");

    let app = Router::new()
        .route("/mcp", post(post_mcp))
        .route("/mcp", get(get_mcp_sse))
        .route("/health", get(health))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("MCP HTTP server listening on http://{addr}/mcp");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c = async {
        // Ignore the error — if we can't install the handler the process
        // will simply not react to Ctrl-C, which is acceptable here.
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("MCP HTTP server shutting down");
}

#[cfg(test)]
mod tests {
    use super::{is_loopback_bind, token_gate};

    #[test]
    fn token_gate_fails_closed_on_exposed_bind_without_token() {
        // The SIGHUP hole: server exposed (require_token=true), token cleared
        // → every request must be DENIED, not opened.
        assert!(
            !token_gate(None, "", true),
            "exposed bind + no token → deny (fail-closed)"
        );
        assert!(
            !token_gate(None, "anything", true),
            "exposed bind + no token → deny even with a presented bearer"
        );
        // An empty / whitespace-only configured token counts as absent — the
        // `--token ""` / SIGHUP-clear-to-"" bypass must also fail closed.
        assert!(
            !token_gate(Some(""), "", true),
            "empty token on exposed bind → deny (not a real credential)"
        );
        assert!(
            !token_gate(Some("   "), "", true),
            "whitespace-only token on exposed bind → deny"
        );
        assert!(
            !token_gate(Some(""), "", true) && token_gate(Some(""), "", false),
            "empty token is treated as absent in both exposure modes"
        );
    }

    #[test]
    fn token_gate_opens_only_when_not_exposed() {
        // Loopback / --insecure-bind (require_token=false) with no token → open,
        // matching the documented default.
        assert!(token_gate(None, "", false));
        assert!(token_gate(None, "ignored", false));
    }

    #[test]
    fn token_gate_matches_and_rejects_bearer() {
        assert!(
            token_gate(Some("s3cret-token"), "s3cret-token", true),
            "exact match authorizes"
        );
        assert!(
            token_gate(Some("s3cret-token"), "s3cret-token", false),
            "match works regardless of exposure"
        );
        assert!(
            !token_gate(Some("s3cret-token"), "wrong", true),
            "wrong token denied"
        );
        assert!(
            !token_gate(Some("s3cret-token"), "", true),
            "empty bearer denied when a token is set"
        );
        assert!(
            !token_gate(Some("s3cret-token"), "s3cret-toke", true),
            "prefix is not a match"
        );
    }

    #[test]
    fn loopback_binds_are_recognised() {
        assert!(is_loopback_bind("127.0.0.1"));
        assert!(is_loopback_bind("127.0.0.5")); // whole 127.0.0.0/8 is loopback
        assert!(is_loopback_bind("::1"));
        assert!(is_loopback_bind("localhost"));
        assert!(is_loopback_bind("LOCALHOST")); // case-insensitive
    }

    #[test]
    fn exposed_binds_are_rejected_as_non_loopback() {
        // The dangerous ones — all-interfaces wildcards.
        assert!(!is_loopback_bind("0.0.0.0"));
        assert!(!is_loopback_bind("::"));
        // LAN / routable addresses.
        assert!(!is_loopback_bind("192.168.1.10"));
        assert!(!is_loopback_bind("10.0.0.1"));
        // Hostnames and junk — fail-closed: treated as exposed.
        assert!(!is_loopback_bind("mcp.example.com"));
        assert!(!is_loopback_bind(""));
    }
}
