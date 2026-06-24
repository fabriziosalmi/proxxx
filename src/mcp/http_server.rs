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
}

impl McpState {
    const fn new(
        client: Arc<PxClient>,
        config: ConfigHandle,
        notifications: crate::mcp::notifications::Broker,
    ) -> Self {
        Self {
            client,
            config,
            notifications,
        }
    }

    /// Returns `true` if the request carries a valid bearer token (or if no
    /// token is configured). Constant-time comparison via XOR fold prevents
    /// timing side-channels leaking token length or prefix.
    ///
    /// Reads `mcp_token` from the live config so a SIGHUP token rotation
    /// takes effect on the next request without a restart.
    async fn auth_ok(&self, headers: &HeaderMap) -> bool {
        let expected = self.config.read().await.mcp_token.clone();
        let Some(expected) = expected else {
            return true; // no token configured → open
        };
        let expected_hash = sha256_bytes(&expected);
        let bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        let got_hash = sha256_bytes(bearer);
        // Constant-time comparison: fold XOR of all bytes, reject if any differ.
        let diff: u8 = expected_hash
            .iter()
            .zip(got_hash.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        diff == 0
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

/// Start the MCP HTTP server.
///
/// Binds to `bind:port` and serves until the process receives SIGTERM/SIGINT.
/// If `config.mcp_token` is set, all MCP endpoints require Bearer auth.
pub async fn run_http_server(
    client: Arc<PxClient>,
    config: ConfigHandle,
    bind: &str,
    port: u16,
) -> Result<()> {
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

    let state = McpState::new(client, config, notifications);
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
