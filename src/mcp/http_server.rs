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
}

impl McpState {
    fn new(client: Arc<PxClient>, config: ConfigHandle) -> Self {
        Self { client, config }
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
/// Sends a periodic ping every 30 s so the connection stays alive through
/// proxies and load balancers. Actual server-initiated notifications (e.g.
/// task completion events) will be added in a future release.
async fn get_mcp_sse(State(state): State<McpState>, headers: HeaderMap) -> Response {
    if !state.auth_ok(&headers).await {
        return (
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Bearer realm=\"proxxx-mcp\"")],
            "Unauthorized",
        )
            .into_response();
    }

    let stream =
        tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(Duration::from_secs(30)))
            .map(|_| {
                Ok::<Event, Infallible>(
                    Event::default()
                        .event("ping")
                        .data(json!({"type": "ping"}).to_string()),
                )
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
    let state = McpState::new(client, config);
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
