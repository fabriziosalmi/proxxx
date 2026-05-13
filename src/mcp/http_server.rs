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
// Session: stateless. The spec's Mcp-Session-Id is accepted but not enforced
// in this release — each request is independently authenticated and dispatched.

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
use crate::config::ProfileConfig;
use crate::mcp::dispatch;

/// Server state shared across handlers.
#[derive(Clone)]
struct McpState {
    client: Arc<PxClient>,
    config: Arc<ProfileConfig>,
    /// Pre-hashed bearer token for constant-time comparison, if configured.
    token_hash: Option<[u8; 32]>,
}

impl McpState {
    fn new(client: Arc<PxClient>, config: Arc<ProfileConfig>) -> Self {
        let token_hash = config.mcp_token.as_deref().map(sha256_bytes);
        Self {
            client,
            config,
            token_hash,
        }
    }

    /// Returns `true` if the request carries a valid bearer token (or if no
    /// token is configured). Constant-time comparison via XOR fold prevents
    /// timing side-channels leaking token length or prefix.
    fn auth_ok(&self, headers: &HeaderMap) -> bool {
        let Some(expected_hash) = self.token_hash else {
            return true; // no token configured → open
        };
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
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // We use a two-pass double-hash trick with DefaultHasher as a lightweight
    // stand-in. For a production token store use ring/sha2; here the token is
    // a shared secret in a TOML file, so the goal is avoid storing plaintext
    // in memory longer than needed, not cryptographic agility.
    //
    // TODO: replace with ring::digest::SHA256 when ring is added to deps.
    let mut h1 = DefaultHasher::new();
    s.hash(&mut h1);
    let v1 = h1.finish();
    let mut h2 = DefaultHasher::new();
    (s, v1).hash(&mut h2);
    let v2 = h2.finish();
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&v1.to_le_bytes());
    out[8..16].copy_from_slice(&v2.to_le_bytes());
    out[16..24].copy_from_slice(&v1.wrapping_add(v2).to_le_bytes());
    out[24..].copy_from_slice(&v1.wrapping_mul(v2 | 1).to_le_bytes());
    out
}

/// `POST /mcp` — JSON-RPC 2.0 request handler.
async fn post_mcp(
    State(state): State<McpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !state.auth_ok(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Unauthorized"})),
        )
            .into_response();
    }

    // Batch requests: the spec allows an array of requests.
    if let Some(arr) = body.as_array() {
        let mut responses = Vec::with_capacity(arr.len());
        for req in arr {
            responses.push(handle_single(&state, req).await);
        }
        return Json(Value::Array(responses)).into_response();
    }

    Json(handle_single(&state, &body).await).into_response()
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
    if !state.auth_ok(&headers) {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
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
    config: Arc<ProfileConfig>,
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
