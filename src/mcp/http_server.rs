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
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
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
pub struct McpState {
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
    /// Bearer token passed via CLI `--token` (`#343`). Stored outside the
    /// reloadable [`ConfigHandle`] so a `SIGHUP` config reload can never drop
    /// or overwrite a token given on the command line.
    cli_token: Option<crate::util::secret::SecretString>,
    /// Allowed `Host` and `Origin` authorities in lowercase (`#342`).
    allowed_authorities: Arc<std::collections::HashSet<String>>,
}

impl McpState {
    const fn new(
        client: Arc<PxClient>,
        config: ConfigHandle,
        notifications: crate::mcp::notifications::Broker,
        require_token: bool,
        cli_token: Option<crate::util::secret::SecretString>,
        allowed_authorities: Arc<std::collections::HashSet<String>>,
    ) -> Self {
        Self {
            client,
            config,
            notifications,
            require_token,
            cli_token,
            allowed_authorities,
        }
    }

    /// Returns `true` if the request is authorized. Uses `cli_token` when set
    /// on the command line (`#343`), otherwise reads `mcp_token` from the live
    /// config so a `SIGHUP` token rotation takes effect on the next request.
    /// When `require_token` is set (exposed bind, no `--insecure-bind`), a
    /// missing token denies every request instead of opening — see
    /// [`token_gate`].
    async fn auth_ok(&self, headers: &HeaderMap) -> bool {
        let cli_tok = self
            .cli_token
            .as_ref()
            .map(crate::util::secret::SecretString::as_str)
            .filter(|t| !t.trim().is_empty());
        let cfg_tok = if cli_tok.is_none() {
            self.config.read().await.mcp_token.clone()
        } else {
            None
        };
        let expected = cli_tok.or_else(|| {
            cfg_tok
                .as_ref()
                .map(crate::util::secret::SecretString::as_str)
        });
        let bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        token_gate(expected, bearer, self.require_token)
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    let h = host.trim().to_ascii_lowercase();
    if h.starts_with('[') && h.ends_with(']') {
        format!("{h}:{port}")
    } else if h.contains(':') {
        format!("[{h}]:{port}")
    } else {
        format!("{h}:{port}")
    }
}

fn insert_allowed_host_entry(
    set: &mut std::collections::HashSet<String>,
    raw: &str,
    default_port: u16,
) {
    let h = raw.trim().to_ascii_lowercase();
    if h.is_empty() {
        return;
    }
    if h.starts_with('[') {
        if h.contains("]:") {
            set.insert(h);
        } else if h.ends_with(']') {
            set.insert(format!("{h}:{default_port}"));
            set.insert(h);
        }
        return;
    }
    if let Some((host_part, port_part)) = h.rsplit_once(':') {
        if !host_part.contains(':') && port_part.parse::<u16>().is_ok() {
            set.insert(h);
            return;
        }
        set.insert(format!("[{h}]:{default_port}"));
        set.insert(format!("[{h}]"));
        return;
    }
    set.insert(format!("{h}:{default_port}"));
    set.insert(h);
}

/// Build the set of lowercase `Host` / `Origin` authorities permitted for a
/// given `(bind, port, allowed_hosts)` configuration (`#342`):
/// * Loopback bind: `127.0.0.1:<port>`, `localhost:<port>`, `[::1]::<port>`
///   (plus `<bind>:<port>` if distinct and any explicit `allowed_hosts`).
/// * Exposed bind: `<bind>:<port>` plus each value of `--allowed-host`.
#[must_use]
pub fn build_allowed_authorities(
    bind: &str,
    port: u16,
    allowed_hosts: &[String],
) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    if is_loopback_bind(bind) {
        set.insert(format!("127.0.0.1:{port}"));
        set.insert(format!("localhost:{port}"));
        set.insert(format!("[::1]:{port}"));
    }
    set.insert(format_host_port(bind, port));
    for entry in allowed_hosts {
        insert_allowed_host_entry(&mut set, entry, port);
    }
    set
}

/// Pure `Host` + `Origin` check (`#342`), returning `Ok(())` when the request
/// passes or `Err((StatusCode, message))` when it must be rejected.
fn check_host_and_origin(
    allowed_authorities: &std::collections::HashSet<String>,
    headers: &HeaderMap,
) -> std::result::Result<(), (StatusCode, String)> {
    let mut host_values = headers.get_all(axum::http::header::HOST).iter();
    let Some(raw_host_val) = host_values.next() else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Bad Request: missing Host header".to_string(),
        ));
    };
    if host_values.next().is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Bad Request: multiple Host headers are not allowed".to_string(),
        ));
    }
    let Ok(raw_host) = raw_host_val.to_str() else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Bad Request: invalid Host header".to_string(),
        ));
    };
    let host_trimmed = raw_host.trim();
    if host_trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Bad Request: missing Host header".to_string(),
        ));
    }
    if !allowed_authorities.contains(&host_trimmed.to_ascii_lowercase()) {
        return Err((
            StatusCode::FORBIDDEN,
            format!("Forbidden: rejected Host '{host_trimmed}'"),
        ));
    }

    let mut origin_values = headers.get_all(axum::http::header::ORIGIN).iter();
    if let Some(raw_origin_val) = origin_values.next() {
        if origin_values.next().is_some() {
            return Err((
                StatusCode::FORBIDDEN,
                "Forbidden: multiple Origin headers are not allowed".to_string(),
            ));
        }
        let Ok(raw_origin) = raw_origin_val.to_str() else {
            return Err((
                StatusCode::FORBIDDEN,
                "Forbidden: invalid Origin header".to_string(),
            ));
        };
        let origin_trimmed = raw_origin.trim();
        let origin_authority = origin_trimmed
            .get(..7)
            .filter(|s| s.eq_ignore_ascii_case("http://"))
            .and_then(|_| origin_trimmed.get(7..))
            .or_else(|| {
                origin_trimmed
                    .get(..8)
                    .filter(|s| s.eq_ignore_ascii_case("https://"))
                    .and_then(|_| origin_trimmed.get(8..))
            });
        let origin_ok = origin_authority.is_some_and(|auth| {
            !auth.is_empty() && allowed_authorities.contains(&auth.to_ascii_lowercase())
        });
        if !origin_ok {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Forbidden: rejected Origin '{origin_trimmed}'"),
            ));
        }
    }

    Ok(())
}

/// Fail-closed DNS-rebinding defence middleware (`#342`).
///
/// Applied on EVERY route (including `/health` and `GET /mcp` SSE) BEFORE
/// [`require_authorized`]. No CORS headers are emitted.
async fn require_allowed_host_and_origin(
    State(state): State<McpState>,
    request: Request,
    next: Next,
) -> Response {
    if let Err((status, msg)) = check_host_and_origin(&state.allowed_authorities, request.headers())
    {
        return (status, msg).into_response();
    }
    next.run(request).await
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

/// Router-level authorization gate.
///
/// Runs before any protected handler. Handlers keep their own
/// `auth_ok` call as defence in depth — belt and braces cost one hash
/// comparison, and a future refactor that drops the layer should not
/// silently open the surface.
async fn require_authorized(
    State(state): State<McpState>,
    request: Request,
    next: Next,
) -> Response {
    if state.auth_ok(request.headers()).await {
        return next.run(request).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", "Bearer realm=\"proxxx-mcp\"")],
        Json(json!({"error": "Unauthorized"})),
    )
        .into_response()
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

#[allow(clippy::let_and_return)]
fn build_router_from_state(state: McpState) -> Router {
    // #253/#258 — authorization is a LAYER, not a per-handler call.
    //
    // It was previously the first statement of each handler, and two of
    // the three routes made that call: `/health` did not. The leak was
    // minor (a status object), but the shape was the problem — on a
    // network-exposed surface a route added by someone who copies
    // `health` rather than `post_mcp` ships open, and neither the build
    // nor the tests would notice.
    //
    // Applying the gate to the whole router inverts the default from
    // open to closed. `/health` is then exempted explicitly below, so
    // the exemption is a visible decision instead of an omission. This
    // is the same reasoning that puts `guard_read_only` and the incident
    // freeze check inside the three write helpers in api::client rather
    // than at their call sites.
    let protected = Router::new()
        .route("/mcp", post(post_mcp))
        .route("/mcp", get(get_mcp_sse))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_authorized,
        ));

    let app = protected
        // Deliberately unauthenticated: a liveness probe must answer
        // before credentials are configured, and it reveals nothing
        // beyond "a proxxx MCP server is listening here".
        .route("/health", get(health))
        // #342 — DNS rebinding defence runs on EVERY route (including
        // `/health` and `GET /mcp` SSE) BEFORE `require_authorized`.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_allowed_host_and_origin,
        ))
        .with_state(state);
    app
}

/// Construct the MCP HTTP [`Router`] with the full middleware stack (`#342`,
/// `#343`) without binding a socket or spawning background pollers.
pub fn build_http_router(
    client: Arc<PxClient>,
    config: ConfigHandle,
    bind: &str,
    port: u16,
    allow_insecure_bind: bool,
    cli_token: Option<crate::util::secret::SecretString>,
    allowed_hosts: &[String],
) -> Router {
    let require_token = !is_loopback_bind(bind) && !allow_insecure_bind;
    let allowed_authorities = Arc::new(build_allowed_authorities(bind, port, allowed_hosts));
    let notifications = crate::mcp::notifications::Broker::new();
    let state = McpState::new(
        client,
        config,
        notifications,
        require_token,
        cli_token,
        allowed_authorities,
    );
    build_router_from_state(state)
}

/// Start the MCP HTTP server without extra CLI token or `--allowed-host`
/// overrides.
///
/// # Errors
/// Returns an error if the non-loopback auth preflight fails or if the TCP
/// listener cannot bind or serve.
pub async fn run_http_server(
    client: Arc<PxClient>,
    config: ConfigHandle,
    bind: &str,
    port: u16,
    allow_insecure_bind: bool,
) -> Result<()> {
    run_http_server_with_options(client, config, bind, port, allow_insecure_bind, None, &[]).await
}

/// Start the MCP HTTP server with explicit CLI `--token` (`#343`) and
/// `--allowed-host` (`#342`) options.
///
/// Binds to `bind:port` and serves until the process receives SIGTERM/SIGINT.
/// If `cli_token` or `config.mcp_token` is set, all MCP endpoints require
/// Bearer auth.
///
/// SECURITY preflight (fail-closed): refuses to start on a non-loopback bind
/// when neither `cli_token` nor `mcp_token` is configured, unless
/// `allow_insecure_bind` is set.
///
/// # Errors
/// Returns an error if the non-loopback auth preflight fails or if the TCP
/// listener cannot bind or serve.
pub async fn run_http_server_with_options(
    client: Arc<PxClient>,
    config: ConfigHandle,
    bind: &str,
    port: u16,
    allow_insecure_bind: bool,
    cli_token: Option<crate::util::secret::SecretString>,
    allowed_hosts: &[String],
) -> Result<()> {
    // Exposed = network-reachable without a conscious --insecure-bind opt-in.
    // Drives BOTH the start-time refusal below AND the per-request fail-closed
    // gate in `auth_ok` (so a later SIGHUP that clears the token can't reopen).
    let require_token = !is_loopback_bind(bind) && !allow_insecure_bind;
    if require_token {
        // Non-empty, mirroring token_gate: `--token ""` must NOT be treated as
        // "authenticated" and start an exposed, effectively-open server.
        let has_cli_token = cli_token
            .as_ref()
            .is_some_and(|t| !t.as_str().trim().is_empty());
        let has_cfg_token = config
            .read()
            .await
            .mcp_token
            .as_ref()
            .is_some_and(|t| !t.as_str().trim().is_empty());
        if !(has_cli_token || has_cfg_token) {
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
        client.profile_config().profile_label().to_owned(),
        notifications.clone(),
    );

    let allowed_authorities = Arc::new(build_allowed_authorities(bind, port, allowed_hosts));
    let state = McpState::new(
        client,
        config,
        notifications,
        require_token,
        cli_token,
        allowed_authorities,
    );
    let addr = format!("{bind}:{port}");
    let app = build_router_from_state(state);

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

    #[test]
    fn host_and_origin_gate_enforces_loopback_and_exposed_rules() {
        use axum::http::{HeaderMap, HeaderValue, StatusCode};

        let loopback_allowed = super::build_allowed_authorities("127.0.0.1", 3000, &[]);
        assert!(loopback_allowed.contains("127.0.0.1:3000"));
        assert!(loopback_allowed.contains("localhost:3000"));
        assert!(loopback_allowed.contains("[::1]:3000"));

        // Missing Host -> 400
        let empty_headers = HeaderMap::new();
        let err = super::check_host_and_origin(&loopback_allowed, &empty_headers).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);

        // Bad Host -> 403 naming the rejected host
        let mut bad_host = HeaderMap::new();
        bad_host.insert("host", HeaderValue::from_static("evil.example"));
        let err = super::check_host_and_origin(&loopback_allowed, &bad_host).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert!(err.1.contains("evil.example"), "got: {}", err.1);

        // Allowed Host without Origin -> Ok
        let mut ok_headers = HeaderMap::new();
        ok_headers.insert("host", HeaderValue::from_static("localhost:3000"));
        assert!(super::check_host_and_origin(&loopback_allowed, &ok_headers).is_ok());

        // Allowed Host + evil Origin -> 403
        let mut bad_origin = ok_headers.clone();
        bad_origin.insert("origin", HeaderValue::from_static("http://evil.example"));
        let err = super::check_host_and_origin(&loopback_allowed, &bad_origin).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert!(err.1.contains("http://evil.example"), "got: {}", err.1);

        // Allowed Host + matching http/https Origin -> Ok
        let mut ok_origin = ok_headers.clone();
        ok_origin.insert("origin", HeaderValue::from_static("http://localhost:3000"));
        assert!(super::check_host_and_origin(&loopback_allowed, &ok_origin).is_ok());
        ok_origin.insert("origin", HeaderValue::from_static("https://127.0.0.1:3000"));
        assert!(super::check_host_and_origin(&loopback_allowed, &ok_origin).is_ok());

        // Exposed bind with --allowed-host mcp.lan:3000 accepts that host and rejects localhost
        let exposed_allowed =
            super::build_allowed_authorities("0.0.0.0", 3000, &["mcp.lan:3000".to_string()]);
        let mut mcp_lan = HeaderMap::new();
        mcp_lan.insert("host", HeaderValue::from_static("mcp.lan:3000"));
        assert!(super::check_host_and_origin(&exposed_allowed, &mcp_lan).is_ok());
        assert_eq!(
            super::check_host_and_origin(&exposed_allowed, &ok_headers)
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }
}

#[cfg(test)]
mod router_gate_tests {
    /// #258 — authorization must be a router layer, not a per-handler
    /// convention, so a route added later cannot ship open by omission.
    ///
    /// Asserted structurally against the source: the protected router
    /// carries a `route_layer`, and `/health` is registered outside it.
    /// A behavioural test would need a live listener and a bound port;
    /// what actually regresses here is someone adding `.route(...)` to
    /// the wrong builder, which this catches.
    #[test]
    fn protected_routes_carry_a_layer_and_health_is_explicitly_outside() {
        let src = include_str!("http_server.rs");
        let protected = src
            .split_once("let protected = Router::new()")
            .expect("the protected router must exist")
            .1;
        let (protected_block, rest) = protected
            .split_once("let app = protected")
            .expect("the protected router must be consumed by `app`");

        assert!(
            protected_block.contains("route_layer(middleware::from_fn_with_state"),
            "the protected router must apply the auth layer"
        );
        assert!(
            protected_block.contains("\"/mcp\""),
            "the MCP routes belong behind the layer"
        );
        assert!(
            !protected_block.contains("\"/health\""),
            "/health must not sit behind the auth layer — it is the liveness probe"
        );
        assert!(
            rest.contains("\"/health\""),
            "/health must be registered outside the layer, deliberately"
        );
        assert!(
            rest.contains("require_allowed_host_and_origin"),
            "the entire router (including /health) must apply require_allowed_host_and_origin"
        );
    }
}
