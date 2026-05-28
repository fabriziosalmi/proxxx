use std::num::NonZeroU32;
use std::sync::Arc;

use anyhow::{Context, Result};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::auth::AuthMethod;
use super::transport::{
    backoff_delay, is_retryable_error, is_retryable_status, parse_json_maybe_blocking,
    read_bounded_body, retry_after_secs, RETRY_MAX_ATTEMPTS,
};
use super::types::ApiResponse;
use super::types::{Guest, GuestType, Node, StoragePool, TaskLog};
use super::ProxmoxGateway;
use crate::config::ProfileConfig;

type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// URL path segment for the two Proxmox guest hierarchies.
/// Forgetting this dispatch was bug #1 — the entire LXC API surface
/// silently routed to `/qemu/...` and returned 500/404 from Proxmox.
const fn type_path(t: crate::api::types::GuestType) -> &'static str {
    match t {
        crate::api::types::GuestType::Qemu => "qemu",
        crate::api::types::GuestType::Lxc => "lxc",
    }
}

/// Minimal URL-encode for path components. Proxmox's `/access/*`
/// surface accepts user ids like `root@pam` — the `@` MUST be encoded
/// in the URL path or some PVE versions misroute. We don't pull a
/// crate for this; the rules are simple.
fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Append URL-encoded query params to an already-built path. Skips
/// the trailing `{qs}` format placeholder pattern that would
/// otherwise show up as a fake path component to the static map gate.
fn append_query(path: &mut String, query: &[(&str, &str)]) {
    if query.is_empty() {
        return;
    }
    path.push('?');
    let mut first = true;
    for (k, v) in query {
        if !first {
            path.push('&');
        }
        first = false;
        path.push_str(k);
        path.push('=');
        path.push_str(&urlenc(v));
    }
}

/// Internal response shape for `POST /access/users/{u}/token/{t}`.
/// Proxmox returns `{"info": {...}, "value": "<secret>"}` — we model
/// just the fields we keep.
#[derive(Debug, serde::Deserialize)]
struct TokenCreateResponse {
    info: TokenCreateInfo,
    value: String,
}

#[derive(Debug, serde::Deserialize)]
struct TokenCreateInfo {
    #[serde(
        default = "default_true_int_local",
        deserialize_with = "deserialize_bool_from_int_local"
    )]
    privsep: bool,
    #[serde(default)]
    comment: String,
    #[serde(default)]
    expire: u64,
}

const fn default_true_int_local() -> bool {
    true
}

fn deserialize_bool_from_int_local<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;
    struct Vis;
    impl de::Visitor<'_> for Vis {
        type Value = bool;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("bool or 0/1 int")
        }
        fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<bool, E> {
            Ok(v)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<bool, E> {
            Ok(v != 0)
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<bool, E> {
            Ok(v != 0)
        }
    }
    deserializer.deserialize_any(Vis)
}

/// (audit) — TOFU (Trust On First Use) cert resolution.
///
/// Returns `Ok(None)` when TOFU is not enabled for the profile — the
/// caller then falls back to `verify_tls`. Returns `Ok(Some(der))`
/// when TOFU is active: either loaded from disk (subsequent connects)
/// or freshly probed and saved (first connect).
///
/// Activation is opt-in via `tls_pin_mode = "tofu"` in the profile
/// (case-insensitive). Any other value is treated as "off" and
/// reported as a warning, on the theory that a typo here should not
/// silently downgrade security.
async fn resolve_tofu_cert(config: &ProfileConfig) -> Result<Option<Vec<u8>>> {
    let mode = match config.tls_pin_mode.as_deref() {
        Some(s) => s.to_ascii_lowercase(),
        None => return Ok(None),
    };
    if mode != "tofu" {
        warn!(
            "tls_pin_mode = {:?} is not recognised (expected \"tofu\"); skipping pinning",
            config.tls_pin_mode
        );
        return Ok(None);
    }
    if let Some(der) =
        crate::api::tls_pin::load_pinned_cert(&config.url).context("loading pinned TLS cert")?
    {
        debug!(
            "TOFU: using pinned cert for {} (fingerprint sha256={})",
            config.url,
            crate::api::tls_pin::fingerprint_sha256(&der)
        );
        return Ok(Some(der));
    }
    info!(
        "TOFU: no pinned cert for {} — probing leaf cert",
        config.url
    );
    let der = crate::api::tls_pin::probe_leaf_cert(&config.url)
        .await
        .with_context(|| format!("TOFU probe for {}", config.url))?;
    crate::api::tls_pin::save_pinned_cert(&config.url, &der).context("saving pinned TLS cert")?;
    let path = crate::api::tls_pin::pinned_cert_path(&config.url)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    info!(
        "TOFU: pinned new cert for {} at {} (fingerprint sha256={})",
        config.url,
        path,
        crate::api::tls_pin::fingerprint_sha256(&der)
    );
    Ok(Some(der))
}

/// Production Proxmox API client with rate limiting and auth refresh.
pub struct PxClient {
    http: Client,
    base_url: String,
    auth: Arc<RwLock<AuthMethod>>,
    limiter: Arc<Limiter>,
    profile_config: ProfileConfig,
}

impl PxClient {
    /// Create a new client for a given profile configuration
    pub async fn new(config: ProfileConfig, cli_secret: Option<&str>) -> Result<Self> {
        // Phase 13 audit fix: TOFU (Trust On First Use) TLS pinning.
        // When `tls_pin_mode = "tofu"` is set in the profile, fetch
        // the leaf cert on first connect, persist it to disk, and
        // build the reqwest client with that cert as the ONLY trusted
        // root. Subsequent connects use the same cert; if the cluster
        // rotates (legit renewal or MITM), reqwest's standard verifier
        // rejects the new cert.
        let pinned_cert = resolve_tofu_cert(&config).await?;

        let mut builder = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            // (audit) — TCP keepalive on the reqwest pool.
            //
            // Without this, a stateful firewall / NAT between proxxx
            // and the PVE cluster that silently drops idle TCP flows
            // (no RST) leaves us with `ESTABLISHED` connections in
            // the pool that are dead from the kernel's perspective
            // on the server side. The next reuse hangs until the
            // 30 s request timeout fires — every time. With keepalive
            // probes every 60 s, the kernel detects the half-open
            // state and evicts the dead connection from the pool
            // long before it can be reused.
            //
            // 60 s is a good compromise: shorter than typical NAT
            // idle timeouts (90–600 s), longer than the server's
            // own keepalive grace, low enough overhead.
            .tcp_keepalive(Some(std::time::Duration::from_mins(1)));
        if let Some(cert_der) = pinned_cert {
            // TOFU mode: trust ONLY the pinned cert. Disable built-in
            // roots so a rogue CA-signed cert from the cluster also
            // fails — the only valid cert is the one we pinned.
            let cert = reqwest::Certificate::from_der(&cert_der)
                .context("decoding pinned cert as reqwest Certificate")?;
            builder = builder
                .tls_built_in_root_certs(false)
                .add_root_certificate(cert);
        } else {
            // No TOFU pin — fall back to the legacy `verify_tls` boolean.
            builder = builder.danger_accept_invalid_certs(!config.verify_tls);
        }
        let http = builder.build().context("Failed to build HTTP client")?;

        let auth = match config.auth_method() {
            crate::config::AuthType::Token => {
                let secret = config.resolve_token_secret(cli_secret).await?;
                AuthMethod::from_token(
                    &config.user,
                    config.token_id.as_deref().unwrap_or_default(),
                    &secret,
                )
            }
            crate::config::AuthType::Password => {
                let password = config.resolve_password().await?;
                AuthMethod::login(&http, &config.url, &config.user, &password).await?
            }
        };

        let rate = config.rate_limit.unwrap_or(10);
        // SAFETY: 10 is a non-zero constant; NonZeroU32::new(10) never
        // returns None. This pattern keeps the `unwrap_used = "deny"`
        // clippy lint clean while preserving the per-second rate quota.
        const TEN: NonZeroU32 = match NonZeroU32::new(10) {
            Some(n) => n,
            None => unreachable!(),
        };
        let quota = Quota::per_second(NonZeroU32::new(rate).unwrap_or(TEN));
        let limiter = Arc::new(RateLimiter::direct(quota));

        info!("Connected to {} as {}", config.url, config.user);

        Ok(Self {
            http,
            base_url: config.url.trim_end_matches('/').to_string(),
            auth: Arc::new(RwLock::new(auth)),
            limiter,
            profile_config: config,
        })
    }

    /// Read-only handle to the profile config the client was built with.
    /// Used by the TUI HITL coordinator to fetch the `[telegram]` block
    /// without re-loading config from disk.
    #[must_use]
    pub const fn profile_config(&self) -> &ProfileConfig {
        &self.profile_config
    }

    /// Retrieve the authentication headers for this client, suitable for
    /// outbound non-HTTP connections that PVE authenticates the same way
    /// (today: WebSocket termproxy + vncproxy handshakes).
    ///
    /// Calls [`PxClient::ensure_auth`] first so a long-idle PAM session
    /// with an expiring ticket gets refreshed before we expose the
    /// `PVEAuthCookie` header — otherwise the WS handshake would carry
    /// a stale ticket and PVE would `401` the upgrade. Token auth is a
    /// no-op refresh (token secrets don't expire).
    ///
    /// The returned vector is `(header-name, header-value)` pairs ready
    /// for the tungstenite request builder:
    /// * Token auth → one `Authorization: PVEAPIToken=<user>!<id>=<secret>`
    /// * Password auth → one `Cookie: PVEAuthCookie=<ticket>`
    ///
    /// The CSRF prevention token is deliberately omitted — PVE only
    /// requires it on state-changing HTTP requests, never on the
    /// WebSocket upgrade.
    pub async fn auth_headers(&self) -> Result<Vec<(String, String)>> {
        self.ensure_auth().await?;
        Ok(self.auth.read().await.headers())
    }

    /// Send a request with retry on transient failures (SPOF 2.2 fix).
    ///
    /// `make_req` rebuilds the `RequestBuilder` on each attempt — required
    /// because reqwest's `RequestBuilder` is not `Clone` once a body has
    /// been attached. The closure also re-acquires auth so a token refresh
    /// during retry is picked up automatically.
    ///
    /// Retry conditions: 503/429/502/504 status, or `is_timeout()` /
    /// `is_connect()` reqwest errors. Body-decode errors and 4xx (other
    /// than 429) are NOT retried — those indicate a request-shape problem
    /// the cluster won't recover from.
    async fn send_with_retry<F>(&self, path: &str, mut make_req: F) -> Result<Response>
    where
        F: FnMut(&Client) -> RequestBuilder,
    {
        let mut attempt: u32 = 0;
        let mut auth_retry_done = false;
        loop {
            attempt += 1;
            self.ensure_auth().await?;
            self.limiter.until_ready().await;

            let auth = self.auth.read().await;
            let req = auth.apply(make_req(&self.http));
            let result = req.send().await;
            drop(auth);

            match result {
                Ok(resp) => {
                    let status = resp.status();
                    // (Gemini wave-3 audit) — reactive re-auth.
                    //
                    // Token TTLs are tracked with `Instant`, which is
                    // monotonic on every modern OS but does NOT advance
                    // during system sleep on Linux. After a 3-day laptop
                    // suspend our cached `expires_at` thinks the token
                    // is fresh, but PVE has long since rotated it. The
                    // server's authoritative answer is `401`. Detect it,
                    // force-refresh once, retry once. ONE retry budget
                    // — if it still fails, surface the auth error.
                    if status == StatusCode::UNAUTHORIZED && !auth_retry_done {
                        auth_retry_done = true;
                        warn!("401 from {path} — forcing auth refresh and retrying once");
                        if let Err(e) = self.force_reauth().await {
                            warn!("force re-auth failed: {e:#}");
                            return Ok(resp);
                        }
                        continue;
                    }
                    if is_retryable_status(status) && attempt < RETRY_MAX_ATTEMPTS {
                        let delay = backoff_delay(attempt, retry_after_secs(&resp));
                        warn!(
                            "transient {status} from {path}, retry {attempt}/{} after {:?}",
                            RETRY_MAX_ATTEMPTS, delay
                        );
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) if is_retryable_error(&e) && attempt < RETRY_MAX_ATTEMPTS => {
                    let delay = backoff_delay(attempt, None);
                    warn!(
                        "transient connection error on {path}: {e}, retry {attempt}/{} after {:?}",
                        RETRY_MAX_ATTEMPTS, delay
                    );
                    tokio::time::sleep(delay).await;
                    // No `continue;` — match is the last expression in
                    // the loop body, so falling through re-enters the
                    // loop naturally.
                }
                Err(e) => {
                    // Surface transport-level failures (DNS NXDOMAIN, TCP
                    // close mid-handshake, TLS errors, connect timeouts)
                    // as the typed `ApiError::Transport` so the exit-code
                    // dispatch in `main.rs` can route them and so
                    // observability layers can `.downcast_ref::<ApiError>()`
                    // instead of grepping the anyhow chain.
                    return Err(anyhow::Error::from(super::ApiError::Transport(format!(
                        "request to {path} failed: {e}"
                    ))));
                }
            }
        }
    }

    /// bypass the proactive `needs_refresh()` check and
    /// force a re-login. Called when the server returns 401 even
    /// though the local clock thinks the token is fresh — typically
    /// after a long laptop suspend. Token-auth profiles have nothing
    /// to refresh (the secret is configured statically) and short-
    /// circuit; password-auth profiles fetch a new ticket.
    async fn force_reauth(&self) -> Result<()> {
        let mut auth = self.auth.write().await;
        if matches!(*auth, AuthMethod::Token { .. }) {
            // Token auth has no expiry to refresh. The 401 is real —
            // surface it to the caller.
            anyhow::bail!("token auth rejected by server (401); secret may be wrong");
        }
        let password = self.profile_config.resolve_password().await?;
        *auth = AuthMethod::login(
            &self.http,
            &self.base_url,
            &self.profile_config.user,
            &password,
        )
        .await?;
        info!("auth refreshed reactively after 401");
        Ok(())
    }

    /// Rate-limited, auth-aware GET request with retry on transient failures.
    async fn get<T: DeserializeOwned + Send + 'static>(&self, path: &str) -> Result<T> {
        let url = format!("{}/api2/json{}", self.base_url, path);
        debug!("GET {}", url);

        let resp = self.send_with_retry(path, |http| http.get(&url)).await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            // typed ApiError so the TUI/CLI can downcast and
            // show category-specific messages (Unauthorized →
            // re-auth modal, NotFound → "already gone", etc.).
            return Err(super::ApiError::from_status(status, path, body).into());
        }

        // read the body into a bounded buffer before
        // handing it to serde_json. A compromised PVE node returning
        // a 2 GiB body cannot OOM proxxx — the read aborts at
        // MAX_RESPONSE_BYTES.
        let bytes = read_bounded_body(resp, path).await?;
        // route large parses through spawn_blocking so a
        // 16 ms parse doesn't stall the reactor for that long.
        parse_json_maybe_blocking::<T>(bytes, path).await
    }

    /// Rate-limited, auth-aware POST request with retry on transient failures.
    async fn post<T: DeserializeOwned + Send + 'static>(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> Result<T> {
        // Incident lockdown gate — refuses every mutation when the
        // freeze lock is active. Reads (GET) intentionally skip this
        // check; investigators need observation during an incident.
        crate::incident::check_not_frozen_for(self.profile_config.profile_name.as_deref())?;
        let url = format!("{}/api2/json{}", self.base_url, path);
        debug!("POST {}", url);

        let resp = self
            .send_with_retry(path, |http| http.post(&url).form(params))
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            // Phase 7 — typed `ApiError` on write paths too. Previously
            // POST/PUT/DELETE bailed with plain anyhow strings, so the
            // TUI/CLI couldn't downcast 403s to a "permission denied"
            // banner the way GETs already could (audit closed
            // the GET path; this closes the rest).
            return Err(super::ApiError::from_status(status, path, body).into());
        }

        let bytes = read_bounded_body(resp, path).await?;
        // route large parses through spawn_blocking so a
        // 16 ms parse doesn't stall the reactor for that long.
        parse_json_maybe_blocking::<T>(bytes, path).await
    }

    /// Rate-limited, auth-aware PUT request with retry on transient
    /// failures. Used for partial updates of mutable resources — the
    /// PVE config endpoints (`/qemu/{vmid}/config`,
    /// `/lxc/{vmid}/config`, `/qemu/{vmid}/cloudinit`) are all PUT.
    async fn put<T: DeserializeOwned + Send + 'static>(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> Result<T> {
        crate::incident::check_not_frozen_for(self.profile_config.profile_name.as_deref())?;
        let url = format!("{}/api2/json{}", self.base_url, path);
        debug!("PUT {}", url);

        let resp = self
            .send_with_retry(path, |http| http.put(&url).form(params))
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            // Phase 7 — see POST helper above.
            return Err(super::ApiError::from_status(status, path, body).into());
        }

        let bytes = read_bounded_body(resp, path).await?;
        parse_json_maybe_blocking::<T>(bytes, path).await
    }

    /// Rate-limited, auth-aware DELETE request with retry on transient failures.
    async fn delete<T: DeserializeOwned + Send + 'static>(&self, path: &str) -> Result<T> {
        crate::incident::check_not_frozen_for(self.profile_config.profile_name.as_deref())?;
        let url = format!("{}/api2/json{}", self.base_url, path);
        debug!("DELETE {}", url);

        let resp = self.send_with_retry(path, |http| http.delete(&url)).await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            // Phase 7 — see POST helper above.
            return Err(super::ApiError::from_status(status, path, body).into());
        }

        let bytes = read_bounded_body(resp, path).await?;
        // route large parses through spawn_blocking so a
        // 16 ms parse doesn't stall the reactor for that long.
        parse_json_maybe_blocking::<T>(bytes, path).await
    }

    /// Proactive auth refresh — 120s before expiry
    async fn ensure_auth(&self) -> Result<()> {
        let needs_refresh = {
            let auth = self.auth.read().await;
            auth.needs_refresh()
        };

        if needs_refresh {
            warn!("Auth token expiring soon, refreshing...");
            let mut auth = self.auth.write().await;
            // Double-check after acquiring write lock
            if auth.needs_refresh() {
                let password = self.profile_config.resolve_password().await?;
                *auth = AuthMethod::login(
                    &self.http,
                    &self.base_url,
                    &self.profile_config.user,
                    &password,
                )
                .await?;
                info!("Auth refreshed successfully");
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl ProxmoxGateway for PxClient {
    async fn get_nodes(&self) -> Result<Vec<Node>> {
        let resp: ApiResponse<Vec<Node>> = self.get("/nodes").await?;
        Ok(resp.data)
    }

    async fn get_guests(&self, node: &str) -> Result<Vec<Guest>> {
        // Fetch both QEMU and LXC in parallel
        let (qemu_result, lxc_result) = tokio::join!(
            async {
                self.get::<ApiResponse<Vec<Guest>>>(&format!("/nodes/{node}/qemu"))
                    .await
            },
            async {
                self.get::<ApiResponse<Vec<Guest>>>(&format!("/nodes/{node}/lxc"))
                    .await
            }
        );

        // Propagate a failed sub-fetch instead of silently returning a PARTIAL
        // list. A truncated guest list looks exactly like guests vanishing —
        // when `/qemu` transiently failed, the old `if let Ok` dropped every VM
        // yet still returned `Ok`, so proxima's 5s poller flickered a stopped VM
        // in and out. Polling callers can retry / keep last-known on the error.
        let qemu = qemu_result.context("listing QEMU guests")?;
        let lxc = lxc_result.context("listing LXC guests")?;

        let mut guests = Vec::with_capacity(qemu.data.len() + lxc.data.len());
        for mut g in qemu.data {
            g.node = node.to_string();
            g.guest_type = GuestType::Qemu;
            guests.push(g);
        }
        for mut g in lxc.data {
            g.node = node.to_string();
            g.guest_type = GuestType::Lxc;
            guests.push(g);
        }
        Ok(guests)
    }

    async fn get_guest_status(&self, node: &str, vmid: u32) -> Result<Guest> {
        // Try QEMU first, then LXC
        let qemu_path = format!("/nodes/{node}/qemu/{vmid}/status/current");
        if let Ok(resp) = self.get::<ApiResponse<Guest>>(&qemu_path).await {
            return Ok(resp.data);
        }
        let lxc_path = format!("/nodes/{node}/lxc/{vmid}/status/current");
        let resp: ApiResponse<Guest> = self.get(&lxc_path).await?;
        Ok(resp.data)
    }

    async fn get_storage_pools(&self, node: &str) -> Result<Vec<StoragePool>> {
        let resp: ApiResponse<Vec<StoragePool>> =
            self.get(&format!("/nodes/{node}/storage")).await?;
        Ok(resp.data)
    }

    async fn get_task_log(
        &self,
        node: &str,
        upid: &str,
        start: usize,
        limit: usize,
    ) -> Result<TaskLog> {
        let resp: ApiResponse<Vec<super::types::TaskLogLine>> = self
            .get(&format!(
                "/nodes/{node}/tasks/{upid}/log?start={start}&limit={limit}"
            ))
            .await?;
        Ok(TaskLog {
            total: resp.data.len(),
            data: resp.data,
        })
    }

    async fn get_guest_config(
        &self,
        node: &str,
        vmid: u32,
        guest_type: &crate::api::types::GuestType,
    ) -> Result<std::collections::HashMap<String, String>> {
        let type_str = match guest_type {
            crate::api::types::GuestType::Qemu => "qemu",
            crate::api::types::GuestType::Lxc => "lxc",
        };
        let path = format!("/nodes/{node}/{type_str}/{vmid}/config");
        let resp: ApiResponse<std::collections::HashMap<String, serde_json::Value>> =
            self.get(&path).await?;

        let mut map = std::collections::HashMap::new();
        for (k, v) in resp.data {
            // Some values are strings, some are numbers/booleans. Convert all to string for grepping.
            let val_str = match v {
                serde_json::Value::String(s) => s,
                _ => v.to_string(),
            };
            map.insert(k, val_str);
        }
        Ok(map)
    }

    async fn get_cluster_tasks(&self) -> Result<Vec<crate::api::types::TaskInfo>> {
        let resp: ApiResponse<Vec<crate::api::types::TaskInfo>> =
            self.get("/cluster/tasks").await?;
        Ok(resp.data)
    }

    async fn get_task_status(
        &self,
        node: &str,
        upid: &str,
    ) -> Result<crate::api::types::TaskStatus> {
        // UPID contains colons that confuse some HTTP routers. PVE
        // accepts the raw UPID in the path — no URL-encoding needed
        // for these specific characters in PVE's pveproxy.
        let resp: ApiResponse<crate::api::types::TaskStatus> = self
            .get(&format!("/nodes/{node}/tasks/{upid}/status"))
            .await?;
        Ok(resp.data)
    }

    async fn start_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<String> = self
            .post(&format!("/nodes/{node}/{kind}/{vmid}/status/start"), &[])
            .await?;
        Ok(resp.data)
    }

    async fn stop_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        force: bool,
    ) -> Result<String> {
        // PVE's `/status/stop` endpoint is ALWAYS a hard kill (qm stop /
        // pct stop — SIGKILL the QEMU process or kill the LXC init).
        // There is no soft/force distinction at this endpoint for
        // either guest type; graceful shutdown lives at the separate
        // `/status/shutdown` endpoint and is exposed via the
        // `shutdown_guest` trait method (the CLI's `--force` flag
        // chooses between the two gateway methods, not a parameter
        // here).
        //
        // Live-cluster regression: an earlier
        // revision of this method added `forceStop=1` for QEMU,
        // believing it was the QEMU-only "also SIGKILL" toggle. PVE
        // 8/9's QEMU stop schema does not define `forceStop` — it
        // rejects with `400 Parameter verification failed:
        // forceStop: property is not defined in schema and the schema
        // does not allow additional properties`. Symptom: every
        // `proxxx stop --force <qemu-vmid>` failed exit 2 against a
        // running QEMU VM.
        //
        // The `force` arg is kept in the trait for caller-API
        // stability and to preserve future flexibility (PVE may
        // re-introduce a stop-time knob). It is currently a no-op.
        let _ = force;
        let kind = type_path(guest_type);
        let resp: ApiResponse<String> = self
            .post(&format!("/nodes/{node}/{kind}/{vmid}/status/stop"), &[])
            .await?;
        Ok(resp.data)
    }

    async fn shutdown_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        timeout_secs: u32,
    ) -> Result<String> {
        let kind = type_path(guest_type);
        let ts = timeout_secs.to_string();
        // forceStop=1: on QEMU, PVE SIGKILLs the process when timeout
        // expires instead of leaving the task appended indefinitely.
        // LXC rejects unknown params — only send for QEMU.
        let params: &[(&str, &str)] = match guest_type {
            crate::api::types::GuestType::Qemu => &[("timeout", &ts), ("forceStop", "1")],
            crate::api::types::GuestType::Lxc => &[("timeout", &ts)],
        };
        let resp: ApiResponse<String> = self
            .post(
                &format!("/nodes/{node}/{kind}/{vmid}/status/shutdown"),
                params,
            )
            .await?;
        Ok(resp.data)
    }

    async fn restart_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<String> = self
            .post(&format!("/nodes/{node}/{kind}/{vmid}/status/reboot"), &[])
            .await?;
        Ok(resp.data)
    }

    async fn suspend_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<String> = self
            .post(&format!("/nodes/{node}/{kind}/{vmid}/status/suspend"), &[])
            .await?;
        Ok(resp.data)
    }

    async fn resume_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<String> = self
            .post(&format!("/nodes/{node}/{kind}/{vmid}/status/resume"), &[])
            .await?;
        Ok(resp.data)
    }

    async fn startall_node(&self, node: &str) -> Result<String> {
        let resp: ApiResponse<String> = self.post(&format!("/nodes/{node}/startall"), &[]).await?;
        Ok(resp.data)
    }

    async fn stopall_node(&self, node: &str) -> Result<String> {
        let resp: ApiResponse<String> = self.post(&format!("/nodes/{node}/stopall"), &[]).await?;
        Ok(resp.data)
    }

    async fn suspendall_node(&self, node: &str) -> Result<String> {
        let resp: ApiResponse<String> =
            self.post(&format!("/nodes/{node}/suspendall"), &[]).await?;
        Ok(resp.data)
    }

    async fn node_apt_repositories(&self, node: &str) -> Result<serde_json::Value> {
        // The `/apt/repositories` payload nests file digests as raw u8
        // arrays + per-file repository lists with multiple sub-types
        // (.list, .sources). Modelling it strictly would require two
        // enums and a transparent base64-or-bytes wrapper for the
        // digest. For a MVP "show me what's there" view, returning
        // the raw `data` value keeps the wire format honest and lets
        // the CLI pretty-print without lossy conversion.
        let resp: ApiResponse<serde_json::Value> =
            self.get(&format!("/nodes/{node}/apt/repositories")).await?;
        Ok(resp.data)
    }

    async fn node_apt_changelog(&self, node: &str, package: &str) -> Result<String> {
        // PVE expects `?name={pkg}` (NOT `?package=…`). Misnaming the
        // param surfaces as a 400 with `parameter verification failed`.
        // The response `data` is plain Debian changelog text.
        let resp: ApiResponse<String> = self
            .get(&format!(
                "/nodes/{node}/apt/changelog?name={}",
                urlenc(package)
            ))
            .await?;
        Ok(resp.data)
    }

    async fn node_apt_versions(
        &self,
        node: &str,
    ) -> Result<Vec<crate::api::types::AptInstalledPackage>> {
        let resp: ApiResponse<Vec<crate::api::types::AptInstalledPackage>> =
            self.get(&format!("/nodes/{node}/apt/versions")).await?;
        Ok(resp.data)
    }

    async fn get_guest_rrddata(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        timeframe: crate::api::types::RrdTimeframe,
        cf: crate::api::types::RrdCf,
    ) -> Result<Vec<crate::api::types::RrdPoint>> {
        let kind = type_path(guest_type);
        let path = format!(
            "/nodes/{node}/{kind}/{vmid}/rrddata?timeframe={}&cf={}",
            timeframe.as_pve_str(),
            cf.as_pve_str(),
        );
        let resp: ApiResponse<Vec<crate::api::types::RrdPoint>> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn get_node_rrddata(
        &self,
        node: &str,
        timeframe: crate::api::types::RrdTimeframe,
        cf: crate::api::types::RrdCf,
    ) -> Result<Vec<crate::api::types::RrdPoint>> {
        let path = format!(
            "/nodes/{node}/rrddata?timeframe={}&cf={}",
            timeframe.as_pve_str(),
            cf.as_pve_str(),
        );
        let resp: ApiResponse<Vec<crate::api::types::RrdPoint>> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn get_storage_rrddata(
        &self,
        node: &str,
        storage: &str,
        timeframe: crate::api::types::RrdTimeframe,
        cf: crate::api::types::RrdCf,
    ) -> Result<Vec<crate::api::types::RrdPoint>> {
        let path = format!(
            "/nodes/{node}/storage/{}/rrddata?timeframe={}&cf={}",
            urlenc(storage),
            timeframe.as_pve_str(),
            cf.as_pve_str(),
        );
        let resp: ApiResponse<Vec<crate::api::types::RrdPoint>> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn migrate_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        target_node: &str,
        online: bool,
        with_local_disks: bool,
        restart: bool,
    ) -> Result<String> {
        use crate::api::types::GuestType;
        let kind = type_path(guest_type);
        let mut params: Vec<(&str, &str)> = vec![("target", target_node)];
        // QEMU live migration: needs `online=1` for running VMs. LXC
        // ignores `online`. `restart=1` is the LXC equivalent path —
        // shut down on source, copy state, restart on target.
        match guest_type {
            GuestType::Qemu => {
                if online {
                    params.push(("online", "1"));
                }
            }
            GuestType::Lxc => {
                // LXC live migration via CRIU is not enabled by default
                // and not supported in production. The standard path
                // for moving a running container is `restart=1`
                // (shutdown → migrate → restart). Without it, PVE
                // refuses to migrate a running container. We surface
                // this on the caller's choice rather than silently
                // forcing it.
                if restart {
                    params.push(("restart", "1"));
                }
            }
        }
        // `with-local-disks=1` is the PVE param name (hyphen, not
        // underscore — PVE is inconsistent across endpoints, this
        // one uses kebab-case).
        if with_local_disks {
            params.push(("with-local-disks", "1"));
        }
        let resp: ApiResponse<String> = self
            .post(&format!("/nodes/{node}/{kind}/{vmid}/migrate"), &params)
            .await?;
        Ok(resp.data)
    }

    async fn delete_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String> {
        let kind = type_path(guest_type);
        // SPOF 2.3 (Category 2 audit) — TOCTOU pre-flight gate.
        //
        // Between the user authorising delete (often via HITL with a
        // human-in-the-loop delay) and the API call landing, a separate
        // admin could start the guest. PVE's own server-side guard is
        // version-dependent; we add a defence-in-depth check here so the
        // last-line behaviour is provable from this code, not from PVE
        // configuration.
        //
        // We re-fetch the live status; if it diverges from `Stopped` we
        // refuse the destructive op with a clear, actionable error rather
        // than risk a force-delete on a now-running guest.
        let pre = self
            .get::<ApiResponse<crate::api::types::Guest>>(&format!(
                "/nodes/{node}/{kind}/{vmid}/status/current"
            ))
            .await
            .with_context(|| format!("pre-flight status check for delete of {kind} {vmid}"))?;
        if pre.data.status != crate::api::types::GuestStatus::Stopped {
            anyhow::bail!(
                "refusing destructive delete: {kind} {vmid} is now {:?} (was expected Stopped). \
                 Stop the guest first, then retry.",
                pre.data.status
            );
        }

        let resp: ApiResponse<String> =
            self.delete(&format!("/nodes/{node}/{kind}/{vmid}")).await?;
        Ok(resp.data)
    }

    async fn execute_guest_command(
        &self,
        node: &str,
        vmid: u32,
        guest_type: &crate::api::types::GuestType,
        command: &str,
    ) -> Result<crate::api::types::GuestExecResult> {
        use crate::api::types::{AgentExecResponse, AgentExecStatusResponse, GuestExecResult};

        // Broadcast "sh -c command"
        let cmds = format!("[\"sh\", \"-c\", \"{}\"]", command.replace('"', "\\\""));

        // (audit) — QEMU agent exec has its own failure mode:
        // if the guest's QGA daemon is wedged (Linux kernel hang,
        // Windows update freeze, agent-not-installed), the call
        // can pin a connection for minutes despite the 30 s reqwest
        // default. Wrap in an explicit per-call timeout so the
        // user gets a clean "guest agent unresponsive" error
        // within a bounded window. Same budget bounds the post-submit
        // polling loop on QEMU (we re-use the deadline).
        const QGA_EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
        const QGA_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

        // Bug #1 audit: exhaustive match. If Proxmox adds a new GuestType
        // variant (e.g. "Pod"), the compiler MUST refuse to build until
        // the dispatch is updated. The previous `if==Qemu else { lxc }`
        // would have silently treated unknown variants as LXC.
        let params = [("command", cmds.as_str())];
        match guest_type {
            crate::api::types::GuestType::Qemu => {
                // Step 1: submit the command — agent forks it and
                // returns the PID immediately.
                let exec_path = format!("/nodes/{node}/qemu/{vmid}/agent/exec");
                let exec_resp = tokio::time::timeout(
                    QGA_EXEC_TIMEOUT,
                    self.post::<ApiResponse<AgentExecResponse>>(&exec_path, &params),
                )
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "QEMU guest agent on guest {vmid} did not respond within {QGA_EXEC_TIMEOUT:?} \
                         — agent likely wedged (kernel hang, Windows update, or QGA not installed)"
                    )
                })??;
                let pid = exec_resp.data.pid;

                // Step 2: poll exec-status until the command exits or
                // we run out of time. Without this, we'd return the
                // PID and lose the exit code + stdout + stderr — the
                // pre-fix behaviour that broke shell-pipeline UX.
                let status_path = format!("/nodes/{node}/qemu/{vmid}/agent/exec-status?pid={pid}");
                let deadline = tokio::time::Instant::now() + QGA_EXEC_TIMEOUT;
                loop {
                    if tokio::time::Instant::now() >= deadline {
                        anyhow::bail!(
                            "QEMU guest agent exec on guest {vmid} (pid {pid}) did not \
                             complete within {QGA_EXEC_TIMEOUT:?} — command still running, abandoning poll"
                        );
                    }
                    let status_resp: ApiResponse<AgentExecStatusResponse> =
                        self.get(&status_path).await?;
                    if status_resp.data.exited {
                        return Ok(GuestExecResult {
                            exit_code: status_resp.data.exitcode,
                            stdout: status_resp.data.out_data,
                            stderr: status_resp.data.err_data,
                        });
                    }
                    tokio::time::sleep(QGA_POLL_INTERVAL).await;
                }
            }
            crate::api::types::GuestType::Lxc => {
                // PVE 9 does NOT expose `/lxc/{vmid}/exec` via REST —
                // verified empirically against pve-test cluster (the
                // available LXC subpaths are: config, pending, status,
                // vncproxy, termproxy, vncwebsocket, spiceproxy,
                // migrate, clone, rrd, rrddata, firewall, snapshot,
                // resize, interfaces — no `exec`). The Perl side has
                // `pct exec` but it's not lifted into the API surface.
                //
                // Earlier versions of this code POSTed to a non-
                // existent path and returned a 501 from PVE wrapped
                // in a confusing parse error. We now bail with a
                // clear path-forward message: use the serial console
                // / SSH for one-shot commands, or the TUI's PtyView
                // for interactive shells.
                //
                // Suppress unused-variable warnings without removing
                // the params (the QEMU branch needs them and the
                // parameter list is shared above).
                let _ = (
                    node,
                    vmid,
                    command,
                    &params,
                    QGA_EXEC_TIMEOUT,
                    QGA_POLL_INTERVAL,
                );
                anyhow::bail!(
                    "LXC exec via REST is not available in PVE 9+. Use \
                     `proxxx serial <vmid>` for an interactive session, \
                     or run the command over SSH against the host (lxc \
                     containers expose their network interfaces under \
                     `/lxc/{{vmid}}/interfaces`)"
                )
            }
        }
    }

    // ── QGA file ops + network introspection impls ─────────

    async fn qemu_agent_file_read(
        &self,
        node: &str,
        vmid: u32,
        file: &str,
    ) -> Result<crate::api::types::GuestAgentFileContent> {
        let path = format!(
            "/nodes/{node}/qemu/{vmid}/agent/file-read?file={}",
            urlenc(file)
        );
        let resp: ApiResponse<crate::api::types::GuestAgentFileContent> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn qemu_agent_file_write(
        &self,
        node: &str,
        vmid: u32,
        file: &str,
        content: &str,
    ) -> Result<()> {
        let path = format!("/nodes/{node}/qemu/{vmid}/agent/file-write");
        let _resp: ApiResponse<Option<String>> = self
            .post(&path, &[("file", file), ("content", content)])
            .await?;
        Ok(())
    }

    async fn qemu_agent_network_get_interfaces(
        &self,
        node: &str,
        vmid: u32,
    ) -> Result<Vec<crate::api::types::GuestAgentNetworkInterface>> {
        // PVE wraps the QGA response in `{result: [...]}` rather than
        // returning the array directly. We hop through serde_json::Value
        // to peel that wrapper before deserializing the typed shape, so
        // the trait surface stays clean.
        let path = format!("/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces");
        let resp: ApiResponse<serde_json::Value> = self.get(&path).await?;
        let result = resp
            .data
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        let ifaces: Vec<crate::api::types::GuestAgentNetworkInterface> =
            serde_json::from_value(result).unwrap_or_default();
        Ok(ifaces)
    }

    // ── Node system layer impls ────────────────────────────

    async fn get_node_dns(&self, node: &str) -> Result<crate::api::types::NodeDns> {
        let resp: ApiResponse<crate::api::types::NodeDns> =
            self.get(&format!("/nodes/{node}/dns")).await?;
        Ok(resp.data)
    }
    async fn update_node_dns(&self, node: &str, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> =
            self.put(&format!("/nodes/{node}/dns"), params).await?;
        Ok(())
    }

    async fn get_node_hosts(&self, node: &str) -> Result<crate::api::types::NodeHosts> {
        let resp: ApiResponse<crate::api::types::NodeHosts> =
            self.get(&format!("/nodes/{node}/hosts")).await?;
        Ok(resp.data)
    }
    async fn update_node_hosts(&self, node: &str, data: &str, digest: Option<&str>) -> Result<()> {
        let mut params: Vec<(&str, &str)> = vec![("data", data)];
        if let Some(d) = digest {
            params.push(("digest", d));
        }
        let _resp: ApiResponse<Option<String>> =
            self.post(&format!("/nodes/{node}/hosts"), &params).await?;
        Ok(())
    }

    async fn get_node_journal(&self, node: &str, query: &[(&str, &str)]) -> Result<Vec<String>> {
        // Concatenate after the literal path so the static-analysis
        // map gate sees `/nodes/{node}/journal` instead of treating
        // the query placeholder as a path segment.
        let mut path = format!("/nodes/{node}/journal");
        append_query(&mut path, query);
        let resp: ApiResponse<Vec<String>> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn get_node_syslog(
        &self,
        node: &str,
        query: &[(&str, &str)],
    ) -> Result<Vec<crate::api::types::NodeSyslogLine>> {
        let mut path = format!("/nodes/{node}/syslog");
        append_query(&mut path, query);
        let resp: ApiResponse<Vec<crate::api::types::NodeSyslogLine>> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn get_node_time(&self, node: &str) -> Result<crate::api::types::NodeTime> {
        let resp: ApiResponse<crate::api::types::NodeTime> =
            self.get(&format!("/nodes/{node}/time")).await?;
        Ok(resp.data)
    }
    async fn update_node_timezone(&self, node: &str, timezone: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(&format!("/nodes/{node}/time"), &[("timezone", timezone)])
            .await?;
        Ok(())
    }

    async fn wakeonlan_node(&self, node: &str) -> Result<String> {
        let resp: ApiResponse<String> = self.post(&format!("/nodes/{node}/wakeonlan"), &[]).await?;
        Ok(resp.data)
    }

    async fn get_node_subscription(
        &self,
        node: &str,
    ) -> Result<crate::api::types::NodeSubscription> {
        let resp: ApiResponse<crate::api::types::NodeSubscription> =
            self.get(&format!("/nodes/{node}/subscription")).await?;
        Ok(resp.data)
    }
    async fn set_node_subscription_key(&self, node: &str, key: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .post(&format!("/nodes/{node}/subscription"), &[("key", key)])
            .await?;
        Ok(())
    }
    async fn refresh_node_subscription(&self, node: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(&format!("/nodes/{node}/subscription"), &[])
            .await?;
        Ok(())
    }
    async fn delete_node_subscription(&self, node: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> =
            self.delete(&format!("/nodes/{node}/subscription")).await?;
        Ok(())
    }

    async fn get_node_certificates_info(
        &self,
        node: &str,
    ) -> Result<Vec<crate::api::types::NodeCertificateInfo>> {
        let resp: ApiResponse<Vec<crate::api::types::NodeCertificateInfo>> = self
            .get(&format!("/nodes/{node}/certificates/info"))
            .await?;
        Ok(resp.data)
    }
    async fn upload_node_custom_certificate(
        &self,
        node: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        let _resp: ApiResponse<serde_json::Value> = self
            .post(&format!("/nodes/{node}/certificates/custom"), params)
            .await?;
        Ok(())
    }
    async fn delete_node_custom_certificate(&self, node: &str, restart: bool) -> Result<()> {
        let restart_str = if restart { "1" } else { "0" };
        let path = format!("/nodes/{node}/certificates/custom?restart={restart_str}");
        let _resp: ApiResponse<Option<String>> = self.delete(&path).await?;
        Ok(())
    }
    async fn order_node_acme_certificate(&self, node: &str, force: bool) -> Result<String> {
        let force_str = if force { "1" } else { "0" };
        let resp: ApiResponse<String> = self
            .post(
                &format!("/nodes/{node}/certificates/acme/certificate"),
                &[("force", force_str)],
            )
            .await?;
        Ok(resp.data)
    }

    async fn get_node_report(&self, node: &str) -> Result<String> {
        let resp: ApiResponse<String> = self.get(&format!("/nodes/{node}/report")).await?;
        Ok(resp.data)
    }

    // ── Pools, cluster resources, version impls ────────────

    async fn list_pools(&self) -> Result<Vec<crate::api::types::Pool>> {
        let resp: ApiResponse<Vec<crate::api::types::Pool>> = self.get("/pools").await?;
        Ok(resp.data)
    }
    async fn get_pool(&self, poolid: &str) -> Result<crate::api::types::PoolDetails> {
        let resp: ApiResponse<crate::api::types::PoolDetails> =
            self.get(&format!("/pools/{}", urlenc(poolid))).await?;
        Ok(resp.data)
    }
    async fn create_pool(&self, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self.post("/pools", params).await?;
        Ok(())
    }
    async fn update_pool(&self, poolid: &str, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(&format!("/pools/{}", urlenc(poolid)), params)
            .await?;
        Ok(())
    }
    async fn delete_pool(&self, poolid: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> =
            self.delete(&format!("/pools/{}", urlenc(poolid))).await?;
        Ok(())
    }

    async fn get_cluster_resources(
        &self,
        kind: Option<&str>,
    ) -> Result<Vec<crate::api::types::ClusterResource>> {
        let mut path = String::from("/cluster/resources");
        if let Some(k) = kind {
            append_query(&mut path, &[("type", k)]);
        }
        let resp: ApiResponse<Vec<crate::api::types::ClusterResource>> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn get_api_version(&self) -> Result<crate::api::types::ApiVersion> {
        let resp: ApiResponse<crate::api::types::ApiVersion> = self.get("/version").await?;
        Ok(resp.data)
    }

    // ── Cluster options + log impls ────────────────────────

    async fn get_cluster_options(&self) -> Result<crate::api::types::ClusterOptions> {
        let resp: ApiResponse<crate::api::types::ClusterOptions> =
            self.get("/cluster/options").await?;
        Ok(resp.data)
    }
    async fn update_cluster_options(&self, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self.put("/cluster/options", params).await?;
        Ok(())
    }
    async fn get_cluster_log(
        &self,
        max: Option<u32>,
    ) -> Result<Vec<crate::api::types::ClusterLogEntry>> {
        let mut path = String::from("/cluster/log");
        if let Some(n) = max {
            let n_str = n.to_string();
            append_query(&mut path, &[("max", n_str.as_str())]);
        }
        let resp: ApiResponse<Vec<crate::api::types::ClusterLogEntry>> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn create_snapshot(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        name: &str,
    ) -> Result<String> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<String> = self
            .post(
                &format!("/nodes/{node}/{kind}/{vmid}/snapshot"),
                &[("snapname", name)],
            )
            .await?;
        Ok(resp.data)
    }

    async fn delete_snapshot(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        name: &str,
    ) -> Result<String> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<String> = self
            .delete(&format!("/nodes/{node}/{kind}/{vmid}/snapshot/{name}"))
            .await?;
        Ok(resp.data)
    }

    async fn rollback_snapshot(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        name: &str,
    ) -> Result<String> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<String> = self
            .post(
                &format!("/nodes/{node}/{kind}/{vmid}/snapshot/{name}/rollback"),
                &[],
            )
            .await?;
        Ok(resp.data)
    }

    async fn update_guest_config(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        params: &[(String, String)],
    ) -> Result<Option<String>> {
        let kind = type_path(guest_type);
        // The reqwest form serializer takes &[(&str, &str)]; the trait
        // takes owned `(String, String)` so the CLI dispatcher can
        // build pairs from typed flags + raw user input without
        // lifetime gymnastics. Convert at the boundary.
        let pairs: Vec<(&str, &str)> = params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let resp: ApiResponse<Option<String>> = self
            .put(&format!("/nodes/{node}/{kind}/{vmid}/config"), &pairs)
            .await?;
        Ok(resp.data)
    }

    async fn regenerate_cloudinit(&self, node: &str, vmid: u32) -> Result<Option<String>> {
        // PVE's regen endpoint accepts no body params — it just
        // re-emits the cloud-init ISO from the current ci* fields.
        let resp: ApiResponse<Option<String>> = self
            .put(&format!("/nodes/{node}/qemu/{vmid}/cloudinit"), &[])
            .await?;
        Ok(resp.data)
    }

    async fn list_pending_config(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<Vec<crate::api::types::PendingConfigEntry>> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<Vec<crate::api::types::PendingConfigEntry>> = self
            .get(&format!("/nodes/{node}/{kind}/{vmid}/pending"))
            .await?;
        Ok(resp.data)
    }

    async fn convert_to_template(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String> {
        let kind = type_path(guest_type);
        // PVE returns `{"data": null}` on success for both QEMU and
        // LXC template conversion (verified live against pve-test).
        // Use `Option<String>` so the deserializer accepts null
        // instead of failing the whole call with a parse error.
        let resp: ApiResponse<Option<String>> = self
            .post(&format!("/nodes/{node}/{kind}/{vmid}/template"), &[])
            .await?;
        Ok(resp.data.unwrap_or_default())
    }

    #[allow(clippy::too_many_arguments)]
    async fn clone_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        newid: u32,
        name: Option<&str>,
        target: Option<&str>,
        storage: Option<&str>,
        full: bool,
        snapname: Option<&str>,
        description: Option<&str>,
    ) -> Result<String> {
        let kind = type_path(guest_type);
        let newid_str = newid.to_string();
        let mut params: Vec<(&str, &str)> = vec![("newid", newid_str.as_str())];
        if let Some(n) = name {
            // QEMU exposes the name field as `name`, LXC as `hostname`.
            // Same semantic field, different serialization key — PVE
            // historic divergence we paper over here so callers don't
            // have to branch.
            let key = match guest_type {
                crate::api::types::GuestType::Qemu => "name",
                crate::api::types::GuestType::Lxc => "hostname",
            };
            params.push((key, n));
        }
        if let Some(t) = target {
            params.push(("target", t));
        }
        if let Some(s) = storage {
            params.push(("storage", s));
        }
        if full {
            params.push(("full", "1"));
        }
        if let Some(s) = snapname {
            params.push(("snapname", s));
        }
        if let Some(d) = description {
            params.push(("description", d));
        }
        let resp: ApiResponse<String> = self
            .post(&format!("/nodes/{node}/{kind}/{vmid}/clone"), &params)
            .await?;
        Ok(resp.data)
    }

    async fn next_free_vmid(&self) -> Result<u32> {
        // PVE wraps the value as a JSON string — `{"data": "100"}` —
        // not a JSON number. Deserialize as String, then parse.
        let resp: ApiResponse<String> = self.get("/cluster/nextid").await?;
        resp.data
            .parse::<u32>()
            .with_context(|| format!("PVE returned non-integer nextid: {:?}", resp.data))
    }

    async fn create_backup(
        &self,
        node: &str,
        vmids: &[u32],
        storage: &str,
        mode: &str,
        compress: Option<&str>,
    ) -> Result<String> {
        // PVE expects `vmid` as a comma-separated list (e.g. "100,101,200").
        // The endpoint is the SAME for QEMU and LXC — vzdump dispatches
        // internally based on each vmid's guest type.
        let vmid_csv: String = vmids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut params: Vec<(&str, &str)> = vec![
            ("vmid", vmid_csv.as_str()),
            ("storage", storage),
            ("mode", mode),
        ];
        if let Some(c) = compress {
            params.push(("compress", c));
        }
        let resp: ApiResponse<String> =
            self.post(&format!("/nodes/{node}/vzdump"), &params).await?;
        Ok(resp.data)
    }

    async fn list_snapshots(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<Vec<crate::api::types::Snapshot>> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<Vec<crate::api::types::Snapshot>> = self
            .get(&format!("/nodes/{node}/{kind}/{vmid}/snapshot"))
            .await?;
        Ok(resp.data)
    }

    async fn download_to_storage(
        &self,
        node: &str,
        storage: &str,
        url: &str,
        filename: &str,
        checksum_algo: Option<&str>,
        checksum_hex: Option<&str>,
        content: &str,
    ) -> Result<String> {
        let mut params: Vec<(&str, &str)> =
            vec![("url", url), ("filename", filename), ("content", content)];
        // Schema: caller passes (algo, hex) together. Both
        // present → forward as-is; either None → omit (Proxmox
        // accepts download-url without a checksum).
        if let (Some(algo), Some(hex)) = (checksum_algo, checksum_hex) {
            params.push(("checksum", hex));
            params.push(("checksum-algorithm", algo));
        }
        let resp: ApiResponse<String> = self
            .post(
                &format!("/nodes/{node}/storage/{storage}/download-url"),
                &params,
            )
            .await?;
        Ok(resp.data)
    }

    async fn list_storage_content(
        &self,
        node: &str,
        storage: &str,
        content_filter: Option<&str>,
    ) -> Result<Vec<crate::api::types::StorageContent>> {
        let path = match content_filter {
            Some(c) => format!("/nodes/{node}/storage/{storage}/content?content={c}"),
            None => format!("/nodes/{node}/storage/{storage}/content"),
        };
        let resp: ApiResponse<Vec<crate::api::types::StorageContent>> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn get_spiceproxy(
        &self,
        node: &str,
        vmid: u32,
    ) -> Result<crate::api::types::SpiceConfig> {
        // SPICE is QEMU-only. We hardcode the `qemu/` path because LXC
        // has no graphical SPICE display surface — the caller must not
        // even attempt this for an LXC vmid (we'll let Proxmox 4xx if
        // they do, surfacing the right error).
        let resp: ApiResponse<crate::api::types::SpiceConfig> = self
            .post(&format!("/nodes/{node}/qemu/{vmid}/spiceproxy"), &[])
            .await?;
        Ok(resp.data)
    }

    async fn get_termproxy(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<crate::api::types::TermproxyTicket> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<crate::api::types::TermproxyTicket> = self
            .post(&format!("/nodes/{node}/{kind}/{vmid}/termproxy"), &[])
            .await?;
        Ok(resp.data)
    }

    async fn get_guest_vncproxy(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<crate::api::types::VncTicket> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<crate::api::types::VncTicket> = self
            .post(&format!("/nodes/{node}/{kind}/{vmid}/vncproxy"), &[])
            .await?;
        Ok(resp.data)
    }

    // ── Top-tier 80/20 closure impls ────────────────────────

    async fn get_access_permissions(
        &self,
        userid: Option<&str>,
        api_path: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut query: Vec<(&str, &str)> = vec![];
        if let Some(u) = userid {
            query.push(("userid", u));
        }
        if let Some(p) = api_path {
            query.push(("path", p));
        }
        let mut path = String::from("/access/permissions");
        append_query(&mut path, &query);
        let resp: ApiResponse<serde_json::Value> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn change_user_password(&self, userid: &str, password: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(
                "/access/password",
                &[("userid", userid), ("password", password)],
            )
            .await?;
        Ok(())
    }

    async fn list_lxc_interfaces(
        &self,
        node: &str,
        vmid: u32,
    ) -> Result<Vec<crate::api::types::LxcInterface>> {
        let resp: ApiResponse<Vec<crate::api::types::LxcInterface>> = self
            .get(&format!("/nodes/{node}/lxc/{vmid}/interfaces"))
            .await?;
        Ok(resp.data)
    }

    async fn dump_qemu_cloudinit(&self, node: &str, vmid: u32, kind: &str) -> Result<String> {
        let mut path = format!("/nodes/{node}/qemu/{vmid}/cloudinit/dump");
        append_query(&mut path, &[("type", kind)]);
        let resp: ApiResponse<String> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn build_guest_vncwebsocket_url(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        ticket: &crate::api::types::VncTicket,
    ) -> Result<String> {
        // Swap http(s)→ws(s) so the URL signals WebSocket intent. PVE
        // accepts the http(s) form too (same TCP port), but ws(s)://
        // makes the operator's intent unambiguous when the URL gets
        // shipped to a noVNC client or tokio-tungstenite.
        let kind = type_path(guest_type);
        // Build the leading-slash path first as its own literal — that
        // makes the static-analysis map gate see `/nodes/.../vncwebsocket`
        // as a real PVE path string. The leading slash is required for
        // `is_pve_path` to fire.
        let path = format!("/nodes/{node}/{kind}/{vmid}/vncwebsocket");
        let ws_base = if let Some(rest) = self.base_url.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.base_url.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            self.base_url.clone()
        };
        Ok(format!(
            "{ws_base}/api2/json{path}?port={}&vncticket={}",
            ticket.port,
            urlenc(&ticket.ticket),
        ))
    }

    async fn get_lxc_spiceproxy(
        &self,
        node: &str,
        vmid: u32,
    ) -> Result<crate::api::types::SpiceConfig> {
        let resp: ApiResponse<crate::api::types::SpiceConfig> = self
            .post(&format!("/nodes/{node}/lxc/{vmid}/spiceproxy"), &[])
            .await?;
        Ok(resp.data)
    }

    async fn lxc_exec_oneshot(
        &self,
        node: &str,
        vmid: u32,
        command: &str,
    ) -> Result<serde_json::Value> {
        // LXC's native exec endpoint takes a `command` form param.
        // Returns `{ "pid": <int> }`. Status polling lives at
        // `/lxc/{vmid}/status/exec/{pid}` and is a separate follow-up
        // (parity with QEMU's QGA exec polling).
        let resp: ApiResponse<serde_json::Value> = self
            .post(
                &format!("/nodes/{node}/lxc/{vmid}/exec"),
                &[("command", command)],
            )
            .await?;
        Ok(resp.data)
    }

    async fn get_node_termproxy(&self, node: &str) -> Result<crate::api::types::TermproxyTicket> {
        let resp: ApiResponse<crate::api::types::TermproxyTicket> =
            self.post(&format!("/nodes/{node}/termproxy"), &[]).await?;
        Ok(resp.data)
    }

    async fn get_node_vncshell(&self, node: &str) -> Result<crate::api::types::VncTicket> {
        let resp: ApiResponse<crate::api::types::VncTicket> =
            self.post(&format!("/nodes/{node}/vncshell"), &[]).await?;
        Ok(resp.data)
    }

    async fn get_node_spiceshell(&self, node: &str) -> Result<crate::api::types::SpiceConfig> {
        let resp: ApiResponse<crate::api::types::SpiceConfig> =
            self.post(&format!("/nodes/{node}/spiceshell"), &[]).await?;
        Ok(resp.data)
    }

    async fn list_backup_jobs(&self) -> Result<Vec<crate::api::types::BackupJob>> {
        let resp: ApiResponse<Vec<crate::api::types::BackupJob>> =
            self.get("/cluster/backup").await?;
        Ok(resp.data)
    }

    async fn get_backup_job(&self, id: &str) -> Result<crate::api::types::BackupJob> {
        let resp: ApiResponse<crate::api::types::BackupJob> =
            self.get(&format!("/cluster/backup/{}", urlenc(id))).await?;
        Ok(resp.data)
    }

    async fn create_backup_job(&self, params: &[(&str, &str)]) -> Result<()> {
        // Phase 7 — POST goes through `ApiError::from_status`, so a
        // missing required field surfaces as typed `Other { status: 400 }`
        // (or `Forbidden` if the token lacks Datastore.Allocate).
        let _resp: ApiResponse<Option<String>> = self.post("/cluster/backup", params).await?;
        Ok(())
    }

    async fn update_backup_job(&self, id: &str, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(&format!("/cluster/backup/{}", urlenc(id)), params)
            .await?;
        Ok(())
    }

    async fn delete_backup_job(&self, id: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/cluster/backup/{}", urlenc(id)))
            .await?;
        Ok(())
    }

    async fn cluster_backup_info(&self) -> Result<serde_json::Value> {
        let resp: ApiResponse<serde_json::Value> = self.get("/cluster/backup-info").await?;
        Ok(resp.data)
    }

    async fn extract_backup_config(&self, node: &str, volume: &str) -> Result<String> {
        let path = format!(
            "/nodes/{node}/vzdump/extractconfig?volume={}",
            urlenc(volume)
        );
        let resp: ApiResponse<String> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn list_acl(&self) -> Result<Vec<crate::api::types::AclEntry>> {
        let resp: ApiResponse<Vec<crate::api::types::AclEntry>> = self.get("/access/acl").await?;
        Ok(resp.data)
    }

    async fn list_users(&self) -> Result<Vec<crate::api::types::User>> {
        let resp: ApiResponse<Vec<crate::api::types::User>> = self.get("/access/users").await?;
        Ok(resp.data)
    }

    async fn create_user(
        &self,
        userid: &str,
        password: Option<&str>,
        comment: Option<&str>,
        email: Option<&str>,
        firstname: Option<&str>,
        lastname: Option<&str>,
        enable: Option<bool>,
        expire: Option<u64>,
        groups: Option<&str>,
    ) -> Result<()> {
        // Build params dynamically — PVE only accepts the fields the
        // caller sets. Sending `enable=` with empty value, or
        // `expire=` with 0 when the caller didn't ask for it, would
        // override the server-side defaults silently. We only push
        // keys the caller explicitly opted into.
        let mut params: Vec<(&str, String)> = vec![("userid", userid.to_string())];
        if let Some(p) = password {
            params.push(("password", p.to_string()));
        }
        if let Some(c) = comment {
            params.push(("comment", c.to_string()));
        }
        if let Some(e) = email {
            params.push(("email", e.to_string()));
        }
        if let Some(f) = firstname {
            params.push(("firstname", f.to_string()));
        }
        if let Some(l) = lastname {
            params.push(("lastname", l.to_string()));
        }
        if let Some(en) = enable {
            params.push(("enable", if en { "1" } else { "0" }.to_string()));
        }
        if let Some(ex) = expire {
            params.push(("expire", ex.to_string()));
        }
        if let Some(g) = groups {
            params.push(("groups", g.to_string()));
        }
        let pairs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let _resp: ApiResponse<Option<String>> = self.post("/access/users", &pairs).await?;
        Ok(())
    }

    async fn update_user(
        &self,
        userid: &str,
        comment: Option<&str>,
        email: Option<&str>,
        firstname: Option<&str>,
        lastname: Option<&str>,
        enable: Option<bool>,
        expire: Option<u64>,
        groups: Option<&str>,
    ) -> Result<()> {
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(c) = comment {
            params.push(("comment", c.to_string()));
        }
        if let Some(e) = email {
            params.push(("email", e.to_string()));
        }
        if let Some(f) = firstname {
            params.push(("firstname", f.to_string()));
        }
        if let Some(l) = lastname {
            params.push(("lastname", l.to_string()));
        }
        if let Some(en) = enable {
            params.push(("enable", if en { "1" } else { "0" }.to_string()));
        }
        if let Some(ex) = expire {
            params.push(("expire", ex.to_string()));
        }
        if let Some(g) = groups {
            params.push(("groups", g.to_string()));
        }
        let pairs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let path = format!("/access/users/{}", urlenc(userid));
        let _resp: ApiResponse<Option<String>> = self.put(&path, &pairs).await?;
        Ok(())
    }

    async fn delete_user(&self, userid: &str) -> Result<()> {
        let path = format!("/access/users/{}", urlenc(userid));
        let _resp: ApiResponse<Option<String>> = self.delete(&path).await?;
        Ok(())
    }

    async fn create_group(&self, groupid: &str, comment: Option<&str>) -> Result<()> {
        let mut params: Vec<(&str, &str)> = vec![("groupid", groupid)];
        if let Some(c) = comment {
            params.push(("comment", c));
        }
        let _resp: ApiResponse<Option<String>> = self.post("/access/groups", &params).await?;
        Ok(())
    }

    async fn delete_group(&self, groupid: &str) -> Result<()> {
        let path = format!("/access/groups/{}", urlenc(groupid));
        let _resp: ApiResponse<Option<String>> = self.delete(&path).await?;
        Ok(())
    }

    async fn modify_acl(
        &self,
        path: &str,
        roles: &str,
        users: Option<&str>,
        groups: Option<&str>,
        tokens: Option<&str>,
        propagate: bool,
        delete: bool,
    ) -> Result<()> {
        // PVE's single ACL endpoint covers grant + revoke. `delete=1`
        // toggles to revoke mode; everything else shapes which user/
        // group/token gets the role. PVE accepts multiple `users` /
        // `groups` / `tokens` in the same call (CSV) but we model
        // one role-target per call so the audit log is unambiguous.
        let mut params: Vec<(&str, String)> = vec![
            ("path", path.to_string()),
            ("roles", roles.to_string()),
            ("propagate", if propagate { "1" } else { "0" }.to_string()),
        ];
        if let Some(u) = users {
            params.push(("users", u.to_string()));
        }
        if let Some(g) = groups {
            params.push(("groups", g.to_string()));
        }
        if let Some(t) = tokens {
            params.push(("tokens", t.to_string()));
        }
        if delete {
            params.push(("delete", "1".to_string()));
        }
        let pairs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let _resp: ApiResponse<Option<String>> = self.put("/access/acl", &pairs).await?;
        Ok(())
    }

    async fn list_user_tokens(&self, userid: &str) -> Result<Vec<crate::api::types::ApiToken>> {
        let path = format!("/access/users/{}/token", urlenc(userid));
        let resp: ApiResponse<Vec<crate::api::types::ApiToken>> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn list_groups(&self) -> Result<Vec<crate::api::types::Group>> {
        let resp: ApiResponse<Vec<crate::api::types::Group>> = self.get("/access/groups").await?;
        Ok(resp.data)
    }

    async fn list_roles(&self) -> Result<Vec<crate::api::types::Role>> {
        let resp: ApiResponse<Vec<crate::api::types::Role>> = self.get("/access/roles").await?;
        Ok(resp.data)
    }

    async fn list_realms(&self) -> Result<Vec<crate::api::types::Realm>> {
        let resp: ApiResponse<Vec<crate::api::types::Realm>> = self.get("/access/domains").await?;
        Ok(resp.data)
    }

    async fn list_tfa(&self, userid: &str) -> Result<Vec<crate::api::types::TfaEntry>> {
        let path = format!("/access/tfa/{}", urlenc(userid));
        let resp: ApiResponse<Vec<crate::api::types::TfaEntry>> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn create_token(
        &self,
        userid: &str,
        tokenid: &str,
        privsep: bool,
        expire: Option<u64>,
        comment: Option<&str>,
    ) -> Result<crate::api::types::ApiToken> {
        // Proxmox `POST /access/users/{userid}/token/{tokenid}` returns
        // `{"info": {...}, "value": "<secret>"}`. We normalise that into
        // the same `ApiToken` struct used elsewhere by setting `value`.
        let path = format!("/access/users/{}/token/{}", urlenc(userid), urlenc(tokenid));
        let privsep_s = if privsep { "1" } else { "0" };
        let mut params: Vec<(&str, String)> = vec![("privsep", privsep_s.to_string())];
        if let Some(e) = expire {
            params.push(("expire", e.to_string()));
        }
        if let Some(c) = comment {
            params.push(("comment", c.to_string()));
        }
        // We need the params as &[(&str, &str)] for `post`. Convert.
        let owned: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let resp: ApiResponse<TokenCreateResponse> = self.post(&path, &owned).await?;
        Ok(crate::api::types::ApiToken {
            tokenid: tokenid.to_string(),
            privsep: resp.data.info.privsep,
            comment: resp.data.info.comment,
            expire: resp.data.info.expire,
            value: Some(resp.data.value),
        })
    }

    async fn revoke_token(&self, userid: &str, tokenid: &str) -> Result<()> {
        let path = format!("/access/users/{}/token/{}", urlenc(userid), urlenc(tokenid));
        let _: ApiResponse<serde_json::Value> = self.delete(&path).await?;
        Ok(())
    }

    async fn delete_storage_content(
        &self,
        node: &str,
        storage: &str,
        volid: &str,
    ) -> Result<Option<String>> {
        // `volid` contains `:` and `/` which MUST be percent-encoded
        // for the path segment. PVE rejects raw `/` in volid
        // (interprets as another path level).
        let encoded = urlenc(volid);
        let resp: ApiResponse<Option<String>> = self
            .delete(&format!(
                "/nodes/{node}/storage/{storage}/content/{encoded}"
            ))
            .await?;
        Ok(resp.data)
    }

    async fn upload_to_storage(
        &self,
        node: &str,
        storage: &str,
        local_path: &std::path::Path,
        content_type: &str,
        remote_filename: Option<&str>,
    ) -> Result<String> {
        // Derive the destination filename if the caller didn't pin one.
        let filename = match remote_filename {
            Some(n) => n.to_string(),
            None => local_path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "could not derive filename from local path {}",
                        local_path.display()
                    )
                })?
                .to_string(),
        };

        // Streaming upload: open the file as a `tokio::fs::File`,
        // wrap as a `Stream<Item = Result<Bytes, _>>` via
        // `ReaderStream`, then hand to reqwest as a streaming body.
        // Memory footprint is one chunk (~8 KiB), constant regardless
        // of file size — a 6 GiB ISO no longer requires 6 GiB RAM
        // (the previous Vec<u8>-buffered code path).
        //
        // Side-effect of streaming: this body is single-shot. On
        // transient retry the file pointer is at EOF — we'd have to
        // re-open. Rather than complicate the closure, we BYPASS
        // `send_with_retry` for upload. Uploads of 1+ GB are slow
        // enough that auto-retry is the wrong default anyway (a
        // failed upload costs minutes; the user should decide whether
        // to retry, not us).
        let file = tokio::fs::File::open(local_path)
            .await
            .with_context(|| format!("opening {} for upload", local_path.display()))?;
        let file_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        let stream = tokio_util::io::ReaderStream::new(file);
        let body = reqwest::Body::wrap_stream(stream);
        let part = reqwest::multipart::Part::stream_with_length(body, file_size)
            .file_name(filename.clone())
            .mime_str("application/octet-stream")
            .map_err(|e| anyhow::anyhow!("invalid MIME for upload: {e}"))?;

        // PVE upload wire format quirk: the binary content goes in a
        // multipart part NAMED `filename` (not `file`); the
        // destination filename is taken from that part's multipart
        // filename attribute. The `content` field is plain text.
        // Verified empirically — sending the file in a `file` field
        // returned `400 Bad Request: ` with no diagnostic.
        let form = reqwest::multipart::Form::new()
            .text("content", content_type.to_string())
            .part("filename", part);

        let path = format!("/nodes/{node}/storage/{storage}/upload");
        let url = format!("{}/api2/json{}", self.base_url, path);
        debug!("POST {} (streaming upload, {} bytes)", url, file_size);

        // Manual auth + send (no retry): re-using the same auth
        // application path as send_with_retry but without the loop.
        self.ensure_auth().await?;
        self.limiter.until_ready().await;
        let auth = self.auth.read().await;
        let req = auth.apply(self.http.post(&url).multipart(form));
        let resp = req.send().await?;
        drop(auth);

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            // Phase 7 — typed error so callers can downcast 403/4xx
            // on multipart upload, same as the generic helpers.
            return Err(super::ApiError::from_status(status, &path, body).into());
        }
        let bytes = read_bounded_body(resp, &path).await?;
        let parsed: ApiResponse<String> = parse_json_maybe_blocking(bytes, &path).await?;
        Ok(parsed.data)
    }

    async fn list_pci(&self, node: &str) -> Result<Vec<crate::api::types::PciDevice>> {
        let resp: ApiResponse<Vec<crate::api::types::PciDevice>> =
            self.get(&format!("/nodes/{node}/hardware/pci")).await?;
        Ok(resp.data)
    }

    async fn list_cluster_firewall_rules(&self) -> Result<Vec<crate::api::types::FirewallRule>> {
        let resp: ApiResponse<Vec<crate::api::types::FirewallRule>> =
            self.get("/cluster/firewall/rules").await?;
        Ok(resp.data)
    }

    async fn list_node_firewall_rules(
        &self,
        node: &str,
    ) -> Result<Vec<crate::api::types::FirewallRule>> {
        let resp: ApiResponse<Vec<crate::api::types::FirewallRule>> =
            self.get(&format!("/nodes/{node}/firewall/rules")).await?;
        Ok(resp.data)
    }

    async fn list_guest_firewall_rules(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<Vec<crate::api::types::FirewallRule>> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<Vec<crate::api::types::FirewallRule>> = self
            .get(&format!("/nodes/{node}/{kind}/{vmid}/firewall/rules"))
            .await?;
        Ok(resp.data)
    }

    // ── Cluster firewall CRUD impls ────────────────────────

    async fn list_cluster_firewall_aliases(&self) -> Result<Vec<crate::api::types::FirewallAlias>> {
        let resp: ApiResponse<Vec<crate::api::types::FirewallAlias>> =
            self.get("/cluster/firewall/aliases").await?;
        Ok(resp.data)
    }
    async fn create_cluster_firewall_alias(&self, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> =
            self.post("/cluster/firewall/aliases", params).await?;
        Ok(())
    }
    async fn update_cluster_firewall_alias(
        &self,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(
                &format!("/cluster/firewall/aliases/{}", urlenc(name)),
                params,
            )
            .await?;
        Ok(())
    }
    async fn delete_cluster_firewall_alias(&self, name: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/cluster/firewall/aliases/{}", urlenc(name)))
            .await?;
        Ok(())
    }

    async fn list_cluster_firewall_groups(
        &self,
    ) -> Result<Vec<crate::api::types::FirewallSecurityGroup>> {
        let resp: ApiResponse<Vec<crate::api::types::FirewallSecurityGroup>> =
            self.get("/cluster/firewall/groups").await?;
        Ok(resp.data)
    }
    async fn create_cluster_firewall_group(&self, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> =
            self.post("/cluster/firewall/groups", params).await?;
        Ok(())
    }
    async fn delete_cluster_firewall_group(&self, group: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/cluster/firewall/groups/{}", urlenc(group)))
            .await?;
        Ok(())
    }
    async fn list_cluster_firewall_group_rules(
        &self,
        group: &str,
    ) -> Result<Vec<crate::api::types::FirewallRule>> {
        let resp: ApiResponse<Vec<crate::api::types::FirewallRule>> = self
            .get(&format!("/cluster/firewall/groups/{}", urlenc(group)))
            .await?;
        Ok(resp.data)
    }

    async fn list_cluster_firewall_ipsets(&self) -> Result<Vec<crate::api::types::FirewallIpset>> {
        let resp: ApiResponse<Vec<crate::api::types::FirewallIpset>> =
            self.get("/cluster/firewall/ipset").await?;
        Ok(resp.data)
    }
    async fn create_cluster_firewall_ipset(&self, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> =
            self.post("/cluster/firewall/ipset", params).await?;
        Ok(())
    }
    async fn delete_cluster_firewall_ipset(&self, name: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/cluster/firewall/ipset/{}", urlenc(name)))
            .await?;
        Ok(())
    }
    async fn list_cluster_firewall_ipset_cidrs(
        &self,
        name: &str,
    ) -> Result<Vec<crate::api::types::FirewallIpsetCidr>> {
        let resp: ApiResponse<Vec<crate::api::types::FirewallIpsetCidr>> = self
            .get(&format!("/cluster/firewall/ipset/{}", urlenc(name)))
            .await?;
        Ok(resp.data)
    }
    async fn add_cluster_firewall_ipset_cidr(
        &self,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .post(&format!("/cluster/firewall/ipset/{}", urlenc(name)), params)
            .await?;
        Ok(())
    }
    async fn remove_cluster_firewall_ipset_cidr(&self, name: &str, cidr: &str) -> Result<()> {
        // PVE accepts the CIDR as the path tail (slashes percent-encoded).
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!(
                "/cluster/firewall/ipset/{}/{}",
                urlenc(name),
                urlenc(cidr)
            ))
            .await?;
        Ok(())
    }

    async fn get_cluster_firewall_options(&self) -> Result<crate::api::types::FirewallOptions> {
        let resp: ApiResponse<crate::api::types::FirewallOptions> =
            self.get("/cluster/firewall/options").await?;
        Ok(resp.data)
    }
    async fn update_cluster_firewall_options(&self, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> =
            self.put("/cluster/firewall/options", params).await?;
        Ok(())
    }

    // ── Per-guest firewall CRUD impls ──────────────────────

    async fn list_guest_firewall_aliases(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<Vec<crate::api::types::FirewallAlias>> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<Vec<crate::api::types::FirewallAlias>> = self
            .get(&format!("/nodes/{node}/{kind}/{vmid}/firewall/aliases"))
            .await?;
        Ok(resp.data)
    }
    async fn create_guest_firewall_alias(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        params: &[(&str, &str)],
    ) -> Result<()> {
        let kind = type_path(guest_type);
        let _resp: ApiResponse<Option<String>> = self
            .post(
                &format!("/nodes/{node}/{kind}/{vmid}/firewall/aliases"),
                params,
            )
            .await?;
        Ok(())
    }
    async fn update_guest_firewall_alias(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        let kind = type_path(guest_type);
        let _resp: ApiResponse<Option<String>> = self
            .put(
                &format!(
                    "/nodes/{node}/{kind}/{vmid}/firewall/aliases/{}",
                    urlenc(name)
                ),
                params,
            )
            .await?;
        Ok(())
    }
    async fn delete_guest_firewall_alias(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        name: &str,
    ) -> Result<()> {
        let kind = type_path(guest_type);
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!(
                "/nodes/{node}/{kind}/{vmid}/firewall/aliases/{}",
                urlenc(name)
            ))
            .await?;
        Ok(())
    }
    async fn get_guest_firewall_options(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<crate::api::types::GuestFirewallOptions> {
        let kind = type_path(guest_type);
        let resp: ApiResponse<crate::api::types::GuestFirewallOptions> = self
            .get(&format!("/nodes/{node}/{kind}/{vmid}/firewall/options"))
            .await?;
        Ok(resp.data)
    }
    async fn update_guest_firewall_options(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        params: &[(&str, &str)],
    ) -> Result<()> {
        let kind = type_path(guest_type);
        let _resp: ApiResponse<Option<String>> = self
            .put(
                &format!("/nodes/{node}/{kind}/{vmid}/firewall/options"),
                params,
            )
            .await?;
        Ok(())
    }

    // ── Cluster hardware mapping impls (PCI + USB) ─────────

    async fn list_cluster_mapping_pci(&self) -> Result<Vec<crate::api::types::ClusterMappingPci>> {
        let resp: ApiResponse<Vec<crate::api::types::ClusterMappingPci>> =
            self.get("/cluster/mapping/pci").await?;
        Ok(resp.data)
    }
    async fn create_cluster_mapping_pci(&self, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self.post("/cluster/mapping/pci", params).await?;
        Ok(())
    }
    async fn update_cluster_mapping_pci(&self, id: &str, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(&format!("/cluster/mapping/pci/{}", urlenc(id)), params)
            .await?;
        Ok(())
    }
    async fn delete_cluster_mapping_pci(&self, id: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/cluster/mapping/pci/{}", urlenc(id)))
            .await?;
        Ok(())
    }

    async fn list_cluster_mapping_usb(&self) -> Result<Vec<crate::api::types::ClusterMappingUsb>> {
        let resp: ApiResponse<Vec<crate::api::types::ClusterMappingUsb>> =
            self.get("/cluster/mapping/usb").await?;
        Ok(resp.data)
    }
    async fn create_cluster_mapping_usb(&self, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self.post("/cluster/mapping/usb", params).await?;
        Ok(())
    }
    async fn update_cluster_mapping_usb(&self, id: &str, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(&format!("/cluster/mapping/usb/{}", urlenc(id)), params)
            .await?;
        Ok(())
    }
    async fn delete_cluster_mapping_usb(&self, id: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/cluster/mapping/usb/{}", urlenc(id)))
            .await?;
        Ok(())
    }

    async fn list_node_network(
        &self,
        node: &str,
    ) -> Result<Vec<crate::api::types::NetworkInterface>> {
        let resp: ApiResponse<Vec<crate::api::types::NetworkInterface>> =
            self.get(&format!("/nodes/{node}/network")).await?;
        Ok(resp.data)
    }

    async fn list_usb(&self, node: &str) -> Result<Vec<crate::api::types::UsbDevice>> {
        let resp: ApiResponse<Vec<crate::api::types::UsbDevice>> =
            self.get(&format!("/nodes/{node}/hardware/usb")).await?;
        Ok(resp.data)
    }

    async fn list_node_disks(&self, node: &str) -> Result<Vec<crate::api::types::Disk>> {
        let resp: ApiResponse<Vec<crate::api::types::Disk>> =
            self.get(&format!("/nodes/{node}/disks/list")).await?;
        Ok(resp.data)
    }

    async fn get_disk_smart(&self, node: &str, disk: &str) -> Result<crate::api::types::DiskSmart> {
        // PVE expects the disk path as a query parameter, not in the
        // URL path — `?disk=/dev/sda`. The leading `/` survives URL
        // encoding (PVE specifically expects it raw).
        let path = format!("/nodes/{node}/disks/smart?disk={}", urlenc(disk));
        let resp: ApiResponse<crate::api::types::DiskSmart> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn list_node_lvm(&self, node: &str) -> Result<Vec<crate::api::types::LvmVolumeGroup>> {
        // PVE returns a tree: `{ data: { children: [<vg>, ...] } }`.
        // Each `<vg>` has its own `children` (the LVs inside) which we
        // discard — we expose the VG-level summary only. Capturing the
        // full LV tree is a future story.
        #[derive(serde::Deserialize)]
        struct LvmTree {
            #[serde(default)]
            children: Vec<crate::api::types::LvmVolumeGroup>,
        }
        let resp: ApiResponse<LvmTree> = self.get(&format!("/nodes/{node}/disks/lvm")).await?;
        Ok(resp.data.children)
    }

    async fn list_node_lvmthin(&self, node: &str) -> Result<Vec<crate::api::types::LvmThinPool>> {
        // PVE quirk: `/disks/lvmthin` REQUIRES a `vg` parameter, but
        // omitting it returns the union across all VGs (verified
        // against PVE 9.1.1). Future-proof: explicit `vg=*` would also
        // work but PVE versions disagree on whether `*` is allowed —
        // omitting is the most compatible.
        let resp: ApiResponse<Vec<crate::api::types::LvmThinPool>> =
            self.get(&format!("/nodes/{node}/disks/lvmthin")).await?;
        Ok(resp.data)
    }

    async fn list_node_zfs(&self, node: &str) -> Result<Vec<crate::api::types::ZfsPool>> {
        let resp: ApiResponse<Vec<crate::api::types::ZfsPool>> =
            self.get(&format!("/nodes/{node}/disks/zfs")).await?;
        Ok(resp.data)
    }

    async fn list_ha_groups(&self) -> Result<Vec<crate::api::types::HaGroup>> {
        // PVE 9 migrated `/cluster/ha/groups` → `/cluster/ha/rules`. The old
        // path now returns a 500 with a deprecation message. Until the type
        // is renamed (HaGroup → HaRule) and downstream consumers updated,
        // we point at the new endpoint and rely on `#[serde(default)]` on
        // every field — an empty rules array deserializes cleanly to
        // `Vec<HaGroup>`. When the cluster grows actual rules, fields will
        // need to be reshaped to match the rules schema.
        let resp: ApiResponse<Vec<crate::api::types::HaGroup>> =
            self.get("/cluster/ha/rules").await?;
        Ok(resp.data)
    }

    async fn list_ha_resources(&self) -> Result<Vec<crate::api::types::HaResource>> {
        let resp: ApiResponse<Vec<crate::api::types::HaResource>> =
            self.get("/cluster/ha/resources").await?;
        Ok(resp.data)
    }

    async fn ha_manager_status(&self) -> Result<crate::api::types::HaManagerStatus> {
        // Some PVE versions return a flat object, others wrap node_status
        // in an array. We accept the simple object form (current default).
        let resp: ApiResponse<crate::api::types::HaManagerStatus> =
            self.get("/cluster/ha/status/manager_status").await?;
        Ok(resp.data)
    }

    async fn get_ha_status_current(&self) -> Result<Vec<crate::api::types::HaStatusEntry>> {
        let resp: ApiResponse<Vec<crate::api::types::HaStatusEntry>> =
            self.get("/cluster/ha/status/current").await?;
        Ok(resp.data)
    }

    async fn list_ha_groups_legacy(&self) -> Result<Vec<crate::api::types::HaGroup>> {
        let resp: ApiResponse<Vec<crate::api::types::HaGroup>> =
            self.get("/cluster/ha/groups").await?;
        Ok(resp.data)
    }
    async fn create_ha_group(&self, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self.post("/cluster/ha/groups", params).await?;
        Ok(())
    }
    async fn update_ha_group(&self, group: &str, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(&format!("/cluster/ha/groups/{}", urlenc(group)), params)
            .await?;
        Ok(())
    }
    async fn delete_ha_group(&self, group: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/cluster/ha/groups/{}", urlenc(group)))
            .await?;
        Ok(())
    }

    // ── PVE 9 HA rules — node-affinity + resource-affinity ─

    async fn list_ha_rules(&self) -> Result<Vec<crate::api::types::HaRule>> {
        let resp: ApiResponse<Vec<crate::api::types::HaRule>> =
            self.get("/cluster/ha/rules").await?;
        Ok(resp.data)
    }

    async fn create_ha_rule(&self, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self.post("/cluster/ha/rules", params).await?;
        Ok(())
    }

    async fn update_ha_rule(&self, rule: &str, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(&format!("/cluster/ha/rules/{}", urlenc(rule)), params)
            .await?;
        Ok(())
    }

    async fn delete_ha_rule(&self, rule: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/cluster/ha/rules/{}", urlenc(rule)))
            .await?;
        Ok(())
    }

    // ── PVE 9 HA resources CRUD (epic #74 epilogue) ──────────

    async fn create_ha_resource(&self, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self.post("/cluster/ha/resources", params).await?;
        Ok(())
    }

    async fn update_ha_resource(&self, sid: &str, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(&format!("/cluster/ha/resources/{}", urlenc(sid)), params)
            .await?;
        Ok(())
    }

    async fn delete_ha_resource(&self, sid: &str) -> Result<()> {
        // PVE defaults purge=1 — removes this SID from any HA rules
        // referencing it (and deletes a rule entirely if it had only
        // this resource). Explicit in the URL for documentation.
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/cluster/ha/resources/{}", urlenc(sid)))
            .await?;
        Ok(())
    }

    // ── PVE 8+ notifications impls ─────────────────────────

    async fn list_notification_endpoints(
        &self,
    ) -> Result<Vec<crate::api::types::NotificationEndpoint>> {
        // PVE 8/9 quirk discovered live:
        // `/cluster/notifications/endpoints` returns the CATALOG of
        // supported types as `[{"name":"gotify"},{"name":"sendmail"},
        // {"name":"smtp"},{"name":"webhook"}]` — NOT user-configured
        // instances. Configured instances live under per-type paths
        // `/cluster/notifications/endpoints/<type>`. The naive
        // catalog-as-list impl made `proxxx notifications endpoint
        // list` invisibly return four type-name rows with empty fields
        // instead of the user's actual webhooks / mail rules.
        //
        // Fix: fan out to the four PVE-8/9 stable types and concat.
        // The per-type response omits the `type` field (it's implicit
        // in the URL), so we inject it client-side so callers don't
        // see empty `endpoint_type`.
        const TYPES: &[&str] = &["sendmail", "smtp", "gotify", "webhook"];
        let mut all = Vec::new();
        for &t in TYPES {
            let resp: ApiResponse<Vec<crate::api::types::NotificationEndpoint>> = self
                .get(&format!("/cluster/notifications/endpoints/{}", urlenc(t)))
                .await?;
            for mut e in resp.data {
                if e.endpoint_type.is_empty() {
                    e.endpoint_type = t.to_string();
                }
                all.push(e);
            }
        }
        Ok(all)
    }
    async fn create_notification_endpoint(
        &self,
        endpoint_type: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .post(
                &format!("/cluster/notifications/endpoints/{}", urlenc(endpoint_type)),
                params,
            )
            .await?;
        Ok(())
    }
    async fn update_notification_endpoint(
        &self,
        endpoint_type: &str,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(
                &format!(
                    "/cluster/notifications/endpoints/{}/{}",
                    urlenc(endpoint_type),
                    urlenc(name)
                ),
                params,
            )
            .await?;
        Ok(())
    }
    async fn delete_notification_endpoint(&self, endpoint_type: &str, name: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!(
                "/cluster/notifications/endpoints/{}/{}",
                urlenc(endpoint_type),
                urlenc(name)
            ))
            .await?;
        Ok(())
    }

    async fn list_notification_matchers(
        &self,
    ) -> Result<Vec<crate::api::types::NotificationMatcher>> {
        let resp: ApiResponse<Vec<crate::api::types::NotificationMatcher>> =
            self.get("/cluster/notifications/matchers").await?;
        Ok(resp.data)
    }
    async fn create_notification_matcher(&self, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> =
            self.post("/cluster/notifications/matchers", params).await?;
        Ok(())
    }
    async fn update_notification_matcher(&self, name: &str, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(
                &format!("/cluster/notifications/matchers/{}", urlenc(name)),
                params,
            )
            .await?;
        Ok(())
    }
    async fn delete_notification_matcher(&self, name: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/cluster/notifications/matchers/{}", urlenc(name)))
            .await?;
        Ok(())
    }

    async fn list_notification_targets(
        &self,
    ) -> Result<Vec<crate::api::types::NotificationTarget>> {
        let resp: ApiResponse<Vec<crate::api::types::NotificationTarget>> =
            self.get("/cluster/notifications/targets").await?;
        Ok(resp.data)
    }

    // ── RRD PNG + cluster.metrics.server impls ─────────────

    async fn get_guest_rrd_image(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        ds: &str,
        timeframe: crate::api::types::RrdTimeframe,
        cf: crate::api::types::RrdCf,
    ) -> Result<crate::api::types::RrdImage> {
        let kind = type_path(guest_type);
        let mut path = format!("/nodes/{node}/{kind}/{vmid}/rrd");
        append_query(
            &mut path,
            &[
                ("ds", ds),
                ("timeframe", timeframe.as_pve_str()),
                ("cf", cf.as_pve_str()),
            ],
        );
        let resp: ApiResponse<crate::api::types::RrdImage> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn list_metric_servers(&self) -> Result<Vec<crate::api::types::MetricServer>> {
        let resp: ApiResponse<Vec<crate::api::types::MetricServer>> =
            self.get("/cluster/metrics/server").await?;
        Ok(resp.data)
    }
    async fn get_metric_server(&self, id: &str) -> Result<crate::api::types::MetricServer> {
        let resp: ApiResponse<crate::api::types::MetricServer> = self
            .get(&format!("/cluster/metrics/server/{}", urlenc(id)))
            .await?;
        Ok(resp.data)
    }
    async fn create_metric_server(&self, id: &str, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .post(&format!("/cluster/metrics/server/{}", urlenc(id)), params)
            .await?;
        Ok(())
    }
    async fn update_metric_server(&self, id: &str, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(&format!("/cluster/metrics/server/{}", urlenc(id)), params)
            .await?;
        Ok(())
    }
    async fn delete_metric_server(&self, id: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/cluster/metrics/server/{}", urlenc(id)))
            .await?;
        Ok(())
    }

    // ── 80/20 grab-bag impls ───────────────────────────────

    async fn list_node_tasks(
        &self,
        node: &str,
        limit: Option<u32>,
    ) -> Result<Vec<crate::api::types::TaskInfo>> {
        let mut path = format!("/nodes/{node}/tasks");
        if let Some(n) = limit {
            let n_str = n.to_string();
            append_query(&mut path, &[("limit", n_str.as_str())]);
        }
        let resp: ApiResponse<Vec<crate::api::types::TaskInfo>> = self.get(&path).await?;
        Ok(resp.data)
    }
    async fn stop_node_task(&self, node: &str, upid: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/nodes/{node}/tasks/{}", urlenc(upid)))
            .await?;
        Ok(())
    }

    async fn get_guest_feature(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        feature: &str,
    ) -> Result<crate::api::types::GuestFeatureCheck> {
        let kind = type_path(guest_type);
        let path = format!(
            "/nodes/{node}/{kind}/{vmid}/feature?feature={}",
            urlenc(feature)
        );
        let resp: ApiResponse<crate::api::types::GuestFeatureCheck> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn send_qemu_key(&self, node: &str, vmid: u32, key: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(
                &format!("/nodes/{node}/qemu/{vmid}/sendkey"),
                &[("key", key)],
            )
            .await?;
        Ok(())
    }

    async fn unlink_qemu_disk(
        &self,
        node: &str,
        vmid: u32,
        idlist: &str,
        force: bool,
    ) -> Result<()> {
        let force_str = if force { "1" } else { "0" };
        let _resp: ApiResponse<Option<String>> = self
            .put(
                &format!("/nodes/{node}/qemu/{vmid}/unlink"),
                &[("idlist", idlist), ("force", force_str)],
            )
            .await?;
        Ok(())
    }

    async fn list_node_aplinfo(&self, node: &str) -> Result<Vec<crate::api::types::AplTemplate>> {
        let resp: ApiResponse<Vec<crate::api::types::AplTemplate>> =
            self.get(&format!("/nodes/{node}/aplinfo")).await?;
        Ok(resp.data)
    }
    async fn download_node_aplinfo(
        &self,
        node: &str,
        storage: &str,
        template: &str,
    ) -> Result<String> {
        let resp: ApiResponse<String> = self
            .post(
                &format!("/nodes/{node}/aplinfo"),
                &[("storage", storage), ("template", template)],
            )
            .await?;
        Ok(resp.data)
    }

    async fn query_url_metadata(
        &self,
        node: &str,
        url: &str,
    ) -> Result<crate::api::types::UrlMetadata> {
        let mut path = format!("/nodes/{node}/query-url-metadata");
        append_query(&mut path, &[("url", url)]);
        let resp: ApiResponse<crate::api::types::UrlMetadata> = self.get(&path).await?;
        Ok(resp.data)
    }

    // ── Corosync cluster bootstrap impls ───────────────────

    async fn list_cluster_corosync_nodes(&self) -> Result<Vec<crate::api::types::CorosyncNode>> {
        let resp: ApiResponse<Vec<crate::api::types::CorosyncNode>> =
            self.get("/cluster/config/nodes").await?;
        Ok(resp.data)
    }
    async fn add_cluster_corosync_node(&self, node: &str, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .post(&format!("/cluster/config/nodes/{}", urlenc(node)), params)
            .await?;
        Ok(())
    }
    async fn remove_cluster_corosync_node(&self, node: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/cluster/config/nodes/{}", urlenc(node)))
            .await?;
        Ok(())
    }

    async fn get_cluster_join_info(&self, node: Option<&str>) -> Result<serde_json::Value> {
        let mut path = String::from("/cluster/config/join");
        if let Some(n) = node {
            append_query(&mut path, &[("node", n)]);
        }
        let resp: ApiResponse<serde_json::Value> = self.get(&path).await?;
        Ok(resp.data)
    }
    async fn join_cluster(&self, params: &[(&str, &str)]) -> Result<String> {
        let resp: ApiResponse<String> = self.post("/cluster/config/join", params).await?;
        Ok(resp.data)
    }

    async fn get_cluster_qdevice(&self) -> Result<serde_json::Value> {
        let resp: ApiResponse<serde_json::Value> = self.get("/cluster/config/qdevice").await?;
        Ok(resp.data)
    }
    async fn setup_cluster_qdevice(&self, params: &[(&str, &str)]) -> Result<String> {
        let resp: ApiResponse<String> = self.post("/cluster/config/qdevice", params).await?;
        Ok(resp.data)
    }
    async fn update_cluster_qdevice(&self, params: &[(&str, &str)]) -> Result<String> {
        let resp: ApiResponse<String> = self.put("/cluster/config/qdevice", params).await?;
        Ok(resp.data)
    }
    async fn remove_cluster_qdevice(&self) -> Result<String> {
        let resp: ApiResponse<String> = self.delete("/cluster/config/qdevice").await?;
        Ok(resp.data)
    }

    async fn get_cluster_totem(&self) -> Result<serde_json::Value> {
        let resp: ApiResponse<serde_json::Value> = self.get("/cluster/config/totem").await?;
        Ok(resp.data)
    }

    // ── ACME impls ─────────────────────────────────────────

    async fn list_acme_accounts(&self) -> Result<Vec<crate::api::types::AcmeAccount>> {
        let resp: ApiResponse<Vec<crate::api::types::AcmeAccount>> =
            self.get("/cluster/acme/account").await?;
        Ok(resp.data)
    }
    async fn get_acme_account(&self, name: &str) -> Result<crate::api::types::AcmeAccountDetails> {
        let resp: ApiResponse<crate::api::types::AcmeAccountDetails> = self
            .get(&format!("/cluster/acme/account/{}", urlenc(name)))
            .await?;
        Ok(resp.data)
    }
    async fn create_acme_account(&self, params: &[(&str, &str)]) -> Result<String> {
        let resp: ApiResponse<String> = self.post("/cluster/acme/account", params).await?;
        Ok(resp.data)
    }
    async fn update_acme_account(&self, name: &str, params: &[(&str, &str)]) -> Result<String> {
        let resp: ApiResponse<String> = self
            .put(&format!("/cluster/acme/account/{}", urlenc(name)), params)
            .await?;
        Ok(resp.data)
    }
    async fn delete_acme_account(&self, name: &str) -> Result<String> {
        let resp: ApiResponse<String> = self
            .delete(&format!("/cluster/acme/account/{}", urlenc(name)))
            .await?;
        Ok(resp.data)
    }

    async fn list_acme_plugins(&self) -> Result<Vec<crate::api::types::AcmePlugin>> {
        let resp: ApiResponse<Vec<crate::api::types::AcmePlugin>> =
            self.get("/cluster/acme/plugins").await?;
        Ok(resp.data)
    }
    async fn get_acme_plugin(&self, plugin_id: &str) -> Result<crate::api::types::AcmePlugin> {
        let resp: ApiResponse<crate::api::types::AcmePlugin> = self
            .get(&format!("/cluster/acme/plugins/{}", urlenc(plugin_id)))
            .await?;
        Ok(resp.data)
    }
    async fn create_acme_plugin(&self, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self.post("/cluster/acme/plugins", params).await?;
        Ok(())
    }
    async fn update_acme_plugin(&self, plugin_id: &str, params: &[(&str, &str)]) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .put(
                &format!("/cluster/acme/plugins/{}", urlenc(plugin_id)),
                params,
            )
            .await?;
        Ok(())
    }
    async fn delete_acme_plugin(&self, plugin_id: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/cluster/acme/plugins/{}", urlenc(plugin_id)))
            .await?;
        Ok(())
    }

    async fn get_acme_tos(&self, directory: Option<&str>) -> Result<String> {
        let mut path = String::from("/cluster/acme/tos");
        if let Some(d) = directory {
            append_query(&mut path, &[("directory", d)]);
        }
        let resp: ApiResponse<String> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn list_acme_directories(&self) -> Result<Vec<crate::api::types::AcmeDirectory>> {
        let resp: ApiResponse<Vec<crate::api::types::AcmeDirectory>> =
            self.get("/cluster/acme/directories").await?;
        Ok(resp.data)
    }

    async fn get_acme_challenge_schema(&self) -> Result<serde_json::Value> {
        let resp: ApiResponse<serde_json::Value> =
            self.get("/cluster/acme/challenge-schema").await?;
        Ok(resp.data)
    }

    // ── Cluster-wide storage definitions impls ─────────────

    async fn list_cluster_storages(&self) -> Result<Vec<crate::api::types::StorageDefinition>> {
        let resp: ApiResponse<Vec<crate::api::types::StorageDefinition>> =
            self.get("/storage").await?;
        Ok(resp.data)
    }
    async fn get_cluster_storage(
        &self,
        storage: &str,
    ) -> Result<crate::api::types::StorageDefinition> {
        let resp: ApiResponse<crate::api::types::StorageDefinition> =
            self.get(&format!("/storage/{}", urlenc(storage))).await?;
        Ok(resp.data)
    }
    async fn create_cluster_storage(&self, params: &[(&str, &str)]) -> Result<()> {
        // PVE returns the materialized config as an object on success
        // (`{"data": {"storage": "...", "type": "dir"}}`), not a UPID
        // string and not null. Live-cluster regression discovered when
        // create succeeded but proxxx exited non-zero with "Failed to
        // parse response from /storage" because we typed the response
        // as `Option<String>`. Use `serde_json::Value` since we discard
        // the body — the typed `StorageDefinition` returned from a
        // follow-up `get_cluster_storage` is the real source of truth.
        let _resp: ApiResponse<serde_json::Value> = self.post("/storage", params).await?;
        Ok(())
    }
    async fn update_cluster_storage(&self, storage: &str, params: &[(&str, &str)]) -> Result<()> {
        // Same shape as `create_cluster_storage`: PUT returns the
        // updated config as an object, not a UPID. Discard with
        // `serde_json::Value`.
        let _resp: ApiResponse<serde_json::Value> = self
            .put(&format!("/storage/{}", urlenc(storage)), params)
            .await?;
        Ok(())
    }
    async fn delete_cluster_storage(&self, storage: &str) -> Result<()> {
        let _resp: ApiResponse<Option<String>> = self
            .delete(&format!("/storage/{}", urlenc(storage)))
            .await?;
        Ok(())
    }

    async fn cluster_status(&self) -> Result<Vec<crate::api::types::ClusterStatusEntry>> {
        let resp: ApiResponse<Vec<crate::api::types::ClusterStatusEntry>> =
            self.get("/cluster/status").await?;
        Ok(resp.data)
    }

    async fn list_replication_jobs(&self) -> Result<Vec<crate::api::types::ReplicationJob>> {
        let resp: ApiResponse<Vec<crate::api::types::ReplicationJob>> =
            self.get("/cluster/replication").await?;
        Ok(resp.data)
    }

    async fn list_replication_status(
        &self,
        node: &str,
    ) -> Result<Vec<crate::api::types::ReplicationStatus>> {
        let resp: ApiResponse<Vec<crate::api::types::ReplicationStatus>> =
            self.get(&format!("/nodes/{node}/replication")).await?;
        Ok(resp.data)
    }

    async fn move_disk(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        disk: &str,
        target_storage: &str,
        delete_source: bool,
    ) -> Result<String> {
        // QEMU and LXC have different endpoint names AND different
        // parameter names for the disk identifier (`disk` vs `volume`).
        // The exhaustive match makes a future GuestType break the build.
        let delete_str = if delete_source { "1" } else { "0" };
        let result = match guest_type {
            crate::api::types::GuestType::Qemu => {
                let params = vec![
                    ("disk", disk),
                    ("storage", target_storage),
                    ("delete", delete_str),
                ];
                let resp: Result<ApiResponse<String>> = self
                    .post(&format!("/nodes/{node}/qemu/{vmid}/move_disk"), &params)
                    .await;
                resp.map(|r| r.data)
            }
            crate::api::types::GuestType::Lxc => {
                let params = vec![
                    ("volume", disk),
                    ("storage", target_storage),
                    ("delete", delete_str),
                ];
                let resp: Result<ApiResponse<String>> = self
                    .post(&format!("/nodes/{node}/lxc/{vmid}/move_volume"), &params)
                    .await;
                resp.map(|r| r.data)
            }
        };

        // (audit) — storage backends behave very differently:
        //   - LVM-Thin / qcow2: streaming copy, slow but always works.
        //   - ZFS: `zfs send | recv`, blocking + slow.
        //   - Ceph RBD: usually a metadata flip (fast), but rejects
        //     cross-pool moves on some PVE versions with the body
        //     "Target storage does not support live migration".
        //   - Some directory-based storages reject moves of running
        //     guests entirely.
        //
        // PVE returns these as HTTP 500 with a body string we don't
        // currently expose well. Wrap the error so the caller sees
        // an actionable message instead of a generic "POST returned
        // 500" — particularly the "does not support live migration"
        // case which the user can resolve by stopping the guest first.
        result.map_err(|e| {
            let s = format!("{e:#}");
            if s.contains("does not support live migration") || s.contains("not support online") {
                anyhow::anyhow!(
                    "move_disk for {disk} → {target_storage}: target storage does not \
                     support live migration. Stop guest {vmid} (`proxxx stop {vmid}`) and \
                     retry — offline migration usually works."
                )
            } else if s.contains("storage") && s.contains("not available") {
                anyhow::anyhow!(
                    "move_disk: target storage '{target_storage}' is not available on node \
                     '{node}' (check `pvesm status` on that node)"
                )
            } else if s.contains("locked") || s.contains("VM is locked") {
                anyhow::anyhow!(
                    "move_disk: guest {vmid} is locked (likely backup or another move). \
                     Wait for the running operation to finish and retry."
                )
            } else {
                e
            }
        })
    }

    async fn resize_disk(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        disk: &str,
        size: &str,
    ) -> Result<String> {
        // Proxmox uses PUT for resize, not POST (yes, it's inconsistent
        // with the rest of the API). Both QEMU and LXC accept the same
        // params and same path suffix.
        let kind = type_path(guest_type);
        let params = vec![("disk", disk), ("size", size)];
        // The trait helpers we have are GET/POST/DELETE; resize uses PUT.
        // We inline a request rather than refactor the helpers — keeping
        // the bug #1 fix surface narrow.
        self.ensure_auth().await?;
        self.limiter.until_ready().await;
        let url = format!(
            "{}/api2/json/nodes/{node}/{kind}/{vmid}/resize",
            self.base_url
        );
        let auth = self.auth.read().await;
        let path = format!("/nodes/{node}/{kind}/{vmid}/resize");
        let resp = auth
            .apply(self.http.put(&url))
            .form(&params)
            .send()
            .await
            // Transport-typed so a dead node on the resize path routes
            // like every other request (it predated the typed-error pass).
            .map_err(|e| super::ApiError::Transport(format!("PUT {path}: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(super::ApiError::from_status(status, &path, body).into());
        }
        // Route through the shared bounded-read + typed-parse helpers so
        // the resize PUT is no longer the one REST read with an unbounded
        // body and an untyped (`anyhow`) parse error. A hostile node can
        // no longer OOM proxxx on this path, and a non-JSON body now
        // yields `ApiError::Parse`.
        let bytes = read_bounded_body(resp, &path).await?;
        let parsed: ApiResponse<Option<String>> = parse_json_maybe_blocking(bytes, &path).await?;
        // Proxmox returns null UPID for synchronous resizes (e.g. a
        // small grow that completes inline). Surface a synthetic marker
        // so callers don't have to special-case Option.
        Ok(parsed.data.unwrap_or_else(|| "synchronous".to_string()))
    }

    async fn apt_update_refresh(&self, node: &str) -> Result<String> {
        let resp: ApiResponse<String> =
            self.post(&format!("/nodes/{node}/apt/update"), &[]).await?;
        Ok(resp.data)
    }

    async fn apt_list_upgradable(
        &self,
        node: &str,
    ) -> Result<Vec<crate::api::types::AptUpgradable>> {
        let resp: ApiResponse<Vec<crate::api::types::AptUpgradable>> =
            self.get(&format!("/nodes/{node}/apt/update")).await?;
        Ok(resp.data)
    }

    async fn node_status_detail(&self, node: &str) -> Result<crate::api::types::NodeStatusDetail> {
        let resp: ApiResponse<crate::api::types::NodeStatusDetail> =
            self.get(&format!("/nodes/{node}/status")).await?;
        Ok(resp.data)
    }

    async fn get_next_vmid(&self) -> Result<u32> {
        let resp: ApiResponse<serde_json::Value> = self.get("/cluster/nextid").await?;
        let id = match &resp.data {
            serde_json::Value::String(s) => {
                s.parse::<u32>().context("cluster/nextid: parse error")?
            }
            serde_json::Value::Number(n) => n
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("cluster/nextid: not u64"))?
                as u32,
            other => anyhow::bail!("cluster/nextid: unexpected shape {other}"),
        };
        Ok(id)
    }

    async fn create_qemu(&self, node: &str, params: &[(&str, &str)]) -> Result<String> {
        let resp: ApiResponse<String> = self.post(&format!("/nodes/{node}/qemu"), params).await?;
        Ok(resp.data)
    }

    async fn create_lxc(&self, node: &str, params: &[(&str, &str)]) -> Result<String> {
        let resp: ApiResponse<String> = self.post(&format!("/nodes/{node}/lxc"), params).await?;
        Ok(resp.data)
    }
}
