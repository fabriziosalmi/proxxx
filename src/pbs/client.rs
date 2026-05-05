//! Proxmox Backup Server REST client (feature #3).
//!
//! Token-only auth (no password). Same architectural pattern as `PxClient`:
//! reqwest + governor rate limiter + auth header.
//!
//! Honest scope: read-only browsing. Restore is a separate concern handled
//! by `crate::pbs::restore` via shell-out to `proxmox-backup-client` —
//! not part of this client.

use std::num::NonZeroU32;
use std::sync::Arc;

use anyhow::{Context, Result};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use reqwest::Client;
use serde::de::DeserializeOwned;
use tracing::{debug, info};

use super::types::{ArchiveInfo, DatastoreInfo, SnapshotInfo};
use crate::api::types::ApiResponse;
use crate::config::PbsConfig;

type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

pub struct PbsClient {
    http: Client,
    base_url: String,
    auth_header: String,
    limiter: Arc<Limiter>,
}

impl PbsClient {
    /// Construct a PBS REST client. Async for symmetry with `PxClient`
    /// (which awaits cookie-based password auth) — PBS uses token auth
    /// only so the body is sync today, but keeping the signature async
    /// avoids a breaking change if password auth ever lands.
    #[allow(clippy::unused_async)]
    pub async fn new(cfg: PbsConfig, cli_secret: Option<&str>) -> Result<Self> {
        let secret = cfg.resolve_token_secret(cli_secret).await?;
        // PBS uses `PBSAPIToken=user@realm!tokenid:secret` — note the
        // **colon** between token id and secret. PVE uses `=` in the
        // same position; the two are NOT interchangeable. Sending the
        // PVE form to PBS gets a 401 with no useful diagnostic.
        // — the secret leaves our zeroizing envelope here
        // when handed to reqwest as a header value; the
        // `Zeroizing<String>` still zeros the original heap copy on Drop.
        let secret_ref: &str = &secret;
        let auth_header = format!("PBSAPIToken={}!{}:{}", cfg.user, cfg.token_id, secret_ref);

        let http = Client::builder()
            .danger_accept_invalid_certs(!cfg.verify_tls)
            .timeout(std::time::Duration::from_secs(30))
            // — TCP keepalive against firewall half-open
            // drops. Same rationale as PxClient.
            .tcp_keepalive(Some(std::time::Duration::from_mins(1)))
            .build()
            .context("building PBS HTTP client")?;

        let rate = cfg.rate_limit.unwrap_or(10);
        // SAFETY: const non-zero, never panics — see api/client.rs.
        const TEN: NonZeroU32 = match NonZeroU32::new(10) {
            Some(n) => n,
            None => unreachable!(),
        };
        let quota = Quota::per_second(NonZeroU32::new(rate).unwrap_or(TEN));
        let limiter = Arc::new(RateLimiter::direct(quota));

        info!("connected to PBS {} as {}", cfg.url, cfg.user);

        Ok(Self {
            http,
            base_url: cfg.url.trim_end_matches('/').to_string(),
            auth_header,
            limiter,
        })
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.limiter.until_ready().await;
        let url = format!("{}/api2/json{}", self.base_url, path);
        debug!("PBS GET {url}");
        let resp = self
            .http
            .get(&url)
            .header("Authorization", &self.auth_header)
            .send()
            .await
            .with_context(|| format!("GET {path}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("PBS GET {path} returned {status}: {body}");
        }
        // same bounded-body read as the PVE client. A
        // misbehaving PBS could otherwise OOM proxxx with a giant
        // backup-listing response.
        const MAX_PBS_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
        if let Some(declared) = resp.content_length() {
            if declared as usize > MAX_PBS_RESPONSE_BYTES {
                anyhow::bail!(
                    "PBS response from {path} declares {declared} bytes, exceeds {MAX_PBS_RESPONSE_BYTES} limit",
                );
            }
        }
        use futures_util::StreamExt;
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.with_context(|| format!("reading PBS response chunk from {path}"))?;
            if buf.len().saturating_add(chunk.len()) > MAX_PBS_RESPONSE_BYTES {
                anyhow::bail!(
                    "PBS response from {path} exceeded {MAX_PBS_RESPONSE_BYTES} bytes mid-stream"
                );
            }
            buf.extend_from_slice(&chunk);
        }
        serde_json::from_slice::<T>(&buf)
            .with_context(|| format!("parsing PBS response from {path}"))
    }
}

/// Read-only browse trait. Separate from `ProxmoxGateway` — different
/// server, different auth, different surface.
#[async_trait::async_trait]
pub trait PbsGateway: Send + Sync {
    async fn list_datastores(&self) -> Result<Vec<DatastoreInfo>>;
    async fn list_snapshots(
        &self,
        store: &str,
        backup_type: Option<&str>,
        backup_id: Option<&str>,
    ) -> Result<Vec<SnapshotInfo>>;
    async fn list_snapshot_files(
        &self,
        store: &str,
        backup_type: &str,
        backup_id: &str,
        backup_time: u64,
    ) -> Result<Vec<ArchiveInfo>>;
}

#[async_trait::async_trait]
impl PbsGateway for PbsClient {
    async fn list_datastores(&self) -> Result<Vec<DatastoreInfo>> {
        let resp: ApiResponse<Vec<DatastoreInfo>> = self.get("/admin/datastore").await?;
        Ok(resp.data)
    }

    async fn list_snapshots(
        &self,
        store: &str,
        backup_type: Option<&str>,
        backup_id: Option<&str>,
    ) -> Result<Vec<SnapshotInfo>> {
        // Build the query string only with the params actually given —
        // PBS rejects unknown empties on some endpoints.
        let mut path = format!("/admin/datastore/{store}/snapshots");
        let mut q: Vec<(&str, &str)> = Vec::new();
        if let Some(t) = backup_type {
            q.push(("backup-type", t));
        }
        if let Some(id) = backup_id {
            q.push(("backup-id", id));
        }
        if !q.is_empty() {
            let qs: String = q
                .iter()
                .map(|(k, v)| format!("{k}={}", urlencode(v)))
                .collect::<Vec<_>>()
                .join("&");
            path.push('?');
            path.push_str(&qs);
        }
        let resp: ApiResponse<Vec<SnapshotInfo>> = self.get(&path).await?;
        Ok(resp.data)
    }

    async fn list_snapshot_files(
        &self,
        store: &str,
        backup_type: &str,
        backup_id: &str,
        backup_time: u64,
    ) -> Result<Vec<ArchiveInfo>> {
        let path = format!(
            "/admin/datastore/{store}/files?backup-type={t}&backup-id={id}&backup-time={time}",
            t = urlencode(backup_type),
            id = urlencode(backup_id),
            time = backup_time
        );
        let resp: ApiResponse<Vec<ArchiveInfo>> = self.get(&path).await?;
        Ok(resp.data)
    }
}

/// Minimal URL-encode for PBS path components. We only need to cover
/// `+ / & = ? #` and whitespace; everything PBS accepts is ASCII.
fn urlencode(s: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_handles_special_chars() {
        assert_eq!(urlencode("vm"), "vm");
        assert_eq!(urlencode("100"), "100");
        assert_eq!(urlencode("a+b"), "a%2Bb");
        assert_eq!(urlencode("a/b"), "a%2Fb");
        assert_eq!(urlencode("a b"), "a%20b");
    }
}
