use anyhow::Result;
use reqwest::{Response, StatusCode};
use serde::de::DeserializeOwned;

/// Retry policy for transient PVE failures (SPOF 2.2 — Category 2 audit).
/// Exponential backoff with jitter, honouring `Retry-After` when present.
pub(super) const RETRY_MAX_ATTEMPTS: u32 = 4;
pub(super) const RETRY_BASE_DELAY_MS: u64 = 100;

/// Treat these as transient and retry: 503 (overloaded pvedaemon), 429
/// (rate-limited), 502/504 (proxy/gateway hiccups). The proxxx-side
/// governor smooths client load but PVE itself can spike under bulk ops.
pub(super) const fn is_retryable_status(s: StatusCode) -> bool {
    matches!(
        s,
        StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::GATEWAY_TIMEOUT
    )
}

/// Connection-level errors worth retrying. We deliberately do NOT retry
/// on body-decode errors or 4xx (other than 429) — those signal a real
/// problem with the request shape, not a transient cluster wobble.
pub(super) fn is_retryable_error(e: &reqwest::Error) -> bool {
    e.is_timeout() || e.is_connect()
}

/// Compute the backoff delay for `attempt` (1-indexed). Uses exponential
/// growth with jitter derived from a process-monotonic nanosecond clock.
/// Honours an upstream `Retry-After: <seconds>` header when supplied.
pub(super) fn backoff_delay(attempt: u32, retry_after_secs: Option<u64>) -> std::time::Duration {
    if let Some(s) = retry_after_secs {
        // Cap at 30s — a server demanding longer is misbehaving and we'd
        // rather surface the failure than block the TUI loop forever.
        return std::time::Duration::from_secs(s.min(30));
    }
    let base = RETRY_BASE_DELAY_MS.saturating_mul(1u64 << (attempt - 1).min(8));
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()))
        .unwrap_or(0)
        % (base / 4 + 1);
    std::time::Duration::from_millis(base + jitter)
}

/// Parse a `Retry-After: <seconds>` header. PVE may also emit HTTP-date
/// form, which we don't bother parsing — fall back to our exponential
/// schedule rather than failing.
pub(super) fn retry_after_secs(resp: &Response) -> Option<u64> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// (Gemini wave-3 audit) — hard cap on response body size
/// before we hand bytes to `serde_json`. A compromised / misbehaving
/// PVE node could respond `200 OK` with a 2 GiB garbage body;
/// `resp.json::<T>()` would buffer the whole thing in memory before
/// parsing. We refuse anything beyond 32 MiB.
///
/// 32 MiB is comfortably above any legitimate PVE list endpoint
/// (`/cluster/resources` on a 100-node mega-cluster is ~5 MiB).
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// (audit) — threshold above which `serde_json::from_slice` is
/// run on `tokio::task::spawn_blocking`.
///
/// `serde_json` parsing is purely synchronous CPU work. For small
/// payloads (sub-millisecond) running it inline on the tokio worker
/// is fine — `spawn_blocking` itself costs ~50 µs. For 15 000-VM
/// payloads benchmarked at 16 ms (`benches/serde_parse.rs`), running
/// inline blocks the reactor and starves every other future on that
/// worker — including networking, signal handlers, and the TUI tick.
///
/// 256 KiB is the inflection point: at that size `from_slice` takes
/// ~250 µs (well above the `spawn_blocking` overhead) and represents
/// "real list endpoints", not single-resource responses. Below it we
/// stay inline.
const PARSE_BLOCKING_THRESHOLD: usize = 256 * 1024;

/// Parse `bytes` into `T` via `serde_json`. For payloads beyond
/// `PARSE_BLOCKING_THRESHOLD`, dispatch to the tokio blocking pool
/// so the reactor stays responsive — audit fix.
pub(super) async fn parse_json_maybe_blocking<T>(bytes: Vec<u8>, path: &str) -> Result<T>
where
    T: DeserializeOwned + Send + 'static,
{
    if bytes.len() < PARSE_BLOCKING_THRESHOLD {
        return serde_json::from_slice::<T>(&bytes).map_err(|source| {
            anyhow::Error::from(super::ApiError::Parse {
                path: path.to_string(),
                source,
            })
        });
    }
    let path_owned = path.to_string();
    tokio::task::spawn_blocking(move || serde_json::from_slice::<T>(&bytes))
        .await
        .map_err(|e| anyhow::anyhow!("parse spawn_blocking join error: {e}"))?
        .map_err(|source| {
            anyhow::Error::from(super::ApiError::Parse {
                path: path_owned,
                source,
            })
        })
}

/// Stream the response body into a bounded buffer, refusing to grow
/// past `MAX_RESPONSE_BYTES`. Pre-flights `Content-Length` when the
/// server provides it so a hostile 2 GiB advertised body is rejected
/// before any bytes are read.
pub(super) async fn read_bounded_body(resp: Response, path: &str) -> Result<Vec<u8>> {
    use futures_util::StreamExt;

    if let Some(declared) = resp.content_length() {
        if declared as usize > MAX_RESPONSE_BYTES {
            anyhow::bail!(
                "response from {path} declares {declared} bytes, exceeds {MAX_RESPONSE_BYTES} limit"
            );
        }
    }

    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            // Body-stream errors (mid-stream TCP close, decompression
            // failures, premature EOF) are transport-level — surface
            // as the typed `ApiError::Transport` so the exit-code
            // dispatch routes them rather than dropping into generic 1.
            anyhow::Error::from(super::ApiError::Transport(format!(
                "reading response chunk from {path}: {e}"
            )))
        })?;
        if buf.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            anyhow::bail!("response from {path} exceeded {MAX_RESPONSE_BYTES} bytes mid-stream");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}
