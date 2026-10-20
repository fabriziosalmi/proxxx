use anyhow::Result;
use reqwest::{Response, StatusCode};
use serde::de::DeserializeOwned;

/// Retry policy for transient PVE failures (SPOF 2.2 — Category 2 audit).
/// Exponential backoff with jitter, honouring `Retry-After` when present.
pub(super) const RETRY_MAX_ATTEMPTS: u32 = 4;
pub(super) const RETRY_BASE_DELAY_MS: u64 = 100;

/// Whether a request is safe to retry after an ambiguous outcome (timeout,
/// `502`, `504`, or `503` without `Retry-After`) where the request may have
/// already reached PVE (`#348`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestIdempotency {
    /// Read-only / idempotent request (`GET`, `HEAD`). Safe to retry on any
    /// transient status (`429`, `502`, `503`, `504`) or transient transport
    /// failure (`is_timeout() || is_connect()` excluding TLS/cert errors).
    Idempotent,
    /// State-changing mutation (`POST`, `PUT`, `DELETE`). Retried ONLY when
    /// the request provably was not processed by PVE:
    /// - connect error that is neither a timeout nor a TLS/cert failure
    ///   (`is_connect() && !is_timeout() && !is_tls_or_cert_error(e)`),
    /// - HTTP `429 Too Many Requests`,
    /// - HTTP `503 Service Unavailable` WITH a `Retry-After` header.
    Mutation,
}

impl RequestIdempotency {
    /// Classify an HTTP method as idempotent read (`GET`, `HEAD`) or
    /// non-idempotent mutation (`POST`, `PUT`, `DELETE`, etc.).
    #[must_use]
    pub fn for_method(method: &reqwest::Method) -> Self {
        if *method == reqwest::Method::GET || *method == reqwest::Method::HEAD {
            Self::Idempotent
        } else {
            Self::Mutation
        }
    }

    /// Return `true` when the request is a state-changing mutation (`POST`,
    /// `PUT`, `DELETE`).
    #[must_use]
    pub const fn is_mutation(self) -> bool {
        matches!(self, Self::Mutation)
    }
}

/// Abstract request outcome passed to [`should_retry`] and
/// [`should_retry_for_method`] for pure table-driven retry classification
/// (`#348`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryOutcome {
    /// Server responded with an HTTP status code and optional `Retry-After`
    /// header.
    HttpStatus {
        status: StatusCode,
        has_retry_after: bool,
    },
    /// Transport error before an HTTP status was received.
    TransportError {
        is_connect: bool,
        is_timeout: bool,
        is_tls_or_cert: bool,
    },
}

/// Treat these as transient and retry for idempotent reads (`GET`):
/// 503 (overloaded pvedaemon), 429 (rate-limited), 502/504 (proxy/gateway
/// hiccups). The proxxx-side governor smooths client load but PVE itself
/// can spike under bulk ops.
pub(super) const fn is_retryable_status(s: StatusCode) -> bool {
    matches!(
        s,
        StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::GATEWAY_TIMEOUT
    )
}

/// Pure retry classifier for HTTP status codes (`#348`).
///
/// - [`RequestIdempotency::Idempotent`] (`GET`, `HEAD`): retries `429`, `502`,
///   `503`, and `504` regardless of whether `Retry-After` is present.
/// - [`RequestIdempotency::Mutation`] (`POST`, `PUT`, `DELETE`): retries ONLY
///   `429` or `503` when `has_retry_after` is `true` (the server refused the
///   request before processing it). Never retries `502`, `504`, `595`, or
///   `503` without `Retry-After`.
#[must_use]
pub const fn should_retry_status(
    idempotency: RequestIdempotency,
    status: StatusCode,
    has_retry_after: bool,
) -> bool {
    match idempotency {
        RequestIdempotency::Idempotent => is_retryable_status(status),
        RequestIdempotency::Mutation => match status {
            StatusCode::TOO_MANY_REQUESTS => true,
            StatusCode::SERVICE_UNAVAILABLE => has_retry_after,
            _ => false,
        },
    }
}

/// Pure retry classifier for transport error flags (`#348`).
///
/// - Never retries TLS or certificate verification failures (`#320`).
/// - [`RequestIdempotency::Idempotent`] (`GET`, `HEAD`): retries timeouts and
///   connect errors (`is_timeout || is_connect`).
/// - [`RequestIdempotency::Mutation`] (`POST`, `PUT`, `DELETE`): retries ONLY
///   a connect error that is NOT a timeout (`is_connect && !is_timeout`), i.e.
///   the TCP handshake never completed so no request bytes reached PVE.
#[must_use]
pub const fn should_retry_error_flags(
    idempotency: RequestIdempotency,
    is_connect: bool,
    is_timeout: bool,
    is_tls_or_cert: bool,
) -> bool {
    if is_tls_or_cert {
        return false;
    }
    match idempotency {
        RequestIdempotency::Idempotent => is_timeout || is_connect,
        RequestIdempotency::Mutation => is_connect && !is_timeout,
    }
}

/// Pure retry decision over `(idempotency, outcome)` (`#348`).
#[must_use]
pub const fn should_retry(idempotency: RequestIdempotency, outcome: RetryOutcome) -> bool {
    match outcome {
        RetryOutcome::HttpStatus {
            status,
            has_retry_after,
        } => should_retry_status(idempotency, status, has_retry_after),
        RetryOutcome::TransportError {
            is_connect,
            is_timeout,
            is_tls_or_cert,
        } => should_retry_error_flags(idempotency, is_connect, is_timeout, is_tls_or_cert),
    }
}

/// Pure retry decision over `(HTTP method, outcome)` (`#348`).
#[must_use]
pub fn should_retry_for_method(method: &reqwest::Method, outcome: RetryOutcome) -> bool {
    should_retry(RequestIdempotency::for_method(method), outcome)
}

/// Return `true` when `err`'s cause chain includes a TLS or certificate
/// verification failure (`rustls::Error` or an `std::io::Error` wrapping one).
///
/// `reqwest::Error::is_connect()` returns `true` for TLS handshake errors
/// because they happen while establishing the connection, but a certificate
/// rejection or TOFU pin mismatch (`#320`) is deterministic and must fail
/// immediately on the first attempt without 4x retry backoff.
pub(super) fn is_tls_or_cert_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(cause) = current {
        if cause.is::<rustls::Error>() {
            return true;
        }
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            if let Some(inner) = io_err.get_ref() {
                if inner.is::<rustls::Error>() {
                    return true;
                }
            }
        }
        current = cause.source();
    }
    let chain = super::ApiError::format_error_chain(err).to_ascii_lowercase();
    chain.contains("certificate")
        || chain.contains("pin mismatch")
        || chain.contains("unknownissuer")
        || chain.contains("badsignature")
        || chain.contains("handshakefailure")
        || chain.contains("invalid peer certificate")
}

/// Evaluate whether an HTTP response should be retried for `idempotency` (`#348`).
pub(super) fn should_retry_response(idempotency: RequestIdempotency, resp: &Response) -> bool {
    let has_retry_after = resp.headers().contains_key(reqwest::header::RETRY_AFTER);
    should_retry_status(idempotency, resp.status(), has_retry_after)
}

/// Evaluate whether a `reqwest::Error` should be retried for `idempotency` (`#348`).
///
/// We deliberately do NOT retry on TLS/certificate errors (`#320`), body-decode
/// errors, or timeouts on mutations (`#348`).
pub(super) fn should_retry_reqwest_error(
    idempotency: RequestIdempotency,
    e: &reqwest::Error,
) -> bool {
    should_retry_error_flags(
        idempotency,
        e.is_connect(),
        e.is_timeout(),
        is_tls_or_cert_error(e),
    )
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
            anyhow::Error::from(super::ApiError::from_transport(
                format!("reading response chunk from {path}"),
                &e,
            ))
        })?;
        if buf.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            anyhow::bail!("response from {path} exceeded {MAX_RESPONSE_BYTES} bytes mid-stream");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Method;

    const fn http(status: StatusCode, has_retry_after: bool) -> RetryOutcome {
        RetryOutcome::HttpStatus {
            status,
            has_retry_after,
        }
    }

    const fn net(is_connect: bool, is_timeout: bool, is_tls_or_cert: bool) -> RetryOutcome {
        RetryOutcome::TransportError {
            is_connect,
            is_timeout,
            is_tls_or_cert,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn issue_348_pure_classifier_matrix_by_method_and_outcome() {
        let status_595 = StatusCode::from_u16(595).unwrap();
        let read_methods = [Method::GET, Method::HEAD];
        let mutation_methods = [Method::POST, Method::PUT, Method::DELETE];

        // (outcome, expected_for_read, expected_for_mutation, label)
        let rows: &[(RetryOutcome, bool, bool, &str)] = &[
            (
                http(StatusCode::TOO_MANY_REQUESTS, false),
                true,
                true,
                "429 without Retry-After",
            ),
            (
                http(StatusCode::TOO_MANY_REQUESTS, true),
                true,
                true,
                "429 with Retry-After",
            ),
            (
                http(StatusCode::SERVICE_UNAVAILABLE, true),
                true,
                true,
                "503 WITH Retry-After",
            ),
            (
                http(StatusCode::SERVICE_UNAVAILABLE, false),
                true,
                false,
                "503 WITHOUT Retry-After",
            ),
            (
                http(StatusCode::BAD_GATEWAY, false),
                true,
                false,
                "502 Bad Gateway",
            ),
            (
                http(StatusCode::BAD_GATEWAY, true),
                true,
                false,
                "502 Bad Gateway with Retry-After",
            ),
            (
                http(StatusCode::GATEWAY_TIMEOUT, false),
                true,
                false,
                "504 Gateway Timeout",
            ),
            (
                http(StatusCode::GATEWAY_TIMEOUT, true),
                true,
                false,
                "504 Gateway Timeout with Retry-After",
            ),
            (
                http(status_595, false),
                false,
                false,
                "595 pveproxy upstream hang",
            ),
            (
                http(StatusCode::INTERNAL_SERVER_ERROR, false),
                false,
                false,
                "500 Internal Server Error",
            ),
            (
                http(StatusCode::BAD_REQUEST, false),
                false,
                false,
                "400 Bad Request",
            ),
            (
                http(StatusCode::FORBIDDEN, false),
                false,
                false,
                "403 Forbidden",
            ),
            (
                http(StatusCode::NOT_FOUND, false),
                false,
                false,
                "404 Not Found",
            ),
            (http(StatusCode::OK, false), false, false, "200 OK"),
            (
                net(true, false, false),
                true,
                true,
                "connect error (not timeout, not TLS)",
            ),
            (
                net(false, true, false),
                true,
                false,
                "request timeout after connection established",
            ),
            (
                net(true, true, false),
                true,
                false,
                "connect + timeout flag together",
            ),
            (
                net(true, false, true),
                false,
                false,
                "TLS/cert error during connect (#320)",
            ),
            (
                net(false, false, false),
                false,
                false,
                "non-connect non-timeout transport error",
            ),
        ];

        for &(outcome, expected_read, expected_mutation, label) in rows {
            assert_eq!(
                should_retry(RequestIdempotency::Idempotent, outcome),
                expected_read,
                "Idempotent mismatch on {label} ({outcome:?})"
            );
            assert_eq!(
                should_retry(RequestIdempotency::Mutation, outcome),
                expected_mutation,
                "Mutation mismatch on {label} ({outcome:?})"
            );
            for m in &read_methods {
                assert_eq!(
                    should_retry_for_method(m, outcome),
                    expected_read,
                    "method {m} mismatch on {label}"
                );
            }
            for m in &mutation_methods {
                assert_eq!(
                    should_retry_for_method(m, outcome),
                    expected_mutation,
                    "method {m} mismatch on {label}"
                );
            }
        }
    }

    #[tokio::test]
    async fn issue_348_reqwest_error_classifier_retries_connect_refused_but_not_timeout_on_mutation(
    ) {
        // 1. Construct a real reqwest connect-refused error by binding a local
        //    ephemeral port and dropping the listener before connecting.
        let closed_addr = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(80))
            .build()
            .unwrap();
        let connect_err = client
            .post(format!("http://{closed_addr}/api2/json/nodes"))
            .send()
            .await
            .expect_err("closed port must fail to connect");
        assert!(
            connect_err.is_connect() && !connect_err.is_timeout(),
            "expected connect error (not timeout), got: {connect_err:?}"
        );
        assert!(
            should_retry_reqwest_error(RequestIdempotency::Idempotent, &connect_err),
            "GET must retry connect-refused"
        );
        assert!(
            should_retry_reqwest_error(RequestIdempotency::Mutation, &connect_err),
            "POST/PUT/DELETE must retry connect-refused (nothing reached PVE)"
        );

        // 2. Construct a real reqwest timeout error by accepting a TCP socket
        //    and holding it open without replying past the 80 ms timeout.
        let slow_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow_addr = slow_listener.local_addr().unwrap();
        let hold_handle = tokio::spawn(async move {
            if let Ok((_socket, _)) = slow_listener.accept().await {
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            }
        });
        let timeout_err = client
            .post(format!("http://{slow_addr}/api2/json/nodes"))
            .send()
            .await
            .expect_err("silent socket must time out");
        hold_handle.abort();
        assert!(
            timeout_err.is_timeout(),
            "expected timeout error, got: {timeout_err:?}"
        );
        assert!(
            should_retry_reqwest_error(RequestIdempotency::Idempotent, &timeout_err),
            "GET must still retry timeout"
        );
        assert!(
            !should_retry_reqwest_error(RequestIdempotency::Mutation, &timeout_err),
            "POST/PUT/DELETE must NEVER retry a timeout (#348)"
        );
    }
}
