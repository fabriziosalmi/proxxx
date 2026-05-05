//! V26.4 (audit) — typed errors for the Proxmox API surface.
//!
//! Pre-fix: every API call returned `anyhow::Result<T>`. Anyhow is
//! perfect for the application boundary (main, CLI report) but
//! ruinous in the domain layer because callers can't `match` on
//! categorical failures. The TUI couldn't show a "credentials
//! rejected — re-auth?" modal differently from a "rate-limited,
//! waiting" toast because everything was `anyhow::Error`.
//!
//! `ApiError` is a closed enum of the categorically-actionable
//! failure shapes. Anyhow remains the application-layer error type;
//! `ApiError: Into<anyhow::Error>` so callers that don't care about
//! the variants keep working unchanged via `?`.
//!
//! ## How to add a new variant
//!
//! 1. Add it to the enum below with a `#[error("…")]` message.
//! 2. Map at the production site (`src/api/client.rs` is the canonical
//!    place) so the variant is reachable from real responses.
//! 3. UI / CLI callers that want differentiated handling
//!    `.downcast_ref::<ApiError>()` on the anyhow chain.

use thiserror::Error;

/// Categorically-actionable Proxmox API failure shape.
///
/// Variants are deliberately coarse — the goal is "what should the
/// caller do differently?", not "what's the exact HTTP status".
#[derive(Debug, Error)]
pub enum ApiError {
    /// Server returned 401. Token wrong, password expired, ticket
    /// expired post-suspend (V11). Caller may force re-auth and
    /// retry, OR surface "credentials rejected" to the user.
    #[error("Proxmox rejected our credentials: {0}")]
    Unauthorized(String),

    /// Server returned 403. The caller's token is valid but lacks
    /// the privilege for this operation. Caller should NOT retry —
    /// surface a clear "permission denied" message.
    #[error("Proxmox refused (insufficient privileges): {0}")]
    Forbidden(String),

    /// Server returned 404. The named resource doesn't exist.
    /// Caller can choose: silently treat as already-gone (during
    /// teardown) or surface a "guest 100 not found" error.
    #[error("Proxmox resource not found: {0}")]
    NotFound(String),

    /// Server returned 429 / 503 / 502 / 504 — transient cluster
    /// overload. The retry helper already absorbs these for the
    /// client; this variant fires only when the retry budget is
    /// exhausted. Caller should back off + surface a "cluster busy"
    /// hint.
    #[error("Proxmox transient failure after retries: {0}")]
    RateLimited(String),

    /// Body exceeded our 32 MiB cap (V14). Either a misbehaving
    /// node or a hostile upstream. Caller should refuse the data,
    /// not parse partial JSON.
    #[error("response body exceeds size limit: {0}")]
    PayloadTooLarge(String),

    /// V27.3 (audit) — pveproxy-specific status `595` ("Network
    /// Connect Timeout Error", non-standard but Proxmox emits it
    /// when an upstream service like pvestatd or an NFS-backed
    /// storage hangs). Categorized separately because the right
    /// caller behaviour is "the cluster is degraded, show a
    /// 'storage hang on node X' banner" rather than retry.
    #[error("Proxmox storage/upstream hang (595) on {0}")]
    StorageHang(String),

    /// Network / TLS / connection failure under reqwest. Includes
    /// timeouts, DNS failures, certificate errors. Caller can
    /// optionally retry at a higher level.
    #[error("transport error: {0}")]
    Transport(String),

    /// JSON deserialization failed — schema drift between proxxx
    /// and PVE, or a hostile non-JSON body served as application/json.
    /// Caller should NOT retry; treat as poisoned.
    #[error("response parse error from {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    /// Catch-all for status codes outside the categorized set, with
    /// the body included for diagnosis. Caller should surface and
    /// not retry.
    #[error("Proxmox {status} from {path}: {body}")]
    Other {
        path: String,
        status: u16,
        body: String,
    },
}

impl ApiError {
    /// Convenience constructor that maps an HTTP status + body into
    /// the right variant. Use at the call site that just received
    /// the response and decided it's not success.
    #[must_use]
    pub fn from_status(status: reqwest::StatusCode, path: &str, body: String) -> Self {
        match status.as_u16() {
            401 => Self::Unauthorized(format!("{path}: {body}")),
            403 => Self::Forbidden(format!("{path}: {body}")),
            404 => Self::NotFound(format!("{path}: {body}")),
            429 | 502 | 503 | 504 => Self::RateLimited(format!("{path} {status}: {body}")),
            // V27.3 — Proxmox-specific 595 (pveproxy upstream hang).
            // The body is usually empty; the path tells the user
            // which endpoint timed out.
            594 | 595 | 596 | 599 => Self::StorageHang(format!("{path} ({status})")),
            _ => Self::Other {
                path: path.to_string(),
                status: status.as_u16(),
                body,
            },
        }
    }

    /// V27.3 — true if the failure is a pveproxy upstream hang
    /// (status 595 family). UI should render the "storage hang"
    /// banner rather than the generic error toast.
    #[must_use]
    pub const fn is_storage_hang(&self) -> bool {
        matches!(self, Self::StorageHang(_))
    }

    /// True if the variant implies the caller might recover by
    /// re-authenticating (V11 reactive re-auth).
    #[must_use]
    pub const fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Unauthorized(_))
    }

    /// True if the variant implies the caller should treat the
    /// resource as already-absent rather than retry.
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }
}

// `From<ApiError> for anyhow::Error` is provided by anyhow's blanket
// `impl<E: std::error::Error + Send + Sync + 'static> From<E>` —
// we get the bridge for free as long as ApiError derives `Error`.
// `?` propagation works in any function that returns
// `anyhow::Result`, and callers can `.downcast_ref::<ApiError>()` on
// the chain to recover the typed variant.

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    #[test]
    fn from_status_categorizes_canonical_codes() {
        assert!(matches!(
            ApiError::from_status(StatusCode::UNAUTHORIZED, "/x", "nope".into()),
            ApiError::Unauthorized(_)
        ));
        assert!(matches!(
            ApiError::from_status(StatusCode::FORBIDDEN, "/x", "no".into()),
            ApiError::Forbidden(_)
        ));
        assert!(matches!(
            ApiError::from_status(StatusCode::NOT_FOUND, "/x", "gone".into()),
            ApiError::NotFound(_)
        ));
        assert!(matches!(
            ApiError::from_status(StatusCode::TOO_MANY_REQUESTS, "/x", "slow".into()),
            ApiError::RateLimited(_)
        ));
        assert!(matches!(
            ApiError::from_status(StatusCode::SERVICE_UNAVAILABLE, "/x", "busy".into()),
            ApiError::RateLimited(_)
        ));
        // Anything else lands in Other with the raw status.
        let other = ApiError::from_status(StatusCode::IM_A_TEAPOT, "/x", "🫖".into());
        assert!(matches!(other, ApiError::Other { status: 418, .. }));
    }

    #[test]
    fn v27_3_pveproxy_595_categorizes_as_storage_hang() {
        // PVE returns 595 (non-standard) when pveproxy times out
        // waiting on an upstream — typically pvestatd or an NFS-
        // backed storage that's hung. Caller should NOT retry; the
        // right action is "storage hang on node X" banner.
        let s = StatusCode::from_u16(595).unwrap();
        let err = ApiError::from_status(s, "/cluster/resources", String::new());
        assert!(matches!(err, ApiError::StorageHang(_)));
        assert!(err.is_storage_hang());
        assert!(!err.is_unauthorized());
    }

    #[test]
    fn variants_round_trip_through_anyhow_downcast() {
        let typed = ApiError::Unauthorized("bad token".into());
        let any: anyhow::Error = typed.into();
        // Caller can recover the typed variant from the anyhow chain.
        let recovered = any
            .downcast_ref::<ApiError>()
            .expect("ApiError survives anyhow round-trip");
        assert!(recovered.is_unauthorized());
        assert!(!recovered.is_not_found());
    }
}
