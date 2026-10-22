//! (audit) — typed errors for the Proxmox API surface.
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
    #[error("Proxmox rejected our credentials (HTTP 401 Unauthorized): {0}")]
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

    /// Body exceeded our 32 MiB cap . Either a misbehaving
    /// node or a hostile upstream. Caller should refuse the data,
    /// not parse partial JSON.
    #[error("response body exceeds size limit: {0}")]
    PayloadTooLarge(String),

    /// (audit) — pveproxy-specific status `595` ("Network
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
            // — Proxmox-specific 595 (pveproxy upstream hang).
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

    /// Map an HTTP status + body into [`ApiError`], enriching ambiguous
    /// gateway/overload failures (`502`, `503` without `Retry-After`, `504`)
    /// on mutating requests (`POST`, `PUT`, `DELETE`) with an explicit warning
    /// that PVE may still have executed the mutation (`#348`).
    #[must_use]
    pub fn from_status_with_idempotency(
        status: reqwest::StatusCode,
        path: &str,
        body: String,
        idempotency: super::transport::RequestIdempotency,
    ) -> Self {
        if idempotency.is_mutation() && matches!(status.as_u16(), 502..=504) {
            return Self::RateLimited(format!(
                "{path} {status}: {body} (mutation was not retried; PVE may still have executed it — check `proxxx tasks` or the PVE task log before retrying)"
            ));
        }
        Self::from_status(status, path, body)
    }

    /// Format an error together with its entire [`std::error::Error::source`]
    /// chain (`outer: cause 1: cause 2`).
    ///
    /// `reqwest::Error`'s `Display` implementation only formats the outer
    /// wrapper (`"error sending request for url (...)"`) and omits the
    /// underlying hyper / rustls / OS socket cause unless `.source()` is
    /// walked explicitly (#323).
    #[must_use]
    pub fn format_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
        let mut chain = err.to_string();
        let mut current = err.source();
        while let Some(cause) = current {
            let cause_str = cause.to_string();
            if !cause_str.is_empty() && !chain.ends_with(&cause_str) {
                chain.push_str(": ");
                chain.push_str(&cause_str);
            }
            current = cause.source();
        }
        chain
    }

    /// Construct [`Self::Transport`] preserving the full `source()` chain of
    /// the underlying transport error (#323).
    #[must_use]
    pub fn from_transport(
        context: impl std::fmt::Display,
        err: &(dyn std::error::Error + 'static),
    ) -> Self {
        Self::Transport(format!("{context}: {}", Self::format_error_chain(err)))
    }

    /// Construct [`Self::Transport`] for a `reqwest::Error`, enriching
    /// mutation timeouts (`POST`, `PUT`, `DELETE` where `err.is_timeout()` is
    /// `true`) with an explicit warning that PVE may still have executed the
    /// mutation (`#348`).
    #[must_use]
    pub fn from_transport_with_idempotency(
        context: impl std::fmt::Display,
        err: &reqwest::Error,
        idempotency: super::transport::RequestIdempotency,
    ) -> Self {
        if idempotency.is_mutation() && err.is_timeout() {
            return Self::Transport(format!(
                "{context}: {} (mutation was not retried after timeout; PVE may still have executed it — check `proxxx tasks` or the PVE task log before retrying)",
                Self::format_error_chain(err)
            ));
        }
        Self::from_transport(context, err)
    }

    /// — true if the failure is a pveproxy upstream hang
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

    /// Map this variant to the process exit code documented in
    /// [docs/reference/exit-codes.md].
    ///
    /// The contract is stable within a major version — shell scripts
    /// and CI pipelines depend on these numbers (see `case $?` examples
    /// in the doc). Changing what an existing code means is a major
    /// bump; adding a new code (for a new variant) is minor.
    ///
    /// Mapping summary:
    /// - `Unauthorized` / `Forbidden` → **4** (auth/authz)
    /// - `NotFound` → **5** (resource gone)
    /// - `RateLimited` / `StorageHang` → **7** (cluster transient)
    /// - `Parse` / `Transport` / `PayloadTooLarge` / `Other` → **1**
    ///   (generic; the retry / diagnosis strategy is variant-specific
    ///   but proxxx exits with `1` because there's no shell-actionable
    ///   distinction the operator can express via exit code alone —
    ///   the hint and the error chain carry the detail)
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Unauthorized(_) | Self::Forbidden(_) => 4,
            Self::NotFound(_) => 5,
            Self::RateLimited(_) | Self::StorageHang(_) => 7,
            Self::Parse { .. }
            | Self::Transport(_)
            | Self::PayloadTooLarge(_)
            | Self::Other { .. } => 1,
        }
    }

    /// One-line actionable hint to surface alongside the error message.
    /// The variant text already describes WHAT failed; this returns
    /// WHAT THE OPERATOR SHOULD DO NEXT.
    ///
    /// The v0.1.10 audit flagged that proxxx's typed error architecture
    /// existed but every error rendered identically as a generic anyhow
    /// chain — operators saw "Proxmox rejected our credentials" with no
    /// follow-up. `actionable_hint` is the differentiator. main.rs's
    /// CLI error path appends it under the `Fatal Error:` line; JSON
    /// output exposes it as a `hint` field on the error object.
    #[must_use]
    pub fn actionable_hint(&self) -> &'static str {
        match self {
            Self::Unauthorized(_) => {
                "credentials rejected — re-run `proxxx init --interactive` to rotate the token, \
                 or verify $PROXXX_TOKEN_SECRET matches the live secret in PVE \
                 (`pveum user token list <user>`)"
            }
            // PVE reserves some endpoints (`/cluster/backup-info`, ...) to
            // the root@pam user itself and refuses every API token, even
            // root@pam's, whatever the ACL says (measured on PVE 9.1.1).
            Self::Forbidden(msg) if msg.contains("user != root@pam") => {
                "PVE reserves this endpoint to the root@pam user itself: every API token \
                 is refused, root@pam's included, whatever the ACL grants; use a profile \
                 that logs in as root@pam with a password"
            }
            Self::Forbidden(_) => {
                "token is valid but lacks the privilege for this op — inspect the ACL with \
                 `proxxx access acl` and grant the needed role on the affected path; \
                 `proxxx perms <user> --node <node>` shows effective rights"
            }
            Self::NotFound(_) => {
                "the resource doesn't exist on the cluster — it may have been deleted, \
                 renamed, or the vmid/storage/node name is wrong (try `proxxx ls guests` / \
                 `proxxx ls nodes` to enumerate)"
            }
            Self::RateLimited(msg) => {
                if msg.contains("may still have executed") {
                    "mutating request failed with 502/503/504 — proxxx did not retry to avoid \
                     duplicate execution; PVE may still have executed the mutation, so check \
                     `proxxx tasks` or the PVE task log before retrying"
                } else {
                    "PVE returned 429/502/503/504 after proxxx's retry budget was exhausted — \
                     the cluster is overloaded; back off 30 s and retry, or check pveproxy \
                     load on the affected node"
                }
            }
            Self::StorageHang(_) => {
                "PVE emitted a 59x status — a node's upstream service is hung, typically \
                 pvestatd or an NFS-backed storage; `proxxx ls nodes` shows which one is \
                 stale (uptime / last-seen vs the others)"
            }
            Self::Transport(msg) => {
                if msg.contains("may still have executed") {
                    "mutating request timed out after being sent — proxxx did not retry to avoid \
                     duplicate execution; PVE may still have executed the mutation, so check \
                     `proxxx tasks` or the PVE task log before retrying"
                } else {
                    "network or TLS failure reaching the PVE URL — verify connectivity \
                     (`curl --cacert ... <url>/api2/json/version`), check that `verify_tls` \
                     in your profile matches the cluster's cert posture, and confirm DNS"
                }
            }
            Self::Parse { .. } => {
                "proxxx couldn't parse a PVE response as the expected JSON shape — likely \
                 schema drift between proxxx and your PVE version; re-run with \
                 `RUST_LOG=proxxx=debug` to log the failing request and file a bug with \
                 the `proxxx pve-version` output"
            }
            Self::PayloadTooLarge(_) => {
                "PVE response exceeded proxxx's 32 MiB cap — proxxx refuses to parse \
                 partial JSON; this typically means a node is emitting garbage (broken \
                 upstream, hostile proxy, or a runaway log endpoint)"
            }
            // PVE answers a missing guest config, snapshot or storage with a
            // 500 "... does not exist", not a 404 (audit #385).
            Self::Other { body, .. } if body.contains("does not exist") => {
                "PVE says the object does not exist — it may have been deleted or renamed, \
                 or the vmid/snapshot/storage name is wrong (`proxxx ls guests` and \
                 `proxxx ls storage` enumerate guests and storage)"
            }
            Self::Other { .. } => {
                "PVE refused the request; the error above carries its HTTP status and \
                 PVE's own message. Check the pveproxy and pvedaemon journal on the \
                 affected node (`journalctl -u pveproxy -u pvedaemon`) for context"
            }
        }
    }
}

/// Walk an anyhow error chain looking for an `ApiError`; return its
/// `actionable_hint` if found. Used by `main.rs` to enrich the
/// `Fatal Error:` line shown to operators.
///
/// Returns `None` for non-API errors (config parse, IO at startup,
/// etc.) — those already render with sufficient context via the
/// anyhow chain itself.
#[must_use]
pub fn extract_hint(err: &anyhow::Error) -> Option<&'static str> {
    err.chain()
        .find_map(|e| e.downcast_ref::<ApiError>())
        .map(ApiError::actionable_hint)
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

    /// Audit #385: a root-only endpoint refuses every token whatever the
    /// ACL (message measured on PVE 9.1.1), and PVE reports a missing
    /// object as a 500 "does not exist", not a 404.
    #[test]
    fn root_only_and_does_not_exist_get_their_own_hints() {
        let root_only = ApiError::Forbidden(
            "/cluster/backup-info: Permission check failed (user != root@pam)".into(),
        );
        assert!(root_only.actionable_hint().contains("root@pam user itself"));
        assert!(!root_only.actionable_hint().contains("access acl"));
        let acl = ApiError::Forbidden("/nodes/pve1/qemu: Permission check failed".into());
        assert!(acl.actionable_hint().contains("perms <user> --node <node>"));
        let gone = ApiError::Other {
            path: "/nodes/pve1/qemu/999/config".into(),
            status: 500,
            body: "Configuration file 'nodes/pve1/qemu-server/999.conf' does not exist".into(),
        };
        assert!(gone.actionable_hint().contains("does not exist"));
        let other = ApiError::Other {
            path: String::new(),
            status: 500,
            body: "boom".into(),
        };
        assert!(!other.actionable_hint().contains("Other {"));
    }

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

    // ── Phase 10 — actionable_hint + extract_hint coverage ─────────

    /// Every variant must produce a non-empty hint. If a new variant
    /// lands and someone forgets to add a hint match arm, this test
    /// fires (the `actionable_hint` match is exhaustive at the type
    /// level, so the compiler catches missing arms — this test
    /// catches "empty string" placeholder hints).
    #[test]
    fn every_variant_has_a_non_empty_hint() {
        let variants = [
            ApiError::Unauthorized("x".into()),
            ApiError::Forbidden("x".into()),
            ApiError::NotFound("x".into()),
            ApiError::RateLimited("x".into()),
            ApiError::PayloadTooLarge("x".into()),
            ApiError::StorageHang("x".into()),
            ApiError::Transport("x".into()),
            ApiError::Parse {
                path: "/x".into(),
                // Build a serde_json::Error by parsing invalid JSON.
                source: serde_json::from_str::<u32>("not json").unwrap_err(),
            },
            ApiError::Other {
                path: "/x".into(),
                status: 418,
                body: "🫖".into(),
            },
        ];
        for v in &variants {
            let h = v.actionable_hint();
            assert!(
                !h.is_empty(),
                "variant {v:?} returned an empty hint — every variant must be actionable"
            );
            // Trim guard — placeholder whitespace-only hints would slip
            // past the empty check above.
            assert!(
                h.trim().len() >= 20,
                "variant {v:?} hint is too short to be actionable: {h:?}"
            );
        }
    }

    /// Unauthorized → mentions `proxxx init` so the operator can rotate.
    #[test]
    fn unauthorized_hint_points_at_init_wizard() {
        let h = ApiError::Unauthorized("bad token".into()).actionable_hint();
        assert!(
            h.contains("proxxx init"),
            "Unauthorized hint should point at the init wizard, got: {h}"
        );
    }

    /// Forbidden → mentions ACL inspection.
    #[test]
    fn forbidden_hint_points_at_access_acl() {
        let h = ApiError::Forbidden("no perms".into()).actionable_hint();
        assert!(
            h.contains("access acl") || h.contains("ACL"),
            "Forbidden hint should reference ACL inspection, got: {h}"
        );
    }

    /// `NotFound` → tells the operator the resource is gone, not retried.
    #[test]
    fn not_found_hint_describes_resource_absent() {
        let h = ApiError::NotFound("vmid 100".into()).actionable_hint();
        assert!(
            h.contains("doesn't exist") || h.contains("deleted") || h.contains("not exist"),
            "NotFound hint should describe absent resource, got: {h}"
        );
    }

    /// `StorageHang` → mentions pvestatd or NFS, the canonical causes.
    #[test]
    fn storage_hang_hint_mentions_pvestatd_or_nfs() {
        let h = ApiError::StorageHang("/cluster/resources".into()).actionable_hint();
        assert!(
            h.contains("pvestatd") || h.contains("NFS") || h.contains("storage"),
            "StorageHang hint should name the canonical cause, got: {h}"
        );
    }

    /// `extract_hint` walks an anyhow chain (with `.context()`-style
    /// wrapping) and finds the inner `ApiError`. This is the canonical
    /// caller pattern from main.rs.
    #[test]
    fn extract_hint_finds_typed_error_through_anyhow_wrap() {
        let typed = ApiError::Unauthorized("expired token".into());
        let any: anyhow::Error = anyhow::Error::from(typed)
            .context("while listing nodes")
            .context("during cluster snapshot");
        let hint = super::extract_hint(&any).expect("ApiError must be reachable through chain");
        assert!(
            hint.contains("proxxx init"),
            "extracted hint must be the Unauthorized one, got: {hint}"
        );
    }

    /// Non-API errors (config parse, IO, generic anyhow!()) return
    /// None — we don't want to attach a misleading hint.
    #[test]
    fn extract_hint_returns_none_for_non_api_error() {
        let any = anyhow::anyhow!("config.toml missing required field `url`");
        assert!(
            super::extract_hint(&any).is_none(),
            "extract_hint must not invent hints for non-API errors"
        );
    }

    // ── Phase 11 — exit_code() per documented mapping ─────────────

    /// Auth-related variants → exit 4 (per docs/reference/exit-codes.md).
    /// Pins both `Unauthorized` (401) and `Forbidden` (403) to the same
    /// shell-actionable category — operators can branch on `$?==4` with
    /// a single case arm regardless of the precise PVE response.
    #[test]
    fn unauthorized_and_forbidden_share_exit_code_4() {
        assert_eq!(ApiError::Unauthorized("x".into()).exit_code(), 4);
        assert_eq!(ApiError::Forbidden("x".into()).exit_code(), 4);
    }

    /// `NotFound` → exit 5. The "resource is gone" signal is its own
    /// code because the right CI behaviour is often "treat as success
    /// during teardown" (see the README's `rc=5` example).
    #[test]
    fn not_found_exit_code_5() {
        assert_eq!(ApiError::NotFound("/vms/100".into()).exit_code(), 5);
    }

    /// Transient cluster failures (post-retry-budget) → exit 7.
    /// Both `RateLimited` (429/502/503/504) and `StorageHang` (59x)
    /// share this code — the right script response is "back off, retry
    /// later" for both. Distinguishing them was deemed not script-
    /// actionable; the hint and stderr message carry the detail.
    #[test]
    fn rate_limited_and_storage_hang_share_exit_code_7() {
        assert_eq!(ApiError::RateLimited("x".into()).exit_code(), 7);
        assert_eq!(ApiError::StorageHang("/x".into()).exit_code(), 7);
    }

    /// Generic / non-shell-actionable variants → exit 1.
    /// `Parse` (schema drift) is not retryable; `Transport` (network)
    /// might be retryable at a higher layer but proxxx itself doesn't
    /// distinguish them via exit code — the chain + hint do.
    #[test]
    fn generic_variants_collapse_to_exit_1() {
        let parse = ApiError::Parse {
            path: "/x".into(),
            source: serde_json::from_str::<u32>("garbage").unwrap_err(),
        };
        assert_eq!(parse.exit_code(), 1);
        assert_eq!(ApiError::Transport("dns failure".into()).exit_code(), 1);
        assert_eq!(ApiError::PayloadTooLarge("/x".into()).exit_code(), 1);
        assert_eq!(
            ApiError::Other {
                path: "/x".into(),
                status: 418,
                body: "🫖".into(),
            }
            .exit_code(),
            1
        );
    }

    /// Verify the *full* documented contract in one assertion table —
    /// catches a future contributor adding a variant and forgetting to
    /// extend the `exit_code` match (clippy's exhaustiveness lint helps
    /// at the compile level; this test pins the runtime semantics).
    #[test]
    fn exit_codes_match_documented_contract() {
        let table: &[(ApiError, i32)] = &[
            (ApiError::Unauthorized("x".into()), 4),
            (ApiError::Forbidden("x".into()), 4),
            (ApiError::NotFound("x".into()), 5),
            (ApiError::RateLimited("x".into()), 7),
            (ApiError::StorageHang("x".into()), 7),
            (ApiError::Transport("x".into()), 1),
            (ApiError::PayloadTooLarge("x".into()), 1),
            (
                ApiError::Other {
                    path: "/x".into(),
                    status: 599,
                    body: String::new(),
                },
                1,
            ),
        ];
        for (variant, expected) in table {
            assert_eq!(
                variant.exit_code(),
                *expected,
                "variant {variant:?} should map to exit {expected}"
            );
        }
    }

    #[test]
    fn issue_348_mutation_status_502_503_504_warns_may_have_executed_and_keeps_exit_code_7() {
        use crate::api::transport::RequestIdempotency;

        for code in [
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            let err = ApiError::from_status_with_idempotency(
                code,
                "/nodes/pve1/vzdump",
                "gateway timeout".into(),
                RequestIdempotency::Mutation,
            );
            assert_eq!(err.exit_code(), 7);
            let msg = err.to_string();
            assert!(
                msg.contains("may still have executed") && msg.contains("proxxx tasks"),
                "mutation {code} Display must warn that PVE may still have executed it, got: {msg}"
            );
            let hint = err.actionable_hint();
            assert!(
                hint.contains("may still have executed") && hint.contains("proxxx tasks"),
                "mutation {code} hint must warn that PVE may still have executed it, got: {hint}"
            );
        }

        // 429 on a mutation was rejected before execution, so after retry
        // budget exhaustion it uses the normal overload hint.
        let err_429 = ApiError::from_status_with_idempotency(
            StatusCode::TOO_MANY_REQUESTS,
            "/nodes/pve1/vzdump",
            "rate limit".into(),
            RequestIdempotency::Mutation,
        );
        assert_eq!(err_429.exit_code(), 7);
        assert!(!err_429.to_string().contains("may still have executed"));
    }
}
