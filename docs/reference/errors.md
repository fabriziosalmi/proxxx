# Error categories

proxxx returns typed error enums in the domain layer (audit) so
callers can `match` on the failure shape instead of grepping prose.
The application layer wraps everything in `anyhow::Error` for the
`?` ergonomics; the CLI exit-code path walks the anyhow chain via
`downcast_ref::<T>()` to surface the right exit code.

There are three families of typed error you'll encounter:

1. **`api::ApiError`** — every HTTP error from PVE / PBS.
2. **`config::ConfigError`** — configuration loading / parsing.
3. **Refusal errors** — `app::preflight::PreflightRefusal` (risk gate)
   and `incident::FreezeRefusal` (incident lockdown).

## The `ApiError` enum

```rust
pub enum ApiError {
    /// 401. Token wrong, password expired, ticket expired post-suspend.
    /// Caller may force re-auth and retry, OR surface "credentials rejected".
    Unauthorized(String),

    /// 403. Token is valid but lacks privilege for this operation.
    /// Caller should NOT retry — surface a clear "permission denied".
    Forbidden(String),

    /// 404. The named resource doesn't exist.
    /// Caller can choose: silently treat as already-gone (during
    /// teardown) or surface "guest 100 not found".
    NotFound(String),

    /// 429 / 502 / 503 / 504 — transient cluster overload.
    /// Fires only when retry budget is exhausted; the client absorbs
    /// transient errors automatically below this threshold.
    RateLimited(String),

    /// Body exceeded our 32 MiB cap. Misbehaving node or hostile
    /// upstream. Caller should refuse, not parse partial JSON.
    PayloadTooLarge(String),

    /// 594 / 595 / 596 / 599 — Proxmox-specific statuses for upstream
    /// service hang (pvestatd freeze, NFS-backed storage hang).
    /// Distinguished because the right caller behaviour is "show
    /// degraded banner", not retry.
    StorageHang(String),

    /// Network / TLS / connection failure. Includes timeouts, DNS
    /// failures, certificate errors. Caller MAY retry at a higher level.
    Transport(String),

    /// JSON deserialization failed. PVE returned non-JSON, schema drift,
    /// or hostile payload. Caller should NOT retry; treat as poisoned.
    Parse { path: String, body_preview: String },

    /// Uncategorised HTTP status (anything not matched above —
    /// 4xx-not-401/403/404, 5xx-not-429/502/503/504/594-599).
    Other { status: u16, path: String, body: String },
}
```

## The `ConfigError` enum

```rust
pub enum ConfigError {
    /// No `config.toml` found on disk. Caller can offer to scaffold.
    NotFound(PathBuf),

    /// File exists but read failed (permissions, IO error).
    Io(std::io::Error),

    /// TOML parse failed OR a required field is missing / malformed.
    Toml(String),
}
```

All three map to exit `3` today; splitting them to distinct codes
later is an additive (minor) bump as long as `3` stays in the set.

## Refusal errors (typed, non-API)

Two refusal kinds short-circuit the dispatch chain with their own
exit codes:

```rust
/// Pre-flight risk gate. Fires from per-guest pre-flight
/// (running guest, HA-managed, tagged prod, etc.) and from
/// state-apply pre-flight (non-empty pool delete, root-role ACL
/// delete, shared-storage delete, batch ≥ 50).
pub struct PreflightRefusal;
impl PreflightRefusal { const EXIT_CODE: i32 = 6; }

/// Incident lockdown active. Fired by every `PxClient::{post,put,delete}`
/// when `proxxx incident freeze` is in effect — even by user code that
/// didn't think to check. Cleared by `proxxx incident thaw` or by TTL.
pub struct FreezeRefusal;
impl FreezeRefusal { const EXIT_CODE: i32 = 8; }
```

These are carried through `anyhow::Error` and downcast in `main.rs`
before any `ApiError::exit_code()` mapping, so they always win.

## How to dispatch

```rust
match operation.await {
    Ok(value) => Ok(value),
    Err(e) => {
        // Refusal-typed errors first — they out-rank API errors.
        if e.downcast_ref::<PreflightRefusal>().is_some() {
            return bail!("refused — re-run with --allow-risk if intentional");
        }
        if e.downcast_ref::<FreezeRefusal>().is_some() {
            return bail!("cluster frozen — run `proxxx incident thaw` first");
        }
        // Then walk the chain for ApiError variants.
        match e.downcast_ref::<ApiError>() {
            Some(ApiError::Unauthorized(_))   => prompt_reauth(),
            Some(ApiError::Forbidden(_))      => bail!("you can't do that here"),
            Some(ApiError::NotFound(_))       => silently_skip(),
            Some(ApiError::RateLimited(_))    => back_off_and_retry(),
            Some(ApiError::StorageHang(node)) => show_degraded_banner(node),
            _                                 => Err(e),
        }
    }
}
```

`ApiError: Into<anyhow::Error>` so callers that don't care about
variants keep working unchanged via `?`.

## Mapping to exit codes

See [Exit codes](/reference/exit-codes) for the full table:

| Error type | Exit code |
| :--- | :---: |
| `ApiError::Unauthorized`, `ApiError::Forbidden` | 4 |
| `ApiError::NotFound`                            | 5 |
| `ApiError::RateLimited`, `ApiError::StorageHang`| 7 |
| `ApiError::Parse`, `ApiError::Transport`, `ApiError::PayloadTooLarge`, `ApiError::Other` | 1 |
| `ConfigError::*` (all three variants)           | 3 |
| `PreflightRefusal`                              | 6 |
| `FreezeRefusal`                                 | 8 |

## Where it's mapped

The canonical `ApiError` production site is `src/api/error.rs` —
`ApiError::from_response` reads HTTP status + body and produces the
right variant. The CLI exit-code dispatch lives in `src/main.rs` and
walks the anyhow chain.

Adding a new `ApiError` variant requires:

1. Add it to the enum with a `#[error("…")]` message.
2. Map at the production site (`from_response` or callers).
3. Update [exit codes](/reference/exit-codes) if the new variant
   warrants its own exit code.
4. UI / CLI callers that want differentiated handling
   `.downcast_ref::<ApiError>()` on the anyhow chain.

## Why typed errors

Pre-fix, every API call returned `anyhow::Result<T>`. Anyhow is
perfect for the application boundary but ruinous in the domain layer
because callers can't `match` on categorical failures. The TUI
couldn't distinguish "credentials rejected — re-auth?" modal from a
"rate-limited, waiting" toast because everything was string-grepped
`anyhow::Error`.

Closed enums let exhaustive matching catch the cases at compile
time. New variants force callers to acknowledge or fall through
explicitly.

## Surfacing in the TUI

Each error category has a UI affordance:

| Category | TUI surface |
| :--- | :--- |
| `Unauthorized`     | Modal: "Token rejected — re-enter or check `token_secret`" |
| `Forbidden`        | Toast: "Permission denied: {path}" |
| `NotFound`         | Toast: "Resource gone — refreshing list" |
| `RateLimited`      | Status bar: "Cluster busy, backing off…" |
| `StorageHang`      | DANGER banner: "Storage hang on node {N} — read-only mode" |
| `Transport`        | Toast: "Network error — will retry" |
| `Parse`            | Modal: "Schema drift; please open an issue with the version" |
| `Other`            | Modal: "Unexpected status {N} from {path}" |
| `PreflightRefusal` | Modal: "Pre-flight refused: {risks} — confirm with --allow-risk" |
| `FreezeRefusal`    | DANGER banner: "Cluster frozen — read-only until thaw" |

## See also

- [Error handling architecture](/architecture/error-handling) — design
  rationale and the boundary between domain and application errors
- [Exit codes](/reference/exit-codes) — stable scripting contract
- [Explain command](/reference/cli#explain) — `proxxx explain <error-id>`
  prints cause + numbered fixes + diagnostic commands for every typed
  error
