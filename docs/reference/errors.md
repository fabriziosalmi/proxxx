# Error categories

proxxx's API client returns a typed `ApiError` enum (V26.4 audit) so
callers can `match` on the failure shape instead of grepping prose.

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

    /// Body exceeded our 32 MiB cap (V14). Misbehaving node or hostile
    /// upstream. Caller should refuse, not parse partial JSON.
    PayloadTooLarge(String),

    /// 595 — Proxmox-specific status for upstream service hang
    /// (pvestatd freeze, NFS-backed storage hang). Distinguished
    /// because the right caller behaviour is "show degraded banner",
    /// not retry.
    StorageHang(String),

    /// Network / TLS / connection failure. Includes timeouts, DNS
    /// failures, certificate errors. Caller MAY retry at a higher level.
    Transport(String),

    /// JSON deserialization failed. PVE returned non-JSON, schema drift,
    /// or hostile payload. Caller should NOT retry; treat as poisoned.
    Schema(String),
}
```

## How to dispatch

```rust
match operation.await {
    Ok(value) => Ok(value),
    Err(e) => match e.downcast_ref::<ApiError>() {
        Some(ApiError::Unauthorized(_)) => prompt_reauth(),
        Some(ApiError::Forbidden(_))    => bail!("you can't do that here"),
        Some(ApiError::NotFound(_))     => silently_skip(),
        Some(ApiError::RateLimited(_))  => back_off_and_retry(),
        Some(ApiError::StorageHang(node)) => show_degraded_banner(node),
        _                               => Err(e),
    }
}
```

`ApiError: Into<anyhow::Error>` so callers that don't care about
variants keep working unchanged via `?`.

## Mapping to exit codes

See [Exit codes](/reference/exit-codes) for the mapping table:

| `ApiError` variant | Exit code |
| :--- | :---: |
| `Unauthorized`, `Forbidden` | 4 |
| `NotFound`                  | 5 |
| `RateLimited`, `StorageHang`| 7 |
| `Transport`, `Schema`, `PayloadTooLarge` | 1 |

## Where it's mapped

The canonical mapping site is `src/api/client.rs` —
`ApiError::from_response` reads HTTP status + body and produces the
right variant. Adding a new variant requires:

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
| `Unauthorized` | Modal: "Token rejected — re-enter or check `token_secret`" |
| `Forbidden`    | Toast: "Permission denied: {path}" |
| `NotFound`     | Toast: "Resource gone — refreshing list" |
| `RateLimited`  | Status bar: "Cluster busy, backing off…" |
| `StorageHang`  | DANGER banner: "Storage hang on node {N} — read-only mode" |
| `Transport`    | Toast: "Network error — will retry" |
| `Schema`       | Modal: "Schema drift; please open an issue with the version" |

## See also

- [Error handling architecture](/architecture/error-handling) — design
  rationale and the boundary between domain and application errors
- [Exit codes](/reference/exit-codes) — stable scripting contract
