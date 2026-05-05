# Error handling

Two layers, deliberately:

1. **Domain layer** — typed `ApiError` enum (audit). Closed
   set of categorically-actionable failure shapes.
2. **Application layer** — `anyhow::Error`. Catch-all at the CLI /
   TUI boundary, supports `?` everywhere.

The boundary is `ApiError: Into<anyhow::Error>`. Callers that don't
care about variants keep working unchanged via `?`. Callers that
want differentiated handling `.downcast_ref::<ApiError>()` on the
anyhow chain.

## Why typed errors at all

Pre-fix, every API call returned `anyhow::Result<T>`. That made the
TUI's error handling string-grep-driven:

```rust
// pre-fix nightmare
if err.to_string().contains("401") { /* re-auth */ }
else if err.to_string().contains("forbidden") { /* … */ }
else if err.to_string().contains("not found") { /* … */ }
```

Strings drift. PVE's error messages are not stable across versions.
A typo on either side and the whole match falls through to the
default, which is usually wrong.

`ApiError` makes this exhaustive, compile-checked, and version-stable.

## The enum

```rust
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Proxmox rejected our credentials: {0}")]
    Unauthorized(String),

    #[error("Proxmox refused (insufficient privileges): {0}")]
    Forbidden(String),

    #[error("Proxmox resource not found: {0}")]
    NotFound(String),

    #[error("Proxmox transient failure after retries: {0}")]
    RateLimited(String),

    #[error("response body exceeds size limit: {0}")]
    PayloadTooLarge(String),

    #[error("Proxmox storage/upstream hang (595) on {0}")]
    StorageHang(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("schema mismatch: {0}")]
    Schema(String),
}
```

Every variant carries a `String` for the human-facing detail. The
variant itself is the categorical signal.

## Where it's mapped

`src/api/error.rs` defines the enum. `src/api/client.rs` is the
canonical mapping site:

```rust
// src/api/client.rs (sketch)
async fn handle_response<T: DeserializeOwned>(resp: Response) -> Result<T, ApiError> {
    let status = resp.status();
    let url = resp.url().clone();

    if status == StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthorized(url.to_string()));
    }
    if status == StatusCode::FORBIDDEN {
        return Err(ApiError::Forbidden(extract_path(&url)));
    }
    if status == StatusCode::NOT_FOUND {
        return Err(ApiError::NotFound(extract_path(&url)));
    }
    if status == 595 {
        return Err(ApiError::StorageHang(extract_node(&url)));
    }
    if status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::SERVICE_UNAVAILABLE
        || status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::BAD_GATEWAY
        || status == StatusCode::GATEWAY_TIMEOUT
    {
        return Err(ApiError::RateLimited(format!("{status} on {url}")));
    }
    if status.is_server_error() || status.is_client_error() {
        return Err(ApiError::Transport(format!("{status} on {url}")));
    }

    let body = read_capped_body(resp, 32 << 20).await?;  // 
    serde_json::from_slice::<ApiResponse<T>>(&body)
        .map(|r| r.data)
        .map_err(|e| ApiError::Schema(e.to_string()))
}
```

## How callers dispatch

```rust
// src/cli/mod.rs (sketch)
match client.delete_guest(node, vmid, gt).await {
    Ok(upid) => Ok(()),
    Err(e) => {
        if let Some(api_err) = e.downcast_ref::<ApiError>() {
            match api_err {
                ApiError::NotFound(_) => {
                    // Idempotent teardown: already gone is success.
                    Ok(())
                }
                ApiError::Unauthorized(_) | ApiError::Forbidden(_) => {
                    Err(e).context("auth check `proxxx version` first")
                }
                _ => Err(e),
            }
        } else {
            Err(e)
        }
    }
}
```

For the TUI:

```rust
// src/tui/mod.rs (sketch)
match data_rx.recv().await {
    DataMsg::ApiError(e) => {
        let action = match e.downcast_ref::<ApiError>() {
            Some(ApiError::Unauthorized(_)) => Action::ShowReauthModal,
            Some(ApiError::StorageHang(node)) => Action::ShowDegradedBanner(node.clone()),
            Some(ApiError::RateLimited(_)) => Action::ShowBackoffToast,
            _ => Action::ShowErrorToast(e.to_string()),
        };
        update(&mut state, action);
    }
    /* … */
}
```

## CLI exit code mapping

`src/cli/mod.rs` collects the `ApiError` and maps to the stable exit
contract:

| Variant | Exit |
| :--- | :---: |
| `Unauthorized`, `Forbidden` | 4 |
| `NotFound` | 5 |
| `RateLimited`, `StorageHang` | 7 |
| `Transport`, `Schema`, `PayloadTooLarge` | 1 |

Pre-flight refusal and configuration errors short-circuit before the
API layer (exit 6 and 3 respectively).

See [Exit codes](/reference/exit-codes).

## Adding a new variant

1. Add it to the enum in `src/api/error.rs` with a `#[error("...")]`.
2. Map it in `src/api/client.rs::handle_response` (or wherever the
   raw HTTP / IO surface lives).
3. Update [error categories](/reference/errors) with the docstring.
4. Update [exit codes](/reference/exit-codes) if the new variant
   warrants its own exit code.
5. Run `cargo test` — exhaustive matches in callers will fail to
   compile until the new variant is handled or `_` matched explicitly.

That last point is the value: the compiler tells you everywhere that
needs to update.

## Anyhow at the boundary

`main.rs` returns `Result<(), anyhow::Error>`. The CLI dispatcher
returns `anyhow::Result<()>`. The boundary between domain and
application is exactly where you `.context("…")` to add
human-readable framing:

```rust
let token = config.resolve_token_secret(cli_secret)
    .await
    .context("loading token from keychain / env / file")?;

let client = PxClient::new(config, Some(&token))
    .await
    .context("connecting to Proxmox")?;

let nodes = client.list_nodes()
    .await
    .context("listing cluster nodes")?;
```

The `ApiError` survives the round trip — `client.list_nodes()` is
already typed. `.context()` adds a layer for the user-facing print
without losing the original variant.

## See also

- [Error categories reference](/reference/errors) — public-facing summary
- [Exit codes](/reference/exit-codes) — stable scripting contract
- [Architecture overview](/architecture/overview)
