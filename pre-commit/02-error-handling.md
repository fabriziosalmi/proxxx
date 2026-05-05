| Invariant (Domain · Description) | Verified E2E | Revisions |
|---|---|---|
| Network · HTTP 503/504 returns `ApiError::Transport` without panic | ❌ | 0 |
| Network · HTTP 429 (Rate Limit) surfaces cleanly, respects `Retry-After` if present | ❌ | 0 |
| Network · Connection drop mid-stream yields `IncompleteBody` error, never panic | ❌ | 0 |
| Network · DNS resolution failure (NXDOMAIN) caught gracefully without thread hang | ❌ | 0 |
| API · HTTP 403 Forbidden surfaces explicitly as permission denied | ❌ | 0 |
| API · HTTP 401 Unauthorized triggers auto-reauth (V11) or clear exit | ❌ | 0 |
| API · JSON payload missing expected fields triggers serde default fallback (V25) | ❌ | 0 |
| API · Endpoint returns HTML (e.g. proxy error page 502) instead of JSON → parse error handled | ❌ | 0 |
| API · Proxmox lock collision (500 `VM is locked`) maps to actionable message | ❌ | 0 |
| API · Target node offline during cluster-wide op yields `NodeUnreachable` skip | ❌ | 0 |
| Storage (SQLite) · ENOSPC (Disk Full) on cache write logs warning, continues | ❌ | 0 |
| Storage (SQLite) · Corrupt `.db` file triggers schema migration error / cache wipe | ❌ | 0 |
| Storage (SQLite) · Database locked (concurrent writers) respects `busy_timeout` | ❌ | 0 |
| Storage (SQLite) · Read-only filesystem gracefully disables local state cache | ❌ | 0 |
| I/O (MCP) · Malformed stdin (no newline) truncated at `MAX_RPC_LINE_BYTES` (V10) | ❌ | 0 |
| I/O (MCP) · Invalid UTF-8 sequence in stdin yields JSON-RPC Parse Error | ❌ | 0 |
| CLI Contract · Any `Err(_)` during `--format json` outputs valid JSON error object | ❌ | 0 |
| CLI Contract · SIGPIPE (e.g. `proxxx ls \| head -n 1`) exits cleanly without panic trace | ❌ | 0 |
| TUI Contract · Any transient `Err(_)` during tick updates banner, keeps rendering | ❌ | 0 |
| TUI Contract · Terminal size smaller than minimum bounds displays "Terminal too small" | ❌ | 0 |
| TUI Contract · Unicode/Emoji strings in VM names calculate correct column width (no wrapping breaks) | ❌ | 0 |
| FFI (SSH) · Drop of TCP connection during `PtyView` returns cleanly to normal mode | ❌ | 0 |
| FFI (SSH) · Host key mismatch (Strict Host Key Checking) aborted cleanly | ❌ | 0 |
| PBS · Missing `proxmox-backup-client` binary yields clear installation instructions | ❌ | 0 |
