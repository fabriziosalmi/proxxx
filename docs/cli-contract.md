# `proxxx` CLI Contract

This document defines the stable, public surface of the `proxxx` CLI. 
Any changes to the behaviors described here require a major version bump.

## 1. Exit Codes

- `0` (Success): Operation completed entirely. For batch ops, *all* targets succeeded.
- `1` (Fatal Error): Configuration error, network unreachable, invalid auth, or parsing error.
- `2` (Partial Failure): In a batch operation (e.g. `start 100 101`), at least one target failed, but others succeeded.
- `3` (HITL Pending): Destructive operation was intercepted by the Policy Engine. The request was queued for human approval. The CLI exits immediately; the operation is *not* running yet.
- `4` (HITL Denied): A synchronous approval was requested but explicitly denied by the approver.

## 2. Standard Output vs Standard Error

- **STDOUT**: Reserved strictly for the requested data payload (e.g., JSON output, ASCII tables).
- **STDERR**: Reserved for logs, progress bars, interactive prompts, and HITL warning banners.
- *Rule:* `proxxx ls nodes --json > out.json` will *always* result in a valid, parseable JSON file, regardless of connection warnings or debug logs printed to STDERR.

## 3. JSON Output Stability (`--json`)

When `--json` is provided:
- The output is guaranteed to be a JSON array (even if a single item is returned).
- Fields will only be *added*, never removed or renamed in a minor version.
- Deprecated fields will remain present but may return `null` or empty strings.
- Keys are strictly `snake_case`.

## 4. Partial Failures in Batch Operations

Example: `proxxx start 100 101 102`
- **Default behavior**: Best-effort. If 101 fails (does not exist), 100 and 102 will still be started. The exit code will be `2`. STDERR will contain the specific error for 101.
- **Strict mode (`--strict`)**: Fail-fast. If `proxxx` can determine *before* execution that 101 is invalid, it aborts the entire batch and exits with `1`. If it fails during execution, subsequent targets are aborted.

## 5. Streaming Output

Example: `proxxx tasks --follow 100`
- Output streams to STDOUT indefinitely.
- **SIGINT (Ctrl-C)**: Graceful exit. Closes the stream and exits with `0`.
- **SIGPIPE**: If piped to another command (e.g., `head -n 10`), `proxxx` will cleanly terminate when the pipe closes without throwing a panic trace.

## 6. Secret Resolution Hierarchy

Secrets (like API tokens or Telegram Bot keys) are resolved in the following strict order. The first one found wins:
1. **CLI Flag**: `--token-secret "xxx"` (Not recommended, leaks in bash history)
2. **Environment Variable**: `PROXXX_TOKEN_SECRET="xxx"`
3. **Secure File**: `token_secret_file = "/etc/proxxx/token"` in TOML (Must have 0600 permissions, or `proxxx` aborts with exit code 1)
4. **OS Keychain**: Fallback/default on macOS. On headless Linux, requires `dbus`/`secret-service` or explicitly falling back to method 2/3.

## 7. Target Selectors (v1)

- Exact VMID: `proxxx start 100`
- **(Not in v1)** Tag selection: `proxxx start tag:prod`. This is reserved for v2 to prevent accidental mass-destructions before the dry-run system is implemented.
