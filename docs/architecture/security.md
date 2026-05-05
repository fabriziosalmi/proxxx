# Security model

proxxx defends in depth across nine surfaces. Each was added in
response to a specific audit finding and is tracked in
`pre-commit/03-security-invariants.md` with E2E verification status.

| Surface | Mechanism | Vector |
| :--- | :--- | :---: |
| Secret heap residue | `Zeroizing<String>` everywhere |  |
| Keychain access | `spawn_blocking` (no runtime stall) | V12 |
| Shell injection | `shell_quote` + 3-layer defence in `pveum` shell-out | V3 |
| TOCTOU on temp files | `tempfile` 0600 + O_EXCL + 128-bit random suffix | V2 |
| API body OOM | 32 MiB body cap on every response |  |
| Async deadlocks | `await_holding_lock = "deny"` | clippy |
| Supply chain | `cargo audit --deny warnings` in gate + CI |  |
| Panic recovery | Flight recorder hook + RAII terminal restore | |
| Daemon shutdown | SIGTERM handler with WAL flush |  |

Plus the human-facing gates:

| Gate | Mechanism |
| :--- | :--- |
| Pre-flight risk | 11 risk variants, per-op weighting, `--allow-risk` override |
| HITL approval | Real Telegram round-trip, deny-on-timeout (120 s) |
| MCP tool registry | Compile-time fixed enum, audit-checksummed |

## Zeroizing&lt;String&gt; everywhere 

Every secret — token, ticket, CSRF, password, PBS token — lives in
`Zeroizing<String>`:

```rust
// src/api/auth.rs
pub enum AuthMethod {
    Token {
        user: String,
        token_id: String,
        token_secret: Zeroizing<String>,
    },
    Password {
        ticket: Zeroizing<String>,
        csrf_token: Zeroizing<String>,
    },
}
```

On `Drop`, the `Zeroize` trait overwrites the heap allocation with
zeros. A core dump or swap-out after the secret has been released
cannot leak the credential.

The cost is a single `memset` on Drop. Hot path is unchanged.

## TOCTOU-safe SPICE handoff (V2)

The `.vv` virt-viewer config file contains the SPICE password in
plaintext. If we wrote it predictably, a malicious local process
could pre-place a symlink and steal the password.

```rust
// src/handoff/spice.rs
let prefix = format!("proxxx-spice-{vmid}-");
let mut builder = tempfile::Builder::new();
builder.prefix(prefix.as_str()).suffix(".vv").rand_bytes(16);
// ↑ 128 bits of entropy in the filename
```

`tempfile::Builder` opens the file with `O_EXCL` — if a symlink or
file already exists at the target path, the open fails. Mode 0600
is set in the `open(2)` call itself, before any byte is written.

The file is in the system temp dir (`%TEMP%` on Windows has user
ACLs, `/tmp` on Linux is typically `1777` with sticky bit). PVE
itself sets `delete-this-file=1` so virt-viewer removes the file
after connecting.

## Shell injection defence (V3)

`proxxx perms <userid>` shells out to `pveum user permissions <userid>`
over SSH. The user-supplied `userid` reaches a remote shell — unsafe
by default. (The newer `proxxx access permissions` hits
`/access/permissions` directly via REST and has no shell layer at all
— but the SSH path stays for cases where the Perl evaluator's full
grant-tree expansion is needed.)

Three layers protect the shell path:

```rust
// src/cli/mod.rs
fn safe_userid_or_refuse(userid: &str) -> Result<()> {
    // 1. Refuse on metachars
    for ch in userid.chars() {
        if "`$;|&\n\\\"".contains(ch) {
            bail!("userid contains shell metachar: {ch:?}");
        }
    }
    Ok(())
}

fn shell_quote(s: &str) -> String {
    // 2. Single-quote wrap, escape internal '
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

let cmd = format!(
    "pveum user permissions -- {}",
    shell_quote(userid),
    // 3. -- separator means even a leading - is treated as data
);
```

Tested against `'; touch /tmp/pwned; '`, `$(rm -rf /)`, backticks,
pipes, semicolons, newlines. Every variant either refuses or
quotes safely.

## Body cap 

Every API response is bounded:

```rust
// src/api/client.rs
const BODY_CAP: usize = 32 * 1024 * 1024;

let body = response.bytes_stream();
let mut buf = Vec::new();
while let Some(chunk) = body.next().await {
    let chunk = chunk?;
    if buf.len() + chunk.len() > BODY_CAP {
        return Err(ApiError::PayloadTooLarge(/* … */));
    }
    buf.extend_from_slice(&chunk);
}
```

A misbehaving node returning a 2 GiB JSON cannot OOM proxxx — the
read aborts at 32 MiB and surfaces a clean error.

## Pre-flight risk gate

11 risk signals, per-op severity weighting, refuses without
`--allow-risk` on `Severe`:

| Risk | What it catches |
| :--- | :--- |
| `Locked` | PVE has a sticky lock (e.g. `lock: backup`) |
| `Running` | Guest is running (Severe for delete, Warning for stop) |
| `LongUptime` | > 30 days uptime — probably serving traffic |
| `TaggedProd` | Tagged `prod` |
| `ActiveNetTraffic` | Avg bps over threshold — actively serving |
| `HaManaged` | CRM will restart it (Severe for stop) |
| `HasManySnapshots` | > N snapshots — config drift indicator |
| `BackupAgeWarning` | Last backup is old |
| `NoBackupFound` | No backup at all |
| `ListeningOnService` | Has listening ports detectable via QGA |
| `DeepCheckSkipped` | Some check couldn't run (agent unavailable) |

The risk levels are `NOTICE` (printed only), `WARN` (printed only),
`SEVERE` (refuses without `--allow-risk`). Per-op weighting means
`Running` is `SEVERE` for `delete` (PVE itself refuses) but only
`WARNING` for `stop` (the op IS the stop).

## HITL gate

Pre-fix (audit #1 P0): the TUI's `check_hitl` simulated approval by
sleeping 3 seconds. **Real path now:**

```rust
// 1. Match policy (TOML-driven), determine if approval required.
let policy = check_policies(&policies, action, target, tags);
if !policy.is_some() { return Ok(()); }

// 2. Register with HitlCoordinator — get oneshot receiver.
let rx = hitl_coord.register(txn_id.clone()).await;

// 3. Send Telegram request.
let Some(tg) = tg_gateway.cloned() else {
    // No Telegram configured but a policy matched → DENY hard.
    return Ok(false);
};
tg.request_approval(action, target, reason, &txn_id).await?;

// 4. Await callback or timeout.
let approved = match tokio::time::timeout(Duration::from_secs(120), rx).await {
    Ok(Ok(b)) => b,
    _ => false,  // Timeout → DENY.
};
```

Four terminal outcomes: configured-and-approved, configured-and-denied,
configured-and-timed-out, not-configured. The last three all DENY —
no silent bypass.

## MCP tool registry — compile-time fixed

```rust
// src/mcp/tools.rs
pub static TOOL_REGISTRY: &[ToolDef] = &[
    ToolDef { name: "list_nodes", destructive: false, ... },
    ToolDef { name: "stop_guest", destructive: true,  ... },
    /* … 10 entries total … */
];
```

There is no runtime registration path. Adding a tool requires a code
change, a PR, and the gate to pass. An attacker controlling the
config file cannot inject tools.

The registry has a deterministic SHA-256 hash:

```sh
$ proxxx mcp tools --checksum
{ "checksum": "8467de772787baa0" }
```

Pin this in your supply-chain tracker. If it changes between builds,
the tool surface changed.

## Panic recovery (+ flight recorder)

Two layers:

1. **`util::panic_hook::install()`** — registered in `main.rs` before
   any I/O. On panic: write the payload to the audit log (file
   appender with rotation), restore raw mode, leave alternate screen,
   show cursor.
2. **`TerminalGuard` (RAII)** — entered at TUI startup. `Drop` runs
   on the happy path AND on `?` early-return. Belt-and-suspenders for
   the panic hook.

Together: there is no path where the TUI exits and leaves your
terminal in raw mode + alternate screen. This was a real symptom
that triggered the audit.

## Daemon shutdown 

```rust
// src/util/shutdown.rs
pub async fn wait_for_shutdown_signal() {
    tokio::select! {
        _ = signal::ctrl_c() => {}
        _ = sigterm_stream() => {}
    }
}
```

Daemons (`alerts watch`, `hitl serve`) `select!` this against their
main loop. On signal, they:

1. Stop the polling loop.
2. Flush the SQLite WAL.
3. Close the SSH pool.
4. Write a final audit log entry.
5. Exit within ~1 s.

systemd's default 90-second SIGTERM grace is comfortable — proxxx
exits cleanly within 1 s, never SIGKILL'd.

## Supply chain 

`.cargo/audit.toml` documents every advisory we accept:

1. The crate + version
2. The dependency path that pulls it in
3. The reason we accept it (with threat model)
4. The planned remediation

Entries without remediation are **debt, not policy**. Today the file
ignores three advisories, all in the `russh` / `ratatui` transitive
surface, all with planned upstream-bumps tracked.

`cargo audit --deny warnings` runs:

- Locally as gate stage 3 (every commit)
- In CI on every push and PR
- In CI nightly via cron (catches CVEs disclosed after last commit)

## What's still ❌

The matrix at `pre-commit/03-security-invariants.md` lists 18
security invariants. As of audit #4, **5 are E2E-verified**, 13 are
not. The gaps are declared, not hidden:

- RBAC: `operator` op on unowned VM → 403
- RBAC: `operator` cannot view global ACLs / Tokens → 403 / empty
- RBAC: token without privilege separation maps to user rights
- HITL: `secure_mode` prevents bypass of `is_destructive` ops
- HITL: replay attack on stale Telegram callback rejected
- HITL: op approved via Telegram but executed by unprivileged user fails
- Injection: env var secret capped at 64 KiB
- Injection: malicious VM name with ANSI escape codes rendered safely
- Crypto: ISO download enforces SHA-256 / SHA-512 manifest
- Crypto: `wsterm` TLS bypass scoped to WS client only
- Crypto: SSH rejects deprecated algorithms (SHA1)
- Memory: panic hook scrubs secrets before stderr / log write
- Memory: `exec_guest_command` output not cached in SQLite

These are the next round's targets.

## See also

- [Pre-commit gate](/guide/pre-commit-gate)
- [HITL via Telegram](/integrations/hitl)
- [MCP server](/integrations/mcp)
- [Architecture overview](/architecture/overview)
