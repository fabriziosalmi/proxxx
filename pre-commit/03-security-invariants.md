| Invariant (Domain · Description) | Verified E2E | Revisions |
|---|---|---|
| Auth · Passwords and tokens drop via `Zeroizing<String>` mathematically (V16) | ✅ | 5 |
| Auth · OS Keychain read occurs on isolated blocking thread (`spawn_blocking`) | ✅ | 5 |
| RBAC · Destructive op by `operator` on unowned VM returns HTTP 403 | ❌ | 0 |
| RBAC · `operator` cannot view global ACLs/Tokens (returns HTTP 403 / empty) | ❌ | 0 |
| RBAC · Token without Privilege Separation maps to user rights accurately | ❌ | 0 |
| HITL · Op approved via Telegram but executed by unprivileged user fails | ❌ | 0 |
| HITL · `secure_mode` flag prevents bypass of `is_destructive` operations | ❌ | 0 |
| HITL · Replay attack on Telegram callback data (stale approval) rejected | ❌ | 0 |
| Injection · `shell_quote()` escapes `'` and blocks `;`, `$`, `\|`, `\n` in pveum calls | ✅ | 5 |
| Injection · Env var secrets capped at 64 KiB to prevent OOM via ENV | ❌ | 0 |
| Injection · Malicious VM name with ANSI escape codes rendered safely in TUI | ❌ | 0 |
| Cryptography · SPICE `.vv` file uses `O_EXCL` and `0600` permissions (V2) | ✅ | 3 |
| Cryptography · ISO Download strictly enforces pinned SHA-256 / SHA-512 manifest | ❌ | 0 |
| Cryptography · `wsterm` TLS bypass (`verify_tls=false`) scoped to WS client only | ❌ | 0 |
| Cryptography · SSH uses modern KEX/Ciphers, rejects deprecated algorithms (SHA1) | ❌ | 0 |
| Memory Hygiene · Panic hook flight recorder scrubs secrets before writing to stderr/log | ❌ | 0 |
| Memory Hygiene · `exec_guest_command` output containing secrets is not cached in SQLite | ❌ | 0 |
| Supply Chain · `cargo audit` in CI enforces 0 CVEs on transitive dependencies (V19) | ✅ | 1 |
