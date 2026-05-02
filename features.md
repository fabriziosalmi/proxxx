# Proxxx Features Status

Stato verificato per ispezione del codice — niente 100% di facciata.
Quando una riga è 100%, è perché esiste, è chiamata, ed è coperta da test.
Quando è X%, sotto trovi "cosa manca" esplicito.

---

## Tier 1 — Core killer features

| Feature                                         | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Cluster-wide instant fuzzy search (`/`)         | 100%   | nucleo-matcher, [src/app/search.rs](src/app/search.rs) |
| Operation queue con dry-run e diff              | 100%   | [src/app/queue.rs](src/app/queue.rs) + view |
| Tag-based bulk ops di prima classe              | 100%   | semicolon-split, `t` keybind |
| Local state cache + time-travel (SQLite)        | 100%   | [src/app/cache.rs](src/app/cache.rs), `replay <ts>` CLI |
| Node evacuation wizard (RAM heuristic)          | 100%   | reducer, max-free-RAM target picking |
| Replay-as-script (proxxx, pvesh, curl, Ansible) | 100%   | `QueuedOp::export_script` |

---

## VM operations (QEMU)

| Feature                                         | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Start VM                                        | 100%   | API `/qemu/{vmid}/status/start` |
| Stop VM (Graceful)                              | 100%   | ✅ bug #2 fixed: `/status/shutdown` + ACPI polling (60s/3s) + force prompt on timeout |
| Force Stop VM                                   | 100%   | `forceStop=1` su `/status/stop` |
| Restart VM                                      | 100%   | `/status/reboot` (ACPI signal) |
| Delete VM                                       | 100%   | DELETE `/qemu/{vmid}` |
| Migrate VM (direct + via queue)                 | 100%   | ✅ bug #9 fixed: reducer emette SideEffect (non più no-op) |
| Create VM Snapshot                              | 100%   | API + TUI + MCP + CLI |
| Delete VM Snapshot                              | 100%   | API + TUI + MCP + CLI |

---

## LXC operations

| Feature                                         | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Start LXC                                       | 100%   | ✅ bug #1 fixed: dispatch `/lxc/...`, wiremock test |
| Stop LXC (Graceful)                             | 100%   | ✅ bug #1+#2: `/lxc/{vmid}/status/shutdown`, test |
| Force Stop LXC                                  | 100%   | ✅ bug #1: `/lxc/{vmid}/status/stop` con forceStop |
| Restart LXC                                     | 100%   | ✅ bug #1: `/lxc/{vmid}/status/reboot` |
| Delete LXC                                      | 100%   | ✅ bug #1: DELETE `/lxc/{vmid}`, test |
| Migrate LXC                                     | 100%   | ✅ bug #1: POST `/lxc/{vmid}/migrate`, test |
| Create LXC Snapshot                             | 100%   | ✅ bug #1: POST `/lxc/{vmid}/snapshot`, test |
| Delete LXC Snapshot                             | 100%   | ✅ bug #1: DELETE `/lxc/{vmid}/snapshot/{name}` |
| Get LXC Status                                  | 100%   | `get_guest_status` ha fallback corretto QEMU→LXC |
| LXC exec (broadcast)                            | 100%   | `execute_guest_command` dispatcha per type |

**Cambio architetturale:** trait `ProxmoxGateway` ora prende `GuestType` su tutti i write-method. Fix tracciato come **bug #1** — write LXC silenziosamente a `/qemu/`. Ora 9 wiremock test verificano il routing corretto in entrambe le direzioni (positive + negative).

---

## TUI & UX

| Feature                                         | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Dashboard Cluster Overview                      | 100%   | [src/tui/views/dashboard.rs](src/tui/views/dashboard.rs) |
| Node List View (CPU, Mem, Disk)                 | 100%   | sortable, sparklines |
| Guest List View (Unified VM/LXC)                | 100%   | mixed table, status pills |
| Storage Pool List View                          | 100%   | + trend column |
| Live Task Log Streamer                          | 100%   | poll-based via `/tasks/{upid}/log` |
| Vim-style Navigation (`j`, `k`, `h`, `l`)       | 100%   | + `g`/`G`, `Tab` |
| Command Palette (`:start`, `:stop`, `:ssh`)     | 100%   | extensible parser, see [src/app.rs](src/app.rs) `parse_command_action` |
| Visual Multi-selection (`Space`)                | 100%   | per-row toggle |
| Select All Visible (`V`)                        | 100%   | inverted by another `V` |
| Tag Input Mode Selection (`t`)                  | 100%   | live filter on input |
| Color-coded Status Highlights                   | 100%   | running/stopped/paused/unknown |
| Confirm modal for destructive ops               | 100%   | `y`/`n`, `Enter` to accept |

---

## CLI & automation

Total: **27 top-level subcommands** (run `proxxx --help` for the live
list). Grouped by domain below — each entry below is a real
subcommand parsed by clap in `src/cli/mod.rs`. Bullet items under a
heading are sub-subcommands (e.g. `proxxx access acl`).

### Read & inspect (no mutation)
| Subcommand | Status | Note |
| :--- | :--- | :--- |
| `proxxx ls nodes` / `ls guests` / `ls storage` (alias `get`) | 100% | clap `#[command(alias = "get")]` so both names work |
| `proxxx search <query> [--limit N]` | 100% | bug #4 fix: cluster-wide fuzzy across nodes/guests/storage |
| `proxxx replay <timestamp>` | 100% | dump JSON of the cached cluster state at a given Unix time |

### Guest lifecycle (mutation)
| Subcommand | Status | Note |
| :--- | :--- | :--- |
| `proxxx start <vmid…>` | 100% | batch + parallel via `Semaphore(32)` (V7 audit) |
| `proxxx stop <vmid…> [--force]` | 100% | graceful by default; force = hard SIGKILL via PVE |
| `proxxx restart <vmid…>` | 100% | bus #2 fix: routes to `/status/reboot` |
| `proxxx delete <vmid…> --yes` | 100% | bug #6 fix: top-level destructive with `--yes` guard |
| `proxxx snapshot create --vmid V --name N` | 100% | bug #3 fix: type-aware dispatch |
| `proxxx snapshot delete --vmid V --name N` | 100% | bug #3 fix |
| `proxxx watch --since/--target/--until` | 100% | poll-based; notifies via Telegram on convergence |

### Console & graphical handoff
| Subcommand | Status | Note |
| :--- | :--- | :--- |
| `proxxx serial <vmid>` | 100% | termproxy WebSocket, raw mode, Ctrl+] q to exit |
| `proxxx spice <vmid> [--write-vv P] [--no-launch]` | 100% | feature 1c — `.vv` via tempfile + O_EXCL (V2) |
| `proxxx novnc <vmid> [--no-launch]` | 100% | builds deep-link URL into PVE web UI |

### Storage & images
| Subcommand | Status | Note |
| :--- | :--- | :--- |
| `proxxx iso list` | 100% | curated library; checksum field is `{algo, digest}` (BLOCKER 1) |
| `proxxx iso download --id ID \| --url U …` | 100% | refuses curated entries lacking pinned checksum |
| `proxxx disk move --vmid V --disk D --target S [--delete-source] --yes` | 100% | feature #6, requires `--yes` |
| `proxxx disk resize --vmid V --disk D --size +5G --yes` | 100% | grow-only (PVE limit) |
| `proxxx pbs datastores` / `pbs snapshots` / `pbs files` | 100% | read-only PBS browse via REST |
| `proxxx pbs restore <snapshot> <archive> <target> [--yes]` | 100% | shells out to proxmox-backup-client (Linux only) |

### HA + replication + hardware
| Subcommand | Status | Note |
| :--- | :--- | :--- |
| `proxxx ha groups` / `ha resources` / `ha status` / `ha preview <id>` | 100% | feature #5, includes failover preview (Option A) |
| `proxxx replication jobs` / `replication status` | 100% | per-node + per-job |
| `proxxx hw pci [--node N]` / `hw usb` / `hw conflicts` | 100% | feature #4, IOMMU-group conflict detector |

### Access control (feature #10)
| Subcommand | Status | Note |
| :--- | :--- | :--- |
| `proxxx access acl` / `access users` / `access groups` / `access roles` | 100% | read-only PVE `/access/*` |
| `proxxx access realms` / `access tfa <userid>` | 100% | read-only |
| `proxxx perms <userid> [--path P] --node N` | 100% | shells out to `pveum user permissions` (Option A — V3 hardened) |
| `proxxx token list <userid>` | 100% | per-user token enumeration |
| `proxxx token create <userid> <id> [--expire UNIX] [--privsep] [--comment …]` | 100% | secret returned ONCE on creation |
| `proxxx token revoke <userid> <id> --yes` | 100% | requires `--yes` |

### Patching + alerts + automation
| Subcommand | Status | Note |
| :--- | :--- | :--- |
| `proxxx patch plan` | 100% | API-only inventory (#9), no SSH for the read path |
| `proxxx patch apply [--reboot {auto,never,always}] [--dry-run]` | 100% | uses SSH layer (Pillar 0) for `apt-get` + `systemctl reboot --no-block` |
| `proxxx alerts test <route> [--severity S]` / `alerts eval <rule>` | 100% | dry-run for routing config |
| `proxxx alerts watch [--interval N]` | 100% | long-running daemon; SIGTERM-aware (V21) |

### Daemons & introspection
| Subcommand | Status | Note |
| :--- | :--- | :--- |
| `proxxx mcp serve` | 100% | stdio JSON-RPC; bounded line reads (V10) |
| `proxxx mcp tools [--json] [--checksum]` | 100% | introspect + SHA-256 of registry payload |
| `proxxx hitl serve` | 100% | Telegram bot daemon; SIGTERM-aware (V21) |
| `proxxx dev-panic` | 100% | BLOCKER 3 manual smoke for the panic hook |

### Cross-cutting
| Mechanism | Status | Note |
| :--- | :--- | :--- |
| `--format {table,json,yaml}` | 100% | global flag; JSON output is always a top-level array |
| `--profile <name>` | 100% | global; selects which `[profiles.X]` block to use |
| `--secure` | 100% | global; forces HITL on every destructive op (tag-independent) |
| `--token-secret <SECRET>` | 100% | global; overrides env / file / keychain |

---

## Security & Governance (HITL)

| Feature                                         | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Destructive action interceptor                  | 100%   | dispatch_side_effect gates on policy match |
| Tag-based Policy Engine (TOML)                  | 100%   | [src/hitl/policy.rs](src/hitl/policy.rs) |
| Telegram Bot Integration (Inline Callbacks)     | 100%   | sendMessage/getUpdates/editMessageText |
| TUI Approval Queue View                         | 100%   | shows pending/approved/denied/timeout |
| Self-HITL via Telegram (`--secure` flag)        | 100%   | ✅ end-to-end: `state.secure_mode` wired (bug #7) + reviewer P0 fix — TUI now sends real Telegram `request_approval` and awaits the callback via shared `HitlCoordinator` (no simulation, no auto-approve). Refuses (denies) if `[telegram]` is unconfigured. |
| Model Context Protocol (MCP) Server             | 100%   | stdio + tool registry checksum |

---

## Tier 2 — Differenziatori

| Feature                                         | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Live Hotspot Heatmap (`H` view)                 | 100%   | top-N CPU/RAM combined heat |
| Backup Health Board                             | 100%   | per-guest last backup, age, duration |
| Config Drift Detector (`D` diff view)           | 100%   | `GuestCompare` view, side-by-side |
| CLI `watch` mode with Notifications             | 100%   | vedi sopra |
| Storage Trend & Forecast (ETA Saturation)       | 100%   | 24h history from cache, ETA col |
| Parallel guest-agent broadcast (`X` from selection) | 100% | ✅ bug #8 etichetta corretta: usa Proxmox API `qemu/{vmid}/agent/exec` + `lxc/{vmid}/exec`, non SSH al nodo |

---

## Tier 3 — Spicy / future

| Feature                                         | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Audit timeline scrubbabile (`T` view)           | 100%   | timeline navigation across cached state |
| Quick-open palette (`Ctrl-K`)                   | 100%   | shortcut to fuzzy-search |
| Cluster-wide config grep (`G`)                  | 100%   | scan all guest configs for keyword |

---

## Pillar 0 — SSH layer (infrastruttura per tavola alta)

Aggiunto come fondazione per #4/#6/#7/#9/parti #5. Senza questo nulla di SSH-bound era possibile.

| Feature                                         | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| `russh` 0.46 client (publickey auth only)       | 100%   | [src/ssh/session.rs](src/ssh/session.rs) |
| TOFU `known_hosts` dedicato (NON `~/.ssh/`)     | 100%   | [src/ssh/known_hosts.rs](src/ssh/known_hosts.rs) |
| `HostKeyVerifier` trait (Tofu/Strict/Off)       | 100%   | pluggabile, default `PolicyVerifier` |
| Per-(profile,node) connection pool              | 100%   | semaphore concurrency cap, idle timeout |
| `exec` (capture, timeout)                       | 100%   | [src/ssh/exec.rs](src/ssh/exec.rs) |
| `exec_stream` (line-by-line callback)           | 100%   | stdout/stderr split, CRLF normalize |
| Threat model: dedicated key + audit log         | 100%   | docstring + audit via tracing |
| Test coverage                                   | 100%   | 7 unit (base64, fingerprint, TOFU) |

---

## Tavola alta — feature shippate

### Feature 1a — SSH guest session (`:ssh <vmid>`)

| Componente                                      | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Russh PTY channel + key encoding                | 100%   | [src/ssh/pty.rs](src/ssh/pty.rs) |
| `vt100` parser screen state                     | 100%   | crate `vt100-ctt` per compat ratatui-29 |
| `PtyView` ratatui widget (cell-by-cell color)   | 100%   | [src/tui/widgets/pty.rs](src/tui/widgets/pty.rs) |
| `SshSessionHandler` (run-loop owned)            | 100%   | [src/tui/ssh_handler.rs](src/tui/ssh_handler.rs) |
| `View::GuestSshSession` + `AppMode::SshSession` | 100%   | reducer transitions, view dispatch |
| `:ssh <vmid>` palette parser                    | 100%   | `parse_command_action` |
| Ctrl+] exit chord, all other keys forwarded     | 100%   | run-loop bypass of map_key |
| Resize forwarding al PTY                        | 100%   | window_change su crossterm Resize |
| Auto-close on remote shell exit                 | 100%   | `is_finished()` polled per tick |
| Per-guest config (`[ssh.guests.\"100\"]`)       | 100%   | `resolve_guest()` con fallback profile |
| Test coverage                                   | 100%   | 7 reducer tests + 5 PTY widget/encode |

**Limiti dichiarati:**
- Nessun prompt per passphrase chiave SSH: usa `PROXXX_SSH_KEY_PASSPHRASE` env o chiave senza passphrase.
- Nessun auto-discovery via qemu-guest-agent: target solo da config TOML.
- TOFU first-use auto-accept con warn log; modal interattivo non implementato.
- Nessun chord configurabile: solo Ctrl+].
- Nessuna copy-paste integration (paste OK, copy via mouse-select del terminale parent).

### Feature 1b — Serial console via termproxy (WebSocket)

| Componente                                      | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Type `TermproxyTicket` (port, ticket, user, upid) | 100%   | Returned by `POST /termproxy` |
| API `get_termproxy(node, vmid, type)`           | 100%   | Type-aware (qemu vs lxc), 2 wiremock test |
| `wsterm::build_ws_target(...)` URL builder      | 100%   | URL-encode ticket (`:` `/` `+` → `%XX`), strip path da base URL, `<user>:<ticket>\n` auth frame |
| `wsterm::tls::dangerous_no_verify_config()`     | 100%   | Custom rustls `ServerCertVerifier` per `verify_tls=false` (homelab self-signed) — mirror del flag reqwest |
| `wsterm::connect(target, verify_tls)`           | 100%   | `connect_async_tls_with_config` con custom Connector quando verify_tls=false |
| `send_resize(ws, cols, rows)` opcode 1          | 100%   | `1:<cols>:<rows>:` frame |
| `send_input(ws, bytes)` opcode 0                | 100%   | `0:<len>:<bytes>` frame |
| `decode_data_frame(payload)`                    | 100%   | Length-prefixed parse + raw passthrough fallback |
| CLI `proxxx serial <vmid> --node N [--kind T]`  | 100%   | Auto-detect kind dal cluster se omesso |
| CLI raw mode + alt screen + cursor hide         | 100%   | Cleanup esplicito + safety net via panic hook (BLOCKER 3) |
| Initial size sync + Resize event forwarding     | 100%   | Crossterm Resize event → `send_resize` |
| Exit chord `Ctrl+] q` (telnet-style)            | 100%   | Stato armed dopo Ctrl+], `q` chiude WS, altro key forwarda Ctrl+] |
| Reuse di `ssh::pty::encode_key` da feature 1a   | 100%   | Stessa key encoding per coerenza Ctrl/Alt/F-keys/arrow |
| Test coverage                                   | 100%   | 8 unit (URL builder + decoders) + 2 wiremock = 10 nuovi |

**Architettura:**
1. `POST /api2/json/nodes/{node}/{type}/{vmid}/termproxy` → `{ port, ticket, user, upid }`
2. `wss://<host>/api2/json/nodes/{node}/{type}/{vmid}/vncwebsocket?port={port}&vncticket=<URL-encoded ticket>`
3. Send `<user>:<ticket>\n` come primo binary frame (auth)
4. Bidirectional: keystrokes encoded + `0:<len>:<bytes>` opcode → WS; WS frames → stdout dopo `decode_data_frame`

**Tagli onesti:**
- ❌ **TUI integration**: rinviata — il pattern mirror di `SshSessionHandler` da 1a richiede refactor a `dyn ConsoleSession` o enum. CLI è il deliverable funzionalmente sufficiente per recovery di VM stuck.
- ⚠️ **Token auth**: PVE 8+ raccomandato. Pre-PVE8 il vncwebsocket è inconsistente con token; non gattamo esplicitamente sulla versione — il REST `termproxy` call o ritorna ticket usabile o no.
- ⚠️ **Live WS roundtrip test**: skip — richiederebbe un mock WS server (più setup di quanto valga). URL builder + frame decoder testati in isolamento; il connect path è run only dal CLI quando un PVE reale risponde.
- ⚠️ **Linux/macOS only**: raw mode + crossterm signal handling — Windows console reading è diverso. Non blocking ma non testato lì.
- ⚠️ **No scrollback**: passthrough byte-by-byte. Se serve, l'utente lancia `proxxx serial` dentro `tmux` o `screen`.

### Feature 1c — SPICE / noVNC handoff esterno

| Componente                                      | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Type `SpiceConfig` (flat HashMap)               | 100%   | `#[serde(flatten)]` — forward-compat con nuove key Proxmox |
| `SpiceConfig::to_vv_file()`                     | 100%   | INI `[virt-viewer]` + sorted keys + newline escape per PEM `ca` |
| `SpiceConfig::host()` helper                    | 100%   | + test |
| API `get_spiceproxy(node, vmid)` — QEMU only    | 100%   | POST + wiremock test |
| `handoff::spice::temp_vv_path(vmid)`            | 100%   | Default: temp dir + nano timestamp |
| `handoff::spice::write_vv_file(path, cfg)`      | 100%   | **Unix mode 0600** (password in plaintext) — verificato test |
| `handoff::launcher::which(bin)`                 | 100%   | PATH walk, Windows .exe fallback, no `which(1)` shell-out |
| `handoff::launcher::open_with_default(url)`     | 100%   | `open` macOS, `xdg-open` Linux, `cmd /C start "" X` Windows |
| `handoff::launcher::open_spice_vv(path)`        | 100%   | Try `remote-viewer` → `virt-viewer` → system default; ritorna nome launcher |
| `handoff::novnc::build_novnc_url(...)`          | 100%   | QEMU=`console=kvm`, LXC=`console=lxc`, `novnc=1`, `resize=scale` |
| Strip path da REST base URL                     | 100%   | Stesso pattern di wsterm |
| CLI `proxxx spice <vmid> --node N`              | 100%   | + `--write-vv <path>` + `--no-launch` |
| CLI `proxxx novnc <vmid> --node N [--kind T]`   | 100%   | Auto-detect kind dal cluster + `--no-launch` |
| Test coverage                                   | 100%   | 14 nuovi: 6 spice (vv format/sorted/newline-escape/host/temp/write+0600) + 4 novnc (qemu/lxc/path-strip/resize) + 2 launcher (which positive/PATH-unset) + 1 wiremock + 1 user secret |

**Architettura per path:**
1. **SPICE** (graphical, QEMU only):
   ```
   POST /nodes/{node}/qemu/{vmid}/spiceproxy
        → { type, host, port, tls-port, password, ca, host-subject, … }
   write .vv (INI [virt-viewer], 0600 perms)
   spawn remote-viewer <path>  (or virt-viewer, or system default)
   ```
2. **noVNC** (browser, QEMU + LXC):
   ```
   build URL: https://<host>:8006/?console=kvm|lxc&novnc=1&vmid=N&node=X&resize=scale
   spawn xdg-open / open / cmd start "" <url>
   ```

**Tagli onesti vs. spec:**
- ❌ **Crate `opener`** (~50KB binary delta): respinto. 3-line `Command::new` per platform è più trasparente da audit + zero dep.
- ❌ **Inject auth ticket nella URL noVNC** via `#PVEAuthCookie=...`: respinto. Il pattern leak il ticket via shell history, browser history, screenshot. L'utente loggato nella web UI ha già la cookie; deep-link → console panel.
- ❌ **Renderizzare frame VNC/SPICE in TUI**: tutti gli altri tool (web UI, pvetui, PDM) handoff a client esterno. Coerente con spec.
- ❌ **MIME-type registration `.vv`**: out of scope — l'utente installa virt-viewer secondo il proprio packaging.
- ⚠️ **Password in chiaro nel `.vv`**: mitigato con 0600 perms su Unix. Su Windows il file vive in `%TEMP%` che ha ACL utente. PVE setta `delete-this-file=1` → virt-viewer rimuove dopo connect.
- ⚠️ **TUI integration**: nessuna — handoff è inerentemente esterno. CLI è il deliverable corretto.

### Feature 10 — Access control: ACL / Token / MFA console

| Componente                                      | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Types: `AclEntry`, `User`, `ApiToken`, `Group`, `Role`, `Realm`, `TfaEntry` | 100% | Tutti con derive serde, parsing tolerante (`bool` da int, optional fields) |
| API: `list_acl/users/user_tokens/groups/roles/realms/tfa` | 100% | 7 read endpoints, urlencoded path components (`@` → `%40`) |
| API: `create_token`, `revoke_token`             | 100%   | Create returns secret nel `value` (one-shot); revoke = DELETE |
| `urlenc()` per `userid` con `@`                 | 100%   | Path encoding minimale handwritten, niente nuova dep |
| `access::pveum::parse_user_permissions(userid, output)` | 100% | **Opzione A del review draconiano**: parser dell'output `pveum user permissions`, NON re-implementazione del CRM |
| Stateful line scanner (header + indented body)  | 100%   | Skip malformed lines senza panic, dedup privileges, sort stabile |
| `EffectivePermissions` + `PathPerms` types      | 100%   | Per-path privilege list con `propagate` flag |
| CLI `proxxx access acl/users/groups/roles/realms/tfa` | 100% | Read-only browse, JSON output |
| CLI `proxxx token list/create/revoke`           | 100%   | Create banner "secret shown ONCE", revoke `--yes` obbligatorio |
| CLI `proxxx perms <userid> [--path P] --node N` | 100%   | SSH shell-out via Pillar 0 a `pveum user permissions`, parse, JSON output |
| `shell_quote(s)` con metachar refusal           | 100%   | Defense contro userid `'; rm -rf` — refuse `` ` $ ; & \| \n `` prima dello shell-out |
| Test coverage                                   | 100%   | 7 wiremock (acl/users/tokens/realms/tfa/create/revoke con urlencode `@`) + 7 pveum parser |

**Tagli onesti vs. spec originale (review draconiano):**
- ✅ **Opzione A scelta** per effective-permission debugger: shell-out a `pveum user permissions` invece di reimplementazione `pve-access-control`. **Ground truth, zero drift, 1/10 il costo.**
- ❌ **Native debugger Opzione B** (port Rust del scoring algorithm): respinto. La regola del review era esplicita: "L'ideologia non vale un CVE."
- ❌ **WebAuthn enrollment dal TUI**: fisicamente impossibile (richiede `navigator.credentials.create()` browser-side).  **Future**: subcommand `proxxx mfa webauthn-handoff <user>` che apre l'URL del web UI Proxmox al pannello TFA pre-popolato e fa polling per detection del nuovo entry.
- ❌ **TOTP enrollment helper interattivo + QR ASCII**: rinviato — richiede crate `qrcode` (~200KB binary) per ASCII rendering. MVP: `proxxx access tfa <user>` mostra solo TFA entries esistenti; setup va via web UI per ora.
- ❌ **Realm test connection**: Proxmox non ha endpoint dedicato per validare AD/LDAP/OIDC senza tentare login reale. Rinviato.
- ❌ **Token rotation grace period automatizzato**: docs only — pattern è `tokenA` + `tokenA-new`, deploy parallelo, revoca old. Future: orchestrator dedicato.
- ⚠️ **TUI view dell'ACL console**: solo CLI per MVP. Read-only browser TUI rinviato (analogo a HW console — replicabile ma pesante per scope MVP).
- ⚠️ **`pveum` shell injection defence**: refuse esplicito di metachar nel userid prima del format del comando, plus `shell_quote()` per il pass-through.

### Feature 8 — Alerting & notification routing

| Componente                                      | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| `[[alerts]]` TOML config                        | 100%   | name, when (closed enum), thresholds, severity, route[], dedup_secs |
| `Severity` (Info/Warning/Critical) + parsing    | 100%   | Tolerant parse, default Warning, emoji icons |
| `AlertEvent` + `render_text()`                  | 100%   | Format `<icon> [rule] target — summary` per Telegram/ntfy |
| `engine::evaluate(rules, snapshot, prev_state)` | 100%   | Pure function, returns events + updated state |
| Predicato `node_offline for_secs N`             | 100%   | Tracking offline-since across calls (state machine temporale) |
| Predicato `storage_above threshold% [storage]`  | 100%   | Optional filter per storage name, skip total=0 |
| Predicato `replication_failing`                 | 100%   | fail_count > 0 OR error non-empty |
| Unknown predicate → warn-skip (no panic)        | 100%   | Forward-compat se aggiungiamo altri |
| Channel `Telegram` (riusa `hitl::telegram`)     | 100%   | Skip-graceful se `[telegram]` non configurato |
| Channel `ntfy:<topic>` (https://ntfy.sh)        | 100%   | Headers Title/Priority/Tags severity-mapped |
| Channel `webhook:<url>`                         | 100%   | POST application/json con full event struct |
| `parse_route(s)` per route specs                | 100%   | Tolerante su unknown (warn-skip), reject ntfy/webhook empty/malformed |
| `DedupCache` per (rule, target) con TTL         | 100%   | In-memory, evict_older_than per housekeeping |
| CLI `proxxx alerts eval`                        | 100%   | One-shot dry-run, JSON dei would-fire events |
| CLI `proxxx alerts watch [--interval 30]`       | 100%   | Daemon long-running con dedup + state across ticks |
| CLI `proxxx alerts test --route R --severity S` | 100%   | Send synthetic event end-to-end |
| Test coverage                                   | 100%   | 23 unit (9 engine + 6 dedup + 6 notifier + 2 types) |

**Esempio config:**
```toml
[[alerts]]
name = "node_down"
when = "node_offline"
for_secs = 120
severity = "critical"
route = ["telegram", "ntfy:proxxx-prod", "webhook:https://hooks.example/notify"]
dedup_secs = 600

[[alerts]]
name = "storage_full"
when = "storage_above"
threshold_percent = 85
storage = "ceph-rbd"           # optional filter
severity = "warning"
route = ["telegram"]

[[alerts]]
name = "replica_broken"
when = "replication_failing"
severity = "critical"
route = ["telegram", "ntfy:proxxx-prod"]
```

**Tagli onesti vs. spec originale (fedele al review draconiano):**
- ❌ **Free-form `when` DSL** (`node.status == 'offline' for 60s`): respinto. Closed enum di 3 predicati. Aggiungerne un quarto richiede una PR — è una protezione, non una limitazione.
- ❌ **Email SMTP**: nuova dep (`lettre`), edge cases TLS/auth.
- ❌ **Gotify, syslog**: nuove dep / RFC framing.
- ❌ **Oncall scheduler / time-windowed routing**: PagerDuty-in-miniatura. Respinto.
- ❌ **Escalation rules**: respinto (era complessità nascosta nella bullet).
- ❌ **Ack via reply**: HITL infra è per approvals (callback inline), reply-based ack è un meccanismo diverso. Future.
- ⚠️ **History persistence**: SQLite cache è disponibile (modulo `cache.rs`), ma alert log su disco rinviato — daemon è stateless on restart by design.
- ⚠️ **Mute time-windows**: skip — l'utente può commentare la `[[alerts]]` rule per ora.

### Feature 4 — Hardware passthrough inventory + conflict detector

| Componente                                      | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Types: `PciDevice` (con `iommugroup`!), `UsbDevice` | 100% | Proxmox API ritorna già `iommugroup` → no SSH/sysfs per il base case |
| `PciDevice::is_gpu()` (class 03xxxx)             | 100%   | Detect GPU per highlighting |
| `PciDevice::short_label()`                       | 100%   | Format `01:00.0  NVIDIA RTX 3070` (strip `0000:` prefix) |
| `UsbDevice::proxmox_id()`                        | 100%   | Format `vendor:product` (es. `046d:c52b`) per `qm set --usbN` |
| API: `list_pci(node)`, `list_usb(node)`          | 100%   | 2 endpoint nuovi, no SSH |
| `app::hw::parse_pci_value`                       | 100%   | Strip `,options=...`, normalizza `01:00.0` → `0000:01:00.0` |
| `app::hw::scan_assignments(configs)`             | 100%   | Estrae `hostpciN` + `usbN` dai configs guest, sort deterministico |
| `app::hw::detect_pci_conflicts`                  | 100%   | DirectShared + IommuGroupSplit, no double-report quando il group ha solo un address |
| `app::hw::pci_inventory`                         | 100%   | Cross-link device + assignments + IOMMU siblings |
| `View::Hardware { node }` + reducer              | 100%   | Stale-fetch protection (data per nodo X non sovrascrive view Y) |
| TUI: header + PCI table + conflicts pane         | 100%   | Color cues: assigned=verde, GPU=accent, conflicts=red/yellow |
| CLI `proxxx hw pci/usb --node N`                 | 100%   | JSON output |
| CLI `proxxx hw conflicts --node N`               | 100%   | Exit 1 se conflicts found, JSON struct con kind=direct_shared/iommu_group_split |
| Keybind `W` da NodeList                          | 100%   | + palette `:hw <node>` / `:hardware <node>` / `:passthrough <node>` |
| Test coverage                                    | 100%   | 12 unit (parse/scan/conflicts/inventory) + 3 wiremock + 3 reducer |

**Cosa rileva il conflict detector:**
1. **DirectShared**: stesso indirizzo PCI assegnato a 2+ guest. Il primo a partire vince, gli altri falliscono con "device busy".
2. **IommuGroupSplit**: device A (es. GPU) e device B (es. audio della stessa scheda) sono nello stesso IOMMU group ma assegnati a guest diversi. Il kernel rifiuta passthrough — entrambi i guest fail.

**Tagli onesti vs. spec originale:**
- ❌ **VFIO binding writes** (modprobe + initramfs + reboot): respinto. Richiede SSH (Pillar 0 c'è) MA anche orchestrazione reboot — separate phase.
- ❌ **NVIDIA MIG / AMD MxGPU partitioning**: ogni vendor è un'integrazione a sé (`nvidia-smi mig` per NVIDIA), 500+ LOC ciascuna. Future iteration, separate features.
- ❌ **GPU pool cluster-wide scheduler**: race conditions + locking distribuito non triviale. Respinto come scope creep.
- ❌ **Assignment writes** dal proxxx: read-only diagnostic in MVP. `qm set --hostpciN` mutations vengono in iter successiva con HITL gate (come #6 disk move).
- ⚠️ **VFIO current driver** (`/sys/bus/pci/devices/{addr}/driver` symlink): richiede SSH. Future, una `exec` call per nodo per leggere tutti i bindings.
- ⚠️ **Detailed lspci `-nnv` tree** (subdevices, capabilities): richiede SSH. Future iteration.
- ✅ **IOMMU group inspection**: gratis dall'API Proxmox — `iommugroup` field in `/hardware/pci`. Niente SSH per il base case.

### Feature 5 — HA + replication console

| Componente                                      | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Types: `HaGroup`, `HaResource`, `HaManagerStatus`, `ClusterStatusEntry`, `ReplicationJob`, `ReplicationStatus`, `ReplicationHealth` | 100% | Tutti con `Serialize`/`Deserialize`, parsano i quirks Proxmox (`bool` da `0`/`1` int) |
| `HaGroup::parse_priority_list()`                | 100%   | Parser Proxmox priority `"pve1:2,pve2:1,pve3"` → sort desc per priority+name |
| `HaResource::vmid()` + `kind()`                 | 100%   | Estrae da SID `"vm:100"` / `"ct:200"`, malformed → None |
| `ReplicationStatus::rpo_secs(now)` + `health()` | 100%   | RPO = lag in seconds; health: Healthy/Stale/Failing con threshold 2× period |
| API: `list_ha_groups/resources/status`, `cluster_status`, `list_replication_jobs/status` | 100% | 6 endpoint nuovi, tutti GET, no SSH |
| `app::ha::preview_failover` (read-only inspector) | 100% | Walk priority list, skip offline nodes, restricted vs unrestricted fallback |
| `app::ha::summarise_replication_health()`       | 100%   | Worst-of rollup: Failing > Stale > Healthy |
| `View::HaConsole` + reducer (Open + DataLoaded) | 100%   | Multi-fetch parallelo via `tokio::join!` + `JoinSet` per per-node status |
| TUI 3-pane view (cluster header + HA + repl)    | 100%   | Quorum badge, master+mode, online nodes con local-marker, "if-fails →" preview per ogni resource |
| Replication health colour cues                  | 100%   | Green/yellow/red + summary badge nel titolo |
| CLI `proxxx ha groups/resources/status`         | 100%   | JSON output |
| CLI `proxxx ha preview --node N`                | 100%   | Failover preview deterministico per ogni HA resource |
| CLI `proxxx replication jobs/status --node N`   | 100%   | Read-only inspect |
| Test coverage                                   | 100%   | 6 wiremock + 21 unit (10 types + 11 ha inspector) + 3 reducer = 30 nuovi |

**Tagli onesti vs. spec originale:**
- ❌ **Editor HA group**: nessuna mutazione tramite TUI/CLI. La direttiva force-enqueue + HITL del Bug review dice che modifiche HA distruttive (cambio priorità in production) devono passare via Operation Queue, ma per ora si fanno via web UI. Future iteration.
- ❌ **Failover simulator full** (re-implementazione `pve-ha-manager` CRM scoring): respinto per debt tecnico permanente. Sostituito con **preview deterministico** "highest-priority remaining online" che è sufficiente per il 95% dei casi.
- ❌ **Fence audit (watchdog/IPMI)**: richiede SSH per `lsmod | grep softdog` o `/proc/modules`. Future iteration con Pillar 0.
- ❌ **Quorum visualizer con corosync latency**: richiede `corosync-cmapctl` via SSH. Future iteration.
- ❌ **Trigger manuale re-sync / swap source-target**: read-only MVP. Mutating ops post-MVP.
- ❌ **RPO trend storico per guest** (grafico): SQLite cache esiste, ma display in widget rinviato.
- ⚠️ **Period default 15 min** per detectare stale: hardcoded — future enhancement parserà il `schedule` field per-job.
- ⚠️ **`*` (local node) marker**: TUI mostra dove proxxx è connesso, fonte = `cluster_status` field `local`.

### Feature 3 — PBS browse + restore

| Componente                                      | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| `[profiles.X.pbs]` config block                 | 100%   | url, user, token_id, token_secret(_file), verify_tls, rate_limit |
| `PbsConfig::resolve_token_secret`               | 100%   | CLI flag → `PROXXX_PBS_TOKEN_SECRET` env → 0600 file → keychain |
| Types: `DatastoreInfo`, `SnapshotInfo`, `ArchiveInfo` | 100% | + `is_pxar()`, `is_encrypted()`, `snapshot_ref()` PBS canonical form |
| `format_pbs_timestamp(epoch)`                   | 100%   | ISO-8601 UTC senza chrono dep — algoritmo civil-from-days (Hinnant 2012) |
| `PbsClient` + `PbsGateway` trait                | 100%   | `PBSAPIToken=user!tokenid=secret` auth header, governor rate-limit |
| `list_datastores`, `list_snapshots`, `list_snapshot_files` | 100% | Filtri opzionali via query string, urlencode minimale handwritten |
| `pbs::restore::run_restore` (shell-out)         | 100%   | tokio Command + line-by-line stdout/stderr streaming, last-50-lines tail |
| `detect_client_binary()`                        | 100%   | Cerca `proxmox-backup-client` su PATH, errore chiaro se assente |
| `build_repository(cfg, store)`                  | 100%   | Format `user@realm!tokenid@host:store` per `PBS_REPOSITORY` env |
| `validate_target(path)`                         | 100%   | Parent-exists check, no-clobber su file esistenti |
| CLI `proxxx pbs datastores`                     | 100%   | JSON list |
| CLI `proxxx pbs snapshots --store S [--backup-type T --backup-id I]` | 100% | Filtri repeatable |
| CLI `proxxx pbs files --store S --type T --backup-id I --time U` | 100% | Lista archive (.pxar.didx / .img.fidx / .blob) |
| CLI `proxxx pbs restore --store S --snapshot R --archive A --target T --yes` | 100% | `--yes` obbligatorio; pre-flight check `proxmox-backup-client` |
| Test coverage                                   | 100%   | 5 wiremock (browse + filters + auth header + 5xx) + 14 unit (timestamp, host parse, repo build, validate, push_capped, urlencode, archive kind) |

**Tagli onesti vs. spec originale:**
- ❌ **FUSE mount in TUI**: macFUSE blocked su Apple Silicon, Windows necessita WinFsp, Linux richiede setuid. Cross-platform fragility = ship o non ship. Scelto: shell-out a binary upstream invece.
- ❌ **Single-file extraction**: pxar non è streamed file-by-file dal client; serve mount FUSE per cherry-pick. Workaround documentato: full archive restore + estrazione locale via `cp` / `tar` / `pxar` CLI.
- ❌ **Cross-snapshot search ("find /etc/nginx in vm-100 last 7d")**: richiederebbe iterare i `.didx` di N snapshot = GB di metadata scaricati. Future quando avremo cataloghi indicizzati locali.
- ❌ **Re-iniezione live nel guest via qemu-guest-agent**: `guest-file-write` API single-call, no permission/ownership preservation, no atomic dir rebuild. Pericoloso per uso reale.
- ❌ **Encrypted backup master-key UX**: MVP assume backup non-encrypted. PBS encrypted needs master key flow — tuti i path crypt-mode=encrypt sono visibili ma restore fallirebbe.
- ⚠️ **Linux-only restore**: il binary `proxmox-backup-client` non è packaged upstream per macOS/Windows. CLI di proxxx detecta missing binary e mostra istruzione di install. Browse REST funziona su tutte le piattaforme.
- ⚠️ **No TUI view**: per MVP solo CLI. TUI browser di snapshot post-MVP (richiede multi-pane gerarchico simile a snaptree).

### Feature 2 — ISO / cloud-image lifecycle

| Componente                                      | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| Curated library (`const LIBRARY`)               | 100%   | 6 entries: Ubuntu 22/24, Debian 12, Fedora 39, Alpine 3.19, Rocky 9 |
| Library invariants enforced via tests           | 100%   | id-uniqueness, https-only, sha256 hex 64 char, content in known set |
| API `download_to_storage(...)`                  | 100%   | POST `/download-url` (PVE 7+), passes `checksum` + `checksum-algorithm=sha256` when provided |
| API `list_storage_content(...)`                 | 100%   | GET `/content` con `?content=<filter>`; type `StorageContent::filename()` |
| `Action::OpenIsoLibrary` + `View::IsoLibrary`   | 100%   | Comando palette: `:iso`, `:images`, `:library` |
| `Action::DownloadIso` + custom URL variant      | 100%   | Library entry resolution, fallback node = first online |
| TUI view (list + side panel + sha256 display)   | 100%   | Enter su entry → download a primo storage |
| CLI `proxxx iso list`                           | 100%   | JSON con tutti i metadata della library |
| CLI `proxxx iso download --id ID --node N --storage S` | 100% | Pin sha256 dalla library |
| CLI `proxxx iso download --url U --filename F --content C` | 100% | Custom URL, sha256 opzionale |
| Test coverage                                   | 100%   | 6 library invariants + 6 reducer + 3 wiremock = 15 nuovi |

**Tagli onesti vs. spec originale:**
- ❌ **GPG signature verification**: Proxmox `download-url` verifica già SHA-256 server-side, sufficiente contro tampering URL una volta che la sha256 è pinnata nel `const`. GPG richiederebbe gestione keyring per-distro.
- ❌ **Resume su interruzione**: download è server-side atomico (Proxmox completa o fallisce). Niente streaming via proxxx.
- ❌ **One-shot "create template"** (download → cloudinit init → convert): 3 step separati, l'utente li chiama in sequenza. Richiederebbe un orchestrator dedicato.
- ❌ **LXC templates (`pveam`)**: endpoint diverso, lifecycle diverso. Non incluso, vedi backlog.
- ❌ **Library YAML community-maintainable** in repo separato: scelto `const` embedded — supply-chain controllato.
- ⚠️ **NixOS / FreeBSD**: omessi dall'MVP — meno richiesta tipica, aggiungibili in append-only.
- ⚠️ **Storage picker UI**: TUI usa il primo storage in elenco. CLI è esplicito (`--storage` obbligatorio). Picker modal post-MVP.
- ✅ **SHA-256 pinning**: BLOCKER 1 chiuso. Le 6 entry hanno `sha256: None`; il reducer/CLI rifiutano il download da curated library finché un'entry non è pinned al manifest upstream. Vedi sezione "Architectural blockers" sopra.

### Feature 6 — Live disk operations (move + resize)

| Componente                                      | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| API `move_disk(node, vmid, type, …)`            | 100%   | Type-aware: QEMU `/move_disk` (`disk`), LXC `/move_volume` (`volume`) |
| API `resize_disk(node, vmid, type, disk, size)` | 100%   | PUT method (Proxmox inconsistency); accetta `+10G` o `100G`; `null` data → `"synchronous"` sentinel |
| `Action::MoveDisk` + `Action::ResizeDisk`       | 100%   | **Force-enqueue invariant**: il reducer NON emette mai SideEffect direttamente |
| `QueuedOp` description type-aware               | 100%   | Mostra delete/keep source, target storage, dimensioni |
| Queue execution dispatch                        | 100%   | Dispatcha API call con dispatch type-aware del bug #1 |
| HITL gate `is_destructive` esteso               | 100%   | `move_disk` / `resize_disk` triggrano HITL con secure_mode o policy match |
| CLI `proxxx disk move/resize --yes`             | 100%   | `--yes` obbligatorio, exit 1 senza |
| Test coverage                                   | 100%   | 4 wiremock (positive + negative LXC→qemu) + 3 reducer enqueue |

**Garanzie architetturali (per direttiva utente):**
1. **Operation Queue obbligatoria via TUI**: `Action::MoveDisk`/`Action::ResizeDisk` non producono `SideEffect`, vengono solo enqueued. L'unica via per eseguire è premere `C` sulla queue view → conferma esplicita.
2. **HITL by default**: `move_disk` e `resize_disk` sono nella lista `is_destructive`, quindi gateate da policy TOML o `--secure` flag.
3. **Type-safe**: la routing diversa QEMU/LXC è dietro un `match` esaustivo — nuovi GuestType rompono il build.
4. **CLI bypassa queue**: `proxxx disk` chiama API direttamente (la queue è una concezione TUI). `--yes` obbligatorio per non sbagliare in pipeline.

**Limiti dichiarati:**
- Format conversion (raw↔qcow2↔vmdk) NON inclusa — richiederebbe `qemu-img` via SSH; rinviato.
- Encryption at rest (LUKS/qcow2-native + KMS) RINVIATA post-v1.0 (vedi review draconiano #6).
- Auto-extend filesystem nel guest via agent NON implementato — utente deve estendere manualmente. Future iteration.
- Trim/discard trigger non implementato — fuori scope MVP.

### Feature 7 — Snapshot tree branching visualizer

| Componente                                      | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| API `list_snapshots(node, vmid, type)`          | 100%   | Type-aware dispatch (qemu/lxc), 2 wiremock test |
| Type `Snapshot` + `is_current()` helper         | 100%   | Modella anche orphans (parent inesistente) |
| `app::snaptree::assemble()` — flat → tree       | 100%   | Supporta branching, sorting deterministico, current-last |
| `diff_between(from, to)` con common ancestor    | 100%   | Forward/reverse path, time delta |
| `View::SnapshotTree { vmid }` + reducer         | 100%   | OpenSnapshotTree, SnapshotsLoaded |
| `views::snaptree::draw` con tree rendering      | 100%   | `├─`/`└─`/`│` connectors, side panel diff |
| Side panel: rollback impact preview             | 100%   | Mostra "discards on rollback" + time delta |
| Keybind `Z` da GuestList                        | 100%   | + palette `:tree <vmid>`/`:snaps <vmid>`/`:snapshots <vmid>` |
| Test coverage                                   | 100%   | 8 unit tree + 4 reducer + 2 wiremock = 14 nuovi |

**Limiti dichiarati (MVP):**
- Read-only: create/delete via `proxxx snapshot create/delete` (CLI già esistente) o tasti dalla GuestList. La view non ha entry point distruttivi.
- Storage cost per snapshot non incluso (richiederebbe `zfs list` / `qemu-img info` via SSH — rinviato a v0.4 quando integriamo).
- Cleanup wizard rinviato — la base "tree + diff" è quella che serve per visualizzare oggi.

### Feature 9 — Patching & rolling-reboot orchestrator

| Componente                                      | Status | Note |
| :---------------------------------------------- | :----- | :--- |
| API: `apt_update_refresh`, `apt_list_upgradable`| 100%   | [src/api/client.rs](src/api/client.rs) |
| API: `node_status_detail`                       | 100%   | uptime, kversion, pveversion |
| `AptUpgradable::requires_reboot()` heuristic    | 100%   | kernel/microcode/libc/systemd |
| `Orchestrator::plan(only_nodes)` (pure API)     | 100%   | refresh + inventory + classify |
| `Orchestrator::apply` state machine             | 100%   | Pending→Refresh→Inventory→Upgrade→Reboot→WaitReboot→Done/Failed |
| SSH `apt-get -y dist-upgrade` con confold       | 100%   | via Pillar 0 |
| `systemctl reboot --no-block`                   | 100%   | accetta connection-drop come success |
| Post-reboot wait (offline→online + kver check)  | 100%   | timeout 600s default |
| Abort safe (primo fail → stop, resto Pending)   | 100%   | rispetta invariante "mai due nodi mid-upgrade" |
| `RebootPolicy` Auto/Always/Never                | 100%   | CLI flag + serde |
| Dry-run mode (zero SSH)                         | 100%   | enforced + tested |
| CLI `proxxx patch plan/apply`                   | 100%   | exit code 1 se any node Failed |
| Test coverage                                   | 100%   | 8 test (classify, skip, abort, dry-run, heuristic, policy) |

**Limiti dichiarati:**
- `max_concurrent` accetta valori >1 ma MVP è seriale (warning a runtime).
- Nessun ordering HA-priority: alfabetico (deterministico).
- Nessun drain integration automatico (esiste a parte, evacuation wizard).
- TUI integration assente — CLI è canale primario.

---

## Tavola alta — backlog (in arrivo, una alla volta)

Ordine: dal meno doloroso al più strategico. Ogni riga sotto 0% finché non scritta + testata.

| # | Feature                                       | Status | Versione | Note |
| -:| :-------------------------------------------- | :----- | :------- | :--- |
| 7 | Snapshot tree branching visualizer            | ✅ 100%| v0.3     | shipped — vedi sezione dedicata sopra |
| 6 | Live disk move/resize (no encryption)         | ✅ 100%| v0.3     | shipped — force-enqueue + HITL by default |
| 2 | ISO/cloud-image lifecycle                     | ✅ 100%| v0.3     | shipped — vedi sezione dedicata sopra |
| 5 | HA + replication console                      | ✅ 100%| v0.4-0.5 | shipped — read-only inspector, preview deterministico (no full simulator) |
| 3 | PBS browse + full archive restore             | ✅ 100%| v0.4     | shipped — REST browse cross-platform + restore Linux-only |
| 4 | Hardware passthrough (PCI/USB/GPU)            | ✅ 100%| v0.4     | shipped — read-only inventory + conflict detector, no SSH (API ha iommugroup) |
| 8 | Alerting & notification routing               | ✅ 100%| v0.4     | shipped — closed enum 3 predicati, 3 canali, dedup |
| 10| ACL/token/MFA console                         | ✅ 100%| v0.4-0.5 | shipped — Opzione A (shell-out `pveum`), TOTP/WebAuthn rinviati a iter |
| 1b| Serial console via termproxy                  | ✅ 100%| v0.4     | shipped — CLI + WS + verify_tls support, TUI rinviato |
| 1c| SPICE/noVNC handoff                           | ✅ 100%| v0.3     | shipped — `.vv` + cross-platform launcher, no opener crate |

**Tagliati dal MVP (rinviati post v1.0):**
- #6 encryption at rest + KMS handoff
- #8 oncall schedule (PagerDuty-in-miniatura)
- #10 effective-permission debugger native (sostituito da shell-out ground-truth)
- #10 WebAuthn enrollment dal TUI (fisicamente impossibile — handoff browser)

---

## Architectural blockers (v1.0.0 review)

Tre blocker dichiarati nel review pre-v1.0 sono stati chiusi.

### BLOCKER 1 — Vettore supply-chain ISO library

**Problema:** le 6 entry curate avevano `sha256: "0000…0000"` come placeholder. Un utente in produzione avrebbe scaricato ISO con verifica server-side bypassata di fatto, contraddicendo l'intera policy HITL+audit.

**Fix:**
- `IsoEntry::sha256` cambiato da `&'static str` a `Option<&'static str>`. `None` = "non ancora pinnato a manifest upstream".
- Tutte le 6 entry sono ora `None`. Commento per ognuna indica l'URL del manifest da consultare a release-time.
- Reducer `Action::DownloadIso` e CLI `proxxx iso download --id` rifiutano con errore esplicito ("release-time TODO") quando `sha256.is_none()`.
- TUI iso_library view mostra `"NOT PINNED — download refused (release-time TODO)"` in giallo bold invece dei placeholder zeros.
- CLI `proxxx iso download --url <X> --sha256 <Y>` resta funzionante — l'utente fornisce e si assume responsabilità.
- Test invariante `sha256_when_pinned_is_hex_64_lowercase_and_not_zero_placeholder`: se mai una entry venisse re-pinnata con tutti zeri, il test fallirebbe.
- Reducer test `test_download_iso_refuses_unpinned_library_entry` + `test_download_iso_curated_refuses_when_unpinned_regardless_of_node`: il refuse-gate fires PRIMA del fallback node-resolution.

### BLOCKER 2 — Gestione segnali FFI per PBS restore

**Problema:** `proxmox-backup-client restore` può girare 40+ minuti. Se proxxx termina (Ctrl+C, panic, kill esterno) il child resta orphan zombie a consumare bandwidth + I/O.

**Fix in `pbs::restore::run_restore`:**
- `Command::kill_on_drop(true)`: sicurezza profonda — se il `Child` handle viene droppato per panic/OOM/anything, tokio invia SIGKILL automaticamente.
- `tokio::signal::ctrl_c()` integrato nel select loop con `biased` priority sopra le letture stdout/stderr. Su SIGINT: log "killing proxmox-backup-client" → `child.kill().await` → bail con messaggio "cancelled by Ctrl+C".
- Test smoke `kill_on_drop_terminates_child_when_handle_dropped` (Unix-only): spawna `/bin/sleep 60` con kill_on_drop, droppa il handle, dopo 200ms verifica via `kill -0` che il processo NON sia più vivo. **Verificato: `kill: <pid>: No such process`** = child correttamente terminato.

### BLOCKER 3 — Flight recorder (panic hook)

**Problema:** in caso di panic Rust, il TUI lasciava il terminale in raw mode + alternate screen. La directive di v1.0.0 richiedeva ripristino aerospace-grade + audit log capture. Inoltre l'hook era TUI-only, mode CLI panicava in modo distruttivo.

**Fix:**
- Nuovo modulo `src/util/panic_hook.rs` con `install()` idempotent (atomic guard, safe a chiamare 2+ volte).
- Hook ordering deliberato:
  1. **`tracing::error!` PRIMA**: payload + location finiscono nell'audit log (`tracing-appender` non-blocking writer flusha sul guard drop in `main`).
  2. `crossterm::terminal::disable_raw_mode()` (best-effort).
  3. `LeaveAlternateScreen` + `cursor::Show`.
  4. Banner stderr `💀 proxxx panicked at <file:line>` + payload + audit log pointer.
  5. Original hook chained per la stack trace colorata default.
- `main.rs` chiama `util::panic_hook::install()` PRIMA del runtime tokio → coverage automatica per TUI e CLI mode.
- TUI mod.rs: rimosso l'hook locale duplicato (commento di transizione).
- Subcommand `proxxx dev-panic [--message <X>]` per smoke test manuale.
- Integration test `tests/panic_hook_test.rs::dev_panic_triggers_flight_recorder_hook`: spawna `proxxx dev-panic --message smoke-payload-xyz`, verifica:
  - exit non-zero (panic propagato)
  - stderr contiene `"proxxx panicked at"` (firma flight recorder)
  - stderr contiene il payload
  - stderr contiene `"audit log:"` (pointer al file)
- Unit test `panic_message_extracts_string_payload` + `install_is_idempotent`.

**Verificato live:**
```
$ proxxx dev-panic --message smoke-payload-xyz
thread 'main' panicked at src/cli/mod.rs:NNN:NN:
[dev-panic] smoke-payload-xyz

💀 proxxx panicked at src/cli/mod.rs:NNN
   payload: [dev-panic] smoke-payload-xyz
   audit log: ~/.local/share/proxxx (proxxx.log)
```

---

## Bug noti / debiti tecnici

Audit condotto contro il codice attuale. Ogni bug ha una traccia di repro.

| #  | Bug                                                        | Severità   | Status      | Note |
| --:| :--------------------------------------------------------- | :--------- | :---------- | :--- |
| 1  | Tutte le ops LXC chiamano `/qemu/...` invece di `/lxc/...` | **alta**   | ✅ FIXED    | Trait write-methods ora prendono `GuestType`; 9 wiremock test |
| 2  | `stop_guest(force=false)` chiama `/status/stop` (hard)     | **alta**   | ✅ FIXED    | Aggiunto `shutdown_guest`; force=false→graceful, test wiremock |
| 3  | `Command::Snapshot` ritorna `"not yet implemented"`        | **media**  | ✅ FIXED    | `execute_snapshot` con dispatch type-aware |
| 4  | CLI `proxxx search <query>` non esiste                     | **bassa**  | ✅ FIXED    | nuovo subcommand `proxxx search <query> [--limit N]` con JSON multi-kind |
| 5  | CLI `proxxx get nodes/guests` non esiste (è `ls`)          | **bassa**  | ✅ FIXED    | clap `#[command(alias = "get")]` su Ls — entrambi i nomi accettati |
| 6  | CLI `proxxx delete <vmid>` non esiste                      | **bassa**  | ✅ FIXED    | top-level subcommand con `--yes` guard |
| 7  | `--secure` flag parsato ma non wired a `state.secure_mode` | **media**  | ✅ FIXED    | `state.secure_mode = secure` in `tui::run` (the wire); reviewer P0 then caught that the gate itself was simulated — `check_hitl` slept 3 s and auto-approved without ever calling Telegram. Replaced with `HitlCoordinator` + real `request_approval` + shared `getUpdates` poller; deny-on-timeout (120 s) and deny-when-unconfigured. |
| 8  | "Multi-pane SSH/qm broadcast" usa API agent/exec           | **bassa**  | ✅ FIXED    | etichetta corretta in features.md (riga "Parallel guest-agent broadcast") |
| 9  | `Action::MigrateGuest` reducer non emette SideEffect       | **media**  | ✅ FIXED    | reducer ora emette `SideEffect::MigrateGuest`; 2 test |

**Tutti e 9 i bug fixati.** Il "fallacia dei bug cosmetici" della code review è stata accolta — un disallineamento doc/impl è di per sé un bug di contratto.

---

## Consolidation phase (post-Tavola-Alta)

Cleanup mechanico + documentation pre-tag. Niente feature change.

| Quality gate                           | Result |
| :------------------------------------- | :----- |
| `cargo test`                           | **295 unique passing** + 4 E2E ignored (`#[ignore]`-gated, opt-in via `PROXXX_E2E_ENABLE=1`); 10 test binaries (lib + main + 8 integration), 0 fail |
| `cargo clippy --all-targets`           | **0 errors** at deny tier (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing`) |
| `cargo build` warnings                 | **0** — ratatui `Table::row_highlight_style` migration applied; `SshHandler` made `pub(crate)` to match `SshSession`'s removed `handle()` accessor |
| Pedantic / nursery warnings            | ~530 stylistic (`unreadable_literal`, `module_name_repetitions`, `cast_precision_loss u64→f64`) — informational, not deny |
| `cargo fmt --check`                    | clean — re-verified after every audit wave |
| Production code obeys deny lints       | yes — `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` all denied; tests relaxed via `cfg_attr(test, allow(...))` |

**Production unwrap/expect/panic eliminated (12 sites):**
- `NonZeroU32` rate-limiter constants → `const TEN: NonZeroU32 = match { Some(n) => n, None => unreachable!() }`
- `SystemTime::now().duration_since(UNIX_EPOCH).unwrap()` → `.map().unwrap_or(0)` (queue id, timeline display, HITL txn id)
- `available_nodes.iter().max_by_key().unwrap()` → `if let Some(target) = ...`
- `child.stdout.take().expect("piped stdout")` → `.ok_or_else(|| anyhow!("internal bug"))`
- `let guest = guest.unwrap()` after `is_none` → `let Some(guest) = guest else { ... }`
- `policy_match.unwrap().channel.clone()` → restructured `if-let` with documented invariant fallback
- `serde_json::to_string_pretty(&err).unwrap()` in main.rs error path → `match` with hand-written JSON fallback
- `panic!("[dev-panic] ...")` (BLOCKER 3 smoke) → opted-out via `#[allow(clippy::panic)]` with comment

**Architectural cleanup:**
- `main.rs` no longer re-declares `mod api; mod app; …` — consumes the lib via `use proxxx::{cli, tui, util};`. Eliminated duplicate compilation (lib + bin) and the ~50 spurious "dead code" warnings it caused.
- Tests inside `src/**/*.rs` `#[cfg(test)] mod tests` blocks: lib + bin both relax via root-level `#![cfg_attr(test, allow(...))]`.
- Integration tests in `tests/*.rs`: each gets `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]` at file head (separate crates from the lib).

**Documentation shipped:**
- [`README.md`](README.md) — quickstart TUI/CLI, build, config, architecture diagram, doc index, honest non-goals.
- [`CHANGELOG.md`](CHANGELOG.md) — chronological per Tier 1/2/3 + Tavola Alta + bug + blockers + verifiche architetturali + code-quality + known limits.
- [`docs/config.example.toml`](docs/config.example.toml) — annotated template for every section (`[telegram]`, `[ssh]`, `[ssh.guests]`, `[pbs]`, `[[alerts]]`, `[[policies]]`).
- [`docs/cluster_smoke.md`](docs/cluster_smoke.md) — 16-section runbook against `pve-test-1/2/3` (test_env.md). Each shipped feature has explicit `proxxx <cmd>` invocations + ✅ pass criteria. Includes live verify of all 9 bug fixes + 3 architectural blockers + flight-recorder smoke.

---

## Stima onesta

- **Test totali:** 295 unici (164 lib + 50 api wiremock + 58 app + 8 hitl + 9 mcp + 5 pbs wiremock + 1 panic_hook integration) + 4 E2E ignored (1 alpha + 3 beta — opt-in via `PROXXX_E2E_ENABLE=1` against a real cluster). Verifica: `cargo test` → 0 fail.
- **LOC di feature code:** ~14500 (escluso target/, doc/, tests/)
- **Build status:** clean — `cargo build --release` 0 warnings, `cargo clippy --all-targets` 0 errors at deny tier, `cargo fmt --check` clean
- **Bug fixati:** 9 / 9 — tutti, anche i "cosmetici" (la code review l'aveva esplicitamente respinto)
- **Verifiche architetturali (review code):**
  - ACPI polling: per-poll `DataMsg::GuestStatusPolled` event-driven, render thread mai bloccato (verificato wiremock)
  - Snapshot tree: cycle detection (self/2-node/3-node), 1000-deep iterative build (no stack overflow), orphans surface in tree
  - Operation Queue persistence: round-trip SQLite via `PersistedQueueEntry`, dirty-flag flush ogni tick TUI
- **Architectural blockers v1.0.0** (3/3 chiusi):
  - BLOCKER 1: ISO supply-chain — `sha256: Option`, refuse-on-None gate, 0-placeholder invariant test
  - BLOCKER 2: PBS restore signal — `kill_on_drop(true)` + `tokio::signal::ctrl_c` + smoke test verificato (`kill -0` returns ESRCH)
  - BLOCKER 3: flight recorder — `util::panic_hook::install` idempotent, dev-panic subcommand + integration test che valida exit-non-zero + stderr signatures
- **Feature Tavola Alta shippate:** **TUTTE** — 1a (SSH guest session), 1b (serial termproxy WS), 1c (SPICE/noVNC handoff), 2 (ISO lifecycle), 3 (PBS browse + restore), 4 (HW passthrough inspector), 5 (HA + replication console), 6 (disk move/resize), 7 (snapshot tree), 8 (alerting), 9 (patching), 10 (ACL/token/MFA console)
- **Pillar 0 (SSH layer):** shipped — abilita 1a/9/10

**Pre-tag checklist (release-time TODO):**
- [ ] Pin SHA-256 reali per le 6 entry della curated ISO library (`src/app/iso_library.rs`) contro upstream `SHA256SUMS`
- [ ] Esegui `docs/cluster_smoke.md` end-to-end contro `pve-cluster` reale
- [ ] `cargo build --release` + binary size check (target <15 MB stripped)
- [ ] Tag v0.4.0

Le feature non shippate nella tabella backlog non sono prossime; sono future onesta. Quando spedite, sostituiranno la riga "0%" con i suoi componenti dettagliati come fatto per #9 e 1a.
