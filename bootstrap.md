🔥 proxxx — The Ultimate Proxmox TUI
Mission: Build the fastest, most elegant, most powerful Proxmox management CLI on the planet.
Stack: Rust + ratatui + tokio + reqwest
Philosophy: Minimal code, maximum impact. Every line earns its place.

1. Competitive Landscape Analysis
1.1 Existing Solutions
Tool	Lang	⭐ Stars	TUI	CLI	Multi-Cluster	Strengths	Weaknesses
pvetui	Go	660	✅	✅	✅ (Groups)	Feature-rich, config wizard	Shells out to external SSH for console, no integrated PTY
lws (yours)	Python	70	❌	✅	✅ (Regions)	AWS-like UX, Docker integration, REST API, broad scope	Python (slow startup, deps), no TUI, no real-time dashboards
proxmoxer	Python	~1.5k	❌	❌	❌	Clean API wrapper, mature	Library only, not a tool
Proxmon	Python	~200	✅	❌	❌	Rich/Textual TUI, pretty	Python (slow), read-only monitoring, no management
Proxmox PDM	Rust	Official	✅ (Web)	❌	✅	Official Proxmox tool	Web-only, not a terminal tool, early/limited
1.2 Gap Analysis — Where EVERYONE Fails
Gap	Impact	proxxx Opportunity
No Rust TUI exists	Zero competition in the Rust+TUI Proxmox space	🏆 First mover, native speed, zero GC
Startup time	Python tools: 500ms+, Go tools: 50ms+	🚀 TTFR (Time To First Render) <500ms local, <2s remote
Async API	All tools do serial API calls	⚡ tokio + parallel API fan-out across nodes
Real-time streaming	Polling-based updates everywhere	📡 Intelligent async polling + ETag diffing (event stream fallback)
Keyboard-first UX	pvetui has vim keys but clunky modal UX	⌨️ Helix/Neovim-grade keybinding system
Scriptability	pvetui CLI is bolted-on, lws is CLI-only	🔗 TUI + CLI + pipe-friendly JSON output, unified
Security	Passwords in YAML, weak secret handling	🔒 OS keychain integration, memory-safe by default
Binary size	Go = 20MB+, Python = install chain	📦 <15MB stripped Rust binary (realistic with tokio+reqwest)
Plugin architecture	pvetui's is Go-specific, lws has none	🧩 WASM plugin system (future) or Lua scripting
HITL / Approvals	Nobody has this	🛡️ Telegram/Teams approval gates for destructive ops
2. Architecture: Surgical Minimal Design
proxxx/
├── Cargo.toml
├── src/
│   ├── main.rs              # Entry: CLI parser + TUI bootstrap
│   ├── app.rs                # App state machine (The Elm Architecture)
│   ├── api/
│   │   ├── mod.rs            # Proxmox API client trait
│   │   ├── client.rs         # reqwest-based async client
│   │   ├── auth.rs           # Token/password auth + refresh
│   │   └── types.rs          # API response types (serde)
│   ├── tui/
│   │   ├── mod.rs            # Terminal setup/teardown
│   │   ├── event.rs          # Crossterm event loop
│   │   ├── views/
│   │   │   ├── dashboard.rs  # Cluster overview dashboard
│   │   │   ├── nodes.rs      # Node list + detail
│   │   │   ├── guests.rs     # VM/LXC unified view
│   │   │   ├── tasks.rs      # Task log viewer
│   │   │   ├── storage.rs    # Storage pools
│   │   │   └── shell.rs      # Integrated SSH/exec
│   │   ├── widgets/
│   │   │   ├── sparkline.rs  # CPU/RAM sparklines
│   │   │   ├── gauge.rs      # Resource gauges
│   │   │   ├── table.rs      # Sortable/filterable tables
│   │   │   └── modal.rs      # Confirmation/input modals
│   │   └── theme.rs          # Color scheme engine
│   ├── hitl/
│   │   ├── mod.rs            # HITL gate trait + policy engine
│   │   ├── telegram.rs       # Telegram Bot API (sendMessage + getUpdates)
│   │   ├── teams.rs          # Teams webhook + approval endpoint
│   │   └── policy.rs         # Which ops require approval, by whom
│   ├── mcp/
│   │   ├── server.rs         # JSON-RPC 2.0 transport (stdio/tcp)
│   │   └── tools.rs          # DETERMINISTIC const tool definitions
│   ├── config/
│   │   ├── mod.rs            # Config loader (TOML)
│   │   └── profile.rs        # Multi-profile management
│   ├── cli/
│   │   └── mod.rs            # Non-interactive CLI commands
│   └── util/
│       ├── keyring.rs        # OS keychain integration
│       └── format.rs         # Human/JSON/table output formatters
├── tests/
│   ├── api_mock.rs           # Wiremock-based API tests
│   └── tui_snapshot.rs       # Insta snapshot tests for TUI
└── README.md
~30 files. That's it. Every file has a clear, single responsibility.

3. Feature Matrix — What We Ship
Phase 1: Foundation (Sprint 1 — "It Works, It's Beautiful")
Feature	Priority	Complexity	Notes
Proxmox API client (async, reqwest)	P0	Medium	Token + password auth, auto-refresh
Multi-profile config (TOML)	P0	Low	~/.config/proxxx/config.toml
Cluster dashboard view	P0	Medium	Nodes, CPU, RAM, uptime sparklines
Node list + detail view	P0	Medium	Status, resources, running guests
Guest list (VM + LXC unified)	P0	Medium	Sortable table, status indicators
Keyboard navigation (vim-style)	P0	Low	j/k/g/G/Enter/Esc/q/:/
CLI mode (proxxx ls nodes --json)	P0	Low	Pipe-friendly output
Color theme system	P1	Low	Terminal-adaptive, 256/truecolor
Deliverable: A single binary that connects to Proxmox, shows a gorgeous real-time dashboard, and lets you browse nodes/guests with vim keybindings.

Phase 2: Operations (Sprint 2 — "It Does Things")
Feature	Priority	Complexity	Notes
Start/stop/restart VMs & LXC	P0	Low	With confirmation modal
Live task log viewer	P0	Medium	Streaming with auto-scroll
Guest detail view (config, resources)	P0	Medium	Full config inspector
Fuzzy search (/ or Ctrl-F)	P0	Low	nucleo/skim-based fuzzy finder
HITL: Telegram approval gate	P0	Medium	Inline keyboard approve/deny, long-polling
HITL: Teams notification	P1	Low	Webhook card + Action.OpenURL to approve endpoint
HITL: Policy engine	P0	Low	TOML rules: which ops, which guests, who approves
MCP server (deterministic)	P0	Medium	Compile-time const tool schemas, zero dynamic registration
Storage pool viewer	P1	Low	Usage bars, type indicators
Snapshot management	P1	Medium	Create/delete/rollback
Console/shell integration	P1	Very High	External SSH handoff or WebSocket (requires Password auth)
Deliverable: Full CRUD operations on guests, live task monitoring, search across everything. MCP server exposes hardened, immutable tool surface to AI agents.

Phase 3: Power User (Sprint 3 — "It's Addictive")
Feature	Priority	Complexity	Notes
Multi-cluster / group mode	P0	Medium	Unified view across clusters
Bulk operations	P0	Medium	Select multiple guests, batch actions
Resource graphs (historical)	P1	Medium	RRDdata sparklines/charts
Migration wizard	P1	High	Live/offline migration with progress
Backup/restore management	P1	Medium	Schedule, status, download
Command palette (: mode)	P0	Medium	Helix-style command input
Configurable keybindings	P1	Low	TOML-based keymap override
Phase 4: Domination (Sprint 4 — "They Can't Compete")
Feature	Priority	Complexity	Notes
Firewall rule viewer/editor	P2	Medium	Cluster/node/guest level
Template marketplace browser	P2	Medium	Browse/download/create
Metrics export (Prometheus)	P2	Low	proxxx export --prometheus
Container exec + log streaming	P1	High	Real-time container logs
HITL: Telegram approval gate	P2	Medium	Inline keyboard approve/deny, long-polling
HITL: Policy engine	P2	Low	TOML rules: which ops, which guests, who approves
HITL: Audit log	P2	Low	Remote Syslog/journald (append-only enforcement)


4. Tech Stack — Surgical Precision
Layer	Crate	Why
TUI Framework	ratatui + crossterm	Industry standard, fast, well-maintained
Async Runtime	tokio	De facto for async Rust, WebSocket support
HTTP Client	reqwest	Mature, TLS, cookie jar for Proxmox sessions
Serialization	serde + serde_json	Zero-overhead JSON parsing
Config	toml + directories	XDG-compliant config paths
CLI Parser	clap (derive)	Type-safe CLI args, shell completions
Fuzzy Search	nucleo	Fastest fuzzy matcher in Rust (used by Helix)
Error Handling	anyhow + thiserror	Ergonomic errors for app + lib code
Logging	tracing	Structured, async-aware, zero-cost when off
Testing	insta + wiremock	Snapshot tests for TUI + API mock server
Keychain	keyring	Cross-platform OS secret storage
5. UX Design — Helix Meets htop
5.1 Layout
┌─ proxxx ─────────────────────────────────────────────────┐
│ ⚡ cluster: homelab  │ 3 nodes │ 12 guests │ 0 tasks     │
├──────────────────────┬───────────────────────────────────┤
│                      │                                   │
│  NODES               │  GUEST DETAIL: vm-100             │
│  ─────               │  ────────────────────             │
│  ● pve1   ██░░ 34%   │  Status:  🟢 running              │
│  ● pve2   ████ 78%   │  CPU:     2 cores ███░ 67%        │
│  ○ pve3   ░░░░ DOWN  │  RAM:     4096 MB ██░░ 45%        │
│                      │  Disk:    32 GB   █░░░ 12%        │
│  GUESTS              │  Uptime:  4d 12h 33m              │
│  ──────              │  Node:    pve1                    │
│  🟢 100 web-server   │  Tags:    prod, web               │
│  🟢 101 db-primary   │                                   │
│  🟡 102 cache-node   │  ┌─ CPU History ──────────────┐   │
│  🔴 103 dev-sandbox  │  │ ▁▂▃▅▇█▇▅▃▂▁▂▃▅▇█▇▅▃▂▁▂▃ │   │
│  🟢 200 k8s-master   │  └──────────────────────────────┘  │
│  🟢 201 k8s-worker1  │                                   │
│                      │  [s]tart [S]top [r]estart          │
│                      │  [c]onsole [m]igrate [snap]shot    │
├──────────────────────┴───────────────────────────────────┤
│ : command mode │ / search │ ? help │ q quit │ ↕ navigate │
└──────────────────────────────────────────────────────────┘
5.2 Keybinding Philosophy
NAVIGATION                    ACTIONS                    META
─────────                     ───────                    ────
j/k     = up/down             Enter = select/expand      q     = quit/back
h/l     = collapse/expand     s     = start guest        :     = command mode
g/G     = top/bottom          S     = stop guest         /     = fuzzy search
Tab     = switch pane         r     = restart             ?     = help overlay
1-5     = switch view         d     = delete (confirm)    R     = force refresh
Space   = toggle select       c     = console/shell       P     = switch profile
Design Principle: If you know vim or Helix, you already know proxxx.

6. Differentiators vs Competition
vs pvetui (Go, 660⭐)
Dimension	pvetui	proxxx
Language	Go (GC, 20MB binary)	Rust (zero-cost, <15MB)
Startup TTFR	~50ms	<500ms
API calls	Sequential	Parallel async fan-out with Keep-Alive
Search	Basic filter	nucleo fuzzy (instant)
Config	YAML + SOPS	TOML + OS keychain
Plugin model	Go-only	WASM (language-agnostic)
CLI mode	Bolted-on subcommands	First-class, pipe-friendly
HITL approvals	❌ None	✅ Telegram + Teams + extensible
Code quality	1150 commits, growing	Minimal, auditable
vs lws (Python, 70⭐ — yours)
Dimension	lws	proxxx
Language	Python (slow, deps)	Rust (instant, zero deps)
Interface	CLI-only	TUI + CLI dual-mode
Real-time	Polling via SSH	Async API + WebSocket
Docker mgmt	✅ Built-in	Phase 4 (containers first)
API server	✅ Flask/Swagger	Not needed (TUI IS the UI)
Distribution	pip install + config	Single binary, curl | sh
vs Proxmon (Python, ~200⭐)
Dimension	Proxmon	proxxx
Mode	Read-only monitoring	Full management
Framework	Python Textual	Rust ratatui
Performance	Slow render on large clusters	O(1) render with virtual scrolling
7. Iterative Development Strategy (Realistic)
Weekly Milestones (Est. 30-45 Days Total MVP)

Week 1: API client + auth + reconnection (2h ticket refresh) + error mapping + TLS config
Week 2: TUI shell (event loop, layout, theme, navigation) + Dashboard/Node/Guest views + Rate Limiting
Week 3: Guest CRUD operations + Live Task Log polling + Fuzzy search/Command palette
Week 4: Multi-profile + Groups (Aggregate mode with prefix `homelab:100` and degraded state handling)
Week 5: MCP server stdio + Snapshot Management
Week 6: HITL Telegram gateway + Syslog Auditing

Quality Gates Per PR:
cargo clippy -- -D warnings — Zero warnings, zero exceptions
cargo test — All unit and wiremock integration tests pass
cargo fmt --check — Consistent formatting

Test Strategy (Strict):
- Unit tests for all parsers, formatters (`format_uptime`, `format_bytes`), and reducers.
- Integration tests with wiremock for the `reqwest` API client.
- Snapshot tests ONLY for static TUI layouts (help overlay, empty states). No snapshots on live dynamic data (CPU%, uptime) to avoid extreme brittleness.
Binary size check — Must stay under 15MB (stripped)
TTFR benchmark — Must render data <500ms on local net
8. Config Format — Clean TOML
toml
# ~/.config/proxxx/config.toml
[profiles.homelab]
url = "https://pve1.local:8006"
user = "root@pam"
auth = "token"          # "token" | "password"
token_id = "proxxx"
# Secret resolution hierarchy:
# 1. CLI Flag (--token-secret)
# 2. Env Var (PROXXX_TOKEN_SECRET)
# 3. Secure File (token_secret_file = "/etc/proxxx/token" with 0600 perms)
# 4. OS Keychain (Default on macOS, fallback on Linux)
verify_tls = false
[profiles.work]
url = "https://pve-prod.corp:8006"  
user = "admin@pve"
auth = "password"
verify_tls = true
[groups.all]
profiles = ["homelab", "work"]
mode = "aggregate"      # "aggregate"
prefix_vmid = true      # Resolves conflicts: homelab:100 vs work:100
[ui]
theme = "auto"          # "auto" | "dark" | "light" | "dracula" | "catppuccin"
icons = true
refresh_interval = 5    # seconds
[keybindings]
quit = "q"
search = "/"
command = ":"
default_profile = "homelab"
# ── HITL: Human-in-the-Loop Approval Gates ──────────────
[hitl]
enabled = true
default_timeout = 300       # seconds to wait for approval (0 = no timeout)
audit_log = "~/.local/share/proxxx/audit.jsonl"
[hitl.telegram]
bot_token = ""              # stored in OS keychain via `proxxx hitl setup telegram`
chat_id = -100123456789     # group chat or user ID
polling_interval = 2        # seconds between getUpdates calls
[hitl.teams]
webhook_url = ""            # Teams incoming webhook URL
approve_endpoint = "auto"   # "auto" = ephemeral localhost:<random>, or fixed URL
# Policy: which operations require approval
[[hitl.policies]]
action = "delete"           # "delete" | "stop" | "migrate" | "snapshot_delete" | "*"
target = "*"                # guest ID, tag pattern ("tag:prod"), or "*"
channel = "telegram"        # "telegram" | "teams" | "all"
require = 1                 # number of approvals needed
[[hitl.policies]]
action = "stop"
target = "tag:prod"         # only prod-tagged guests need approval to stop
channel = "telegram"
require = 1
[[hitl.policies]]
action = "migrate"
target = "*"
channel = "all"             # notify both Telegram and Teams
require = 1
9. CLI Mode — Pipe-Friendly
bash
# List all nodes across all profiles
$ proxxx ls nodes
NAME    STATUS   CPU    RAM     UPTIME
pve1    online   34%    12/32G  4d 12h
pve2    online   78%    28/64G  12d 3h
pve3    offline  -      -       -
# JSON output for scripting
$ proxxx ls guests --profile homelab --json | jq '.[] | select(.status=="running")'
# Quick actions
$ proxxx start 100 101 102
$ proxxx stop 103 --force
$ proxxx snapshot create 100 --name "pre-upgrade"
# Interactive TUI (default)
$ proxxx
$ proxxx --profile work
$ proxxx --group all
10. HITL Architecture — Zero New Dependencies
Key insight: Telegram and Teams both speak HTTP. We already have reqwest + tokio. Zero new crates needed.

10.1 How It Works
Approver (Human)
Telegram Bot API
proxxx (Policy Engine)
User (TUI/CLI)
Approver (Human)
Telegram Bot API
proxxx (Policy Engine)
User (TUI/CLI)
TUI shows ⏳ spinner
loop
[Poll every 2s]
proxxx stop 100
Check policies → match: "stop" + "tag:prod"
sendMessage (inline keyboard: ✅ Approve / ❌ Deny)
getUpdates (long-polling)
callback_query: "approve:txn_abc123"
Clicks ✅ Approve
callback_data = "approve:txn_abc123"
Log to audit.jsonl
editMessageText → "✅ Approved by @fabriziosalmi"
Proceed with stop
10.2 Telegram — Full Bidirectional (Recommended)
Why it's perfect: Telegram Bot API is pure HTTP, no WebSocket, no SDK. Just 3 endpoints:

Endpoint	Method	Purpose
/bot{token}/sendMessage	POST	Send approval request with inline keyboard
/bot{token}/getUpdates	GET	Long-poll for button callbacks
/bot{token}/editMessageText	POST	Update message after approval/denial
Message format (what the approver sees):

🛡️ PROXXX APPROVAL REQUEST
  Action:  ⛔ STOP
  Guest:   vm-100 (web-server)
  Tags:    prod, web
  Node:    pve1
  User:    root@pam
  Reason:  maintenance window
  Profile: homelab
  ┌─────────┐  ┌─────────┐
  │✅ Approve│  │❌ Deny  │
  └─────────┘  └─────────┘
Implementation: ~150 lines of Rust. One struct, three async functions.

10.3 Teams — Notification + URL Approval
Limitation discovered: Teams incoming webhooks do NOT support Action.Submit — they're one-way only. Buttons that POST back require a full Bot Framework registration.

Our elegant solution: Action.OpenURL → tiny ephemeral HTTP endpoint in proxxx.

Teams Card                         proxxx
┌──────────────┐                  ┌──────────────┐
│ 🛡️ APPROVAL  │  ──OpenURL──→   │ GET /approve │
│              │                  │   /txn_abc   │
│ [Approve URL]│                  │ → 200 OK ✅  │
│ [Deny URL]   │                  └──────────────┘
└──────────────┘                  (auto-shutdown)
proxxx spins up a one-shot tokio HTTP listener on a random port
The Adaptive Card contains Action.OpenURL pointing to http://proxxx-host:PORT/approve/txn_abc
When clicked, the listener receives the GET, records the decision, and shuts down
If behind NAT: configure approve_endpoint in TOML to a fixed URL/reverse proxy
Implementation: ~100 lines. Reuses tokio::net::TcpListener (already in our dep tree).

10.4 Policy Engine — Surgical TOML Rules
rust
// src/hitl/policy.rs — the entire mental model
pub struct Policy {
    action: ActionPattern,    // "delete" | "stop" | "migrate" | "*"
    target: TargetPattern,    // "*" | "100" | "tag:prod" | "node:pve1"
    channel: Channel,         // Telegram | Teams | All
    require: u8,              // approvals needed (usually 1)
}
pub enum Decision {
    Approved { by: String, via: Channel, elapsed: Duration },
    Denied   { by: String, via: Channel, reason: Option<String> },
    Timeout  { after: Duration },
    Skipped, // no matching policy → proceed immediately
}
Matching logic: First matching policy wins. No match = no gate = immediate execution.

10.5 Audit Log — Append-Only JSONL
jsonl
{"ts":"2026-05-01T15:30:12Z","txn":"abc123","action":"stop","target":"vm-100","decision":"approved","by":"@fabriziosalmi","via":"telegram","elapsed_ms":12400,"reason":"maintenance window"}
{"ts":"2026-05-01T15:28:44Z","txn":"def456","action":"delete","target":"vm-200","decision":"denied","by":"@admin","via":"teams","elapsed_ms":3200,"reason":null}
10.6 HITL Bloat Analysis
Component	New Code	New Deps	Binary Impact
hitl/mod.rs (trait + dispatch)	~80 LOC	0	~0 KB
hitl/telegram.rs	~150 LOC	0 (reqwest already in tree)	~0 KB
hitl/teams.rs	~100 LOC	0 (tokio TcpListener already in tree)	~0 KB
hitl/policy.rs	~60 LOC	0	~0 KB
Total	~390 LOC	0 new crates	<2 KB binary delta
390 lines. Zero new dependencies. Zero binary bloat. That's how you add a killer feature without bloating.

11. MCP Server — Hardened Deterministic Architecture
Threat model for AI Agents manipulating infrastructure:
1. Agent hallucinates a `stop_guest` call.
2. Prompt injection via API return values (e.g. guest name contains prompt injections triggering secondary actions).
3. Privilege escalation through malformed parameters.

Our answer is correctness and strict validation at the compilation boundary:

## Design Principles
- **Closed tool surface**: Compile-time `ToolAction` enum, no runtime registration or reflection.
- **Per-parameter typed validation**: Rigorous constraints (Regex, boundaries) before dispatching to Proxmox.
- **Destructive operations gated**: The `destructive: bool` flag routes calls through the exact same HITL policy engine used by the TUI.
- **Release Verification**: SHA-256 digest of the tool registry exposed via `proxxx mcp tools --checksum`.

11.1 Our Approach: Compile-Time Determinism
rust
// src/mcp/tools.rs — THE ENTIRE TOOL SURFACE IS HERE, AS CONST
/// Closed enum. No `Other(String)`. No dynamic variants. Ever.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolAction {
    ListNodes,
    ListGuests,
    GetGuestStatus,
    StartGuest,
    StopGuest,
    RestartGuest,
    CreateSnapshot,
    ListSnapshots,
    GetTaskLog,
    GetNodeResources,
    GetStoragePools,
}
/// Compile-time tool definition. Cannot be constructed at runtime
/// outside this module (private fields + no public constructor).
pub struct ToolDef {
    name: &'static str,
    description: &'static str,
    params: &'static [ParamDef],
    action: ToolAction,
    destructive: bool,          // triggers HITL gate if true
}
struct ParamDef {
    name: &'static str,
    description: &'static str,
    param_type: ParamType,
    required: bool,
    validation: Validation,     // compile-time constraints
}
enum ParamType { String, Integer, Boolean }
enum Validation {
    None,
    GuestId,                    // must be u32, range 100..999999
    NodeName,                   // must match ^[a-zA-Z][a-zA-Z0-9\-]{0,62}$
    SnapshotName,               // must match ^[a-zA-Z0-9_\-]{1,40}$
    ProfileName,                // must exist in loaded config
    Enum(&'static [&'static str]),  // fixed set of allowed values
}
/// THE REGISTRY. Immutable. Baked into the binary.
pub const TOOLS: &[ToolDef] = &[
    ToolDef {
        name: "list_nodes",
        description: "List all Proxmox nodes with status and resource usage",
        params: &[
            ParamDef {
                name: "profile",
                description: "Connection profile name",
                param_type: ParamType::String,
                required: false,
                validation: Validation::ProfileName,
            },
        ],
        action: ToolAction::ListNodes,
        destructive: false,
    },
    ToolDef {
        name: "stop_guest",
        description: "Stop a VM or LXC container",
        params: &[
            ParamDef {
                name: "guest_id",
                description: "Guest VMID (100-999999)",
                param_type: ParamType::Integer,
                required: true,
                validation: Validation::GuestId,
            },
            ParamDef {
                name: "force",
                description: "Force stop without graceful shutdown",
                param_type: ParamType::Boolean,
                required: false,
                validation: Validation::None,
            },
        ],
        action: ToolAction::StopGuest,
        destructive: true,  // → triggers HITL approval gate
    },
    // ... remaining tools follow same pattern
];
11.2 Security Properties
Property	Guarantee	Mechanism
No tool injection	Cannot add tools at runtime	const TOOLS array, no Vec, no push
No schema mutation	Tool params are &'static	Borrow checker prevents mutation of 'static refs
No dynamic dispatch	Closed ToolAction enum	match is exhaustive — compiler rejects unknown variants
Input sanitization	Every param has typed Validation	Regex/range checked before tool execution
HITL integration	destructive: true → approval required	Compile-time flag, not runtime config
11.4 Transport: JSON-RPC 2.0 over stdio
bash
# Start MCP server mode (for AI agents)
$ proxxx mcp serve                    # stdio (default, for Claude/Cursor/etc)
$ proxxx mcp serve --transport tcp     # TCP on localhost:9741
$ proxxx mcp serve --transport tcp --bind 0.0.0.0:9741  # network
# Introspect tools (verification)
$ proxxx mcp tools                    # list all tools + schemas
$ proxxx mcp tools --json             # machine-readable
$ proxxx mcp tools --checksum         # SHA-256 of tool registry (for audit)
Checksum feature: proxxx mcp tools --checksum outputs a SHA-256 hash of the serialized tool registry. This hash is deterministic per binary version. If an auditor compares the checksum against the expected value from the release, any tampering is instantly detectable.

11.4 MCP ↔ HITL Integration
When an AI agent calls a destructive: true tool via MCP:

Agent → MCP → Policy Engine → HITL Gate → Telegram → Human → Approve/Deny → Execute/Reject
The agent cannot bypass the HITL gate. The destructive flag is const — it's in the binary, not in a config file the agent could theoretically influence.

11.6 Bloat Analysis
Component	New Code	New Deps	Binary Impact
mcp/server.rs (JSON-RPC transport)	~200 LOC	0 (tokio + serde_json already in tree)	~1 KB
mcp/tools.rs (const definitions)	~250 LOC	0	~2 KB
Total	~450 LOC	0 new crates	<3 KB binary delta
12. Transversal Engineering Requirements

12.1 Logging Strategy
- Target: `tracing` spans and events are logged to a rolling file `~/.local/state/proxxx/proxxx.log`.
- Log Level: Default is `INFO`. Configurable via `PROXXX_LOG` env var (e.g., `PROXXX_LOG=debug proxxx`).
- STDERR: Never used for raw logs in TUI mode to prevent rendering artifacts. In CLI mode, `ERROR` and `WARN` are pushed to STDERR.

12.2 Crash Reporting & Resilience
- **Aerospace Panic Hook**: We use a custom `std::panic::set_hook` that ALWAYS calls `crossterm::terminal::disable_raw_mode()` and `LeaveAlternateScreen` before dumping the stack trace. The user's terminal is unconditionally protected from raw mode corruption upon fatal errors.
- Traces include Git commit hash and release version to streamline GitHub issue triage.

12.3 Versioning Policy (SemVer)
- **TUI UI Changes**: Not covered by SemVer. Layouts can change in MINOR versions.
- **CLI Commands & Exit Codes**: Strictly SemVer. A breaking change requires a MAJOR version bump.
- **JSON Output (`--json`)**: Additive changes only. Removing/renaming fields requires a MAJOR version bump.
- **Config Schema**: Backwards compatible. If a schema breaking change is required, it must auto-migrate or bump MAJOR.
- **MCP Tool Registry**: Tools are append-only. Param signature changes require a MAJOR version bump.

12.4 Update Mechanism
- No bloatware self-updater. 
- The app performs an async background check to the GitHub Releases API (once per day max, cached). 
- If a new version is available, a non-intrusive badge `[Update v1.1.0 available]` appears in the top navigation.
- Updates are handled via the user's package manager or by re-running the installation script.

12.5 i18n (Internationalization)
- **English Only (EN-US)** for v1. No gettext or localization layers to maintain minimum binary size and development velocity.

12.6 Accessibility (A11y)
- **Not Supported**. Screen reader compatibility is inherently hostile in Crossterm/Ratatui matrix rendering. 
- Users relying on assistive technologies are officially directed to use the `proxxx` CLI mode (`--json` or plain text) rather than the TUI.