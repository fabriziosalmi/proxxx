| Invariant (Domain · Description) | Verified E2E | Revisions |
|---|---|---|
| OS · SIGTERM initiates clean WAL flush and graceful exit  | ❌ | 0 |
| OS · SIGHUP (Terminal disconnect) terminates background tasks, avoids zombies | ❌ | 0 |
| OS · SIGWINCH resize storm debounced (max 1 per 50ms) to SSH remote (V8) | ❌ | 0 |
| OS · SIGCONT (Wake from Suspend) allows TUI redraw via Ctrl+L fallback (V13) | ❌ | 0 |
| CPU · `crossterm::poll` blocks on syscall (epoll), 0% CPU at idle | ❌ | 0 |
| CPU · Telegram long-polling implements exponential backoff on outage (V6) | ❌ | 0 |
| Memory · TUI `pop_view` triggers `shrink_to_fit` dropping old data  | ❌ | 0 |
| Memory · WS frame max size capped at 4 MiB (`tokio-tungstenite` bounds) (V1) | ❌ | 0 |
| Memory · Application survives under tight cgroup RAM limit (e.g., 64MB) without OOM | ❌ | 0 |
| Resources · Batch operations limited by `Semaphore(32)` to prevent FD exhaustion (V7) | ❌ | 0 |
| Resources · Exhaustion of local PTYs (`/dev/pts/`) handled gracefully on SSH connect | ❌ | 0 |
| Time · NTP backward jump does not trigger false timeouts (`Instant` monotonicity) | ❌ | 0 |
| Proxmox Quirks · Loss of Cluster Quorum displays global DANGER banner (V17) | ❌ | 0 |
| Proxmox Quirks · `pvestatd` freeze detected via uptime drift  | ❌ | 0 |
| Proxmox Quirks · HA-managed VM destructive ops blocked locally  | ❌ | 0 |
| Proxmox Quirks · QEMU Guest Agent hang detected and timed out independently (15s) | ❌ | 0 |
| Proxmox Quirks · Migration state tracking avoids vmid duplication during live-migrate | ❌ | 0 |
| Logging · Tracing log files cap at 14 days rotating, preventing disk fill (V22) | ❌ | 0 |
| Logging · High-frequency API errors (e.g. 502 loop) deduplicated to prevent log flooding | ❌ | 0 |
