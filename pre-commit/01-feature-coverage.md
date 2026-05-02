| Feature | Verified end-to-end | Revisions across commits |
|---|---|---|
| Nodes & Cluster · Read node list (Cluster API) | ✅ | 8 |
| Nodes & Cluster · Read node metrics (CPU, RAM, uptime) | ✅ | 8 |
| Nodes & Cluster · Detect offline / partitioned node | ❌ | 8 |
| Nodes & Cluster · Read corosync quorum state | ❌ | 8 |
| Nodes & Cluster · Read node syslog | ❌ | 8 |
| Nodes & Cluster · Read PCI hardware inventory | ⚠️ upstream-blocked (Sys.Audit) | 1 |
| Nodes & Cluster · Read USB hardware inventory | ⚠️ upstream-blocked (Sys.Audit) | 1 |
| Nodes & Cluster · Map IOMMU groups | ⚠️ upstream-blocked (Sys.Audit) | 1 |
| Nodes & Cluster · Compute PCI conflicts (Shared / IommuSplit) | ⚠️ upstream-blocked (Sys.Audit) | 1 |
| Guest lifecycle (QEMU) · Start VM (POST /status/start) | ❌ | 8 |
| Guest lifecycle (QEMU) · Hard-stop VM (POST /status/stop, forceStop=1) | ❌ | 8 |
| Guest lifecycle (QEMU) · Graceful shutdown VM (POST /status/shutdown) | ❌ | 8 |
| Guest lifecycle (QEMU) · Poll ACPI shutdown with timeout | ❌ | 8 |
| Guest lifecycle (QEMU) · Reboot VM (POST /status/reboot) | ❌ | 8 |
| Guest lifecycle (QEMU) · Delete VM (DELETE) | ❌ | 8 |
| Guest lifecycle (QEMU) · Detect lock state (e.g. lock: backup) | ❌ | 5 |
| Guest lifecycle (QEMU) · Detect HA-managed state (CRM lock) | ❌ | 5 |
| Guest lifecycle (LXC) · Start container (POST /status/start) | ✅ | 8 |
| Guest lifecycle (LXC) · Hard-stop container (POST /status/stop) | ✅ | 8 |
| Guest lifecycle (LXC) · Graceful shutdown container (POST /status/shutdown) | ❌ | 8 |
| Guest lifecycle (LXC) · Reboot container (POST /status/reboot) | ❌ | 8 |
| Guest lifecycle (LXC) · Delete container (DELETE) | ✅ | 8 |
| Disks & storage · Read storage pool list | ✅ | 8 |
| Disks & storage · Read storage contents (ISO, templates, volumes) | ✅ | 8 |
| Disks & storage · Live-migrate VM disk (QEMU move_disk) | ❌ | 8 |
| Disks & storage · Migrate container volume (LXC move_volume) | ❌ | 8 |
| Disks & storage · Resize VM disk (resize_disk) | ❌ | 8 |
| Disks & storage · Resize container volume (resize_volume) | ❌ | 8 |
| Disks & storage · Download ISO from remote URL to node | ❌ | 8 |
| Disks & storage · Download ISO from curated library (SHA-256 verified) | ❌ | 2 |
| Snapshots & backup · Read flat snapshot list (QEMU) | ❌ | 8 |
| Snapshots & backup · Read flat snapshot list (LXC) | ✅ | 8 |
| Snapshots & backup · Build hierarchical snapshot tree (Orphans + Branches) | ❌ | 1 |
| Snapshots & backup · Create snapshot (QEMU) | ❌ | 8 |
| Snapshots & backup · Create snapshot (LXC) | ✅ | 8 |
| Snapshots & backup · Delete snapshot (QEMU) | ❌ | 8 |
| Snapshots & backup · Delete snapshot (LXC) | ❌ | 8 |
| Snapshots & backup · Rollback to snapshot (QEMU/LXC) | ❌ | 8 |
| Networking & migration · Live-migrate VM (cross-node) | ❌ | 8 |
| Networking & migration · Offline-migrate container | ❌ | 8 |
| Networking & migration · Read HA groups | ⚠️ upstream-blocked (Sys.Audit) | 1 |
| Networking & migration · Read HA resources | ⚠️ upstream-blocked (Sys.Audit) | 1 |
| Networking & migration · Deterministic offline-node failover simulation | ❌ | 1 |
| Networking & migration · Read ZFS replication state | ✅ | 8 |
| Networking & migration · Compute replication health (Stale / Failing) | ❌ | 8 |
| Shell & console (FFI) · Open native SSH session into guest (via IP/config) | ❌ | 3 |
| Shell & console (FFI) · Forward vt100 input over PTY | ❌ | 3 |
| Shell & console (FFI) · Clean PTY exit (Ctrl+]) | ❌ | 3 |
| Shell & console (FFI) · Generate termproxy ticket (WebSocket auth) | ❌ | 2 |
| Shell & console (FFI) · Stream serial via WebSocket (Opcode 0) | ❌ | 2 |
| Shell & console (FFI) · Propagate terminal resize via WebSocket (Opcode 1) | ❌ | 2 |
| Shell & console (FFI) · SPICE handoff (write .vv with 0600 perms) | ❌ | 3 |
| Shell & console (FFI) · noVNC handoff (open OS browser) | ❌ | 3 |
| Shell & console (FFI) · Run command via QEMU Guest Agent (/agent/exec) | ❌ | 8 |
| Shell & console (FFI) · Run command via LXC (/exec) | ❌ | 8 |
| Security & governance · Read user list (ACL) | ✅ | 1 |
| Security & governance · Read API tokens | ⚠️ upstream-blocked (token can't list other tokens) | 1 |
| Security & governance · Create API token (single-shot secret capture) | ❌ | 1 |
| Security & governance · Revoke API token | ❌ | 1 |
| Security & governance · Compute effective permissions via shell-out (pveum) | ❌ | 1 |
| Security & governance · Detect 401 Unauthorized and refresh PAM ticket | ⚠️ typed errors validated; no expiry observed live | 3 |
| Security & governance · Parse HITL policy TOML | ❌ | 3 |
| Security & governance · Intercept mutating payload (queue enqueue) | ❌ | 4 |
| Patching & OS · Refresh apt repository | ❌ | 3 |
| Patching & OS · Detect upgradable packages | ✅ | 3 |
| Patching & OS · Reboot-needed heuristic (kernel, libc, systemd) | ❌ | 3 |
| Patching & OS · Apply upgrade (apt-get dist-upgrade) | ❌ | 3 |
| Patching & OS · Launch non-blocking systemctl reboot | ❌ | 3 |
| Patching & OS · Wait for post-reboot reconnection | ❌ | 3 |
| PBS · PBS ticket authentication | ❌ separate user db on PBS host | 4 |
| PBS · Read PBS datastores | ❌ blocked by auth | 4 |
| PBS · Read snapshots inside datastore | ❌ blocked by auth | 4 |
| PBS · Read physical files (.pxar.didx, .blob) of snapshot | ❌ blocked by auth | 4 |
| PBS · Shell handoff to proxmox-backup-client restore | ❌ blocked by auth | 4 |
| PBS · Guaranteed SIGKILL drop of PBS process on user exit | ✅ unit-tested (kill_on_drop) | 4 |
| Internal architecture · O(1) in-RAM fuzzy search | ✅ | 2 |
| Internal architecture · Isolated local SQLite cache update (upsert) | ✅ | 5 |
| Internal architecture · SQLite incremental vacuum | ✅ | 5 |
| Internal architecture · CLI argument parse and validation via clap | ✅ | 5 |
| Internal architecture · Deterministic JSON serialization (stdout) | ✅ | 5 |
| Internal architecture · Telegram daemon startup (long-polling) | ❌ | 1 |
| Internal architecture · MCP server startup (stdio) | ❌ | 4 |
| Internal architecture · Panic capture and dump to audit log (flight recorder) | ❌ | 3 |
| Internal architecture · TUI memory eviction on view pop (garbage collection) | ❌ | 9 |
| RBAC & multi-persona · Deterministic provisioning of 4-persona test fixture (root / operator / auditor / blind) via `tests/fixtures/setup_rbac.sh` | ❌ | 0 |
| RBAC & multi-persona · Multi-token E2E env injection (`PROXXX_E2E_TOKEN_{ROOT,OPERATOR,AUDITOR,BLIND}`) | ❌ | 0 |
| RBAC & multi-persona · TUI survives empty cluster view as `blind@pve` (0 nodes / 0 storage / 1 VM) — no div-by-zero in CPU%, no crash on auto-focus of empty list, `q` exits with code 0 | ❌ | 0 |
| RBAC & multi-persona · `auditor@pve` running `start <vmid>` surfaces `ApiError::Forbidden` with typed CLI message — not a raw reqwest error | ❌ | 0 |
| RBAC & multi-persona · Live task-log streamer degrades gracefully when `GET /nodes/X/tasks/UPID/log` returns 403 (PVEVMAdmin can start a VM but may lack Sys.Audit on the node) | ❌ | 0 |
| RBAC & multi-persona · Bulk ops are atomic-per-target (`proxxx start 100 200` as operator: 100 succeeds, 200 fails 403, deterministic exit code, no pipeline abort) | ❌ | 0 |
| RBAC & multi-persona · SQLite cache segregation per-profile (no read-leak: `proxxx --profile auditor` must not surface VMs cached during a prior `--profile root` session) | ❌ | 0 |
| RBAC & multi-persona · `TestResourceGuard` Drop teardown always uses a root-credentialed client, never the test's persona credentials (so cleanup can't 403) | ❌ | 0 |
| RBAC & multi-persona · `hw pci --node X` as operator returns structured JSON `{"error":"Forbidden",…}` on 403 — JSON contract not broken by unstructured stderr | ❌ | 0 |
| RBAC & multi-persona · Security/Token TUI views disable themselves cleanly on 403 (e.g. `auditor` opening `access tfa`) instead of crashing or leaking partial state | ❌ | 0 |
| RBAC & multi-persona · HITL approval does NOT privilege-escalate (op approved via Telegram by admin but executed under operator token still 403s — proxxx uses the calling token, never re-issues with admin creds) | ❌ | 0 |
| RBAC & multi-persona · Tests use privilege-separated tokens (token has its own ACL row, not inheriting the user's roles) — verifies real token-RBAC, not the parent user's permissions | ❌ | 0 |
