# Cluster smoke runbook — `pve-cluster` (test_env.md)

A walkthrough for validating proxxx end-to-end against a real Proxmox
VE cluster. Targets the test environment described in
[`test_env.md`](../test_env.md):

```
pve-test-1   192.168.0.122
pve-test-2   192.168.0.123
pve-test-3   192.168.0.124
cluster: pve-cluster
user: root  (PAM)
```

> **Why a runbook instead of automated cluster integration tests?**
> Spinning a 3-node PVE cluster in CI is expensive and the wiremock
> coverage already validates URL routing per endpoint. This runbook
> walks the *non-mockable* parts: real ticket flows, signal handling,
> `pveum` parsing against actual output. Each section calls out
> exactly what to look for; "✅" in the expected column = pass criterion.

---

## 0. Setup

Drop a profile config at `~/.config/proxxx/config.toml`:

```toml
url = "https://192.168.0.122:8006"
user = "root@pam"
auth = "token"
token_id = "proxxx"
verify_tls = false
rate_limit = 10
```

Issue the API token on the cluster:

```bash
ssh root@192.168.0.122
pveum user token add root@pam proxxx --privsep 0 --comment "smoke test"
# Capture the secret it prints — set as PROXXX_TOKEN_SECRET in your shell.
```

Build proxxx:

```bash
cd /Users/fab/Documents/git/proxxx
cargo build --release
ln -sf "$PWD/target/release/proxxx" /usr/local/bin/proxxx
```

---

## 1. Read-only sanity (no destructive ops)

| Command                                         | Expected                                                   |
| :---------------------------------------------- | :--------------------------------------------------------- |
| `proxxx ls nodes`                               | 3 rows: pve-test-1/2/3 online                              |
| `proxxx ls guests`                              | All VMs + LXCs across the cluster                          |
| `proxxx ls storage`                             | Storages reachable from any node                           |
| `proxxx get nodes`                              | Same output as `ls nodes` — bug #5 alias check ✅          |
| `proxxx ha groups`                              | HA groups defined (or empty array)                         |
| `proxxx ha resources`                           | HA-managed VMs/CTs                                         |
| `proxxx ha status`                              | Manager + per-node service status                          |
| `proxxx replication jobs`                       | Configured pve-zsync jobs                                  |
| `proxxx replication status --node pve-test-1`   | Last sync + RPO + fail count per job                       |
| `proxxx hw pci --node pve-test-1`               | PCI list with `iommugroup` field present                   |
| `proxxx hw conflicts --node pve-test-1`         | Either `count: 0` or list of DirectShared/IommuGroupSplit  |
| `proxxx access acl`                             | ACL entries                                                |
| `proxxx access realms`                          | Includes `pam` and `pve` realm at minimum                  |
| `proxxx mcp tools --checksum`                   | SHA-256 hash of MCP tool registry (deterministic)          |

**Anti-regression for bug #1 (LXC routing).** If you have any LXC in the
cluster, run:

```bash
LXC_VMID=<your-lxc-id>
proxxx ls guests --format json | jq '.[] | select(.vmid==$LXC_VMID) | .type'
# expect: "Lxc"
```

---

## 2. Bug #2 verification — graceful shutdown polling

Pick a guest you can safely stop and start. Watch the audit log file
(`~/.local/share/proxxx/proxxx.log`) in another terminal.

```bash
proxxx stop $VMID
# expect: starts a graceful shutdown, polls every ~3s until Stopped or
# the 60s timeout. Timeout case → confirm modal in TUI; CLI completes
# with exit 0 once the guest reports Stopped.
proxxx start $VMID
```

What to verify in the log:
- ✅ The dispatch hits `/status/shutdown`, NOT `/status/stop`.
- ✅ Per-poll lines `status poll {vmid} → running` repeat.
- ✅ On stopped: single "shutdown completed" log entry.

---

## 3. Feature #1a — SSH guest session (TUI)

Pick a guest with SSH listening. Add a `[ssh.guests."<vmid>"]` block to
the config matching its IP. Then in TUI mode:

```
proxxx
:ssh <vmid>
```

Expected:
- ✅ TUI flips to PTY view, you see the remote shell prompt
- ✅ Arrow keys, Tab, Ctrl+C all reach the shell (NOT proxxx)
- ✅ Press Ctrl+] → returns to the previous TUI view
- ✅ TOFU: first connection logs a `tofu: trusting unknown host` warn
  with fingerprint; second connection silent (entry persisted in
  `~/.config/proxxx/known_hosts`).

---

## 4. Feature #1b — Serial console via termproxy (CLI)

```bash
proxxx serial $VMID --node pve-test-1
```

Expected:
- ✅ Terminal goes raw-mode, screen clears, header shows
  `[serial console: vmid X on pve-test-1]  Ctrl+] then 'q' to exit`
- ✅ For a Linux VM with serial enabled (`qm set <id> --serial0 socket`),
  you see kernel messages or a getty
- ✅ Press `Ctrl+]` then `q` → terminal restored, JSON summary printed
- ✅ Resize the terminal window mid-session → remote PTY adjusts

---

## 5. Feature #1c — SPICE / noVNC handoff

Requires virt-viewer / remote-viewer locally for SPICE.

```bash
# SPICE (graphical) — guest must have a SPICE display configured
proxxx spice $VMID --node pve-test-1 --no-launch
# Inspect the .vv file; verify mode 0600 on Unix:
stat -f "%Lp" $(proxxx spice $VMID --node pve-test-1 --no-launch | jq -r .vv_file)
# expect: 600

# Without --no-launch, virt-viewer should pop up if installed:
proxxx spice $VMID --node pve-test-1

# noVNC (browser) — works for both QEMU and LXC
proxxx novnc $VMID --node pve-test-1
# Browser opens to https://192.168.0.122:8006/?console=kvm&novnc=1&vmid=...
# If you're not logged into the web UI, it redirects to the login form.
```

Expected:
- ✅ `.vv` file contains `[virt-viewer]` header + `host=192.168.0.122`
- ✅ `.vv` file is mode 0600 on Unix
- ✅ noVNC URL contains `console=kvm` for QEMU, `console=lxc` for LXC

---

## 6. Feature #2 — ISO library (refuse-on-None gate)

```bash
proxxx iso list
# expect: array with 6 entries; each has sha256: null

proxxx iso download --id ubuntu-24.04-cloud --node pve-test-1 --storage local
# expect: ERROR — "library entry 'ubuntu-24.04-cloud' has no pinned SHA-256
#          (release-time TODO)". Exit code != 0.

# Custom URL path still works (user takes responsibility):
proxxx iso download \
  --url https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img \
  --filename noble.img \
  --content import \
  --node pve-test-1 --storage local
# expect: download UPID returned; check task progress in web UI
```

---

## 7. Feature #3 — PBS browse + restore

Requires PBS reachable from your client. Add `[pbs]` block to config.

```bash
proxxx pbs datastores
proxxx pbs snapshots --store main --backup-type vm --backup-id 100
proxxx pbs files --store main --type vm --backup-id 100 --time 1700000000

# Restore (Linux only — needs proxmox-backup-client on PATH).
# This will spawn a real restore. Test with a small archive first.
mkdir /tmp/proxxx-restore
proxxx pbs restore \
  --store main \
  --snapshot vm/100/2024-01-15T10:00:00Z \
  --archive root.pxar.didx \
  --target /tmp/proxxx-restore \
  --yes
```

**Bug #2 signal handling smoke** — start a long restore, then hit Ctrl+C:

- ✅ proxxx prints `(received Ctrl+C — killing proxmox-backup-client)`
- ✅ Bails with `restore cancelled by Ctrl+C (last exit: ...)`
- ✅ `ps aux | grep proxmox-backup-client` shows NO orphan child

---

## 8. Feature #4 — Hardware passthrough conflicts

If the cluster has GPU passthrough configured, you can stress-test the
detector by creating a deliberate conflict:

```bash
# On pve-test-1: assign 0000:01:00.0 to vmid 100 and 200 (same address).
qm set 100 --hostpci0 0000:01:00.0
qm set 200 --hostpci0 0000:01:00.0

proxxx hw conflicts --node pve-test-1 --format json
# expect: count >= 1, kind=direct_shared, vmids=[100, 200]
# exit code: 1
```

Don't forget to revert (`qm set <id> --delete hostpci0`) when done.

---

## 9. Feature #5 — HA failover preview

```bash
proxxx ha preview --node pve-test-1
```

For each HA-managed resource currently on pve-test-1, the JSON tells
you where it would land. Verify by hand:

- ✅ Each preview's `target` is in the resource's HA group `nodes` list
- ✅ Targets are sorted by priority (highest first), with offline nodes
  skipped
- ✅ Resources NOT on pve-test-1 show `kind: not_affected`

---

## 10. Feature #6 — Live disk move/resize (force-enqueue invariant)

In TUI mode, the queue is mandatory. From CLI:

```bash
# CLI bypasses queue but requires --yes
proxxx disk resize $VMID --disk scsi0 --size +1G --yes
# expect: UPID returned; web UI shows the resize task running
```

In TUI:
1. Open a guest detail view, trigger a disk resize via palette command
   (future — currently use CLI)
2. Verify the operation appears in the queue with `Pending` status
3. Press `C` on the queue view → executes; status flips to `Running`
   then `Success`

---

## 11. Feature #7 — Snapshot tree

```bash
# Create a branching scenario
qm snapshot $VMID baseline
qm snapshot $VMID pre-upgrade
qm rollback $VMID baseline
qm snapshot $VMID alternate-branch
```

In TUI: `:tree <vmid>` — should show:

```
└─ baseline
   ├─ pre-upgrade
   ├─ alternate-branch
   └─ current
```

✅ Branching renders correctly with `├─` connectors.
✅ Side panel shows rollback impact preview when selecting any snapshot.

Cleanup: `qm delsnapshot $VMID baseline pre-upgrade alternate-branch`.

---

## 12. Feature #8 — Alerting (one-shot eval against the live cluster)

Add the `[[alerts]]` rules from `docs/config.example.toml` to your
config. Then:

```bash
proxxx alerts eval
# expect: JSON with `evaluated_rules: 3` and an `events` array.
# Empty array if everything is healthy.
```

To stress-test: stop pve-test-3, wait 2 minutes, then `proxxx alerts eval`.
Should fire `node_down` if `for_secs <= 120`.

```bash
proxxx alerts test --route telegram --severity warning
# expect: a Telegram message from the configured bot
```

---

## 13. Feature #9 — Patching orchestrator (dry-run only)

```bash
# Plan only — no SSH needed
proxxx patch plan
# expect: per-node JSON with kernel_pending / security_pending / reboot_required

# Dry-run — walks the state machine without running apt or rebooting
proxxx patch apply --dry-run
# expect: each node transitions Pending → Refresh → Inventory → Done(rebooted=false)
```

**Do NOT run `proxxx patch apply` (no `--dry-run`) on test_env's cluster
unless you mean it** — it executes `apt-get -y dist-upgrade` and reboots
nodes serially. The orchestrator is designed to be safe (max one node
in upgrade at a time) but it IS destructive.

---

## 14. Feature #10 — ACL + effective permissions

```bash
proxxx access users
proxxx access tfa root@pam
proxxx token list root@pam

# Effective permissions via SSH shell-out to pveum
proxxx perms root@pam --node pve-test-1
# expect: JSON with paths[]; root@pam should have `/` propagate=true
#         with the Administrator role's full privilege list.
```

The shell-out invariant: proxxx must NOT re-implement the algorithm.
Verify by checking the audit log — it should show
`ssh exec pveum user permissions root@pam` and a single response.

---

## 15. BLOCKER 3 — Flight-recorder smoke

```bash
proxxx dev-panic --message hello-world
# expect:
#   - exit code != 0
#   - stderr contains "💀 proxxx panicked at <file:line>"
#   - stderr contains "[dev-panic] hello-world"
#   - stderr contains "audit log: ~/.local/share/proxxx (proxxx.log)"
#   - terminal is restored (no raw-mode artifacts, cursor visible)
#   - audit log has the panic captured via tracing
tail -n 20 ~/.local/share/proxxx/proxxx.*.log | grep -A 2 PANIC
# expect: a `target=panic` log entry with location + payload
```

If after the panic your terminal still feels broken (no echo, weird
keys), `reset` will fix it. The fact that you might need `reset` ever
is a regression — the hook is supposed to make it unnecessary.

---

## 16. Stale data + cache time-travel

```bash
# After running proxxx for a while, the SQLite cache fills up.
ls -la ~/.cache/proxxx/

# Time-travel: dump cluster state from 1h ago
TS=$(date -u -v-1H +%s)
proxxx replay $TS
# expect: snapshot from ~1h ago if proxxx was running then; otherwise
# error about "no snapshot found for the requested time"

proxxx watch --since 1h
# expect: diff between now and 1h ago (status changes, created, deleted)
```

---

## Pass criteria summary

The runbook is a pass if:

1. All 14 read-only commands in §1 succeed and return non-empty
   output where applicable.
2. Bug #1 (LXC) verifiable by inspecting any LXC type in `ls guests`.
3. Bug #2 (graceful) verifiable by `tail` of audit log during stop.
4. Bug #5 (`get` alias) verifiable by §1.
5. Each shipped feature has at least one observed pass criterion (✅).
6. The flight-recorder hook (§15) restores the terminal.

If any step fails, capture the audit log + stderr and file an issue
with the section number.
