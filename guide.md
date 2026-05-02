# proxxx — manual test guide

This is a personal walkthrough that exercises every shipped feature against
a real Proxmox cluster. The cluster topology and credentials live in
`test_env.md` (gitignored). The IPs/hostnames in this file match that
environment — adjust if you fork the project for a different lab.

> The generic version of this runbook is [`docs/cluster_smoke.md`](docs/cluster_smoke.md).
> That doc is template-shaped (no specific IPs); this `guide.md` is the
> ready-to-paste version for the home cluster.

---

## Cluster under test

| Role          | Hostname     | IP              |
| :------------ | :----------- | :-------------- |
| PVE node 1    | `pve-test-1` | 192.168.0.122   |
| PVE node 2    | `pve-test-2` | 192.168.0.123   |
| PVE node 3    | `pve-test-3` | 192.168.0.124   |
| Cluster name  | `pve-cluster` |                |
| PBS server    | `pve-pbs`    | 192.168.0.125   |

Templates already on `local`:
- ISO: `alpine-standard-3.23.4-x86_64.iso` (VM tests)
- LXC: `alpine-3.22-default_20250617_amd64.tar.xz`

Credentials live in `test_env.md`. The walkthrough below assumes
`PROXXX_TOKEN_SECRET` is set in your shell.

---

## 0 — Pre-flight (run once)

### 0.1 Build proxxx

```bash
cd /Users/fab/Documents/git/proxxx
cargo build --release
ln -sf "$PWD/target/release/proxxx" /usr/local/bin/proxxx
proxxx --version
```

### 0.2 Issue an API token on the cluster

SSH to any node and create a dedicated token (privsep=0 so it inherits
root's permissions for the test):

```bash
ssh root@192.168.0.122
pveum user token add root@pam proxxx --privsep 0 --comment "proxxx smoke test"
# Copy the printed secret. It will look like:
#   value: 00000000-0000-0000-0000-000000000000
exit

# Back on your laptop:
export PROXXX_TOKEN_SECRET='<secret-from-above>'
```

### 0.3 Drop the proxxx config

```bash
mkdir -p ~/.config/proxxx
cat > ~/.config/proxxx/config.toml <<'EOF'
url = "https://192.168.0.122:8006"
user = "root@pam"
auth = "token"
token_id = "proxxx"
verify_tls = false
rate_limit = 10

[ssh]
user = "root"
key_path = "~/.ssh/proxxx_homelab"
strict_host_key_checking = "tofu"

[pbs]
url = "https://192.168.0.125:8007"
user = "root@pam"
token_id = "proxxx"
verify_tls = false
EOF
```

### 0.4 SSH key for Pillar 0 (features 9, 10, 1a)

```bash
ssh-keygen -t ed25519 -f ~/.ssh/proxxx_homelab -N ""
for h in 192.168.0.122 192.168.0.123 192.168.0.124; do
  ssh-copy-id -i ~/.ssh/proxxx_homelab.pub root@$h
done
```

### 0.5 PBS token (feature 3)

```bash
ssh root@192.168.0.125
proxmox-backup-manager user generate-token root@pam proxxx
# Copy the secret:
exit

export PROXXX_PBS_TOKEN_SECRET='<pbs-secret>'
```

---

## 1 — Read-only sanity (no side effects)

| # | Command                                                | ✅ Pass criteria                                      |
| -:| :----------------------------------------------------- | :---------------------------------------------------- |
| 1 | `proxxx ls nodes`                                       | 3 rows online: pve-test-1/2/3                         |
| 2 | `proxxx get nodes`                                      | identical output (bug #5 alias check)                 |
| 3 | `proxxx ls guests`                                      | All guests on the cluster (likely empty/few at first) |
| 4 | `proxxx ls storage`                                     | `local`, plus any other configured                    |
| 5 | `proxxx ha groups`                                      | groups list (may be empty)                            |
| 6 | `proxxx ha status`                                      | manager + per-node service state                      |
| 7 | `proxxx replication jobs`                               | configured pve-zsync jobs (may be empty)              |
| 8 | `proxxx hw pci --node pve-test-1`                       | PCI list with `iommugroup` field present              |
| 9 | `proxxx hw conflicts --node pve-test-1`                 | `count: 0` (or list, if you've configured passthrough)|
|10 | `proxxx access users`                                   | at minimum `root@pam`                                 |
|11 | `proxxx access realms`                                  | includes `pam` and `pve`                              |
|12 | `proxxx mcp tools --checksum`                           | deterministic SHA-256 hash                            |

```bash
# Run them all in one shot:
for cmd in \
  "ls nodes" \
  "get nodes" \
  "ls guests" \
  "ls storage" \
  "ha groups" \
  "ha status" \
  "replication jobs" \
  "hw pci --node pve-test-1" \
  "hw conflicts --node pve-test-1" \
  "access users" \
  "access realms" \
  "mcp tools --checksum"; do
  echo "── proxxx $cmd ──"
  proxxx $cmd
  echo
done
```

---

## 2 — Create test VMs + LXCs (so we have things to operate on)

### 2.1 Create a VM (vmid 9001) using the Alpine ISO

```bash
ssh root@192.168.0.122 'qm create 9001 \
  --name proxxx-test-vm \
  --memory 512 \
  --cores 1 \
  --net0 virtio,bridge=vmbr0 \
  --ide2 local:iso/alpine-standard-3.23.4-x86_64.iso,media=cdrom \
  --scsihw virtio-scsi-pci \
  --scsi0 local:8 \
  --boot order=ide2'
```

### 2.2 Create an LXC (vmid 9002) using the Alpine template

```bash
ssh root@192.168.0.122 'pct create 9002 \
  local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz \
  --hostname proxxx-test-ct \
  --memory 256 \
  --cores 1 \
  --rootfs local:1 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp'
```

### 2.3 Start both and verify proxxx sees them

```bash
proxxx start 9001 9002
proxxx ls guests --format json | jq '.[] | select(.vmid==9001 or .vmid==9002)'
```

**✅ pass:** both guests appear, each with the correct `type` (`Qemu` / `Lxc`)
and `status: Running`.

**Bug #1 spot-check:** the LXC must show `type: Lxc`, not be silently
mismatched.

---

## 3 — VM ops (bug #1, bug #2, bug #9)

```bash
# Force stop QEMU — direct hard /status/stop
proxxx stop 9001 --force
proxxx ls guests --format json | jq '.[] | select(.vmid==9001) | .status'
# expect: "Stopped"

# Graceful shutdown (bug #2 — must hit /status/shutdown, NOT /status/stop)
proxxx start 9001
sleep 2
tail -f ~/.local/share/proxxx/proxxx.*.log &
TAIL_PID=$!
proxxx stop 9001
kill $TAIL_PID

# Restart
proxxx start 9001
proxxx restart 9001
```

**✅ pass for bug #2:** the audit log shows `dispatch_side_effect`
hitting `/status/shutdown`, NOT `/status/stop`. The polling loop runs
and emits `GuestStatusPolled` events every ~3s.

```bash
grep -E "shutdown|status/stop" ~/.local/share/proxxx/proxxx.*.log | tail -10
# expect: shutdown lines, NO status/stop lines for force=false
```

---

## 4 — LXC ops (bug #1 verification)

```bash
# These all MUST hit /lxc/{vmid}/..., never /qemu/...
proxxx stop 9002
proxxx start 9002
proxxx restart 9002
```

**✅ pass:** every LXC op succeeds. If any fails with HTTP 500/404,
bug #1 has regressed.

---

## 5 — Snapshots + snapshot tree (#7)

```bash
# Create a chain (note: the LXC at 9002 doesn't support online snapshots
# unless you add `--memory 0` to the snapshot command; using the VM 9001
# is simpler).
proxxx snapshot create --vmid 9001 --name baseline
proxxx snapshot create --vmid 9001 --name pre-config

# In the TUI: open proxxx, navigate to guest 9001, press Z
proxxx
# inside TUI:
#   3 (guest list) → cursor on 9001 → Z
# expect: snapshot tree view with `baseline → pre-config → current`

# Cleanup
proxxx snapshot delete --vmid 9001 --name pre-config
proxxx snapshot delete --vmid 9001 --name baseline
```

**✅ pass:** tree renders with `├─` / `└─` connectors, `current` is
italic + bottom of its branch, side panel shows rollback impact.

---

## 6 — ISO library (#2 + BLOCKER 1)

```bash
proxxx iso list --format json | jq '.[] | {id, sha256}'
# expect: 6 entries, every sha256 is null

proxxx iso download --id ubuntu-24.04-cloud --node pve-test-1 --storage local
# expect: ERROR with exit code != 0, message about
# "library entry 'ubuntu-24.04-cloud' has no pinned SHA-256 (release-time TODO)"
echo "exit: $?"

# Custom URL path bypasses the gate (user takes responsibility)
proxxx iso download \
  --url https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-virt-3.19.1-x86_64.iso \
  --filename alpine-virt-3.19.1.iso \
  --content iso \
  --node pve-test-1 \
  --storage local
# expect: UPID returned, web UI Tasks shows the download running
```

**✅ pass for BLOCKER 1:** curated downloads refused, custom URLs work.

---

## 7 — HA + replication console (#5)

```bash
proxxx ha groups
proxxx ha resources
proxxx ha status
proxxx replication jobs
proxxx replication status --node pve-test-1

# What-if preview: simulate pve-test-1 going offline
proxxx ha preview --node pve-test-1
# expect: per HA-managed resource currently on pve-test-1, the JSON
# shows where it would land (highest-priority remaining online node).
```

If you have no HA-managed resources yet, add 9001 to HA via web UI
(Datacenter → HA → Add) and re-run.

**TUI**: open `proxxx`, command palette `:ha` → 3-pane HA console.

---

## 8 — Hardware passthrough (#4)

```bash
proxxx hw pci --node pve-test-1 --format json | jq '.[] | select(.iommugroup >= 0) | {id, iommugroup, vendor_name}'
proxxx hw usb --node pve-test-1
proxxx hw conflicts --node pve-test-1
```

To exercise the conflict detector intentionally:
```bash
# Pick any PCI device address from the listing above
ADDR='0000:00:1f.3'  # adjust to a real address from the listing
ssh root@192.168.0.122 "qm set 9001 --hostpci0 $ADDR"
ssh root@192.168.0.122 "qm set 9001 --hostpci1 $ADDR"  # same address twice → DirectShared

proxxx hw conflicts --node pve-test-1 --format json | jq
# expect: count >= 1, kind: direct_shared, address matches, vmids: [9001]

# Cleanup
ssh root@192.168.0.122 'qm set 9001 --delete hostpci0 --delete hostpci1'
```

**TUI**: from the node list, press `W` on the cursor.

---

## 9 — Patching orchestrator dry-run (#9)

```bash
proxxx patch plan --format json | jq '.nodes[] | {node, kernel_pending, security_pending, reboot_required, packages: (.upgradable | length)}'

# Dry-run: walks state machine, no SSH commands fired against apt
proxxx patch apply --dry-run
# expect: each node transitions Pending → Refresh → Inventory → Done(rebooted=false, packages_upgraded=N)
```

> **DO NOT run `proxxx patch apply` without `--dry-run` on the test cluster
> unless you're prepared for `apt-get -y dist-upgrade` and serial reboots.**
> The orchestrator IS safe (max one node mid-upgrade) but it executes for real.

---

## 10 — Alerting (#8)

Add to `~/.config/proxxx/config.toml`:
```toml
[[alerts]]
name = "node_down"
when = "node_offline"
for_secs = 60
severity = "critical"
route = ["webhook:https://httpbin.org/post"]
dedup_secs = 600

[[alerts]]
name = "storage_full"
when = "storage_above"
threshold_percent = 50  # Lower threshold so it fires on test data
severity = "warning"
route = ["webhook:https://httpbin.org/post"]
```

Test:
```bash
# One-shot evaluation
proxxx alerts eval --format json | jq '.events'

# Stress: reboot pve-test-3 then watch
ssh root@192.168.0.124 'systemctl reboot'
sleep 65  # wait for_secs threshold
proxxx alerts eval --format json | jq '.events'
# expect: an event for rule "node_down" targeting "node:pve-test-3"

# Send a test event end-to-end
proxxx alerts test --route webhook:https://httpbin.org/post --severity info
# expect: status: "sent"; httpbin echoes the JSON payload
```

**TUI watch daemon** (Ctrl+C to stop):
```bash
proxxx alerts watch --interval 30
```

---

## 11 — Access control + token + permissions (#10)

```bash
proxxx access acl --format json | jq
proxxx access users
proxxx access groups
proxxx access roles --format json | jq '.[] | {roleid, privs}'
proxxx access tfa root@pam

# Token CRUD
proxxx token list root@pam
proxxx token create root@pam ci-test --comment "smoke test"
# captures the secret in `value` — printed once
proxxx token list root@pam | jq '.[] | select(.tokenid=="ci-test")'
proxxx token revoke root@pam ci-test --yes

# Effective permissions via SSH shell-out (Option A — pveum)
proxxx perms root@pam --node pve-test-1 --format json | jq '.paths[0:3]'
# expect: paths array with privilege names + propagate flags
```

**✅ pass:** `proxxx perms` output matches `ssh root@192.168.0.122 'pveum user permissions root@pam'` after parsing.

---

## 12 — PBS browse + restore (#3 + BLOCKER 2)

Add the PBS storage to PVE first:
```bash
ssh root@192.168.0.122 'pvesm add pbs pbs-test \
  --server 192.168.0.125 \
  --datastore main \
  --username root@pam \
  --password "$(cat /tmp/pbs-pwd)" \
  --fingerprint "$(ssh root@192.168.0.125 proxmox-backup-manager cert info | grep Fingerprint | head -1 | cut -d: -f2- | xargs)"'
```

(Or do it via the web UI: Datacenter → Storage → Add → Proxmox Backup Server.)

```bash
# Take a backup
ssh root@192.168.0.122 'vzdump 9001 --storage pbs-test --mode stop'

# Browse via proxxx
proxxx pbs datastores
proxxx pbs snapshots --store main --backup-type vm --backup-id 9001
proxxx pbs files \
  --store main --type vm --backup-id 9001 \
  --time <backup-time-from-snapshots-output>

# Restore (requires proxmox-backup-client locally)
which proxmox-backup-client || sudo apt install proxmox-backup-client
mkdir /tmp/proxxx-restore
proxxx pbs restore \
  --store main \
  --snapshot vm/9001/<timestamp> \
  --archive root.pxar.didx \
  --target /tmp/proxxx-restore \
  --yes

# BLOCKER 2 smoke: start a long restore, hit Ctrl+C in another window
# expect: proxxx prints "(received Ctrl+C — killing proxmox-backup-client)"
#         bails with "restore cancelled by Ctrl+C"
ps aux | grep proxmox-backup-client
# expect: no orphaned children

# Cleanup
rm -rf /tmp/proxxx-restore
```

---

## 13 — Console handoff (1a, 1b, 1c)

### 13.1 SSH guest session (#1a)

The Alpine VM 9001 needs SSH installed + DHCP. Boot it via console once,
run `setup-alpine`, install openssh, set a root password, then:

```bash
# Find its DHCP IP from the cluster:
ssh root@192.168.0.122 'qm guest cmd 9001 network-get-interfaces' | jq

# Add to ~/.config/proxxx/config.toml:
# [ssh.guests."9001"]
# host = "<the-VM-ip>"
# user = "root"
# key_path = "~/.ssh/proxxx_homelab"

proxxx
# in TUI: command palette `:ssh 9001`
# expect: PTY view with the VM's shell prompt
# press Ctrl+] to return
```

### 13.2 Serial console via termproxy (#1b)

The Alpine VM doesn't have serial enabled by default. Enable it:
```bash
ssh root@192.168.0.122 'qm set 9001 --serial0 socket'
proxxx restart 9001
sleep 5

# Now connect via termproxy WS
proxxx serial 9001 --node pve-test-1
# Press Ctrl+] then 'q' to disconnect
# expect: terminal restored cleanly
```

### 13.3 SPICE (#1c)

The Alpine ISO doesn't ship a SPICE-aware display. To exercise this,
either skip OR convert to SPICE via web UI: Hardware → Display → Type:
SPICE. Restart, then:

```bash
proxxx spice 9001 --node pve-test-1 --no-launch
# Inspect the .vv file:
stat -f "%Lp" $(proxxx spice 9001 --node pve-test-1 --no-launch | jq -r .vv_file)
# expect: 600 (Unix mode 0600 — password is plaintext inside)
```

### 13.4 noVNC (#1c)

```bash
proxxx novnc 9001 --node pve-test-1
# Browser opens to https://192.168.0.122:8006/?console=kvm&novnc=1&vmid=9001&node=pve-test-1...
# If you're not logged into the Proxmox web UI, you'll be redirected to the login form.
```

---

## 14 — BLOCKER 3 flight recorder smoke

```bash
proxxx dev-panic --message "smoke-test-payload"
echo "exit: $?"
# expect:
#   - stderr contains "💀 proxxx panicked at <file:line>"
#   - stderr contains "[dev-panic] smoke-test-payload"
#   - stderr contains "audit log: ~/.local/share/proxxx (proxxx.log)"
#   - exit code != 0
#   - terminal is normal afterwards (no raw mode artifacts, cursor visible)

# Audit log capture
tail -n 50 ~/.local/share/proxxx/proxxx.*.log | grep -A 2 PANIC
# expect: a tracing entry with target=panic, location, payload
```

---

## 15 — Time-travel cache

```bash
# Make a state change (start a guest)
proxxx start 9002

# Wait for the next tick (5s default poll interval inside the TUI;
# the CLI persists state at the end of `ls guests` etc.)
sleep 6

# Replay the state from 1 minute ago
TS=$(date -u -v-1M +%s)  # macOS; use `date -u -d '1 minute ago' +%s` on Linux
proxxx replay $TS --format json | jq '.guests[] | select(.vmid==9002) | .status'
# expect: the previous status (likely "stopped")

# Watch for changes since 1h ago
proxxx watch --since 1h --format json | jq '.diff'
```

---

## 16 — Cleanup

```bash
# Stop + delete the test guests
proxxx stop 9001 --force
proxxx stop 9002 --force
sleep 5
proxxx delete 9001 9002 --yes

# Revoke the smoke-test API token
ssh root@192.168.0.122 'pveum user token remove root@pam proxxx'
ssh root@192.168.0.125 'proxmox-backup-manager user delete-token root@pam proxxx'

# Drop the PBS storage entry from PVE
ssh root@192.168.0.122 'pvesm remove pbs-test'

# Drop the local cache (optional — frees a few KB)
rm -rf ~/.cache/proxxx

# Remove temp downloads from /tmp
rm -f /tmp/proxxx-spice-*.vv
```

---

## Pass summary

If every section completes without `❌` and:

- §3 audit log shows `/status/shutdown` (NOT `/status/stop`) for graceful stops
- §4 LXC ops succeed (bug #1 verified live)
- §6 curated ISO download is refused (BLOCKER 1)
- §10 a real alert event fires when pve-test-3 reboots
- §12 Ctrl+C during restore leaves no orphan child (BLOCKER 2)
- §13.3 the `.vv` file is mode 0600
- §14 terminal is restored cleanly after panic (BLOCKER 3)
- §11 `proxxx perms` output matches raw `pveum user permissions` (Option A)

…then proxxx is functionally complete against this cluster and ready
to tag.

---

## When something fails

1. Capture the full stderr of the failing command
2. `tail -n 100 ~/.local/share/proxxx/proxxx.*.log`
3. Note the section number from this guide
4. File an issue with:
   - section number
   - command verbatim
   - stderr + audit log excerpt
   - cluster state (`proxxx ls nodes --format json`)
