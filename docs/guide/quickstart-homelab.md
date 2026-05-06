# Quickstart: Homelab in 5 minutes

You have one Proxmox node (or two or three), a few VMs, a router
that doesn't fight you, and 5 minutes. By the end you'll be running
`proxxx` against the cluster from your laptop.

::: tip
This is the **homelab path**. If you're deploying for a team,
start at [Production checklist](/guide/production-checklist)
instead — it's stricter on TLS, secret storage, and HITL.
:::

## 1. Install the binary (1 min)

```bash
TARGET=aarch64-apple-darwin   # macOS Apple Silicon
# TARGET=x86_64-unknown-linux-musl  # Linux
gh release download \
  --repo fabriziosalmi/proxxx \
  --pattern "*-${TARGET}.tar.gz" \
  --pattern "*-${TARGET}.tar.gz.sha256"
shasum -a 256 -c proxxx-*-${TARGET}.tar.gz.sha256
tar xzf proxxx-*-${TARGET}.tar.gz
sudo mv proxxx-*/proxxx /usr/local/bin/
proxxx --version
```

If you'd rather build from source: `cargo install --path .` from
a clone.

## 2. Mint a token on the node (1 min)

In the PVE web UI: **Datacenter → Permissions → API Tokens →
Add**. Untick "Privilege Separation" (homelabs rarely need it),
copy the secret immediately — PVE shows it once.

Or from the node's shell:

```bash
ssh root@<node>
pveum user token add root@pam proxxx --privsep=0
# → token id: proxxx@pve!proxxx
# → secret  : <uuid>     # save this
```

## 3. Run the wizard (2 min)

```bash
proxxx init --interactive
```

Five prompts:

| Step | Pick | Why |
| :--- | :--- | :--- |
| 1. URL | `https://<node>:8006` | Your PVE host |
| 2. Verify TLS | `n` | Self-signed cert in homelabs is normal |
| 3. Auth method | `1` (token) | Pasta the full `user!id=secret` string |
| 4. SSH | skip (`n`) | Add later only if you'll run `proxxx perms` |
| 5. Telegram HITL | skip (`n`) | Solo operator = implicit consent |

The wizard probes the cluster live at each step — wrong token
gets caught at the prompt, never lands in TOML.

## 4. Drive it (1 min)

```bash
proxxx ls nodes
proxxx ls guests
proxxx                  # TUI mode — vim keys, ? for help
```

In the TUI:

- `g` → guest list
- `j/k` → up/down
- `Enter` → detail
- `s` / `S` / `r` → start / stop / restart selected
- `c` → SSH session (needs `[ssh.guests."<vmid>"]` or QGA agent)
- `Esc` → back, `q` → quit
- `?` → keymap reference

Bottom row footer shows the relevant binds for the current view.

## 5. Where next

| You want to… | Read… |
| :--- | :--- |
| Snapshot before risky changes | `proxxx snapshot create <vmid> --name pre-upgrade` |
| Migrate a VM between nodes | `proxxx migrate <vmid> <target> --yes` |
| Move a disk to NFS | `proxxx disk move <vmid> --disk scsi0 --storage <nfs> --yes` |
| Browse PBS backups | [PBS integration](/integrations/pbs) |
| Hook Claude / Cursor in | [MCP server](/integrations/mcp) (5-min setup) |
| Get Telegram approvals | [HITL](/integrations/hitl) (more involved) |

## Common stumbles

| Error | Fix |
| :--- | :--- |
| `Token secret not found` | Re-run wizard; the inline `token_secret = ` is the simplest. |
| `Identity file not accessible` (SSH wizard) | The wizard auto-discovers keys in `~/.ssh/` from v0.1.3 — pick the right one from the list. |
| `proxxx ssh <vmid>` says "no [ssh.guests…]" | Either install `qemu-guest-agent` in the guest (auto-discovery resolves IP) or pin the host in `[ssh.guests."<vmid>"]`. |

Full list at [Troubleshooting](/guide/troubleshooting).
