# Console handoff

Four ways to get into a guest, from text-only to graphical. The right
one depends on whether the network is up, whether the agent is up,
whether you want graphics, and whether you trust the local machine
with a graphical client.

| Path | Transport | Renders here | Needs |
| :--- | :--- | :--- | :--- |
| `proxxx ssh`    | russh PTY        | yes (vt100) | guest network up + SSH server in guest |
| `proxxx serial` | termproxy WebSocket | yes (raw)| serial console enabled in guest |
| `proxxx spice`  | SPICE over TLS   | external    | `remote-viewer` / `virt-viewer` on local machine |
| `proxxx novnc`  | HTML5 VNC        | external    | system browser + active web UI session |

## `proxxx ssh <vmid>` — the main daily driver

russh-based, publickey only, no passphrase prompt. Per-guest SSH
target lives in config:

```toml
[ssh.guests."100"]
host = "10.10.10.100"
user = "fab"

[ssh]
key  = "/home/fab/.ssh/proxxx_homelab"   # falls back here for any guest without per-guest key
```

Inside the TUI, press `c` on a selected guest, or run `:ssh 100` in
the command palette. From the CLI:

```sh
proxxx ssh 100
```

Exit chord: `Ctrl+]`. All other keys forward to the remote PTY,
including `Ctrl+C`, `Ctrl+D`, `Ctrl+Z`. Resize is forwarded
on `crossterm::Resize`.

### TOFU host keys

proxxx maintains a dedicated `known_hosts` at
`$XDG_CONFIG_HOME/proxxx/known_hosts` — separate from your
`~/.ssh/known_hosts`. First connect logs the fingerprint with a
warning and accepts; subsequent connects refuse on mismatch.

This is intentional: proxxx's threat model assumes the user uses a
dedicated key for proxxx (declared in `[ssh].key`) and that the
known_hosts file is auditable separately.

### Encrypted private keys

If your SSH key is passphrase-protected, set
`PROXXX_SSH_KEY_PASSPHRASE`. proxxx never prompts interactively for
a passphrase — it would block the TUI's event loop.

## `proxxx serial <vmid>` — recovery console

Raw termproxy over WebSocket, useful when:

- The guest's network is down
- The guest agent is dead
- The guest is stuck at the bootloader
- You're recovering a misconfigured `/etc/network/interfaces`

```sh
proxxx serial 100 --node pve1
```

Auto-detects QEMU vs LXC if `--kind` is omitted. Puts the local
terminal in raw mode + alternate screen. Exit: `Ctrl+]` then `q`
(telnet-style chord; any other key after `Ctrl+]` forwards `Ctrl+]`
to the remote).

The `verify_tls = false` flag in your profile mirrors into the
WebSocket TLS verifier — `wsterm::tls::dangerous_no_verify_config`
respects the same homelab self-signed allowance as the REST client.

## `proxxx spice <vmid>` — graphical, QEMU only

```sh
proxxx spice 100 --node pve1                   # writes .vv, launches remote-viewer
proxxx spice 100 --node pve1 --write-vv /tmp   # write but don't launch
proxxx spice 100 --node pve1 --no-launch       # write to default temp path, don't launch
```

The flow:

1. POST `/nodes/{node}/qemu/{vmid}/spiceproxy` to PVE.
2. Render the response as a `.vv` virt-viewer ConfigFile (INI format
   with `[virt-viewer]` section).
3. Write atomically with **mode 0600 + O_EXCL** to a randomly-named
   temp file (TOCTOU-safe, Vector 2 audit).
4. `spawn` the first available of: `remote-viewer`, `virt-viewer`,
   system default `.vv` handler.

`.vv` files contain the SPICE password in plaintext. Mode 0600
restricts read to the owning user. virt-viewer respects PVE's
`delete-this-file=1` directive and removes the file after connecting.

## `proxxx novnc <vmid>` — graphical, browser

```sh
proxxx novnc 100 --node pve1
```

Builds a deep-link URL to PVE's web UI noVNC console:

```
https://pve1.lan:8006/?console=kvm&novnc=1&vmid=100&node=pve1&resize=scale
```

(or `console=lxc` for containers) and opens it via `xdg-open`,
`open`, or `cmd /C start`.

::: warning
The user must **already be logged into the Proxmox web UI** in the
browser. proxxx does not inject a session ticket into the URL — that
pattern leaks tokens via browser history, screen capture, and shell
history. If you want unattended browser-side access, look at PVE's
own ticket flow, not proxxx.
:::

## Why no in-TUI graphics

ratatui renders text. Proper SPICE / VNC needs pixel buffers, audio
sync, USB redirection, clipboard sharing. Even text-mode VNC clients
(`vncviewer`'s text mode) are a fraction of what `remote-viewer`
provides. The handoff approach is correct: proxxx coordinates, the
graphical client renders.

## Per-platform launcher

```rust
// src/handoff/launcher.rs
fn open_with_default(url: &str) {
    let cmd = if cfg!(target_os = "macos") { "open" }
              else if cfg!(target_os = "windows") { "cmd /C start \"\"" }
              else { "xdg-open" };
    Command::new(cmd).arg(url).spawn();
}
```

No `opener` crate dependency — three lines, two `cfg!` arms, audit-friendly.

## See also

- [BLOCKER 2 — restore subprocess supervision](/architecture/security#pbs-restore-supervision)
- [Vector 2 audit — TOCTOU-safe `.vv`](/architecture/security#spice-vv-handoff)
- [Configuration → `[ssh]`](/reference/configuration#ssh-top-level-default)
