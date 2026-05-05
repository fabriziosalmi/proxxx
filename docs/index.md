---
layout: home

hero:
  name: proxxx
  text: Terminal cockpit for Proxmox VE & PBS.
  tagline: A Rust TUI and CLI that talks to real Proxmox clusters. Every commit is gated against fmt, clippy, audit, 600+ tests and a live LXC mutation lifecycle. Nothing ships unverified.
  image:
    src: /screenshot.png
    alt: proxxx TUI dashboard
  actions:
    - theme: brand
      text: Get started
      link: /guide/installation
    - theme: alt
      text: Quick start
      link: /guide/quick-start
    - theme: alt
      text: GitHub
      link: https://github.com/fabriziosalmi/proxxx

features:
  - title: 01 — Six-stage commit gate
    details: cargo fmt, clippy --all-targets, cargo audit against a pinned advisory policy, 600+ unit and integration tests, read-only live cluster probes, and a full LXC 9999 mutation lifecycle. Either every stage passes, or the commit does not land.
  - title: 02 — TUI and CLI in one binary
    details: A 6 MB single static binary. 18 TUI views over the same Elm-pattern reducer that backs 65 CLI subcommands. The TUI is for interactive operations; the CLI is the same operations, scriptable, JSON-friendly, and CI-ready.
  - title: 03 — Native PVE and PBS clients
    details: Direct REST against PVE (token or password) and PBS (token only). Typed error categories — Unauthorized, Forbidden, NotFound, RateLimited, StorageHang, Transport, Schema — so callers can match on the failure shape instead of grepping prose.
  - title: 04 — Console handoff that works
    details: Native russh SSH session, SPICE handoff via remote-viewer or virt-viewer, noVNC handoff via the system browser, and command execution via QEMU Guest Agent or LXC exec. SPICE .vv files written O_EXCL with mode 0600 atomically.
  - title: 05 — HITL approval flow
    details: Destructive operations are gated behind a real Telegram round trip. The request is queued, an admin replies in chat, proxxx executes only on confirmation. Deny-on-timeout, deny-when-Telegram-unconfigured, no silent bypass.
  - title: 06 — MCP server, alerts, pre-flight risk
    details: A stdio MCP server exposes proxxx operations to LLM agents. Alert routing via ntfy, Telegram, or webhook with a TOML route table. A pre-flight risk gate stops you from deleting prod by accident — running, HA-managed, sticky-locked, no-recent-backup all surface before you confirm.
---

<script setup>
import { onMounted } from 'vue'

// Char-by-char compose for the status row. Splits each top-level
// segment span into per-character inline-block spans with staggered
// animation-delay. Idempotent (skips already-processed rows so SPA
// re-mount doesn't double-split). Honours prefers-reduced-motion.
onMounted(() => {
  if (typeof document === 'undefined') return
  if (window.matchMedia &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    const row = document.querySelector('.status-row')
    if (row) row.classList.add('ready')
    return
  }
  const row = document.querySelector('.status-row:not(.ready)')
  if (!row) return

  let i = 0
  // Walk every descendant text node of the status-row and replace
  // each character with a <span class="char"> carrying its global
  // index as a custom property `--i`. CSS uses `--i` to drive both
  // the compose stagger AND the metallic shine wave — so the L→R
  // sweep is a true per-glyph luminance pass, not a rectangular
  // overlay. Structural elements (<strong>, <span class="ok">) are
  // preserved.
  const splitNode = (node) => {
    const children = Array.from(node.childNodes)
    for (const child of children) {
      if (child.nodeType === Node.TEXT_NODE) {
        const text = child.textContent
        const frag = document.createDocumentFragment()
        for (const ch of Array.from(text)) {
          const c = document.createElement('span')
          c.className = 'char'
          c.textContent = ch === ' ' ? ' ' : ch
          c.style.setProperty('--i', i)
          frag.appendChild(c)
          i++
        }
        node.replaceChild(frag, child)
      } else if (child.nodeType === Node.ELEMENT_NODE) {
        splitNode(child)
      }
    }
  }
  splitNode(row)

  // Reveal the row in the next frame so the first char's
  // animation-delay is honoured from a clean baseline.
  requestAnimationFrame(() => {
    row.classList.add('ready')
  })
})
</script>

<div class="vp-doc home-postscript">

<div class="status-row">
  <span><span class="ok">●</span> <strong>main</strong> · gate green</span>
  <span><strong>v0.1.0</strong> · pre-release</span>
  <span><strong>608</strong> tests · 16 binaries</span>
  <span><strong>38/38</strong> live probes</span>
  <span><strong>~6.5 MB</strong> stripped · 0 system deps</span>
</div>

## By the numbers

| Surface               | Today                                          |
| :-------------------- | :--------------------------------------------- |
| Source                | ~28 KLOC Rust · ~5 KLOC tests                  |
| Quality gate          | 6 stages · ~10–90 s wall time                  |
| Tests                 | 608 across 16 binaries · 0 failing             |
| Live cluster coverage | 38/38 read-only probes · full LXC lifecycle    |
| Binary                | ~6.5 MB stripped · single static · no installer |
| Supply chain          | `cargo audit --deny warnings` per push + cron  |
| System dependencies   | 0 — rustls only, no native-tls, no openssl     |
| MCP tool registry     | 10 tools · SHA-256 pinned · compile-time fixed |

## A taste

```bash
# Read the cluster
proxxx ls nodes
proxxx ls guests --format json | jq '.[] | select(.status == "running")'
proxxx ha preview --node pve1
proxxx hw conflicts --node pve1
proxxx perms root@pam --node pve1

# Operate it (with consent)
proxxx start 100 101 102
proxxx delete 100 --yes
proxxx snapshot create 100 --name pre-upgrade
proxxx disk move 100 --disk scsi0 --storage ceph-rbd --yes
proxxx patch apply --reboot=auto --dry-run

# Hand off to a graphical client
proxxx ssh    100                       # russh PTY
proxxx serial 100 --node pve1           # raw termproxy WebSocket
proxxx spice  100 --node pve1           # writes .vv (0600), launches remote-viewer
proxxx novnc  100 --node pve1           # opens browser to web UI's noVNC

# Drive it from an LLM
proxxx mcp serve                        # stdio JSON-RPC server
proxxx mcp tools --checksum             # registry hash for audit
```

## What it is not

proxxx does not replace the Proxmox web UI. It is built for the workflows where the web UI is slow, repetitive, or unreachable from a terminal-only context. It does not render graphical SPICE or VNC frames — those hand off to `remote-viewer` and the system browser. It is not a Perl rewrite — when ground truth lives in `pveum`, proxxx shells out, parses, and stays out of the way.

## Where to start

- **First time?** Read the [installation guide](/guide/installation), then [quick start](/guide/quick-start).
- **Setting up a cluster?** [Configuration](/guide/configuration) covers profiles, secret resolution, TLS, and HITL policies.
- **Wiring an LLM agent?** [MCP server](/integrations/mcp) describes the deterministic stdio tool surface.
- **Running in CI?** [CLI reference](/reference/cli) plus [exit codes](/reference/exit-codes) plus [error categories](/reference/errors).
- **Threat-modelling?** [Security model](/architecture/security) and [pre-commit gate](/guide/pre-commit-gate).

</div>

<style scoped>
.VPHome .container {
  max-width: var(--vp-layout-max-width);
}
.home-postscript {
  max-width: 980px;
  margin: 88px auto 0;
  padding: 0 24px 120px;
}
.home-postscript h2 {
  font-size: 22px;
  font-weight: 600;
  letter-spacing: -0.015em;
  margin-top: 64px;
  padding-top: 40px;
  border-top: 1px solid var(--vp-c-divider);
}
.home-postscript h2:first-of-type {
  margin-top: 0;
  padding-top: 0;
  border-top: none;
}
</style>
