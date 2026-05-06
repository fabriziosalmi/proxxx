---
layout: home

hero:
  name: proxxx
  text: Terminal cockpit for Proxmox VE & PBS.
  tagline: A Rust TUI and CLI that talks to real Proxmox clusters. REST against PVE and PBS, SSH for the rest. No agent on the cluster.
  # Mirrors the README hero infographic (assets/proxxx-overview.jpg).
  # vitepress's home layout slots `image.src` to the right of the
  # headline + tagline + actions; `base: /proxxx/` from .vitepress/
  # config.ts auto-prefixes the URL at build time, so we write the
  # path as if served from the site root.
  image:
    src: /proxxx-overview.jpg
    alt: proxxx overview — six panels covering installation, authentication wizard, cluster navigation, pre-flight risk gate, HITL approval workflow, and the contributor quality gate
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
  - title: One binary, three callers
    details: CLI, TUI, and MCP server in the same executable. Same risk gate, same HITL gate, same API client. The TUI is for interactive operations; the CLI is the same operations, scriptable, JSON-friendly, and CI-ready; the MCP surface is a deterministic 10-tool registry for LLM agents.
  - title: No agent on the cluster
    details: Direct REST against PVE (token or password) and PBS (token only), with typed error categories so callers match on the failure shape instead of grepping prose. SSH only for the paths PVE never exposed over REST — patch apply, full effective-permissions, per-guest interactive sessions.
  - title: Six-stage commit gate, no skip flags
    details: cargo fmt, cargo clippy --all-targets at deny tier, cargo audit against a pinned advisory policy, the full test suite, 88 read-only probes against a live cluster, and a full mutation lifecycle covering LXC, cluster-level CRUD, QEMU, and opt-in QGA agent-required round-trips. Every commit on main passes locally and in CI.
  - title: Pre-flight risk gate plus HITL
    details: 11 risk variants — running, locked, HA-managed, tagged prod, listening on service, no recent backup — refuse destructive operations on guests that look like production unless overridden explicitly. Above that, a real Telegram round-trip with deny-on-timeout for any op marked destructive by policy.
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
          c.textContent = ch === ' ' ? ' ' : ch
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
  <span><strong>v0.1.7</strong></span>
  <span><strong>full mutation lifecycle</strong> · LXC + cluster + QEMU + QGA</span>
  <span><strong>0</strong> system deps · rustls only</span>
  <span><strong>MIT</strong></span>
</div>

## By the numbers

| Surface               | Today                                                    |
| :-------------------- | :------------------------------------------------------- |
| Source                | ~28 KLOC Rust · ~5 KLOC tests                            |
| Quality gate          | 6 stages · ~80–260 s wall time                           |
| Live cluster coverage | 88 read probes + full mutation lifecycle per gate run    |
| Mutation lifecycle    | LXC create→start→snapshot→stop→delete · cluster-level CRUD (pool / firewall-cluster / backup-jobs / notifications / storage-defs) · QEMU 9998 from alpine ISO · opt-in QGA round-trips |
| Binary                | 6–9 MB stripped depending on target · single static · no installer |
| Supply chain          | `cargo audit --deny warnings` per push + nightly cron    |
| System dependencies   | 0 — rustls only, no native-tls, no openssl               |
| MCP tool registry     | 10 tools · SHA-256 pinned · compile-time fixed           |

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
proxxx migrate 100 pve2 --yes
proxxx snapshot create 100 --name pre-upgrade
proxxx disk move 100 --disk scsi0 --storage ceph-rbd --yes
proxxx patch apply --reboot=auto --dry-run

# Hand off to a graphical client
proxxx ssh    100                       # interactive SSH into the guest (system ssh)
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
