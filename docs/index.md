---
layout: home

hero:
  text: Terminal cockpit for Proxmox VE & PBS.
  tagline: A Rust TUI and CLI that talks to real Proxmox clusters. REST against PVE and PBS, SSH for the rest. No agent on the cluster.
  # Animated SVG slideshow mirroring the README hero (assets/demo.svg).
  # vitepress's home layout slots `image.src` to the right of the
  # headline + tagline + actions; `base: /proxxx/` from .vitepress/
  # config.ts auto-prefixes the URL at build time, so we write the
  # path as if served from the site root.
  image:
    src: /demo.svg
    alt: proxxx animated demo — a destructive command refused by the pre-flight risk gate, approved via Telegram HITL, then executed
  actions:
    - theme: brand
      text: Install in 60 s
      link: /guide/installation
    - theme: alt
      text: 5-min quickstart
      link: /guide/quick-start
    - theme: alt
      text: GitHub
      link: https://github.com/fabriziosalmi/proxxx

features:
  - title: One binary, four surfaces
    details: CLI, TUI, MCP server (stdio + Streamable HTTP/SSE with server-sent cluster-event notifications), and a unified `daemon serve` mode in the same executable. Same risk gate, same HITL gate, same API client. The TUI is for interactive operations; the CLI is the same operations, scriptable, JSON-friendly, and CI-ready; the MCP surface is a deterministic 25-tool registry for LLM agents; the daemon folds alerts + HITL listener + interval scheduler into one SIGTERM-clean process.
  - title: No agent on the cluster
    details: Direct REST against PVE (token or password) and PBS (token only), with typed error categories so callers match on the failure shape instead of grepping prose. SSH only for the paths PVE never exposed over REST — patch apply, full effective-permissions, per-guest interactive sessions, per-node journalctl tailing, GPU/IOMMU readiness probing.
  - title: Eight-stage commit gate, no skip flags
    details: secret-shape scan, cargo fmt, cargo clippy --all-targets at deny tier, cargo audit against a pinned advisory policy, cargo deny check (license whitelist + banned crates + crates.io-only sources + wildcard ban), the full test suite (536 lib tests + 49 new integration tests (error-handling + resilience-chaos sweeps) including ~25 proptest properties at 256 random cases each, ~6 400 invariant checks total), 87 read-only probes against a live cluster, and a full mutation lifecycle covering LXC, cluster-level CRUD, QEMU, and opt-in QGA agent-required round-trips. Every commit on main passes locally and in CI.
  - title: Pre-flight risk gate plus HITL
    details: 11 risk variants — running, long-uptime, locked, HA-managed, tagged prod, active net traffic, listening on service, many snapshots, backup age warning, no backup found, deep-check skipped — refuse destructive operations on guests that look like production unless overridden explicitly. Above that, a real Telegram round-trip with deny-on-timeout for any op marked destructive by policy. The same gate fires on `state apply` for non-empty pool deletes, root-role ACL deletes, shared-storage removal, and batches ≥ 50.
  - title: GitOps loop for Proxmox
    details: '`proxxx state export` → `proxxx state diff` → `proxxx state apply` over pools, ACL grants, and cluster storage definitions. Byte-stable TOML snapshots, structural diff with exit code 2 on drift (CI-gateable), and a converge step with `--dry-run`, `--prune`, `--continue-on-error`, `--allow-risk`, and `--interactive` per-Severe stdin prompts.'
  - title: Incident lockdown
    details: '`proxxx incident freeze` raises a cluster-wide write kill-switch with TTL + audit log. Every `POST`/`PUT`/`DELETE` is refused with typed `FreezeRefusal` → exit code 8 until `proxxx incident thaw` or the TTL fires. Reads keep working. Designed for the "stop the bleeding" minute.'
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
  <span><strong>v0.2.1</strong></span>
  <span><strong>full mutation lifecycle</strong> · LXC + cluster + QEMU + QGA</span>
  <span><strong>0</strong> system deps · rustls only</span>
  <span><strong>MIT</strong></span>
</div>

## By the numbers

| Surface               | Today                                                    |
| :-------------------- | :------------------------------------------------------- |
| Source                | ~60 KLOC Rust · ~14 KLOC tests · 536 lib tests + 49 new integration tests (error-handling + resilience-chaos sweeps)           |
| Quality gate          | 8 stages · ~340–480 s wall time (live cluster path)      |
| Live cluster coverage | 87 read probes + 47 mutation probes per gate run         |
| Property testing      | ~25 proptest properties × 256 random cases = ~6 400 invariant checks per `cargo test` |
| Mutation lifecycle    | LXC create→start→snapshot→stop→delete · cluster-level CRUD (pool / firewall-cluster / backup-jobs / notifications / storage-defs) · QEMU 9998 from alpine ISO · opt-in QGA round-trips |
| Binary                | 6–9 MB stripped depending on target · single static · no installer |
| Supply chain          | `cargo audit --deny warnings` + `cargo deny check` per push + nightly cron + CodeQL Rust SAST |
| System dependencies   | 0 — rustls only, no native-tls, no openssl (banned in `deny.toml`) |
| MCP surface           | 25-tool registry · stdio + HTTP · compile-time fixed · server-sent `notifications/cluster-event` over both transports |
| Exit code contract    | 9 stable codes (0–8) — see [exit-codes](/reference/exit-codes) |

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
proxxx snapshot rollback 100 --name pre-upgrade --yes
proxxx disk move 100 --disk scsi0 --storage ceph-rbd --yes
proxxx patch apply --reboot=auto --dry-run

# Hand off to a graphical client
proxxx ssh    100                       # interactive SSH into the guest (system ssh)
proxxx serial 100 --node pve1           # raw termproxy WebSocket
proxxx spice  100 --node pve1           # writes .vv (0600), launches remote-viewer
proxxx novnc  100 --node pve1           # opens browser to web UI's noVNC

# GitOps loop over pools / ACLs / cluster storage
proxxx state export > cluster.toml      # byte-stable TOML snapshot
proxxx state diff cluster.toml          # exit 2 if drift (CI-gateable)
proxxx state apply cluster.toml --dry-run
proxxx state apply cluster.toml --prune --interactive

# Incident lockdown (writes refused with exit 8 until thaw)
proxxx incident freeze --ttl 1h --reason "ceph osd flapping"
proxxx incident status
proxxx incident thaw

# Cross-cluster fanout (read-only)
proxxx ls guests --all-profiles --format json
proxxx find 100                          # which profile owns this vmid
proxxx describe --output llm-context     # paste at the top of an LLM chat

# Observability + chargeback
proxxx logs tail --service pveproxy --since "1h ago" --grep error
proxxx upgrade-check --target 9.x        # exit 1 on any block-severity finding
proxxx accounting --group-by pool --timeframe month
proxxx heatmap                           # per-node API RTT
proxxx anomaly                           # z-score outliers
proxxx backup-verify --max-age-days 7

# Drive it from an LLM
proxxx mcp serve                        # stdio JSON-RPC + cluster-event notifications
proxxx mcp serve-http --bind 127.0.0.1:8765   # HTTP/SSE + cluster-event notifications
proxxx mcp tools --checksum             # registry hash for audit

# Long-running daemon (alerts + HITL + scheduler under one SIGTERM)
proxxx daemon serve
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
