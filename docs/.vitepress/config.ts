import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'proxxx',
  description: 'Terminal cockpit for Proxmox VE and Backup Server, gated on a real cluster.',
  // Site is hosted at https://fabriziosalmi.github.io/proxxx/ — every
  // asset URL must be prefixed with /proxxx/ for GH Pages routing to
  // resolve correctly. Without this, navigation works but assets
  // (CSS, JS, favicon) 404. The trailing slash IS required (vitepress
  // panics at build time without it).
  base: '/proxxx/',
  cleanUrls: true,
  lastUpdated: true,

  head: [
    // Manual hrefs in `head` bypass vitepress's `base` auto-prefix
    // (it only rewrites URLs that go through the build pipeline).
    // Hard-code the prefix here to match `base` above — without this
    // the favicon 404s on the deployed site.
    ['link', { rel: 'icon', href: '/proxxx/favicon.ico', sizes: 'any' }],
    ['meta', { name: 'theme-color', content: '#2563eb' }],
  ],

  themeConfig: {
    // Pin the logo at an explicit display size so the official brand
    // mark renders at the same dimensions in light + dark themes.
    // Without `width` / `height`, VitePress falls back to the SVG's
    // intrinsic viewBox (or the PNG's pixel size at 1x), which makes
    // a 256-px PNG render as a thumbnail in the navbar.
    logo: { src: '/logo.png', width: 28, height: 28 },

    nav: [
      { text: 'Documentation', link: '/guide/installation', activeMatch: '/guide/' },
      {
        text: 'Reference',
        activeMatch: '/reference/',
        items: [
          { text: 'CLI', link: '/reference/cli' },
          { text: 'TUI', link: '/reference/tui' },
          { text: 'Configuration', link: '/reference/configuration' },
          { text: 'Exit codes', link: '/reference/exit-codes' },
        ],
      },
      {
        text: 'Integrations',
        activeMatch: '/integrations/',
        items: [
          { text: 'Proxmox VE', link: '/integrations/pve' },
          { text: 'Proxmox Backup Server', link: '/integrations/pbs' },
          { text: 'SSH / SPICE / noVNC handoff', link: '/integrations/console' },
          { text: 'HITL via Telegram', link: '/integrations/hitl' },
          { text: 'MCP server', link: '/integrations/mcp' },
          { text: 'Alerts', link: '/integrations/alerts' },
        ],
      },
      { text: 'Architecture', link: '/architecture/overview', activeMatch: '/architecture/' },
      {
        text: 'Releases',
        link: 'https://github.com/fabriziosalmi/proxxx/releases',
      },
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Getting started',
          items: [
            { text: 'Installation', link: '/guide/installation' },
            { text: 'Quick start', link: '/guide/quick-start' },
            { text: 'Configuration', link: '/guide/configuration' },
          ],
        },
        {
          text: 'Operating',
          items: [
            { text: 'Pre-commit gate', link: '/guide/pre-commit-gate' },
            { text: 'Bypass policy', link: '/guide/bypass-policy' },
            { text: 'Troubleshooting', link: '/guide/troubleshooting' },
          ],
        },
      ],
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'CLI', link: '/reference/cli' },
            { text: 'TUI', link: '/reference/tui' },
            { text: 'Configuration schema', link: '/reference/configuration' },
            { text: 'Exit codes', link: '/reference/exit-codes' },
            { text: 'Error categories', link: '/reference/errors' },
          ],
        },
      ],
      '/integrations/': [
        {
          text: 'Integrations',
          items: [
            { text: 'Proxmox VE', link: '/integrations/pve' },
            { text: 'Proxmox Backup Server', link: '/integrations/pbs' },
            { text: 'Console handoff', link: '/integrations/console' },
            { text: 'HITL via Telegram', link: '/integrations/hitl' },
            { text: 'MCP server', link: '/integrations/mcp' },
            { text: 'Alerts', link: '/integrations/alerts' },
          ],
        },
      ],
      '/architecture/': [
        {
          text: 'Architecture',
          items: [
            { text: 'Overview', link: '/architecture/overview' },
            { text: 'Elm pattern', link: '/architecture/elm-pattern' },
            { text: 'Error handling', link: '/architecture/error-handling' },
            { text: 'Security model', link: '/architecture/security' },
          ],
        },
      ],
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/fabriziosalmi/proxxx' },
    ],

    search: { provider: 'local' },

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2026 Fabrizio Salmi',
    },

    outline: { level: [2, 3] },

    docFooter: { prev: 'Previous', next: 'Next' },
  },
})
