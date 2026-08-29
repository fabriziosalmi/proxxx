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

  // Emit sitemap.xml at build time. The hostname must carry the
  // /proxxx/ base — vitepress joins it with base-less route paths,
  // so leaving it at the origin would emit URLs that 404 on GH Pages.
  sitemap: {
    hostname: 'https://fabriziosalmi.github.io/proxxx/',
  },

  // Per-page og:url. Crawlers treat og:url as the canonical URL, so a
  // single global value would advertise every subpage as the homepage;
  // this derives the canonical from the page path instead (cleanUrls
  // form: strip .md, collapse index to the directory root).
  transformPageData(pageData) {
    const canonical =
      'https://fabriziosalmi.github.io/proxxx/' +
      pageData.relativePath.replace(/(^|\/)index\.md$/, '$1').replace(/\.md$/, '')
    pageData.frontmatter.head ??= []
    pageData.frontmatter.head.push(['meta', { property: 'og:url', content: canonical }])
  },

  head: [
    // Everything this site loads is first-party. 'unsafe-inline' is required
    // because VitePress emits an inline appearance script and inline styles.
    // Applied to the built site only: `vitepress dev` serves HMR over a
    // websocket, which a strict connect-src would block as soon as the dev
    // server is not same-origin (--host, or a custom server.hmr.port).
    ...(process.env.NODE_ENV === 'production'
      ? [
          [
            'meta',
            {
              'http-equiv': 'Content-Security-Policy',
              content:
                "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
                "font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'",
            },
          ] as [string, Record<string, string>],
        ]
      : []),
    // Manual hrefs in `head` bypass vitepress's `base` auto-prefix
    // (it only rewrites URLs that go through the build pipeline).
    // Hard-code the prefix here to match `base` above — without this
    // the favicon 404s on the deployed site.
    ['link', { rel: 'icon', href: '/proxxx/favicon.ico', sizes: 'any' }],
    ['meta', { name: 'theme-color', content: '#2563eb' }],
    // Social cards. Absolute URLs on purpose: og:image/og:url must be
    // absolute per the OG spec, and absolute hrefs also sidestep the
    // base-prefix pitfall described above.
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'proxxx' }],
    ['meta', { property: 'og:title', content: 'proxxx — terminal cockpit for Proxmox VE & PBS' }],
    [
      'meta',
      {
        property: 'og:description',
        content: 'Terminal cockpit for Proxmox VE and Backup Server, gated on a real cluster.',
      },
    ],
    ['meta', { property: 'og:image', content: 'https://fabriziosalmi.github.io/proxxx/proxxx-overview.jpg' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:image', content: 'https://fabriziosalmi.github.io/proxxx/proxxx-overview.jpg' }],
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
          text: 'Quickstarts by persona',
          items: [
            { text: 'Homelab in 5 min', link: '/guide/quickstart-homelab' },
            { text: 'LLM / MCP server', link: '/guide/quickstart-llm-mcp' },
          ],
        },
        {
          text: 'Operating',
          items: [
            { text: 'Production checklist', link: '/guide/production-checklist' },
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
      message: 
        'Released under the MIT License. · <a href="https://fabriziosalmi.github.io/privacy">Privacy &amp; legal</a>',
      copyright: 'Copyright © 2026 Fabrizio Salmi',
    },

    outline: { level: [2, 3] },

    docFooter: { prev: 'Previous', next: 'Next' },
  },
})
