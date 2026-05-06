// @ts-expect-error — `medium-zoom` ships its own bundled types but
// vitepress's bundled tsconfig doesn't pick them up under SSR.
import mediumZoom from 'medium-zoom'
import { onMounted, watch, nextTick } from 'vue'
import { useRoute } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import './style.css'

// Click-to-zoom for content images. Why: the home-page hero
// embeds a 6-panel infographic that's unreadable at the slot's
// rendered size — operators need to zoom in to read the labels.
// Vitepress doesn't ship a built-in lightbox; medium-zoom is
// the canonical recipe (~3 KB, no Vue requirement, lazy-init).
//
// Selector strategy: `.VPHero img` covers the home-page hero
// slot; `.vp-doc img` covers article content (any future
// /guide/ or /reference/ screenshot benefits automatically).
// `.VPNavBar img` (the navbar logo) is intentionally excluded
// — clicking the brand mark in the corner shouldn't zoom it.
//
// SSR-safety: vitepress's `setup()` runs on the client only
// after mount; medium-zoom touches the DOM, so we gate the
// init in `onMounted`. The route watcher re-binds after every
// SPA navigation since vitepress swaps the DOM tree.
export default {
  ...DefaultTheme,
  setup() {
    const route = useRoute()
    const initZoom = () => {
      mediumZoom('.VPHero img, .vp-doc img', {
        // Backdrop matches the page background so the zoom feels
        // like the image inflating in place rather than a popup.
        background: 'var(--vp-c-bg)',
        // Generous margin so the zoomed image doesn't touch the
        // viewport edges on smaller windows.
        margin: 24,
      })
    }
    onMounted(() => {
      initZoom()
    })
    watch(
      () => route.path,
      () => nextTick(() => initZoom()),
    )
  },
}
