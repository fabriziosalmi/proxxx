# Brand assets

Generated from [`../proxxx.png`](../proxxx.png) (1024×1024 source).
Re-run [`build.py`](build.py) after editing the source — the pipeline
is idempotent.

```sh
python3 assets/build.py
```

## What's in here

### `proxxx-transparent.png`

The 1024×1024 source with the white background knocked out
(alpha-falloff on anti-aliased edges, no halo). Drop on any
background. The "neutral" master from which every other variant is
derived.

### `icon/flat-transparent-{N}.png`

Same as above, downscaled with Lanczos to `N ∈ {16, 32, 48, 64, 128,
256, 512, 1024}`. Use when you need a transparent icon at a specific
pixel size and the surrounding container provides shape (e.g. inline
in markdown, alongside body text, in a sidebar widget).

### `icon/round-{N}.png`

Circular crop of the transparent base for `N ∈ {128, 256, 512,
1024}`. Transparent outside the circle, logo inside. Use for avatar
slots, social profile pictures, anywhere a circular viewport is
expected.

### `icon/rounded-square-{N}.png`

iOS-style rounded square (22% corner radius), transparent
background, for `N ∈ {128, 256, 512, 1024}`. Use when the icon
should feel app-icon-shaped but you want the surrounding context to
show through the corners (e.g. floating on a custom gradient).

### `icon/brand-square-{N}.png`

Same iOS-style rounded square but filled with the brand blue
(`#2563eb`) and the logo composited on top, for `N ∈ {256, 512,
1024}`. Use for app stores, app launchers, social-card thumbnails —
anywhere the icon is the only thing onscreen and needs its own
background.

### `icon/apple-touch-icon.png`

180×180, rounded-square shape, transparent. iOS pinned-site icon.
Reference from HTML:

```html
<link rel="apple-touch-icon" href="/icon/apple-touch-icon.png">
```

### `icon/favicon-{16,32,48}.png`

Round crops at low resolution. Browser tabs, bookmark lists.

### `icon/favicon.ico`

Multi-resolution ICO bundle (16, 32, 48). The single file Windows
and legacy browsers expect at the site root. Reference from HTML:

```html
<link rel="icon" type="image/x-icon" href="/favicon.ico">
```

## How the white knockout works

`build.py` does a smooth alpha falloff:

| `min(r, g, b)`     | Resulting alpha |
| :----------------- | :-------------- |
| `≥ 250`            | `0` (transparent) |
| `220 .. 250`       | linear `0 .. 255` |
| `< 220`            | `255` (opaque)  |

The middle band (`220–250`) catches anti-aliased edge pixels — what
would otherwise become a thin white halo around the logo on coloured
backgrounds — and feathers them out. The full-opacity threshold sits
at `220` so a logo with very light grey content survives unaltered.

If your source has off-white grays in the logo body that shouldn't
be transparent, raise `soft` in `build.py`. If it has darker
backgrounds the knockout misses, switch to a content-aware approach
(e.g. `rembg`).

## Where these are used

- **Docs site** ([`docs/public/`](../docs/public/)) — `logo.svg` and
  `favicon.svg` are still hand-authored vector marks. The PNG
  variants here are the raster fallbacks for places SVG can't go
  (Open Graph cards, app stores).
- **GitHub social preview** — upload `brand-square-1024.png` (or
  the equivalent through GitHub's repo settings → Social preview).
- **README badges / inline mark** — any `flat-transparent-{N}.png`
  works inline.
