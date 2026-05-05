#!/usr/bin/env python3
"""
proxxx asset generator.

Reads ../proxxx.png (1024x1024, white-bg RGB) and produces a full set
of icon variants under ./icon/:

  - flat-transparent-{16,32,48,64,128,256,512,1024}.png
        White background knocked out with smooth alpha on anti-aliased
        edges. The "neutral" variant — drop on any background.

  - round-{128,256,512,1024}.png
        Circular crop of the transparent base. Transparent outside the
        circle; logo inside. Use for avatar slots, social profiles.

  - rounded-square-{128,256,512,1024}.png
        Square with iOS-style rounded corners (22% radius), transparent.
        Logo inside the rounded square. Use where you want the icon to
        feel "app-icon-shaped" but transparent outside.

  - brand-square-{256,512,1024}.png
        Same rounded square but filled with the brand blue (#2563eb).
        Logo composited on top. Use for app stores / app launcher.

  - apple-touch-icon.png (180x180)
        rounded-square shape, transparent. iOS pinned site icon.

  - favicon-{16,32,48}.png
        Round crops, low-res. Browser tab.

  - favicon.ico
        Multi-resolution ICO (16/32/48). The single file Windows /
        legacy browsers expect at /favicon.ico.

Idempotent: re-run after editing the source PNG to refresh everything.
"""

from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent
SRC = ROOT.parent / "proxxx.png"
OUT = ROOT / "icon"
OUT.mkdir(parents=True, exist_ok=True)

BRAND = (37, 99, 235, 255)  # var(--vp-c-brand-1) from the docs theme


def knockout_white(img: Image.Image,
                   hard: int = 250,
                   soft: int = 220) -> Image.Image:
    """White → transparent, with smooth falloff on anti-aliased edges.

    hard : pixels with min(r,g,b) >= hard become fully transparent.
    soft : pixels with min(r,g,b) in [soft, hard] get partial alpha,
           so anti-aliased glyph edges don't develop a halo.
    """
    img = img.convert("RGBA")
    data = []
    for r, g, b, _ in img.getdata():
        m = min(r, g, b)
        if m >= hard:
            data.append((r, g, b, 0))
        elif m >= soft:
            alpha = int((hard - m) / (hard - soft) * 255)
            data.append((r, g, b, alpha))
        else:
            data.append((r, g, b, 255))
    out = Image.new("RGBA", img.size)
    out.putdata(data)
    return out


def round_mask(size: int) -> Image.Image:
    m = Image.new("L", (size, size), 0)
    ImageDraw.Draw(m).ellipse([(0, 0), (size - 1, size - 1)], fill=255)
    return m


def rounded_square_mask(size: int, radius_pct: float = 0.22) -> Image.Image:
    radius = int(size * radius_pct)
    m = Image.new("L", (size, size), 0)
    ImageDraw.Draw(m).rounded_rectangle(
        [(0, 0), (size - 1, size - 1)], radius=radius, fill=255
    )
    return m


def apply_mask(base: Image.Image, mask: Image.Image) -> Image.Image:
    out = Image.new("RGBA", base.size, (0, 0, 0, 0))
    out.paste(base, (0, 0), mask)
    return out


def composite_on_brand(transparent_logo: Image.Image, size: int) -> Image.Image:
    """Brand-blue rounded square with the transparent logo on top."""
    mask = rounded_square_mask(size)
    bg = apply_mask(Image.new("RGBA", (size, size), BRAND), mask)
    logo = transparent_logo.resize((size, size), Image.LANCZOS)
    composed = Image.alpha_composite(bg, logo)
    # Re-mask so anything escaping the rounded edge is clipped.
    return apply_mask(composed, mask)


def main() -> None:
    if not SRC.exists():
        raise SystemExit(f"source not found: {SRC}")

    print(f"reading {SRC.relative_to(ROOT.parent)}")
    src = Image.open(SRC)
    print(f"  source: mode={src.mode}, size={src.size}")

    transparent = knockout_white(src)
    transparent_path = ROOT / "proxxx-transparent.png"
    transparent.save(transparent_path)
    print(f"  wrote   {transparent_path.relative_to(ROOT.parent)}")

    # --- Flat transparent (the neutral set) -----------------------
    for sz in (16, 32, 48, 64, 128, 256, 512, 1024):
        out = OUT / f"flat-transparent-{sz}.png"
        transparent.resize((sz, sz), Image.LANCZOS).save(out)
        print(f"  wrote   {out.relative_to(ROOT.parent)}")

    # --- Round (circular crop, transparent outside) ----------------
    for sz in (128, 256, 512, 1024):
        out = OUT / f"round-{sz}.png"
        base = transparent.resize((sz, sz), Image.LANCZOS)
        apply_mask(base, round_mask(sz)).save(out)
        print(f"  wrote   {out.relative_to(ROOT.parent)}")

    # --- Rounded square (iOS-style 22% radius, transparent) -------
    for sz in (128, 256, 512, 1024):
        out = OUT / f"rounded-square-{sz}.png"
        base = transparent.resize((sz, sz), Image.LANCZOS)
        apply_mask(base, rounded_square_mask(sz)).save(out)
        print(f"  wrote   {out.relative_to(ROOT.parent)}")

    # --- Brand-bg rounded square (for app stores / launchers) -----
    for sz in (256, 512, 1024):
        out = OUT / f"brand-square-{sz}.png"
        composite_on_brand(transparent, sz).save(out)
        print(f"  wrote   {out.relative_to(ROOT.parent)}")

    # --- Apple touch icon (180×180 rounded square, transparent) ---
    out = OUT / "apple-touch-icon.png"
    base = transparent.resize((180, 180), Image.LANCZOS)
    apply_mask(base, rounded_square_mask(180)).save(out)
    print(f"  wrote   {out.relative_to(ROOT.parent)}")

    # --- Favicons (round, multiple sizes + ICO bundle) ------------
    favicons = []
    for sz in (16, 32, 48):
        out = OUT / f"favicon-{sz}.png"
        base = transparent.resize((sz, sz), Image.LANCZOS)
        masked = apply_mask(base, round_mask(sz))
        masked.save(out)
        favicons.append(masked)
        print(f"  wrote   {out.relative_to(ROOT.parent)}")

    ico_out = OUT / "favicon.ico"
    favicons[0].save(
        ico_out,
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48)],
    )
    print(f"  wrote   {ico_out.relative_to(ROOT.parent)}")

    print("done.")


if __name__ == "__main__":
    main()
