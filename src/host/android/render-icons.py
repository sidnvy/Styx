#!/usr/bin/env python3
"""Deterministically render Android launcher, adaptive, monochrome and status-bar
icons from the canonical Styx brand glyph (src/assets/brand/styx-logo.png).
"""
from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "src/assets/brand/styx-logo.png"
RES = Path(__file__).resolve().parent / "app/src/main/res"

DENSITIES = {
    "mdpi": 1.0,
    "hdpi": 1.5,
    "xhdpi": 2.0,
    "xxhdpi": 3.0,
    "xxxhdpi": 4.0,
}


def trim_alpha(img: Image.Image) -> Image.Image:
    bbox = img.getbbox()
    return img.crop(bbox) if bbox else img


def fit_centered(glyph: Image.Image, canvas_size: int, ratio: float) -> Image.Image:
    target = max(1, round(canvas_size * ratio))
    scaled = glyph.resize((target, target), Image.Resampling.LANCZOS)
    canvas = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    offset = (canvas_size - target) // 2
    canvas.paste(scaled, (offset, offset), scaled)
    return canvas


def to_white_monochrome(glyph: Image.Image) -> Image.Image:
    _, _, _, alpha = glyph.split()
    white = Image.new("L", glyph.size, 255)
    return Image.merge("RGBA", (white, white, white, alpha))


def composite_on_shape(glyph: Image.Image, size: int, circle: bool) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    inset = max(1, round(size * 0.04))
    if circle:
        draw.ellipse((inset, inset, size - 1 - inset, size - 1 - inset), fill=255)
    else:
        radius = max(2, round(size * 0.22))
        draw.rounded_rectangle(
            (inset, inset, size - 1 - inset, size - 1 - inset),
            radius=radius,
            fill=255,
        )
    bg = Image.new("RGBA", (size, size), (255, 255, 255, 255))
    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    out.paste(bg, (0, 0), mask)
    fg = fit_centered(glyph, size, 0.78)
    out.alpha_composite(fg)
    return out


def main() -> None:
    if not SOURCE.is_file():
        raise SystemExit(f"Missing canonical brand source: {SOURCE}")
    glyph = trim_alpha(Image.open(SOURCE).convert("RGBA"))
    white_glyph = to_white_monochrome(glyph)

    for density, scale in DENSITIES.items():
        mipmap_dir = RES / f"mipmap-{density}"
        mipmap_dir.mkdir(parents=True, exist_ok=True)
        legacy_px = round(48 * scale)
        adaptive_px = round(108 * scale)

        composite_on_shape(glyph, legacy_px, circle=False).save(
            mipmap_dir / "ic_launcher.png", optimize=True
        )
        composite_on_shape(glyph, legacy_px, circle=True).save(
            mipmap_dir / "ic_launcher_round.png", optimize=True
        )
        # 61% of 108dp (~66dp) keeps the full Styx orb inside Android's adaptive safe zone.
        fit_centered(glyph, adaptive_px, 0.61).save(
            mipmap_dir / "ic_launcher_foreground.png", optimize=True
        )
        fit_centered(glyph, adaptive_px, 0.61).save(
            mipmap_dir / "ic_launcher_monochrome.png", optimize=True
        )

        drawable_dir = RES / f"drawable-{density}"
        drawable_dir.mkdir(parents=True, exist_ok=True)
        stat_px = round(24 * scale)
        fit_centered(white_glyph, stat_px, 0.88).save(
            drawable_dir / "ic_stat_styx.png", optimize=True
        )


if __name__ == "__main__":
    main()
