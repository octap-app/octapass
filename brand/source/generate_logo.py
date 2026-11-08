"""Generates the Octa Pass logo SVGs.

The mark: an "OP" monogram. An outer O ring, open at the bottom, and an inner P whose stem passes out
through that opening, with a keyhole in the P's bowl. Open (the ring with a way through), Pass (the P
and the keyhole only you can open). Painted in the trust-to-freedom gradient: blue for trust, green for
open source.

Usage (from the repo root; needs `pip install fonttools brotli`):
    python brand/source/generate_logo.py
"""
import math
from pathlib import Path

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'brand'
FONT = ROOT / 'apps/website/node_modules/@fontsource-variable/mona-sans/files/mona-sans-latin-wdth-normal.woff2'

TRUST, FREE = '#2456F0', '#10B77F'
TRUST_DARK, FREE_DARK = '#5C86FF', '#2FD394'
INK, NIGHT_INK = '#0B1220', '#F5F6F8'


def squircle(size=64, n=4.6, steps=120):
    a = size / 2
    pts = []
    for i in range(steps):
        t = 2 * math.pi * i / steps
        c, s = math.cos(t), math.sin(t)
        pts.append(f'{a + a * math.copysign(abs(c) ** (2 / n), c):.2f} {a + a * math.copysign(abs(s) ** (2 / n), s):.2f}')
    return 'M' + 'L'.join(pts) + 'Z'


TILE = squircle()


def polar(cx, cy, r, deg):
    a = math.radians(deg)
    return cx + r * math.cos(a), cy + r * math.sin(a)


# Monoline "OP" monogram on a 64 grid (SVG angles: 0 = right, 90 = down).
# O: outer ring, open at the bottom where the P's stem passes through.
# P: inner ring (the bowl), open at the lower left, whose end turns straight down into the stem.
CX, CY, R_O, R_P, STROKE = 32, 29.5, 25.5, 14.5, 5.2
STEM_X = 28.4
o1, o2 = polar(CX, CY, R_O, 120), polar(CX, CY, R_O, 77)
p1 = polar(CX, CY, R_P, 152)
p_end_deg = 180 - math.degrees(math.acos((CX - STEM_X) / R_P))  # where the bowl meets the stem line
p2 = polar(CX, CY, R_P, p_end_deg)
STEM_BOTTOM = 61.5
O_PATH = f'M{o1[0]:.2f} {o1[1]:.2f}A{R_O} {R_O} 0 1 1 {o2[0]:.2f} {o2[1]:.2f}'
P_PATH = f'M{p1[0]:.2f} {p1[1]:.2f}A{R_P} {R_P} 0 1 1 {p2[0]:.2f} {p2[1]:.2f}L{STEM_X} {STEM_BOTTOM}'
KEYHOLE = f'M{CX} 23.4a3.9 3.9 0 0 1 2.2 7.1l1.1 5.4h-6.6l1.1-5.4A3.9 3.9 0 0 1 {CX} 23.4Z'


def gradient(gid, a, b, x1=8, y1=6, x2=56, y2=60):
    return (f'<linearGradient id="{gid}" x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" gradientUnits="userSpaceOnUse">'
            f'<stop offset="0" stop-color="{a}"/><stop offset="1" stop-color="{b}"/></linearGradient>')


def glyph(paint):
    """The monogram strokes + keyhole, painted with `paint` (a colour or url(#id))."""
    return (f'<g fill="none" stroke="{paint}" stroke-width="{STROKE}" stroke-linecap="round" stroke-linejoin="round">'
            f'<path d="{O_PATH}"/><path d="{P_PATH}"/></g><path d="{KEYHOLE}" fill="{paint}"/>')


def mark(a=TRUST, b=FREE, size=64, title=True):
    """Gradient monogram on a transparent background."""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="{size}" height="{size}">'
            + ('<title>Octa Pass</title>' if title else '')
            + f'<defs>{gradient("op-g", a, b)}</defs>{glyph("url(#op-g)")}</svg>\n')


def mark_mono(size=64):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="{size}" height="{size}" color="{INK}">'
            f'<title>Octa Pass</title>{glyph("currentColor")}</svg>\n')


def tile(size=64, title=True):
    """App icon / favicon: white monogram on the gradient squircle."""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="{size}" height="{size}">'
            + ('<title>Octa Pass</title>' if title else '')
            + f'<defs>{gradient("op-t", TRUST, FREE, 0, 0, 64, 64)}</defs>'
            f'<path d="{TILE}" fill="url(#op-t)"/>'
            f'<g transform="translate(32 32.6) scale(0.66) translate(-32 -33.5)">{glyph("#FFFFFF")}</g></svg>\n')


def favicon():
    return tile(title=False)


def wordmark(parts=(('Octa ', 380), ('Pass', 740)), width=108, size=46):
    """'Octa Pass': Octa light, a space, Pass bold."""
    commands, x, cap = [], 0.0, 0.0
    for text, weight in parts:
        font = instancer.instantiateVariableFont(TTFont(FONT), {'wght': weight, 'wdth': width})
        glyphs, cmap, hmtx = font.getGlyphSet(), font.getBestCmap(), font['hmtx']
        upm = font['head'].unitsPerEm
        scale, tracking = size / upm, -0.02 * upm
        pen = SVGPathPen(glyphs)
        for ch in text:
            name = cmap[ord(ch)]
            glyphs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, x, 0)))
            x += (hmtx[name][0] + tracking) * scale
        commands.append(pen.getCommands())
        cap = font['OS/2'].sCapHeight * scale
    return ' '.join(commands), x, cap


def lockup(text_color, a, b):
    d, width, cap = wordmark()
    height, gap = 64, 20
    total = height + gap + width
    baseline = CY + cap / 2  # optically centred on the O, not the stem
    inner = mark(a, b, title=False)
    inner = inner[inner.index('>') + 1: inner.rindex('</svg>')]
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total:.1f} {height}" width="{total:.0f}" height="{height}">'
            f'<title>Octa Pass</title>{inner}'
            f'<path transform="translate({height + gap} {baseline:.2f})" d="{d}" fill="{text_color}"/></svg>\n')


if __name__ == '__main__':
    (OUT / 'logo-tile.svg').write_text(tile())
    (OUT / 'logo-mark.svg').write_text(mark())
    (OUT / 'logo-mark-dark.svg').write_text(mark(TRUST_DARK, FREE_DARK))
    (OUT / 'logo-mark-mono.svg').write_text(mark_mono())
    (OUT / 'logo-lockup.svg').write_text(lockup(INK, TRUST, FREE))
    (OUT / 'logo-lockup-dark.svg').write_text(lockup(NIGHT_INK, TRUST_DARK, FREE_DARK))
    (OUT / 'favicon.svg').write_text(favicon())
    print('Wrote logo SVGs to', OUT)
