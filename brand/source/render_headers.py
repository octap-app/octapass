"""Writes HTML for the README headers, social image and app icons into brand/source/render/.
Render them to PNG with headless Chrome (see brand/README.md)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FONTS = ROOT / 'node_modules/.pnpm/node_modules/@fontsource-variable/mona-sans/files'
if not FONTS.exists():
    FONTS = ROOT / 'apps/website/node_modules/@fontsource-variable/mona-sans/files'
tile = (ROOT / 'brand/logo-tile.svg').read_text()

themes = {
    'light': dict(bg='#FBFBFD', ink='#0B1220', mist='#5E6576', glow_a='#2456F055', glow_b='#10B77F44'),
    'dark': dict(bg='#000000', ink='#F5F6F8', mist='#9BA3B4', glow_a='#2456F088', glow_b='#10B77F66'),
}


def banner(t, w, h, title_size, icon=112):
    icon_svg = tile.replace('width="64" height="64"', f'width="{icon}" height="{icon}"')
    return f'''<!doctype html><html><head><meta charset="utf-8"><style>
@font-face{{font-family:Mona;src:url(file://{FONTS}/mona-sans-latin-wdth-normal.woff2) format("woff2");font-weight:200 900;font-stretch:75% 125%}}
*{{box-sizing:border-box}}html,body{{margin:0;width:{w}px;height:{h}px;overflow:hidden}}
body{{background:{t['bg']};color:{t['ink']};font-family:Mona;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;position:relative}}
.glow{{position:absolute;inset:0;background:radial-gradient(40% 55% at 38% 105%, {t['glow_a']}, transparent 70%),radial-gradient(40% 55% at 64% 105%, {t['glow_b']}, transparent 70%);filter:blur(30px)}}
.icon{{position:relative;filter:drop-shadow(0 18px 30px #2456f040)}}
h1{{position:relative;font-size:{title_size}px;font-weight:760;font-stretch:112%;letter-spacing:-.05em;line-height:1;margin:34px 0 18px}}
p{{position:relative;font-size:{round(title_size*0.33)}px;color:{t['mist']};margin:0;letter-spacing:-.01em}}
.word{{font-weight:380}} .word b{{font-weight:740}}
</style></head><body><div class="glow"></div>
<div class="icon">{icon_svg}</div>
<h1>The password manager<br>only you can open.</h1>
<p><span class="word">Octa<b>Pass</b></span>: free, open source, end-to-end encrypted. No ads, ever.</p>
</body></html>'''


def icon(size):
    return (f'<!doctype html><html><body style="margin:0;width:{size}px;height:{size}px;background:transparent">'
            + tile.replace('width="64" height="64"', f'width="{size}" height="{size}"') + '</body></html>')


out = Path(__file__).resolve().parent / 'render'
out.mkdir(exist_ok=True)
for name, t in themes.items():
    (out / f'header-{name}.html').write_text(banner(t, 1280, 640, 72))
(out / 'og.html').write_text(banner(themes['dark'], 1200, 630, 70))
(out / 'icon-512.html').write_text(icon(512))
(out / 'icon-180.html').write_text(icon(180))
print('Wrote', out)
