"""Writes HTML for the README images, social image and app icons into brand/source/render/.
Render them to PNG with headless Chrome (see brand/README.md).

The README images say what Octa Pass is: one encrypted place for everything sensitive,
not only a password manager. Item icons come from the website's set, so both stay in step."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PNPM = ROOT / 'node_modules/.pnpm/node_modules'
FONTS = PNPM / '@fontsource-variable/mona-sans/files'
if not FONTS.exists():
    FONTS = ROOT / 'apps/website/node_modules/@fontsource-variable/mona-sans/files'
MONO = PNPM / '@fontsource/monaspace-neon/files'
tile = (ROOT / 'brand/logo-tile.svg').read_text()
ICONS = json.loads((ROOT / 'apps/website/src/lib/vault-icons.json').read_text())

themes = {
    'light': dict(bg='#FBFBFD', ink='#0B1220', mist='#5E6576', glow_a='#2456F055', glow_b='#10B77F44', chip='#FFFFFF', line='#E3E5EC', icon='#2456F0'),
    'dark': dict(bg='#000000', ink='#F5F6F8', mist='#9BA3B4', glow_a='#2456F088', glow_b='#10B77F66', chip='#12151E', line='#232838', icon='#5C86FF'),
}

FONT_CSS = f'''@font-face{{font-family:Mona;src:url(file://{FONTS}/mona-sans-latin-wdth-normal.woff2) format("woff2");font-weight:200 900;font-stretch:75% 125%}}
@font-face{{font-family:Mono;src:url(file://{MONO}/monaspace-neon-latin-400-normal.woff2) format("woff2");font-weight:400}}
@font-face{{font-family:Mono;src:url(file://{MONO}/monaspace-neon-latin-600-normal.woff2) format("woff2");font-weight:600}}'''


def svg(name, cls='i'):
    return f'<svg class="{cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">{ICONS[name]}</svg>'


def logo(size):
    return tile.replace('width="64" height="64"', f'width="{size}" height="{size}"')


# ---------------------------------------------------------------- banner (README header + social image)

BANNER_CHIPS = [('login', 'Passwords'), ('passkey', 'Passkeys'), ('ssh', 'SSH keys'), ('env', '.env secrets'),
                ('passport', 'IDs'), ('card', 'Cards'), ('wallet', 'Crypto'), ('safe', 'Safes')]


def banner(t, w, h, title_size, icon=104):
    chips = ''.join(f'<span class="chip">{svg(i)}{label}</span>' for i, label in BANNER_CHIPS)
    return f'''<!doctype html><html><head><meta charset="utf-8"><style>
{FONT_CSS}
*{{box-sizing:border-box}}html,body{{margin:0;width:{w}px;height:{h}px;overflow:hidden}}
body{{background:{t['bg']};color:{t['ink']};font-family:Mona;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;position:relative}}
.glow{{position:absolute;inset:0;background:radial-gradient(40% 55% at 38% 105%, {t['glow_a']}, transparent 70%),radial-gradient(40% 55% at 64% 105%, {t['glow_b']}, transparent 70%);filter:blur(30px)}}
.icon{{position:relative;filter:drop-shadow(0 18px 30px #2456f040)}}
h1{{position:relative;font-size:{title_size}px;font-weight:760;font-stretch:112%;letter-spacing:-.05em;line-height:1.02;margin:28px 0 18px}}
h1 span{{background:linear-gradient(120deg,#2456F0,#1A86C8,#10B77F);-webkit-background-clip:text;color:transparent}}
p{{position:relative;font-size:{round(title_size*0.31)}px;color:{t['mist']};margin:0;letter-spacing:-.01em}}
.word{{font-weight:380}} .word b{{font-weight:740}}
.chips{{position:relative;display:flex;gap:10px;margin-top:30px}}
.chip{{display:inline-flex;align-items:center;gap:7px;padding:8px 14px 8px 11px;border-radius:999px;background:{t['chip']};border:1px solid {t['line']};font-size:{round(title_size*0.22)}px;font-weight:620}}
.chip .i{{width:18px;height:18px;color:{t['icon']}}}
</style></head><body><div class="glow"></div>
<div class="icon">{logo(icon)}</div>
<h1>Everything sensitive.<br><span>One place only you can open.</span></h1>
<p><span class="word">Octa<b>Pass</b></span>: free, open source, end-to-end encrypted. No ads, ever.</p>
<div class="chips">{chips}</div>
</body></html>'''


# ---------------------------------------------------------------- the tall "everything" showcase

STATS = [
    ('shield', '22 kinds of secret'), ('devices', '8 platforms, one vault'), ('key', '1 key per item'),
    ('eye', 'Zero-knowledge sync'), ('code', 'MIT open source'), ('ban', '0 ads, 0 trackers'),
]
STAT_ICONS = {
    'shield': '<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6z"/><path d="M8.8 12l2.2 2.2 4.2-4.4"/>',
    'devices': '<rect x="2.5" y="4.5" width="14" height="10" rx="1.8"/><path d="M6 18.5h7"/><rect x="17" y="8" width="4.5" height="11" rx="1.2"/>',
    'key': '<circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3M21 12v2.5"/>',
    'eye': '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.8"/><path d="M4 20L20 4"/>',
    'code': '<path d="M8.5 7L3.5 12l5 5M15.5 7l5 5-5 5M13.5 4.5l-3 15"/>',
    'ban': '<circle cx="12" cy="12" r="8.5"/><path d="M6 6l12 12"/>',
}

# (icon, short label, badge) in rows of 4 and 5 so the hexagons interlock.
HEXES = [
    [('login', 'Passwords', ''), ('passkey', 'Passkeys', ''), ('otp', '2FA codes', ''), ('recovery', 'Recovery', '')],
    [('alias', 'Masked email', ''), ('wifi', 'Wi-Fi', ''), ('note', 'Notes', ''), ('card', 'Cards', ''), ('bank', 'Bank', '')],
    [('wallet', 'Crypto', ''), ('licence', 'Licences', ''), ('identity', 'Identities', ''), ('passport', 'Passports', '')],
    [('document', 'Documents', ''), ('safe', 'Safes', 'Folders'), ('file', 'Sealed files', ''), ('ssh', 'SSH keys', 'Agent'), ('api', 'API keys', '')],
    [('env', '.env', ''), ('database', 'Databases', ''), ('cert', 'Certificates', ''), ('custom', 'Your own', '')],
]


def item_card(icon, title, sub, rows, hue):
    fields = ''.join(f'<div class="f"><small>{k}</small><span class="{c}">{v}</span></div>' for k, v, c in rows)
    return (f'<div class="card"><div class="ch"><span class="av" style="--h:{hue}">{svg(icon)}</span>'
            f'<div><b>{title}</b><small>{sub}</small></div><span class="seal">Encrypted</span></div>{fields}</div>')


CARDS = [
    item_card('ssh', 'GitHub signing key', 'SSH key · Ed25519', [('Public key', 'ssh-ed25519 AAAAC3Nz…k9Rw', 'm'), ('Fingerprint', 'SHA256:Xq3vR8…k9Rw', 'm'), ('SSH agent', 'Asks with Touch ID', '')], 255),
    item_card('passport', 'Passport', 'ID document', [('Number', '•••••••84', 'm'), ('Expires', 'March 2031', ''), ('Scans', '2 attachments', '')], 32),
    item_card('env', 'Shop API · production', 'Environment', [('DATABASE_URL', 'octapass://Work/Postgres/url', 'm'), ('STRIPE_KEY', '••••••••••••', 'm'), ('LOG_LEVEL', 'info', 'm')], 140),
    item_card('login', 'GitHub', 'github.com', [('Username', 'maya.rahman@example.com', ''), ('Password', '••••••••••••••••', 'm'), ('One-time code', '781 674', 'm')], 222),
    item_card('wallet', 'Cold wallet', 'Crypto wallet', [('Seed phrase', '•••• •••• •••• ••••', 'm'), ('Bitcoin', 'bc1q9h…x7ke', 'm'), ('Never shown as', 'a QR code', '')], 45),
    item_card('safe', 'Taxes', 'Safe · 6 files', [('2026/return.pdf', '1.2 MB', ''), ('passport-scan.jpg', '3.4 MB', ''), ('On disk', 'fy547rm6npai3iaxn3t33x', 'm')], 190),
    item_card('wifi', 'Home Wi-Fi', 'WPA3 Personal', [('Network', 'Rahman-5G', ''), ('Password', '••••••••••', 'm'), ('Share', 'as a QR code', '')], 160),
    item_card('card', 'Travel card', 'Visa ending 4242', [('Cardholder', 'Maya Rahman', ''), ('Expires', '09/29', 'm'), ('CVV', '•••', 'm')], 205),
]


def showcase(w=1000):
    stats = ''.join(f'<div class="stat"><svg class="si" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">{STAT_ICONS[i]}</svg><span>{label}</span></div>' for i, label in STATS)
    rows = ''
    for row in HEXES:
        cells = ''
        for icon, label, badge in row:
            b = f'<em>{badge}</em>' if badge else ''
            cells += f'<div class="hexw">{b}<div class="hex"><div class="hi">{svg(icon)}</div><div class="hl">{label}</div></div></div>'
        rows += f'<div class="row">{cells}</div>'
    cards = ''.join(CARDS)
    return f'''<!doctype html><html><head><meta charset="utf-8"><style>
{FONT_CSS}
*{{box-sizing:border-box}}html,body{{margin:0;width:{w}px}}
body{{background:#05070d;color:#F5F6F8;font-family:Mona;position:relative;overflow:hidden;text-align:center}}
.bg{{position:absolute;inset:0;background:
  radial-gradient(60% 18% at 50% 0%, #2456F040, transparent 70%),
  radial-gradient(50% 14% at 15% 44%, #2456F026, transparent 70%),
  radial-gradient(50% 14% at 85% 52%, #10B77F22, transparent 70%);}}
.dots{{position:absolute;inset:0;background-image:radial-gradient(#ffffff10 1px, transparent 1.2px);background-size:22px 22px;-webkit-mask-image:linear-gradient(#000,transparent 30%,transparent 70%,#000);mask-image:linear-gradient(#000,transparent 30%,transparent 70%,#000)}}
main{{position:relative;padding:76px 70px 0}}
.mark{{display:inline-block;filter:drop-shadow(0 16px 30px #2456f066)}}
h1{{font-size:66px;font-weight:760;font-stretch:112%;letter-spacing:-.05em;line-height:1.02;margin:26px 0 0}}
.under{{position:relative;display:inline-block}}
.under svg{{position:absolute;left:-2%;bottom:-16px;width:104%;height:28px}}
.sub{{font-size:22px;color:#9BA3B4;margin:34px auto 0;max-width:30em;line-height:1.4}}
.sub b{{color:#F5F6F8;font-weight:600}}
.stats{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:52px 30px 0}}
.stat{{display:flex;flex-direction:column;align-items:flex-start;gap:14px;padding:22px 24px;border:1.5px dashed #2c3346;border-radius:16px;background:#0b0e16cc;text-align:left}}
.stat .si{{width:28px;height:28px;color:#2FD394}}
.stat span{{font-size:17px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}}
h2{{font-size:46px;font-weight:740;font-stretch:110%;letter-spacing:-.04em;line-height:1.08;margin:84px 0 0}}
h2 .g{{background:linear-gradient(120deg,#5C86FF,#1A86C8,#2FD394);-webkit-background-clip:text;color:transparent}}
.lede{{color:#9BA3B4;font-size:19px;margin:16px 0 0}}
.honey{{margin:44px 0 0}}
.row{{display:flex;justify-content:center;gap:16px}}
.row+.row{{margin-top:-26px}}
.hexw{{position:relative;width:134px}}
.hex{{width:134px;height:154px;clip-path:polygon(50% 0,100% 25%,100% 75%,50% 100%,0 75%,0 25%);background:linear-gradient(180deg,#ffffff,#e8ecf5);position:relative;overflow:hidden}}
.hi{{position:absolute;inset:0 0 34% 0;display:grid;place-items:center;padding-top:24px}}
.hi .i{{width:46px;height:46px;stroke:url(#g);color:#2456F0}}
.hl{{position:absolute;left:0;right:0;bottom:0;height:40%;background:#c9d0de;color:#0B1220;font-size:15px;font-weight:700;display:flex;align-items:flex-start;justify-content:center;padding-top:12px;letter-spacing:-.01em}}
.hexw em{{position:absolute;z-index:2;top:-4px;left:50%;transform:translateX(-50%);font-style:normal;font-size:12px;font-weight:700;background:#10B77F;color:#fff;padding:3px 9px;border-radius:6px;white-space:nowrap}}
.plus{{font-size:84px;font-weight:300;line-height:1;margin:46px 0 6px;color:#F5F6F8}}
.big{{display:flex;align-items:center;justify-content:center;gap:26px}}
.zero{{padding-right:.08em;font-size:250px;font-weight:800;font-stretch:118%;letter-spacing:-.06em;line-height:.8;background:linear-gradient(160deg,#ffffff 30%,#9fb6ff 70%,#2FD394);-webkit-background-clip:text;color:transparent;padding-bottom:12px}}
.bt{{text-align:left}}
.bt b{{display:block;font-size:70px;font-weight:800;font-stretch:118%;letter-spacing:-.04em;line-height:.95}}
.bt i{{display:block;font-size:26px;font-style:normal;font-weight:500;color:#9BA3B4;margin-top:10px}}
.bt i+i{{margin-top:2px}}
.floor{{position:relative;height:560px;margin:20px -70px 0;perspective:1600px;overflow:hidden}}
.plane{{position:absolute;left:50%;top:40px;width:1500px;transform:translateX(-50%) rotateX(52deg) rotateZ(-28deg);transform-style:preserve-3d;display:grid;grid-template-columns:repeat(4,330px);gap:34px;justify-content:center}}
.card{{background:#fff;color:#0B1220;border-radius:18px;padding:18px 18px 8px;text-align:left;box-shadow:0 40px 60px -20px #000c, 0 0 0 1px #ffffff22;font-size:13px}}
.card:nth-child(3n+2){{background:#0d1017;color:#F5F6F8;box-shadow:0 40px 60px -20px #000c,0 0 0 1px #2a3045}}
.card:nth-child(3n+2) .f{{border-color:#232838}}
.card:nth-child(3n+2) small{{color:#9BA3B4}}
.ch{{display:flex;align-items:center;gap:10px;margin-bottom:10px}}
.ch b{{display:block;font-size:16px;letter-spacing:-.01em}}
.ch small{{display:block;color:#5E6576;font-size:12px}}
.av{{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,hsl(var(--h) 75% 58%),hsl(calc(var(--h) + 30) 70% 45%));flex:none}}
.av .i{{width:22px;height:22px}}
.seal{{margin-left:auto;font-size:11px;font-weight:650;color:#077A54;background:#10B77F22;padding:4px 9px;border-radius:999px}}
.card:nth-child(3n+2) .seal{{color:#4FE0A8}}
.f{{display:flex;flex-direction:column;padding:8px 0;border-top:1px solid #E3E5EC}}
.f small{{color:#5E6576;font-size:11px}}
.f .m{{font-family:Mono;font-size:12.5px}}
.fade{{position:absolute;left:0;right:0;bottom:0;height:380px;background:linear-gradient(transparent,#05070d)}}
.foot{{position:relative;margin:-40px 0 0;padding:0 0 64px;font-size:21px;color:#9BA3B4}}
.foot b{{color:#F5F6F8;font-weight:650}}
</style></head><body><div class="bg"></div><div class="dots"></div>
<svg width="0" height="0" style="position:absolute"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2456F0"/><stop offset="1" stop-color="#10B77F"/></linearGradient>
<linearGradient id="u" x1="0" x2="1"><stop offset="0" stop-color="#2456F0"/><stop offset=".5" stop-color="#1A86C8"/><stop offset="1" stop-color="#10B77F"/></linearGradient></defs></svg>
<main>
<div class="mark">{logo(92)}</div>
<h1>Not just a<br><span class="under">password manager.<svg viewBox="0 0 400 28" preserveAspectRatio="none"><path d="M6 18C90 8 200 6 394 12" stroke="url(#u)" stroke-width="9" fill="none" stroke-linecap="round"/><path d="M40 24C140 17 250 16 360 20" stroke="url(#u)" stroke-width="4" fill="none" stroke-linecap="round" opacity=".6"/></svg></span></h1>
<p class="sub">One encrypted vault for <b>everything sensitive</b>: logins and keys, money and IDs, secrets for your code and whole folders of files.</p>
<div class="stats">{stats}</div>
<h2>22 kinds of secret.<br><span class="g">One place to keep them.</span></h2>
<p class="lede">Every one encrypted on your device, synced and shared the same way.</p>
<div class="honey">{rows}</div>
<div class="plus">+</div>
<div class="big"><div class="zero">0</div><div class="bt"><b>KNOWLEDGE</b><i>We store it.</i><i>We can’t read it.</i></div></div>
</main>
<div class="floor"><div class="plane">{cards}</div><div class="fade"></div></div>
<p class="foot"><b>Free</b> · Browsers · Mac · Windows · Linux · iPhone · Android · Web · CLI</p>
</body></html>'''


# ---------------------------------------------------------------- developers (wide)

def developers(w=1280, h=720):
    pts = [('ssh', 'SSH agent that asks', 'ssh and git sign with vault keys. Every use asks Touch ID or Windows Hello.'),
           ('env', '.env without the file', '<code>octapass run</code> hands secrets to one command. Nothing on disk.'),
           ('api', 'CI that can’t leak', 'Read-only service accounts. GitHub Action and GitLab template.'),
           ('cert', 'Local toolkit', 'Certificates, a local CA, JWTs, hashes. All on your device.')]
    points = ''.join(f'<div class="pt"><span class="pi">{svg(i)}</span><div><b>{t}</b><p>{d}</p></div></div>' for i, t, d in pts)
    return f'''<!doctype html><html><head><meta charset="utf-8"><style>
{FONT_CSS}
*{{box-sizing:border-box}}html,body{{margin:0;width:{w}px;height:{h}px;overflow:hidden}}
body{{background:#000;color:#F5F6F8;font-family:Mona;position:relative;display:grid;grid-template-columns:520px 1fr;gap:50px;align-items:center;padding:0 64px}}
.glow{{position:absolute;inset:0;background:radial-gradient(45% 60% at 0% 100%, #2456F055, transparent 70%),radial-gradient(40% 55% at 100% 0%, #10B77F33, transparent 70%);filter:blur(20px)}}
.l,.r{{position:relative}}
.eye{{font-size:14px;font-weight:700;letter-spacing:.1em;color:#4FE0A8;margin:0 0 14px}}
h1{{font-size:50px;font-weight:760;font-stretch:112%;letter-spacing:-.05em;line-height:1.02;margin:0 0 30px}}
h1 span{{background:linear-gradient(120deg,#5C86FF,#1A86C8,#2FD394);-webkit-background-clip:text;color:transparent}}
.pt{{display:flex;gap:14px;margin-top:18px;text-align:left}}
.pi{{flex:none;width:40px;height:40px;border-radius:11px;background:#141824;border:1px solid #232838;display:grid;place-items:center;color:#5C86FF}}
.pi .i{{width:22px;height:22px}}
.pt b{{font-size:17px}}
.pt p{{margin:3px 0 0;font-size:15px;color:#9BA3B4;line-height:1.35}}
code{{font-family:Mono;font-size:13.5px;color:#DFE5F1}}
.term{{background:#0d1017;border:1px solid #232838;border-radius:16px;box-shadow:0 40px 80px -30px #000;position:relative}}
.bar{{display:flex;align-items:center;gap:14px;padding:12px 16px;border-bottom:1px solid #232838;font-size:13px;color:#9BA3B4}}
.lights{{display:flex;gap:7px}}.lights i{{width:12px;height:12px;border-radius:50%;background:#ff5f57}}.lights i:nth-child(2){{background:#febc2e}}.lights i:nth-child(3){{background:#28c840}}
pre{{margin:0;padding:22px 22px 196px;font-family:Mono;font-size:14.5px;line-height:1.75;color:#DFE5F1;white-space:pre}}
.p{{color:#2FD394}}.d{{color:#8b93a6}}
.caret{{display:inline-block;width:.55em;height:1.1em;vertical-align:-.2em;background:#DFE5F1;margin-left:3px}}
.ask{{position:absolute;right:26px;bottom:-44px;width:300px;padding:16px 18px 18px;border-radius:18px;background:#1c202ceb;border:1px solid #2c3346;box-shadow:0 30px 60px -20px #000;text-align:center}}
.at{{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:650}}
.ask p{{margin:12px 0 10px;font-size:15.5px;font-weight:650;line-height:1.3}}
.touch{{width:46px;height:46px;fill:none;stroke:#ff5a7a;stroke-width:2.4;stroke-linecap:round}}
.ask small{{display:block;color:#9BA3B4;font-size:12px;margin-top:4px}}
</style></head><body><div class="glow"></div>
<div class="l"><p class="eye">FOR DEVELOPERS</p><h1>Secrets in your code.<br><span>Not in your repo.</span></h1>{points}</div>
<div class="r"><div class="term"><div class="bar"><span class="lights"><i></i><i></i><i></i></span>Terminal</div>
<pre><span class="p">$</span> ssh-add -l
<span class="d">256 SHA256:Xq3vR8…k9Rw GitHub signing key (ED25519)</span>
<span class="d">256 SHA256:p0LmT2…7aZe Deploy key (ED25519)</span>
<span class="p">$</span> octapass run --env "Shop API (production)" -- ./migrate.sh
<span class="d">migrate: 3 applied, database is up to date</span>
<span class="p">$</span> git commit -S -m "Rotate the billing key"<span class="caret"></span></pre>
<div class="ask"><div class="at">{logo(22)}Octa Pass</div><p>Allow “git” to sign with “GitHub signing key”?</p>
<svg class="touch" viewBox="0 0 48 48"><path d="M24 6a17 17 0 0 0-17 17M41 23A17 17 0 0 0 30 7.2M13 39c3-4 4-8.5 4-16a7 7 0 0 1 14 0c0 3 0 6-.6 9M24 23c0 8-1.6 14-5 19M31 36c-.6 2.4-1.5 4.6-2.6 6.4M12.5 30c.4-2.3.5-4.6.5-7a11 11 0 0 1 22 0c0 1.5 0 3-.1 4.4"/></svg><small>Touch ID</small></div>
</div></div>
</body></html>'''


def icon(size):
    return (f'<!doctype html><html><body style="margin:0;width:{size}px;height:{size}px;background:transparent">'
            + logo(size) + '</body></html>')


out = Path(__file__).resolve().parent / 'render'
out.mkdir(exist_ok=True)
for name, t in themes.items():
    (out / f'header-{name}.html').write_text(banner(t, 1280, 640, 66))
(out / 'og.html').write_text(banner(themes['dark'], 1200, 630, 62, icon=92))
(out / 'showcase.html').write_text(showcase())
(out / 'developers.html').write_text(developers())
(out / 'icon-512.html').write_text(icon(512))
(out / 'icon-180.html').write_text(icon(180))
print('Wrote', out)
