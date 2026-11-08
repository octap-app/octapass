# Octa Pass brand

The logo, colours, type and voice for Octa Pass. Everything here is MIT like the rest of the repo. The **name and logo are trademarks of the project**: forks must use their own name and logo (see the trademark note in `plans/10-operations-and-funding.md`).

## Logo

| File | Use |
|---|---|
| `logo-mark.svg` | Primary mark: the gradient OP monogram on a transparent background (light backgrounds) |
| `logo-mark-dark.svg` | Brighter gradient for dark backgrounds |
| `logo-mark-mono.svg` | One colour (`currentColor`), for print, embossing and monochrome UI |
| `logo-tile.svg` | App icon: white monogram on the gradient squircle. Also the favicon |
| `logo-lockup.svg` / `logo-lockup-dark.svg` | Mark + "OctaPass" wordmark (outlined, so no font is needed) |
| `app-icon-512.png`, `apple-touch-icon.png` | App and home-screen icons |
| `readme-header-light.png` / `readme-header-dark.png` | GitHub README banner (2560×1280) |
| `readme-showcase.png` | Tall README image: "Not just a password manager", the 22 kinds of item, zero knowledge (2000×5544) |
| `readme-developers.png` | README image for developers: SSH agent, `octapass run`, CI, toolkit (2560×1440) |
| `og.png` | Social preview (1200×630). Also upload it as the GitHub repo's social preview |

**The idea.** An **O** ring, open at the bottom, around a **P** whose stem passes out through that opening, with a keyhole in the P's bowl. *Open*: the ring has a way through, and nothing about how the lock works is hidden. *Pass*: the P and the keyhole that only your key opens. The concept started from a reference sketch and was redrawn as an even-weight monoline with round ends.

**Rules**
- Clear space around the mark is at least ¼ of its width. Minimum size: 20 px for the bare mark, 16 px for the tile.
- Below 24 px, use the tile (`logo-tile.svg`). The bare monogram's lines get too thin.
- Don't rotate the mark, change the gradient direction, outline it, or add shadows.
- The wordmark is **OctaPass**, one word: "Open" light (380), "Pass" bold (740). In running text write "Octa Pass"; in code and URLs, `octapass`.

## Colour

Two brand colours that meet in one gradient: **trust** (blue) and **freedom** (green, the colour of open source).

| Token | Light | Dark | Role |
|---|---|---|---|
| Trust | `#2456F0` | `#5C86FF` | Primary actions, links, the start of the gradient. Buttons always use `#2456F0` with white text |
| Freedom | `#10B77F` | `#2FD394` | "Encrypted", "open", success and progress states, the end of the gradient |
| Trust text / Freedom text | `#1D47D6` / `#077A54` | `#86A6FF` / `#4FE0A8` | The same colours tuned for AA text contrast |
| Ink | `#0B1220` | `#F5F6F8` | Text |
| Mist | `#5E6576` | `#9BA3B4` | Secondary text |
| Paper | `#FBFBFD` | `#000000` | Page background |
| Tile | `#F2F3F7` | `#12151E` | Bento tiles, footer, sidebars |
| Line | `#E3E5EC` | `#232838` | Hairlines |

Signature gradient: `linear-gradient(120deg, #2456F0, #1A86C8, #10B77F)`. Use it on the logo, one headline per page at most, and hero glows. Never put body text on it.

## Type

- **Mona Sans** (variable, OFL, by GitHub): everything. Headlines use the width axis at 112% with weight 720–760 and tight tracking (−0.04em to −0.05em). Body is 400 at 17 px.
- **Monaspace Neon** (OFL, by GitHub): only for real data: passwords, codes, ciphertext, commands.
- Both are **self-hosted** (`@fontsource*`), never loaded from Google Fonts. A privacy product shouldn't send visitors to third parties.
- The native Android app bundles the same files as TTF, converted without changes by [`tools/native-fonts`](../tools/native-fonts/), which also checks they stay the web's versions.

## Look and feel

- Product-first, like a hardware product page: big type, generous space, real UI rendered in HTML/CSS (no screenshots to go stale), alternating light and black bands.
- Real data in demos (live TOTP codes, real ciphertext made in the browser), never lorem ipsum.
- One orchestrated motion moment per view. Respect `prefers-reduced-motion`.

## What we say Octa Pass is

**Everything sensitive, in one place only you can open.** Octa Pass is a full password manager, but that's never the whole description: lead with the wider idea and prove it with the things people don't expect to find, like SSH keys, `.env` files, passports, seed phrases and Safes. Say "password manager" where people search for one, and where it's simply what you mean. See the positioning in `plans/01-product-spec.md`.

## Voice

- Plain and specific: "Your vault is encrypted on your device before it syncs", not "military-grade security".
- Honest about status: say "planned" until something ships.
- No fear-selling, no superlatives, no comparisons we can't back up with a date and a source.
- Sentence case everywhere. Buttons say what happens ("Read the docs", "Export vault").

## Regenerating assets

```bash
# Logo SVGs (needs: pip install fonttools brotli)
python brand/source/generate_logo.py

# Banner / OG / icon HTML, then render with headless Chrome
python3 brand/source/render_headers.py
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
"$CHROME" --headless=new --hide-scrollbars --allow-file-access-from-files --force-device-scale-factor=2 \
  --window-size=1280,640 --screenshot=brand/readme-header-light.png "file://$PWD/brand/source/render/header-light.html"
# same for header-dark (1280×640 @2x), og (1200×630 @1x), showcase (1000×2772 @2x),
# developers (1280×720 @2x); icons with --default-background-color=00000000
# at 512×512 (icon-512) and 180×180 (icon-180 → apple-touch-icon.png)
```

Then copy `favicon.svg`, `og.png`, `apple-touch-icon.png`, `app-icon-512.png` (as `icon-512.png`) into `apps/website/public/`, and `logo-mark.svg`, `logo-mark-dark.svg` and `logo-tile.svg` into `apps/website/src/assets/` (as `logo.svg`, `logo-dark.svg`, `logo-tile.svg`).

The Apple app icons come from `logo-tile.svg` too: `swift apps/safari/scripts/icons.swift` (on a Mac) renders the Safari app's icons and the iPhone icon, which it also puts in `apps/ios` and the Tauri phone app's `gen/apple` as their only icon (Xcode makes the other sizes). iOS rounds the corners itself, so that icon is the tile's gradient edge to edge, with no transparency. The desktop app's icons are in `apps/desktop/src-tauri/icons/`, and Android draws the mark as a vector (`ic_launcher_foreground.xml`).
