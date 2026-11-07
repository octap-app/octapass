# Native fonts

The brand fonts for the native Android app, as TTF files converted from the ones the web vault bundles (`@fontsource-variable/mona-sans` and `@fontsource/monaspace-neon`, as `apps/web` resolves them). See [brand/README.md](../../brand/README.md) for how they're used.

```sh
node tools/native-fonts/check.mjs                     # exit 1 when the app's fonts aren't the web's (after pnpm install)
node --test "tools/native-fonts/test/*.test.mjs"

# After a font package update: convert again and commit the result.
python3 -m venv /tmp/fonts && /tmp/fonts/bin/pip install fonttools brotli
/tmp/fonts/bin/python tools/native-fonts/convert.py
```

| Output | From |
|---|---|
| `apps/android/app/src/main/res/font/mona_sans.ttf` | `mona-sans-latin-wdth-normal.woff2`: variable, weight 200–900 and width 75–125% |
| `…/res/font/monaspace_neon_regular.ttf`, `monaspace_neon_semibold.ttf` | `monaspace-neon-latin-400-normal.woff2`, `…-600-normal.woff2`: the web's two weights |
| `apps/android/app/src/main/assets/licenses/*-OFL.txt` | Each package's `LICENSE`, shipped with the app |
| `fonts.json` | Package versions and SHA-256 of every source and output, for `check.mjs` |

**Unmodified.** WOFF2 is a compressed container for the same font data, so converting to TTF changes nothing in the font, and the fonts keep their names under the SIL Open Font License (both reserve theirs: "Mona", "Monaspace"). Subsetting, merging or making static instances would be a Modified Version that couldn't use those names, so the converter does none of that.

**Latin only.** Fontsource splits Mona Sans into `latin`, `latin-ext` and `vietnamese` files, and variable fonts can't be merged without modifying them, so only `latin` is converted. Android draws any character a font lacks with the phone's own font, as it does for Arabic (the web's Noto Sans Arabic isn't bundled; Android ships it).
