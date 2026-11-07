"""Converts the web's brand fonts (the @fontsource packages the web vault bundles) to TTF for the
native Android app, and records what it converted in fonts.json for check.mjs.

The conversion is lossless: WOFF2 is a compressed container for the same font data, so the fonts
stay unmodified under the SIL Open Font License, Reserved Font Names included. Their OFL
license files go with them.

    python3 -m venv /tmp/fonts && /tmp/fonts/bin/pip install fonttools brotli
    /tmp/fonts/bin/python tools/native-fonts/convert.py     # from the repository root, after pnpm install
"""

import hashlib
import json
import sys
from pathlib import Path

from fontTools.ttLib import TTFont

ROOT = Path(__file__).resolve().parents[2]
# The packages as the web vault resolves them, so the app gets the same versions.
WEB_MODULES = ROOT / "apps/web/node_modules"
FONT_DIR = "apps/android/app/src/main/res/font"
LICENSE_DIR = "apps/android/app/src/main/assets/licenses"

# Mona Sans is a variable font (weight 200–900, width 75–125%). Only fontsource's `latin` subset
# is converted: its subsets can't be merged without modifying the font, and Android falls back to
# the system font for any other character, as it does for Arabic.
FONTS = [
    ("@fontsource-variable/mona-sans", "files/mona-sans-latin-wdth-normal.woff2", "mona_sans.ttf"),
    ("@fontsource/monaspace-neon", "files/monaspace-neon-latin-400-normal.woff2", "monaspace_neon_regular.ttf"),
    ("@fontsource/monaspace-neon", "files/monaspace-neon-latin-600-normal.woff2", "monaspace_neon_semibold.ttf"),
]
LICENSES = [
    ("@fontsource-variable/mona-sans", "mona-sans-OFL.txt"),
    ("@fontsource/monaspace-neon", "monaspace-neon-OFL.txt"),
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package(name: str) -> tuple[Path, str]:
    folder = WEB_MODULES / name
    if not folder.exists():
        sys.exit(f"{folder} is missing: run pnpm install first")
    return folder, json.loads((folder / "package.json").read_text())["version"]


def main() -> None:
    manifest = {"fonts": [], "licenses": []}
    for name, source, output in FONTS:
        folder, version = package(name)
        font = TTFont(folder / source)
        font.flavor = None
        # Keep the font's own dates, so the same source always gives the same file.
        font.recalcTimestamp = False
        target = ROOT / FONT_DIR / output
        target.parent.mkdir(parents=True, exist_ok=True)
        font.save(target)
        manifest["fonts"].append(
            {
                "package": name,
                "version": version,
                "source": source,
                "sourceSha256": sha256(folder / source),
                "fontVersion": font["name"].getDebugName(5),
                "output": f"{FONT_DIR}/{output}",
                "outputSha256": sha256(target),
            }
        )
    for name, output in LICENSES:
        folder, version = package(name)
        target = ROOT / LICENSE_DIR / output
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((folder / "LICENSE").read_bytes())
        manifest["licenses"].append(
            {"package": name, "version": version, "output": f"{LICENSE_DIR}/{output}", "sha256": sha256(target)}
        )
    (Path(__file__).parent / "fonts.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
