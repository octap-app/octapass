---
title: Translations
description: How Octa Pass is translated, where the strings and Arabic docs live, how Weblate fits in, the rules for right-to-left text, and how to add a new language.
status: stable
sidebar:
  order: 5
---

:::note[Weblate]
English and Arabic are in the repository. The Weblate project isn't open yet: it will open when the repository goes public. Until then, send fixes as pull requests.
:::

English is the source language. Everything else follows it.

## What gets translated

| What | Source | Translations |
|---|---|---|
| Web vault, used by every app | `apps/web/src/i18n/en.ts` | `ar.ts`, and `translations/web/<language>.json` |
| Browser extension | `apps/extension/src/i18n.ts` | `translations/extension/<language>.json` |
| Desktop app (Windows, Linux) | `apps/desktop/src/i18n.ts` | `translations/desktop/<language>.json` |
| Phone apps | `apps/web/src/i18n/phone.ts` | `translations/phone/<language>.json` |
| Website | `apps/website/src/i18n/landing/en.json` | `<language>.json` beside it |
| Docs interface | `apps/website/src/content/i18n/en.json` | `<language>.json` beside it |
| Docs pages | `docs/<path>.md` | `docs/<language>/<path>.md` |

The changelog stays in English. The native iPhone, iPad, Mac and Android apps take their strings from the web and phone catalogs through `tools/native-resources`, so they need no translation of their own.

## Fixing a translation

Open **Weblate** once it's live, or edit the file in a pull request:

- **App strings:** edit `ar.ts` or the `ar` block in the app's catalog, then run `node tools/translations/sync.mjs export`. CI checks that the two match.
- **Docs:** edit the page under `docs/ar/`.

Weblate commits to the `translations/` files and to `docs/ar/`. Run `node tools/translations/sync.mjs import` to carry Arabic fixes from `translations/` back into the TypeScript catalogs.

## Keeping docs in step

`node tools/translations/check-docs.mjs` lists English pages with no translation, and fails on translations that have lost their English page, changed a page's `status`, or link to an English page. A page with no translation shows the English text with a notice, so a new English page never leaves a hole in the site.

## Rules for Arabic

- Modern Standard Arabic, plain and direct, in the same voice as the English.
- Use the words the apps use. The Arabic catalog, `apps/web/src/i18n/ar.ts`, is the glossary: for example, «الخزنة» for vault and «البريد المُقنَّع» for masked email.
- Product names stay in Latin letters: Octa Pass, Touch ID, Windows Hello, Weblate.
- Western digits (0–9), as in the apps.
- Commands, code, file names, setting names like `OCTAPASS_PUBLIC_URL` and URLs stay as they are.
- Counted messages need all six plural forms: zero, one, two, few, many and other.
- No letter-spacing on Arabic text: it breaks the joins between letters.

## Adding a language

1. Open the language in Weblate, or add `translations/<component>/<language>.json` by hand.
2. Add it to `LOCALES` in `apps/web/src/i18n/core.ts`, with its direction, and load its catalogs in each app.
3. Add it to `locales` in `apps/website/astro.config.mjs`.
4. Translate the [docs pages](#what-gets-translated) you can. The rest fall back to English.

Step 2 is a code change on purpose: a language ships when its app strings are complete, because a half-translated password manager is easy to misread.

## Weblate setup

For maintainers. `.weblate` points the `wlc` client at the project, and `translations/weblate.json` lists every component with its file mask, format and settings. Docs pages use one Markdown component each, created by the component discovery add-on, with **Translate front matter values** turned on. See `translations/README.md`.
