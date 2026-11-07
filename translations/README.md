# Translations

The files Weblate edits. English is the source everywhere; see [`docs/contributing/translations.md`](../docs/contributing/translations.md).

| Folder | What it is | Source of the English |
|---|---|---|
| `web/`, `extension/`, `desktop/`, `phone/` | App strings as i18next v4 JSON (`key_one`, `key_other`, all six Arabic forms) | The TypeScript catalogs |

Website strings (`apps/website/src/i18n/landing/`), the docs interface (`apps/website/src/content/i18n/`) and docs pages (`docs/ar/`) are edited in place, because they have no TypeScript catalog.

## After changing app strings

The TypeScript catalogs stay the source of truth, so the apps build and type-check as they always did. After you add or change a string:

```sh
node tools/translations/sync.mjs export
```

CI runs `export --check`. To bring Arabic fixes from Weblate back into the catalogs:

```sh
node tools/translations/sync.mjs import
node tools/translations/sync.mjs export
```

## Setting up Weblate

Not done yet: it needs a public repository and a project on Weblate's hosting. Then, once:

1. Create the project and the components listed in [`weblate.json`](weblate.json). Check the identifiers against your Weblate version: `i18nextv4`, `json-nested` and `markdown` are from its documentation as of 2026-11-02, and this file hasn't been tried on a live server.
2. Add the component discovery add-on with the `docs_discovery` settings, and turn on **Translate front matter values**.
3. Point Weblate at a `weblate` branch and merge its pull requests like any other. Run `import` and `export` on that branch first, so CI's check passes.
4. Require reviewed strings (Weblate's "Enable reviews") for Arabic and any new language: mistranslating a security warning is worse than leaving it in English.

`.weblate` at the repository root points the `wlc` client at the project. Never commit an API key.
