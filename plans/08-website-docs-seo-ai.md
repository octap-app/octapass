# 08 — Website, docs, SEO and AI-friendliness

The website is the first thing built (Phase 0). It's live in `apps/website`.

## Positioning on the website

Hosted-first: the landing page sells the **free Octa Pass service** (hero, "See what's free" call to action, a free-plan section explaining how it's funded). Open source appears as a trust argument ("so you don't have to trust us"), and self-hosting as an option for organisations, near the end of the page and in the footer.

## What the website contains

| Route | Content | Source |
|---|---|---|
| `/`, `/ar/` | Landing page: what Octa Pass is, how the encryption works, item types, platform matrix, roadmap, open source | `src/components/Landing.astro`, words in `src/i18n/landing/` |
| `/docs/…`, `/ar/docs/…` | Open-source documentation (Starlight) | Repo-root `docs/` and `docs/ar/` |
| `/og/<language>/….png` | Per-page social images, drawn at build time | `src/pages/og`, `src/lib/og-image.ts` |
| `/docs/….md` | **Raw Markdown of every docs page**, for AI agents and tools | Generated endpoint |
| `/index.md`, `/ar/index.md` | The landing page as Markdown | `src/lib/landing-markdown.ts`, from the same strings as the page |
| `/changelog/index.md`, `/changelog/<slug>.md` | The changelog and each entry as Markdown | Generated endpoints |
| `/changelog/` + `/changelog/<slug>/` | Project changelog | Repo-root `changelog/` folder |
| `/changelog/rss.xml` | RSS feed of the changelog | Generated |
| `/llms.txt`, `/llms-full.txt`, `/llms-small.txt` | AI-readable indexes and full-text docs (llmstxt.org convention) | `starlight-llms-txt` plugin |
| `/skills/octapass-docs/SKILL.md` | The agent skill, downloadable | Repo-root `skills/` folder |
| `/skills/octapass-cli/SKILL.md` (and its `references/*.md`) | The CLI agent skill, downloadable | Repo-root `skills/` folder |
| `/robots.txt`, `/sitemap-index.xml` | Crawling | Generated |
| `/.well-known/security.txt` | RFC 9116 contacts from `SECURITY.md`, with `Expires` a year after the build | Generated endpoint |
| Later: `/download`, `/security`, `/privacy`, `/terms`, `/status` link, `/s/<id>` (share-link viewer), `/app` (web vault) | | |

## Tech

- **Astro 7 + Starlight**: static HTML, zero JS by default, Pagefind search, i18n with RTL, accessible components.
- **Fonts are self-hosted** (Mona Sans, Monaspace Neon and Noto Sans Arabic via `@fontsource*`, no Google Fonts requests). A privacy product shouldn't leak visits to third parties.
- **No analytics** at launch. If ever needed: self-hosted, cookieless, aggregate only (e.g. Plausible self-hosted), announced in the changelog.
- **Hosting:** any static host (Cloudflare Pages, Netlify, GitHub Pages, or our own Caddy). The build output is `apps/website/dist`.
- **Docs from the repo root:** the `docs` collection uses Astro's `glob` loader on `../../docs`, and Starlight's `markdown.processedDirs` covers that folder so asides and heading links work. After changing Markdown plugin config, clear `node_modules/.astro` (rendered content is cached).
- **Brand:** tokens, logo and images come from `brand/` (see `brand/README.md`). There's a branded 404 page (`src/pages/404.astro`).
- **Languages:** English at the root and Arabic under `/ar/`. A docs page with no translation shows the English text with a notice. The changelog is English only. See `docs/contributing/translations.md`.
- **Single config:** `apps/website/src/site.config.ts` holds the site URL, repo URL, name and description. Set `PUBLIC_SITE_URL` and `PUBLIC_REPO_URL` at build time.

## SEO checklist

- [x] Static, server-rendered HTML for every page
- [x] Unique `<title>` and meta description per page (docs pages *require* `description` in front matter)
- [x] Canonical URLs, `sitemap-index.xml`, `robots.txt` pointing at the sitemap
- [x] Sitemap `<lastmod>` per URL and `xhtml:link` alternates (en, ar, x-default) for pages in both languages
- [x] Open Graph + Twitter card tags; default social image
- [x] JSON-LD: `SoftwareApplication` + `Organization` + `WebSite` on the landing page, `FAQPage` for the FAQ section, `TechArticle` (with `dateModified`) + `BreadcrumbList` on docs pages, `BlogPosting` + `BreadcrumbList` on changelog entries
- [x] One of each social tag: our tags replace Starlight's in its head list rather than repeating them
- [x] `/.well-known/security.txt`
- [x] Semantic headings (one `h1`), descriptive link text, `lang`/`dir` attributes
- [x] Fast: no client JS on content pages except search; fonts subset and preloaded
- [x] Accessible: contrast AA, focus styles, reduced motion respected
- [x] Per-page OG images (generated at build time)
- [x] `hreflang` alternates, with `x-default`, on docs and the landing page
- [ ] Submit to Google Search Console and Bing Webmaster Tools after the domain is chosen

### Target search intents
"open source password manager", "1Password alternative", "free password manager", "self-hosted password manager", "password manager with passkeys", "Bitwarden alternative", "LastPass alternative", "import from 1Password/LastPass/Chrome", "password manager for Linux". Docs pages for each importer and each comparison capture long-tail traffic. Comparison pages must be factual and dated.

## AI-friendliness

1. **`/llms.txt`**: index of all docs with one-line descriptions. **`/llms-full.txt`**: all docs in one file. **`/llms-small.txt`**: compact version.
2. **Markdown twins:** every docs page is available at the same path + `.md` (e.g. `/docs/security/encryption.md`), and so are the landing page (`/index.md`, `/ar/index.md`), the changelog (`/changelog/index.md`) and each entry. Each HTML page advertises its twin with `<link rel="alternate" type="text/markdown">`, and `llms.txt` lists the site pages and the newest changelog entries next to the docs.
3. **`robots.txt` explicitly allows** AI crawlers (GPTBot, ClaudeBot, Claude-SearchBot, PerplexityBot, Google-Extended, Applebot-Extended, CCBot) on docs. Being cited by AI assistants is a goal for an open-source project.
4. **Agent skill** (`skills/octapass-docs/SKILL.md`): teaches Claude Code, Codex and other agents how to search the docs, locally in the repo or remotely through `llms.txt` and the `.md` twins, and how to answer with citations. It includes a zero-dependency search script.
5. **Stable structure:** front matter (`title`, `description`, `status`) on every page, and one topic per page, so retrieval stays precise.
6. **MCP server** (`octapass-docs-mcp`, `skills/octapass-docs/scripts/docs_mcp.py`) exposing `search_docs`, `get_page` and `list_pages`, built on the same index.
7. **CLI agent skill** (`skills/octapass-cli/SKILL.md`): teaches agents to use the `octapass` CLI for a user without exposing secrets. Agents print no secret unless asked, inject secrets with `octapass run` instead of copying them, never handle the master password or Secret Key, and confirm before anything destructive. It's tested against the built CLI's `--help` in CI, so it can't name a command, option or value that doesn't exist, and a new command fails the tests until the skill covers it.

## Docs information architecture

```
docs/
├── index.md                      What Octa Pass is, project status
├── getting-started/              Overview, quick start, Recovery Kit
├── features/                     Item types, autofill, passkeys, TOTP, generator, health, sharing,
│                                 masked email, recovery info, emergency access, biometrics, offline
├── import-export/                Overview + one page per major source
├── platforms/                    Support matrix, browser extension, desktop, mobile, CLI
├── security/                     Overview/whitepaper, encryption & keys, authentication,
│                                 recovery, threat model, what the server sees, breach checks
├── self-hosting/                 Overview, Docker, configuration, backups
├── developers/                   Architecture, sync API, crypto test vectors (later)
├── contributing/                 How to contribute, dev setup, writing docs, AI agents & skill
└── reference/                    FAQ, glossary, roadmap, license
```

Every page carries a `status` (`planned` / `in-progress` / `beta` / `stable`), shown as a badge. Until code ships, docs describe the **design** and say so.

## History
- 2026-11-02 (branch `m25-platform-extras`): the MCP docs server is built, as one zero-dependency Python file beside `search_docs.py`, importing its loading and search so both stay the same index. Decisions: stdio only, so there's no port, account or hosted service to run; newline-delimited JSON-RPC by hand, because the skill's rule is no dependencies and three read-only tools don't need an SDK; it offers the MCP versions 2025-06-18, 2025-03-26 and 2024-11-05, answering with the client's when it knows it. `list_pages` is added to the planned two so a client can browse. Pages are found by matching known slugs, never by building a file path from the request, so a tool call can't read outside the docs. Local docs are read again on each call; remote mode uses the skill's one-day cache.
- 2026-11-02 (branch `m25-scope-docs`): Arabic website and docs, per-page OG images, hreflang. Decisions:
  - **Arabic pages live in `docs/ar/`**, with the same paths as the English pages, so Weblate's Markdown format can map them by file mask. `slugFromPath` in `content.config.ts` gives them Starlight's `ar/docs/…` ids.
  - **The landing page's words are JSON** (`src/i18n/landing/`) so Weblate can edit them directly, with one `Landing.astro` for both languages. A test keeps the two files the same shape.
  - **OG images use `sharp`'s Pango text renderer**, which Astro already depends on, rather than Satori (no real Arabic shaping) or a headless browser. Each page's image is under `/og/<language>/`. The Latin font is the Android app's `mona_sans.ttf`, which `tools/native-fonts` keeps equal to the web's, and Arabic is `@fontsource/noto-sans-arabic`'s static WOFF, because Pango can't read WOFF2 and silently falls back to a system font. This adds about 230 images to the build.
  - **The changelog stays English:** there are 66 entries and more each day, and a translated changelog that lags is worse than an honest English one. Arabic pages link to it and say so.
  - **One 404 file** says it in both languages, because a static host serves one 404.
  - **`hreflang`:** Starlight adds it to docs pages, `Site.astro` to the landing page, both with `x-default`. English-only pages have none.
  - The landing page's phase numbers and "Phase N" badges are gone: they stopped making sense once phases 7 and 8 moved before phase 6. Its roadmap shows state instead.
- 2026-11-08: sitemap dates, Markdown for every content page, security.txt. Decisions:
  - **`@astrojs/sitemap` is configured in `astro.config.mjs`** instead of the copy Starlight adds, for `serialize`. `<lastmod>` is the last commit to the page's source file (`src/lib/lastmod.mjs`, one `git log` per build); a changelog entry uses its `date`; anything unknown gets the build date. The Docker build has no `.git`, so `deploy/octap.app/deploy.sh` writes the same `git log` to `apps/website/.git-dates.txt` (ignored by git) before `docker build`.
  - **The landing page's Markdown is built from `src/i18n/landing/*.json`**, with headings taken from the page's own strings, so it is translated whenever the page is and can't say something the page doesn't.
  - **Arabic fallback docs pages stay in the sitemap**, with the same `<title>` as the English page. They are real pages that hreflang points to; giving them an English canonical instead is open.
