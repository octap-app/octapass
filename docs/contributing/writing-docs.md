---
title: Writing docs
description: How to write and structure Octa Pass documentation, including front matter, status badges, asides, link style, Markdown twins, llms.txt and changelog entries.
status: stable
sidebar:
  order: 3
---

## Where docs live

Docs are Markdown files in the repository's root `docs/` folder. The website in `apps/website` (Astro + Starlight) loads them and serves them under `/docs/`. The file path becomes the URL:

| File | URL |
|---|---|
| `docs/index.md` | `/docs/` |
| `docs/security/encryption.md` | `/docs/security/encryption/` |
| `docs/ar/security/encryption.md` | `/ar/docs/security/encryption/` |

Files and folders starting with `_` are ignored.

Each page is also published as:

- A **Markdown twin** at the page URL plus `.md`, for example `/docs/security/encryption.md`
- Part of **`/llms.txt`** (index), **`/llms-full.txt`** (all docs) and **`/llms-small.txt`** (compact)

So write pages that make sense as standalone Markdown. See [docs for AI agents](/docs/contributing/ai-agents/).

## Front matter

```yaml
---
title: Encryption and keys
description: One sentence, 120–160 characters, unique, describing the page for search results.
status: planned
sidebar:
  order: 2
---
```

| Field | Required | Notes |
|---|---|---|
| `title` | Yes | Sentence case. It becomes the page's `h1`, so don't repeat it in the body. |
| `description` | Yes | Used for the meta description, social cards and `llms.txt`. Be specific. |
| `status` | Yes | `planned`, `in-progress`, `beta` or `stable`. It describes the **feature**, not the page. |
| `sidebar.order` | Recommended | Order within the folder |

### Status values

| Status | Meaning |
|---|---|
| `planned` | Designed, not built. The page describes the design. |
| `in-progress` | Being built; details may change. |
| `beta` | Available for testing. |
| `stable` | Released, or a page about the project itself. |

## Asides

Pages about unbuilt features open with a note:

```md
:::note[Planned]
This describes the design. It isn't available yet. See the [roadmap](/docs/reference/roadmap/).
:::
```

Also available: `:::tip`, `:::caution` and `:::danger`. Use `caution` and `danger` only for real risks to data or security.

## Style

- Plain English, short sentences, sentence-case headings, no emojis in headings.
- Present tense for the design ("Octa Pass encrypts…"). Never claim a download or store listing exists before it does.
- Use tables for data that's actually tabular, and tag code blocks with a language (`bash`, `yaml`, `json`, `text`).
- One topic per page. Split pages longer than about 1,500 words.
- Call the product **Octa Pass** in prose and `octapass` in commands and identifiers.

## Links

Use absolute site paths with a trailing slash:

```md
See [encryption](/docs/security/encryption/) and [conflicts](/docs/features/offline-and-sync/#conflicts).
```

## Changelog

For a notable change (a new page section, a changed design decision, a release), add a file to `changelog/` named `YYYY-MM-DD-short-slug.md`. The format is in `changelog/README.md`.

## Translations

English is the source. Arabic pages live in `docs/ar/` with the same paths, and a page with no translation shows the English text with a notice. Write English first: see [translations](/docs/contributing/translations/) for how the other languages follow.

## Keep plans and docs in sync

Decisions are recorded in `plans/`. When a plan changes something users can see, update the matching docs page in the same pull request.
