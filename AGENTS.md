# AGENTS.md

Instructions for AI coding agents (Claude Code, Codex, Cursor, Copilot, etc.) working in this repository.

## Hard rules

1. **Never list yourself as an author.** Commits, PRs, changelog entries and file headers are authored by the human maintainer only.
   - Do not add `Co-Authored-By:` trailers for an AI/agent.
   - Do not add "Generated with …" / "Created by …" lines to commit messages, PR bodies, docs or code.
   - Do not change `git config user.name` / `user.email`, and do not pass `--author`.
2. Only commit or push when the maintainer asks.
3. Never weaken the security model in [`plans/03-security-model.md`](plans/03-security-model.md) (zero-knowledge, client-side encryption) without an explicit decision recorded in `plans/`.
4. No ads, trackers, or third-party scripts anywhere: not in the website, the apps or the extensions.

## Repository layout

| Path | What lives there |
|---|---|
| `plans/` | Internal product and engineering plans: decisions, architecture, roadmap. Numbered, read in order. |
| `docs/` | Public open-source documentation. Served by the website at `/docs/`, Arabic from `docs/ar/` at `/ar/docs/`. Markdown with Starlight front matter. |
| `changelog/` | One dated Markdown file per notable change (`YYYY-MM-DD-slug.md`). Served at `/changelog/`. |
| `translations/` | App strings for Weblate, generated from the TypeScript catalogs. Run `node tools/translations/sync.mjs export` after changing a catalog. |
| `skills/octapass-docs/` | Agent skill that teaches AI agents to query the Octa Pass docs. |
| `apps/website/` | Astro + Starlight website (landing page, docs, changelog, `llms.txt`). |
| `integrations/` | Files other systems consume: the GitHub Action and GitLab CI template. Thin wrappers over the CLI. |
| `brand/` | Logo, colours, type, voice, README banner and the scripts that generate them. Follow `brand/README.md` for any UI. |

## When you change things

- A change to behaviour or architecture → update the relevant `plans/` file **and** the matching `docs/` page.
- Any user-visible or notable change → add a file in `changelog/` (see `changelog/README.md`).
- New docs page → needs `title`, `description` and `status` front matter (see `docs/contributing/writing-docs.md`).
- Run `pnpm build` from the repo root before saying website work is done.
