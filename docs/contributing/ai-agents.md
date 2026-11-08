---
title: Docs for AI agents
description: How AI agents read the Octa Pass docs through llms.txt, Markdown twins and the octapass-docs skill, use the CLI safely with octapass-cli, and follow repo rules.
status: stable
sidebar:
  order: 4
---

The Octa Pass docs are written to be easy for AI assistants and coding agents to find, read and cite.

## Machine-readable entry points

| URL | Contents |
|---|---|
| `https://octap.app/llms.txt` | An index of every docs page with a one-line description ([llmstxt.org](https://llmstxt.org) convention) |
| `https://octap.app/llms-full.txt` | All docs in one Markdown file |
| `https://octap.app/llms-small.txt` | A compact version for small context windows |
| `https://octap.app/docs/<page>.md` | The **Markdown twin** of any page, for example `/docs/security/encryption.md` |
| `https://octap.app/index.md`, `/ar/index.md` | The home page as Markdown: what Octa Pass is, features, the free plan, platforms and whether each is available, open source links, FAQ |
| `https://octap.app/changelog/index.md` | The changelog, newest first, linking to each entry's Markdown at `/changelog/<slug>.md` |
| `https://octap.app/sitemap-index.xml` | Every page, with its last-change date and its English and Arabic versions |

Every HTML page with a Markdown version advertises it:

```html
<link rel="alternate" type="text/markdown" href="/docs/security/encryption.md">
```

The site's `robots.txt` allows AI crawlers on the docs.

## The `octapass-docs` skill

The repository ships an [Agent Skill](https://agentskills.io) that teaches agents how to search these docs and answer with citations:

- In the repository: `skills/octapass-docs/SKILL.md`
- On the web: `https://octap.app/skills/octapass-docs/SKILL.md`

It includes a zero-dependency search script:

```bash
# Inside the repository: searches the local docs/ folder
python3 skills/octapass-docs/scripts/search_docs.py "secret key recovery"

# Anywhere: downloads llms-full.txt and searches it
python3 skills/octapass-docs/scripts/search_docs.py --remote "self-hosting postgres"
```

### Installing the skill

| Agent | How |
|---|---|
| Claude Code (all projects) | Copy `skills/octapass-docs/` to `~/.claude/skills/octapass-docs/` |
| Claude Code (one project) | Copy it to `.claude/skills/octapass-docs/` in that project |
| Other agents (Codex, Cursor, Copilot…) | Point to it from your project's `AGENTS.md`, for example: "To answer questions about Octa Pass, follow `skills/octapass-docs/SKILL.md`." |

## The `octapass-cli` skill

A second skill teaches agents to use the [`octapass` command-line tool](/docs/platforms/cli/) for a user: finding and reading items, creating and editing them, generating passwords, getting one-time codes, handing secrets to commands with `octapass run` and `octapass://` references, environments, service accounts and CI, SSH keys and file encryption.

- In the repository: `skills/octapass-cli/SKILL.md`, with `references/commands.md` (every command) and `references/ci.md` (GitHub Actions, GitLab CI, cloud tools and Connect)
- On the web: `https://octap.app/skills/octapass-cli/SKILL.md`

It starts with rules an agent follows before anything the task asks:

1. Don't print a secret unless the user asks for that value. `octapass get <item>` shows an item with its secrets left out, and `octapass list --json` never holds secrets. `octapass get <item> --json` without `--field` includes them.
2. Inject secrets rather than copying them: `octapass run`, `octapass inject` and `octapass://` references keep the value out of the agent's output.
3. Never ask for, store or pass the master password or Secret Key. When the vault is locked (exit code 4), the user unlocks it in their own terminal or through the desktop app.
4. Confirm before deleting, overwriting, exporting or changing the account, and never add `--yes` to skip the CLI's own question.

Install it the same way as `octapass-docs`: copy `skills/octapass-cli/` to `~/.claude/skills/octapass-cli/`, or point to it from `AGENTS.md`.

The skill can't drift from the CLI. Its tests read the built binary's `--help` for every command and fail if the skill names a command, option or value that doesn't exist, an environment variable the CLI doesn't read, or exit codes other than those in `apps/cli/src/error.rs`. They also fail when the CLI gains a command the skill doesn't mention. CI runs them on every push:

```bash
cargo build -p octapass-cli
python3 -m unittest discover -s skills/octapass-cli/tests
```

## The MCP docs server

`octapass-docs-mcp` gives any [Model Context Protocol](https://modelcontextprotocol.io) client the same search as the skill, as tools. It's one Python file with no dependencies, needs Python 3.9 or later, and talks over stdio, so nothing listens on a port and it needs no account.

| Tool | What it does |
|---|---|
| `search_docs` | Searches the docs. Takes `query` and an optional `limit` (1–20). Returns each match's title, section, status, URL, page and a snippet |
| `get_page` | Returns one full page. Takes `page`, such as `security/encryption` |
| `list_pages` | Lists every page with its status and description |

All three only read. Add it to your client's MCP settings. Inside a checkout it reads `docs/`:

```json
{
  "mcpServers": {
    "octapass-docs": {
      "command": "python3",
      "args": ["/path/to/octapass/skills/octapass-docs/scripts/docs_mcp.py"]
    }
  }
}
```

Outside a checkout it reads the website, or add `"--remote"` to `args` to force that. `--docs-dir PATH` and `--base-url URL` work as they do for `search_docs.py`. Search queries stay on your computer: remote mode only downloads the docs' public pages and caches them for a day.

## Rules for agents working in the repository

Agents that change this repository must follow `AGENTS.md` at the repository root. The most important rules:

1. **Never list an AI as an author.** No `Co-Authored-By` trailers for agents, no "Generated with…" lines in commits, PRs, docs or code, and no changes to the git author. The human maintainer is the author.
2. Commit or push only when the maintainer asks.
3. Never weaken the zero-knowledge security model without a recorded decision in `plans/`.
4. No ads, trackers or third-party scripts.
5. Keep `plans/`, `docs/` and `changelog/` in sync. See [writing docs](/docs/contributing/writing-docs/).

## Citing the docs

When an agent answers a question about Octa Pass, it should link the page it used (for example `https://octap.app/docs/security/encryption/`) and mention the page's `status`. Most features are still `planned`, so they shouldn't be described as available.
