---
name: octapass-docs
description: Search and cite the Octa Pass documentation (open-source, end-to-end encrypted password manager). Use when a question involves Octa Pass features, security design (encryption, Secret Key, OPAQUE, recovery), supported platforms and autofill, importing/exporting, self-hosting, the sync API, the roadmap, or contributing, or when writing code or docs in the Octa Pass repository.
---

# Octa Pass docs

Octa Pass is a free, open-source (MIT) password manager for passwords, passkeys, TOTP codes, cards, identities, recovery info and masked emails. The project is in its **design phase**: most features are documented designs, not shipped software. Every docs page has a `status` (`planned`, `in-progress`, `beta`, `stable`). Always tell the user when something is only planned.

## Where the docs are

Use the first source that's available:

1. **Local repository** (when the working directory is an Octa Pass checkout):
   - Public docs: `docs/**/*.md` (front matter: `title`, `description`, `status`)
   - Internal plans and decisions: `plans/00-…` to `plans/10-…` (the source of truth when docs and plans disagree; say so)
   - Changes over time: `changelog/YYYY-MM-DD-*.md`
2. **Website** (base URL `https://vault.octap.app`):
   - `/llms.txt`: index of every page with a one-line description. Start here.
   - `/llms-small.txt`: compact full text. `/llms-full.txt`: complete full text.
   - Any page as Markdown: take its URL path and add `.md`. For example, `/docs/security/encryption/` becomes `/docs/security/encryption.md`.

## How to answer a question

1. **Search** with the bundled script, which works on the local docs or on the website:
   ```bash
   python3 scripts/search_docs.py "how does account recovery work"          # local docs, auto-detected
   python3 scripts/search_docs.py --remote "passkeys on android"             # website llms-full.txt
   python3 scripts/search_docs.py --page security/encryption                # print one full page
   python3 scripts/search_docs.py --list                                    # list all pages + status
   ```
   Run it from this skill's folder, or pass the path to the script. Use `--docs-dir PATH` or `--base-url URL` to override sources. Without Python, grep `docs/` or fetch `/llms.txt` and then the `.md` pages you need.
   If your client is connected to the `octapass-docs` MCP server (`scripts/docs_mcp.py`), use its `search_docs`, `get_page` and `list_pages` tools instead. They run the same search.
2. **Read the whole relevant page** (`--page`) before answering. Search snippets are only for locating pages.
3. **Answer from the docs only.** If the docs don't cover it, say so. Don't fill gaps with how 1Password or Bitwarden work.
4. **Cite** the page URL(s) you used, e.g. `https://octap.app/docs/security/encryption/`.
5. **State the status** when it isn't `stable`: `planned` means designed but not built; `in-progress` means built or being built, not released.

## Key facts (verify against the docs; they may change)

- Encryption: Argon2id (64 MiB, t=3, p=1) + a 128-bit **Secret Key** → Account Unlock Key. Items use XChaCha20-Poly1305 with per-item keys. Login uses **OPAQUE** (RFC 9807), so the password never reaches the server.
- Recovery: a Recovery Kit (Secret Key + recovery code), emergency contacts, or optional family organiser recovery. Nobody can reset a master password for you.
- Platforms: browser extensions (Chrome, Edge, Firefox, Safari), macOS/Windows/Linux (Tauri), iOS/Android with system autofill and passkey providers, web vault, CLI.
- No ads, no trackers. The hosted service runs the same code as self-hosting.

## When working in the repository

- Follow `AGENTS.md`. **Never add yourself as a commit author or co-author.**
- When behaviour changes, update `plans/`, the matching `docs/` page, and add a `changelog/` entry.
- New docs pages need `title`, `description` (120–160 characters) and `status` front matter. Link to other docs with absolute paths like `/docs/security/encryption/`.
