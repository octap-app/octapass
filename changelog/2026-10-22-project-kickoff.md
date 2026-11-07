---
title: Octa Pass kicks off, with plans, docs and a website
date: 2026-10-22
summary: The idea was reviewed and renamed to Octa Pass, the plans and security design were written, and the docs website went up with llms.txt and an agent skill.
tags: [decision, docs, website, security]
---

Octa Pass started as an idea for an open-source 1Password alternative called "All Pass". Today it became a plan.

## Decisions

| Topic | Decision |
|---|---|
| Name | **Octa Pass** (renamed from All Pass; trademark check pending) |
| Stack | Rust core shared everywhere (WASM, UniFFI, Tauri) with TypeScript/React interfaces |
| License | MIT. The free hosted service and the self-hosted version are the same code |
| Ads | None, ever. Funded by donations, sponsors and grants |
| "Email and phone verification" | Masked email aliases and per-login recovery info (recovery email/phone, backup codes) |

## Added

- **Plans** (`plans/00`–`10`): idea review, product spec, architecture, security model, sync server, clients and autofill, sharing and aliases, import/export, website/SEO/AI, roadmap, operations and funding.
- **Security design**: zero-knowledge encryption with a Secret Key, Argon2id, XChaCha20-Poly1305, OPAQUE login, Recovery Kit and recovery code. See the [security overview](/docs/security/overview/).
- **Documentation website** built from the repo's `docs/` folder, with search, status badges on every page, and Markdown versions of each page at `<page>.md`.
- **AI-friendly docs**: `/llms.txt`, `/llms-full.txt`, `/llms-small.txt`, and an [agent skill](/docs/contributing/ai-agents/) that teaches AI agents to search and cite the docs.
- **Changelog** with an RSS feed.
- `AGENTS.md` and `CLAUDE.md` with repository rules for AI agents. AI tools are never listed as commit authors.
- **Brand**: an open ring around a keyhole (*open* source, *pass*), ink-blue and brass palette, Schibsted Grotesk + JetBrains Mono (self-hosted), README banner, social image and app icon. See `brand/README.md`.
- **Repository basics**: README, MIT `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.

## Next

Trademark search and domain, then the Phase 1 spikes: OPAQUE + Argon2id in WASM, and Tauri 2 mobile with an iOS AutoFill extension. See the [roadmap](/docs/reference/roadmap/).
