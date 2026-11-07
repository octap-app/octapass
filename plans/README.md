# Plans

Internal product and engineering plans for **Octa Pass**. Read them in order. Public, user-facing documentation lives in [`/docs`](../docs) and is built from the decisions recorded here.

**Current scope (maintainer decision, 2026-11-02):** everything planned for after 1.0 (roadmap phases 7 and 8, every P2 item in plan 01, all of plan 16) is inside 1.0. Where an older plan says "P2", read "required for 1.0, built after P1". Plan 16's "starts after 1.0" is superseded. See [plan 09](09-roadmap.md).

| # | Plan | What it decides |
|---|---|---|
| 00 | [Idea review](00-idea-review.md) | Decisions on the original idea; what was added, removed or edited; name risk; open questions |
| 01 | [Product spec](01-product-spec.md) | Audience, principles, item types, full feature list with priorities, non-goals |
| 02 | [Architecture](02-architecture.md) | Monorepo layout, Rust core + TS UIs, modules, data flow |
| 03 | [Security model](03-security-model.md) | Crypto, key hierarchy, OPAQUE login, unlock, recovery, threat model |
| 04 | [Sync server](04-sync-server.md) | Server stack, data model, sync protocol, API conventions, self-hosting |
| 05 | [Clients and autofill](05-clients-and-autofill.md) | Platform matrix, extension, passkeys, desktop, mobile, CLI, autofill quality |
| 06 | [Health, sharing, aliases](06-health-sharing-aliases.md) | Security dashboard, sharing, masked email, emergency access, account 2FA |
| 07 | [Import and export](07-import-export.md) | Importers by priority, export formats, testing |
| 08 | [Website, docs, SEO, AI](08-website-docs-seo-ai.md) | Website routes, SEO checklist, `llms.txt`, Markdown twins, agent skill |
| 09 | [Roadmap](09-roadmap.md) | Phases, durations, current checklist, exit criteria, risks |
| 10 | [Operations and funding](10-operations-and-funding.md) | Hosting costs, funding without ads, legal, incident response |
| 11 | [Milestone 1: web vault](11-milestone-1-web-vault.md) | How the web vault was built: tasks, decisions, history |
| 12 | [Milestone 2: extension foundations](12-milestone-2-extension-foundations.md) | Autofill engine, corpus, local mode foundations |
| 13 | [Milestone 3: extension and desktop](13-milestone-3-extension-and-desktop.md) | Browser extension, desktop apps, passkeys, native messaging |
| 14 | [Milestone 4: mobile](14-milestone-4-mobile.md) | The Tauri phone apps and native autofill services |
| 15 | [Milestone 5: sharing backend](15-milestone-5-sharing-backend.md) | Shared vaults, families, share links, emergency access |
| 16 | [Developer toolkit and files](16-developer-toolkit-and-files.md) | Generators, inspectors, integrations, the file safe (inside 1.0) |
| 17 | [Native mobile apps](17-native-mobile-apps.md) | SwiftUI and Jetpack Compose apps on the Rust core |
| 18 | [Stay unlocked](18-stay-unlocked.md) | Built: staying unlocked while logged in to the device, reveal once, high-risk actions always ask |
| 19 | [Native desktop apps](19-native-desktop-apps.md) | SwiftUI on macOS first, then WinUI 3 and GTK4, on the phones' `OctaPassVault` API; Tauri desktop dropped on macOS (2026-11-06), stays on Windows and Linux until parity |

## Rules for plans

- A plan records **decisions and reasons**. When a decision changes, edit the plan and add a `changelog/` entry. Don't keep stale alternatives around.
- Open questions go in the table at the end of `00-idea-review.md`.
- When a plan changes behaviour users can see, update the matching page in `/docs`.
