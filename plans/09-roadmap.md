# 09 — Roadmap

**Scope (maintainer decision, 2026-11-02):** everything planned for after 1.0 (phases 7 and 8 below, every P2 item in plan 01, all of plan 16) is inside 1.0. Phases 7 and 8 keep their numbers so older references still work, but they now come **before** phase 6: the audit reviews what actually ships.

"Built" below means the code exists and its tests pass. It doesn't mean released. Nothing is in a store, nothing has had its external audit, and the only running deployment is the maintainer's own (`vault.octap.app`, invite only).

| Phase | Goal | Status (2026-11-05, every `m25-*` branch merged) | Ships |
|---|---|---|---|
| **0. Foundations** | Decide, design, publish | Mostly done; see the checklist | Plans, docs website, security design, name/domain/trademark check, repo + CI, `SECURITY.md`, contribution guide |
| **1. Core + server + CLI** | A working encrypted vault, end to end | **Built.** Since the m25 merge the CLI signs up, creates and edits items, and unlocks through the desktop app | `octapass-core` (crypto, keys, items, sync, TOTP, generator), server (OPAQUE, sync, email), CLI, minimal web vault |
| **2. Browser extensions + web vault** | Daily-usable on desktop browsers | **Built, not released.** Public alpha not opened. Local mode is in the extension, the desktop app and the native phone apps (m25 merge) | Chrome/Edge/Firefox extensions (autofill, save, passkeys, TOTP, cards, identities), full web vault, P0 importers, security dashboard v1, **local mode** in the extension, self-host image. **Public alpha** on the hosted service |
| **3. Desktop apps** | Native desktop + biometrics | **Built, not released.** Builds aren't notarised or signed for distribution; no updater; no Flatpak or AUR package; desktop local mode built in the m25 merge but not tried on signed builds; Safari extension not verified in Safari itself | Tauri app for macOS/Windows/Linux, Touch ID/Windows Hello, native messaging unlock, auto-type, macOS AutoFill provider, Safari extension (macOS) |
| **4. Mobile apps** | Autofill on phones | **Built on Tauri, replaced by phase 5b.** Public beta not opened. No store builds; local mode is in the native apps (phase 5b), not the Tauri app | iOS + Android apps, system autofill + passkey providers, camera TOTP, Safari on iOS. **Public beta** |
| **5. Sharing & completeness** | Feature parity with paid managers | **Built.** Push and the push relay came last (2026-11-08, plan 04 History): built and tested against local stand-ins for Apple and Google, not yet run with real credentials, and the project's relay isn't deployed. The bank account, API credential, software licence, ID document, crypto wallet and database types, email breach alerts, security questions, version history, and Secret Key and vault key rotation came with the m25 merges | Shared vaults, families, share links, emergency access, masked email integrations, recovery map, P1 importers + CXF, attachments, account 2FA, Arabic UI |
| **5b. Native phone apps** | Native feel on phones | **Plan 17 phases 1 and 2 built.** Phase 3 is in progress: native SSH key and environment screens and the reveal gate are merged, but the UI tests are incomplete and the autofill gate isn't built on the phones (plan 17a). The Tauri phone app (`apps/mobile`) was removed on 2026-11-05 | SwiftUI (iOS/iPadOS) and Jetpack Compose (Android) on the Rust core through one UniFFI vault API |
| **5c. Native desktop apps** | Native feel on computers | **Plan 19 phase 1 started** (2026-11-06): the Mac app on the phones' vault API. On macOS the native app replaced the Tauri app on 2026-11-06 (its Mac support removed, no migration); the Tauri app stays on Windows and Linux until their native apps reach parity | SwiftUI (macOS), then WinUI 3 (Windows) and GTK4 (Linux), on the Rust core through the same UniFFI vault API |
| **7. Growth features** (inside 1.0) | Everything that was "after 1.0" | **Built, not yet reviewed** (m25 merges): SSH agent, teams and organisations with SSO sign-in, post-quantum sharing, key transparency, the Windows 11 passkey provider (tested with a stand-in, never run on real Windows), Apple Watch and Wear OS code apps, the MCP docs server (`skills/octapass-docs/scripts/docs_mcp.py`), and every P2 item in plan 01 except Nearby. Left: SCIM and SAML. Key log witnesses are built (2026-11-08); nobody is chosen to witness the hosted service. Post-quantum sharing and key transparency still need the outside cryptographer's review | Windows passkey provider, SSH agent, teams and organisations, watch apps, post-quantum sharing, key transparency, MCP docs server, every P2 item in plan 01. Own masked-email service only if plan 00's open question is answered yes |
| **8. Developer toolkit and file safe** (inside 1.0) | Beyond passwords | **Built, not yet reviewed** (m25 merges): environments, SSH keys, the developer toolkit (plan 16 sections 1, 2 and 5), Octa Pass Connect, service accounts and CLI secret injection. File encryption, secure delete and Octa Pass Safe are built (`m25-file-safe`, merged 2026-11-04): the CLI, desktop app and Linux mount are tested; the Finder, Explorer and phone integrations are built but not yet run on those systems | Plan 16: certificates, keys, JWT/JWS reader and signer, hashes, encodings, QR, Octa Pass Connect and CLI secret injection, file encryption, then the Octa Pass Safe encrypted drive |
| **6. Audit → 1.0** | Trust | **Not started.** Comes last | External audit of the full scope, fixes, published report, bug bounty, reproducible builds verified. **1.0 GA** |

## What isn't built

Checked against the code on 2026-11-05, with every `m25-*` branch merged into `main`. Each line says where the gap shows.

**Features**

- **Organisations:** SCIM and SAML are built (2026-11-08, plan 03 "SAML" and "SCIM provisioning"; plan 15 History), and organisations run from the CLI (`octapass org`) and the Windows and Linux app as well as the web vault. Left: an organisation screen in the native Mac, iPhone, iPad and Android apps (they use `crates/octapass-mobile`, which has no organisation engine yet), and SAML and SCIM tried against real identity providers. Admin account recovery and group keys are left out on purpose (plan 03 History).
- **Witnesses for the hosted service:** key log witnesses are built (`apps/witness`, `OCTAPASS_KEY_LOG_WITNESSES`, plan 03 "Witnesses"), but nobody has been chosen to witness `vault.octap.app`, so it runs without them.
- **The autofill gate on the phones:** with stay unlocked (plan 18) off, the AutoFill extension and the Android services still ask on every fill (plan 17a, "Device auth: autofill switch"). With it on, the default, they fill without asking.
- **Nearby:** the sidebar shows it as "Soon" and `parseScope('nearby')` falls back to All items (`apps/web/src/lib/scope.test.ts`). The last P2 item in plan 01 that isn't built.
- **New item types, the rest:** expiry warnings cover cards and ID documents only, not software licences or API credentials (`packages/vault-client/src/tools/health.ts`); no autofill from the new types; `octapass create` takes login, password, note, card, identity and wifi only (`apps/cli/src/cli.rs`).
- **Health checks:** "recovery email breached" for an address that is neither the account email nor an alias, the backup reminder (plan 05), and the signed passkey-data update (plan 06).
- **Native phone apps (plan 17 phase 3):** the UI tests.
- **Our own masked email service:** `apps/relay` is built, off by default and not deployed. Whether the hosted service runs it is still open in plan 00.

**Built, but never run where it ships**

- Push (plan 04): never sent through the real APNs or FCM (no credentials; tests use local fakes), the project's push relay isn't deployed, and Android needs its Firebase settings at build time.
- The file safe's Finder, Explorer and phone integrations.
- The Windows 11 passkey provider (tested with a stand-in for Windows only).
- The quick lists and pins in the Swift and Kotlin apps (never compiled).
- The Safari extension in Safari, and desktop local mode on signed builds.

**Release**

- No signed or notarised desktop builds: `release.yml` has no signing step. No updater plugin, no Flatpak or AUR package.
- No store builds of the phone apps, and the iOS app hasn't run on a phone (no signing team on the build Mac).
- No reproducible-build setup for the extension or the web vault.
- No opt-in crash report, so the beta's crash-free figure can't be measured.

**Review and audit**

- None of the `m25-*` slices has been reviewed since it merged.
- Post-quantum sharing and key transparency need the outside cryptographer.
- Phase 6 hasn't started.

The Phase 0 checklist and the exit criteria below list the rest.

## Estimate

The old figure was 15–18 months to 1.0 with 2–3 full-time engineers. It no longer holds, for two reasons: the scope grew, and phases 1 to 5b were built in about a week by the maintainer with coding agents, at preview quality. So there are now two estimates. Both are rough, and neither is a promise.

| Work left | With 2–3 full-time engineers | With the maintainer and agents |
|---|---|---|
| Finish phases 1–5b (the gaps above, real-device testing, signing, stores) | ~2–3 months | ~1–2 months |
| Phase 7 | ~7–9 months | Weeks of code, then review |
| Phase 8 | ~8–10 months, A and B overlapping with phase 7 | Weeks of code, then review |
| Public alpha, then public beta, with their exit criteria | Overlaps the above | ~3–4 months: these are measured in calendar time and real use |
| Phase 6: audit, fixes, retest | ~3–4 months (was ~2): the surface roughly doubles | ~3–4 months: it doesn't get faster with agents |
| **Total from 2026-11-02** | **~18–24 months: into 2028** | **~8–11 months: Q3 2027 at the earliest** |

What sets the date isn't writing code any more. It's the human gates: review of each merged slice, real devices, store review, weeks of dogfooding, booking and paying for an audit, and fixing what it finds. Anything an agent builds still has to pass them. Phases 7 and 8 together add more code than phases 1–5 did, most of it security-sensitive, so review time is the likeliest place for this estimate to slip.

## Phase 0 checklist

- [x] Idea review and decisions (`plans/00`)
- [x] Product, architecture, security, server, client, import, website plans
- [x] Docs website with `llms.txt`, Markdown twins, SEO, changelog, RSS
- [x] Agent skill for querying the docs
- [x] `AGENTS.md` / `CLAUDE.md` rules (no AI authorship)
- [x] Brand: logo, colours, type, voice, README banner, social image, app icon (`brand/`)
- [x] Professional README, LICENSE (MIT), SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md
- [x] Create GitHub org + repo and push: `github.com/octap-app/octapass` (private for now)
- [x] CI: `.github/workflows` (`ci.yml`, `fuzz.yml`, `release.yml`)
- [x] Issue and PR templates (`.github/`)
- [x] Spike: OPAQUE + Argon2id in WASM in the browser: answered by the web vault (plan 11). The < 1.5 s unlock budget on low-end Android was never measured; it's now a public beta check
- [x] Spike: Tauri 2 mobile + iOS AutoFill extension sharing an App Group store: answered by plan 14, then superseded by the native apps (plan 17)
- [ ] Trademark search for "Octa Pass" and domain purchase
- [ ] Real security and conduct contact addresses (`security@octap.app` and `conduct@octap.app` are placeholders until the domain is chosen)
- [ ] Enable branch protection and required reviews: GitHub doesn't offer them on this private repo's plan, so this waits until the repo is public or the plan changes
- [ ] Deploy the website to the chosen domain, set `PUBLIC_SITE_URL`
- [ ] Make the repository public

## Milestone exit criteria

Status is as of 2026-11-02. A criterion is met only when someone can point at the evidence.

**Public alpha**

- [x] Core crypto has property tests and test vectors (`crates/octapass-core/tests`, weekly fuzzing in `fuzz.yml`)
- [x] Export works (Octa Pass JSON, encrypted export, CSV, CXF; plan 07)
- [ ] No known high-severity issues: not assessed since the last review, and the `m25-*` slices add new code
- [ ] Data-loss bugs = 0 in two weeks of dogfooding: the maintainer's deployment has run since 2026-10-24, but no dogfooding log exists yet

**Public beta**

- [x] Autofill success ≥ 90% on the corpus: 100% on the pages the engine was tuned on, 95.0% on the held-out pages (plan 12), all synthetic. The top-500 snapshots in plan 05 don't exist
- [ ] Import success ≥ 95% on fixtures: importer tests pass, but no pass-rate figure has been recorded
- [ ] Crash-free sessions ≥ 99.5%: can't be measured yet. There are no analytics by design, so this needs an opt-in, content-free crash report first
- [ ] Unlock in under 1.5 s on low-end Android (the Phase 0 spike's budget): not measured

**1.0**

- [ ] Audit high/critical findings fixed and retested
- [ ] Docs complete for every shipped feature
- [ ] Reproducible builds for the extension and web vault
- [ ] Every P2 item in plan 01 and all of plan 16 built, or moved out by a recorded decision: all built (2026-11-05) except Nearby, and plan 00's open question on running our own masked email service

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Crypto/design mistake | Catastrophic | Use proven constructions only, test vectors, early informal review by a cryptographer (phase 1), formal audit (phase 6) |
| Autofill breakage across sites | Users leave | Corpus-driven CI, fast extension releases, user reports |
| Scope growth (2026-11-02) | 1.0 slips, audit costs more | Keep phases 7 and 8 behind phases 1–5b, build plan 16 in its A, B, C order, and move items out only by a recorded decision |
| Review can't keep up with generated code | Security bugs ship | One reviewer per merge, security section required (plan 03), audit last |
| Free hosting cost growth | Service shutdown | Quotas, donations, sponsor program, efficient storage (plan 10); self-hosting always available |
| Store policy rejections (Apple, Chrome) | Delays | Follow guidelines from day one, no remote code, clear privacy labels |
| Name/trademark conflict | Rebrand | Still open from phase 0; resolve before any store listing or the public website |
| Burnout of a small team | Everything slows | Strict scope per phase, community contributors, good docs |

## History
- 2026-11-05: status checked against the code with every `m25-*` branch merged. Phase 5's item types, and phase 7's Windows passkey provider, watch apps and MCP docs server, were listed as not built but had merged on 2026-11-04. Added "What isn't built", which names where each gap shows in the code. Public version: `docs/reference/roadmap.md`.
- 2026-11-02: rewritten for the maintainer's scope decision. Phases 7 and 8, every P2 item and all of plan 16 are inside 1.0 and come before the audit. Status, the Phase 0 checklist and the exit criteria now say what's actually built; the GitHub repo exists at `octap-app/octapass`. The total is re-estimated: ~18–24 months with a small team, or ~8–11 months with the maintainer and agents, because the human gates set the date. Public version: `docs/reference/roadmap.md`.
- 2026-10-24: phase 1's CLI built as a preview in `apps/cli` (`octapass`): login, unlock with a keyring session and idle timeout, list, get, totp, generate, read, run with `octapass://` references, import and JSON/CSV export, tested end to end against the real server. Details in plan 05's History; docs in `docs/platforms/cli.md`.
