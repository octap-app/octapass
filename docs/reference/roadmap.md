---
title: Roadmap
description: The Octa Pass roadmap to 1.0, with what is built today, what each phase delivers, how long the rest should take, and the public alpha, beta and audit milestones.
status: stable
sidebar:
  order: 3
---

:::note[What changed on 2026-11-02]
Everything that was planned for after 1.0 is now part of 1.0: the Windows passkey provider, the SSH agent, teams, watch apps, post-quantum sharing, key transparency, the developer toolkit and the file safe. The audit comes last, so it covers what actually ships.
:::

"Built" means the code exists and its tests pass. It doesn't mean released: only the browser extension is in a store so far (Chrome Web Store and Firefox Add-ons), and nothing has had its external audit. The hosted service is open as a public alpha at [vault.octap.app](https://vault.octap.app).

| Phase | Goal | State | Deliverables |
|---|---|---|---|
| **0. Foundations** | Decide, design, publish | Mostly done. The name check, domain and public launch of the website and repository are left. | Plans, this docs website, security design, repository and CI |
| **1. Core, server, CLI** | A working encrypted vault end to end | Built. The CLI is a preview. | Rust core, server (OPAQUE, sync, email), CLI, web vault |
| **2. Browser extensions + web vault** | Daily use on desktop browsers | **Public alpha**: the web vault is open, and the extension is in the Chrome Web Store and on Firefox Add-ons. Edge Add-ons to come. | Chrome, Edge and Firefox extensions, full web vault, main importers, security dashboard, local vaults in the extension, self-host image |
| **3. Desktop apps** | Native desktop and biometrics | Built, not released. Signed downloads, updates and some Linux packages are missing. | macOS, Windows and Linux apps, Touch ID and Windows Hello, auto-type, macOS AutoFill, Safari on macOS |
| **4. Mobile apps** | Autofill on phones | Built, not released. **Public beta** not opened. | iOS and Android apps with system autofill and passkeys, camera scanning |
| **5. Sharing and completeness** | Parity with paid managers | Built. Push notifications are built but haven't run with Apple's and Google's real services, and the Octa Pass push relay isn't running yet. | Shared vaults, families, share links, emergency access, masked email, recovery map, more importers + CXF, attachments, two-step sign-in, Arabic interface |
| **5b. Native phone apps** | Native feel on phones | Built. Every flow has a UI test, and a few of those tests still fail. The older Tauri phone app was removed. | SwiftUI and Jetpack Compose apps on the same Rust core |
| **7. Growth features** | What was "after 1.0" | Built, not yet reviewed. | Windows passkey provider, SSH agent, teams and organisations, watch apps, post-quantum sharing, key transparency, a docs MCP server and the remaining item types |
| **8. Developer toolkit and file safe** | Beyond passwords | Built, not yet reviewed: the [developer toolkit](/docs/features/developer-toolkit/), [environments](/docs/features/environments/), [SSH keys](/docs/features/ssh-keys/), [Octa Pass Connect](/docs/features/connect/), [file encryption](/docs/features/file-encryption/) and [Octa Pass Safe](/docs/features/octa-pass-safe/). The Finder, Explorer and phone integrations haven't run on those systems yet. | Certificates, keys, JWT tools, hashes, encodings, Octa Pass Connect, file encryption, the Octa Pass Safe drive |
| **6. Audit → 1.0** | Trust | Not started. Comes last. | Independent audit with fixes and a published report, bug bounty, verified reproducible builds. **1.0.** |

Phases keep their numbers, so phases 7 and 8 now come before phase 6.

## Not built yet

As of 2026-11-09:

- **Push notifications in use.** [Push sync](/docs/self-hosting/push-relay/) is built and tested against stand-ins for Apple and Google, but the Octa Pass push relay isn't running yet, so phones sync when you open the app and while it's open.
- **Single sign-on in the Mac and phone apps.** [Organisations](/docs/features/organisations/) now run from every app except the browser extension, but signing in with your organisation's identity provider still needs the web vault or the desktop app. [SAML](/docs/features/single-sign-on/) and [SCIM](/docs/features/scim/) are built but haven't been tried with real identity providers yet.
- **Witnesses for the hosted service.** [Key log witnesses](/docs/self-hosting/key-log-witnesses/) are built; nobody has been chosen to witness the hosted service yet.
- **Filling the newer [item types](/docs/features/item-types/) on phones.** The browser extension fills bank accounts, databases, licence keys, ID numbers and wallet addresses; on phones you copy them from the app, because Android and iOS offer other apps only logins to fill.
- **Our own masked email service.** The forwarding service is written but not running, and whether the hosted service will run it hasn't been decided. [Masked email](/docs/features/masked-email/) works with the services it integrates with today.
- **Release work:** signed and notarised desktop downloads, automatic updates, Flatpak and AUR packages, app store builds, reproducible builds, and an opt-in crash report.
- **Testing where it ships:** the Windows passkey provider on real Windows, the file safe in Finder and Explorer and on phones, and the Safari extension in Safari.
- **Review and the audit:** the features built since 2026-11-02 haven't been reviewed yet, and post-quantum sharing and key transparency still need a cryptographer's review before the audit.

## Timing

These are rough estimates, not promises. From 2026-11-02, 1.0 is about **8–11 months** away at the pace of the maintainer working with coding agents, so Q3 2027 at the earliest. A traditional team of 2–3 full-time engineers would need about 18–24 months.

Writing code is no longer what sets the date. Review, real devices, store approval, weeks of real use before each public milestone, and the audit all take calendar time.

## Milestone criteria

| Milestone | Must be true |
|---|---|
| Public alpha | Crypto covered by property tests and test vectors; no known high-severity issues; export works; no data-loss bugs in two weeks of internal use |
| Public beta | Autofill succeeds on at least 90% of the test corpus; imports succeed on at least 95% of fixtures; at least 99.5% crash-free sessions |
| 1.0 | All high and critical audit findings fixed and retested; docs complete for every shipped feature; reproducible builds for the extension and web vault |

Progress is posted in the [changelog](/changelog/).
