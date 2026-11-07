# 00 — Idea review

Review of the original idea before planning: what was decided, what was added, removed or changed, and what is still open.

## The original idea (summarised)

> Build an open-source 1Password alternative that keeps every kind of credential in one place: passwords, passkeys, TOTP, email and phone verification, identities and addresses, and payment info if possible. Ship Chrome, Firefox and Safari extensions, a website, mobile apps, and desktop apps for macOS, Windows and Linux. Autofill on every OS, breach checking like Apple and Chrome, import from every provider, Face ID and fingerprint unlock, email sign-up and login for sync. Host it free for everyone, with an open-source version that has the same features. Leave room for ads but don't build them.

## Decisions made (2026-10-22)

| Topic | Decision | Notes |
|---|---|---|
| Name | **Octa Pass** (wordmark `OctaPass`, slug `octapass`) | Renamed from "All Pass". See [name risk](#name-risk). |
| Tech stack | **Rust core + TypeScript UIs** | One Rust crate for crypto, vault and sync, compiled to WASM (web, extensions), UniFFI (Swift/Kotlin) and native (Tauri desktop, server). |
| License | **MIT** for everything | The hosted service *is* the open-source code. No open-core split, no "community edition". |
| Ads | **No ads, ever** | Removed from the plan. Funding moves to donations and sponsors; see [10-operations-and-funding](10-operations-and-funding.md). |
| "Email/phone verification" | **Masked email aliases** + **recovery info** stored per login | Masked phone numbers are out of scope. Autofill of SMS codes is left to the OS. |
| Local mode (2026-10-23) | **Use without an account**: a vault that lives only on one device, no server, no email. Ships in phase 2 with the browser extension | Free entry point; one tap to "Turn on sync" later. See plans 01, 03, 05. |
| Positioning (2026-10-23) | **Hosted-first.** The free Octa Pass service is the product; open source and self-hosting are extras that build trust | Website, README and docs lead with the free service. Self-hosters use the same official apps with a server picker. See plan 05. |

## Changes to the idea

### Added

These are standard in 1Password, Bitwarden, Proton Pass and Apple Passwords, or needed to run a password manager safely. They are now in the plan.

| Addition | Why |
|---|---|
| **Zero-knowledge, end-to-end encryption** as the foundation | The server must never be able to read a vault. Everything else depends on this. See [03-security-model](03-security-model.md). |
| **Secret Key + Recovery Kit** | Zero-knowledge means no "reset password" link. Users need a printable kit and a recovery code, or they lose everything. |
| **OPAQUE login** (password never reaches the server) | Stronger than sending a password hash like most managers. |
| **Export, in open formats** | No lock-in is the point of open source: CSV, encrypted JSON and the FIDO Credential Exchange Format (CXF). |
| **Passkey import/export (CXF)** | Today this is the only standard way to move passkeys between managers. |
| **Secure notes, documents, SSH keys, API keys, Wi-Fi, licences, bank accounts, IDs/passports** | Expected item types in a 1Password alternative. |
| **Password and passphrase generator** | Core feature. It feeds the "save new login" flow. |
| **Security dashboard** (breached, reused, weak, missing 2FA, passkey available, insecure HTTP) | Extends "breach checking" into a full Watchtower-style report. |
| **Sharing**: shared vaults, families, one-time share links | Most users need to share the Wi-Fi password or Netflix login. |
| **Emergency access** | A trusted contact can request access after a waiting period. |
| **Recovery map** | New idea built on your "phone/email verification" input: shows which accounts are recoverable through which email or phone. If your email is compromised, you see everything at risk. |
| **CLI** | Needed early for dogfooding and for developers (secrets in scripts, CI). |
| **Web vault** | The "website" also hosts a full web app, for when no extension is installed. |
| **Self-hosting** (single Docker image, SQLite or Postgres) | The open-source version must be runnable by anyone. |
| **Offline access** | Local encrypted cache; sync when back online. |
| **Phishing-safe autofill** | Exact domain matching, no silent fill in cross-origin iframes, user gesture required. This defends against the 2025 class of extension clickjacking attacks. |
| **i18n + RTL** (Arabic first-class) | Global audience from day one is much cheaper than adding it later. |
| **Accessibility** (WCAG 2.2 AA) | Required for a tool people rely on to log in to everything. |
| **Security process**: third-party audit before 1.0, bug bounty, reproducible and signed builds, SBOM | Trust is the product. |
| **Docs website, `llms.txt` and an AI agent skill** | From your request. AI-friendly docs and SEO are part of the website plan. |

### Removed or descoped

| Removed / descoped | Why | Replacement |
|---|---|---|
| **Ads** (and the reserved ad slot) | Third-party ad code near secrets is a security hole, and ads destroy trust in a password manager. | Donations, sponsors, optional supporter tier (see plan 10). |
| **Masked phone numbers / receiving SMS** | Costs real money per number and per message, attracts abuse, and needs telecom compliance in each country. | Store recovery phone per login; SMS code autofill is done natively by iOS and Android. |
| **Reading verification emails from the user's inbox** | Needs full mailbox access (Gmail/IMAP OAuth scopes): a huge privacy and security surface. | Masked email aliases. Codes still arrive in the user's inbox. |
| **"Autofill on every OS" as one feature** | Linux has no system autofill API, and Windows has none for passwords (only passkeys). | Per-platform matrix in [05-clients](05-clients.md): native autofill where the OS allows it, browser extension and **auto-type** hotkey elsewhere. |
| **Safari "if possible"** | It *is* possible, but only as a Safari Web Extension shipped inside the macOS/iOS app (Xcode, $99/yr Apple Developer account). | Planned with the desktop/mobile phases, not as a separate extension. |

### Edited

| Original | Now |
|---|---|
| "Email registration and login for syncing" | Email is the account identifier. Login uses master password + Secret Key via OPAQUE. Email verification codes are used only to confirm the address and new devices, never to unlock the vault. |
| "Face ID and fingerprint auth" | Biometrics **unlock a device-local key** (Secure Enclave, Android Keystore, Windows Hello/TPM). They never replace the master password for a new device. |
| "Password checking in data leaks" | Pwned Passwords k-anonymity checks run on the device, so nothing identifying leaves it. Email breach alerts are an optional, opt-in server feature. |
| "Import from all providers" | A prioritised list of 20+ importers (see [07-import-export](07-import-export.md)), plus authenticator apps for TOTP. |
| "Payment info if possible" | Yes: cards and bank accounts are ordinary encrypted item types. No payment processing, so PCI-DSS doesn't apply. Autofill of card forms is in the extension. |
| "Free online + an open-source version with the same functionality" | One codebase. The free hosted service runs exactly the published MIT code, and self-hosters get the same thing. |

## Name risk

**Decided 2026-11-07:** the project is published as **Octa Pass** (domain `octap.app`, org `github.com/octap-app`). It was developed as "Open Pass", but "OpenPass" is already used by an identity/sign-in product from The Trade Desk, so the public release uses the new name.

Before publishing to the stores:

1. Run a trademark search (USPTO, EUIPO, WIPO) for "Octa Pass" / "OctaPass" in Nice classes 9 and 42.
2. Check the Chrome Web Store, Firefox Add-ons, the App Store and Google Play for conflicting listings.

The website and docs read the name from one config value (`apps/website/src/site.config.ts`) and a few docs mentions.

## Licence decision

**Decided 2026-11-07:** the public release is licensed under **MIT** instead of AGPL-3.0-only. The maintainer chose a permissive licence so the code can be reused freely (including in other apps and services). Nothing in the security model changes: the hosted service still runs exactly the published code, by choice rather than by licence obligation.

## Still open (needs a decision later)

| Question | Default if undecided | Needed by |
|---|---|---|
| Final domain | **Decided:** `octap.app` (website and docs), `vault.octap.app` (sync server and web vault) | — |
| GitHub org name | **Decided:** the repository is `github.com/octap-app/octapass` (public) | — |
| Hosting region(s) for the free service | EU (Germany/Finland), for GDPR-friendly defaults | Phase 1 |
| Run our own masked-email domain, or integrate existing alias providers only | Providers are built. Phase B is inside 1.0's scope since 2026-11-02, but **whether to run a mail service is still undecided**: until it is, nobody builds `apps/relay` | Before the phase 7 work starts |
| Optional paid tier (families/teams, extra storage) to fund free hosting | Not planned; donations only | Before teams ship (they're in 1.0 now) |
| How to pay for a larger external audit | Grants and donations (plan 10) | Before booking the audit |
| Mobile UI: Tauri 2 mobile vs React Native | **Decided 2026-10-24:** native SwiftUI and Jetpack Compose (plan 17) | — |
| Sign in with Google / Apple (incl. a One Tap corner prompt on the website) | **Not planned (cancelled 2026-10-23).** If it comes back: Google/Apple can only replace account sign-in, never vault unlocking (zero-knowledge). The vault would still need the master password or device unlock. The One Tap prompt should use browser-native FedCM, not Google's script. App Store rule 4.8 requires Sign in with Apple whenever Google sign-in is offered in the iOS app. | — |
| Company/foundation structure (who owns the trademark, receives donations) | Fiscal host via Open Collective | Before accepting money |
