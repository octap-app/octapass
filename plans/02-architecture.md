# 02 — Architecture

## Overview

```
                    ┌──────────────────────────── clients ────────────────────────────┐
                    │                                                                  │
 React UI (packages/ui) ──► Web vault   Browser ext.   Desktop (Tauri)   Mobile (Tauri 2)   CLI
                    │        (WASM)       (WASM)        (native Rust)     (UniFFI + native   (native
                    │                                                      autofill ext.)    Rust)
                    │           └────────────┬──────────────┬─────────────────┘               │
                    │                        ▼              ▼                                 │
                    │              crates/octapass-core  (crypto · vault · sync · TOTP ·       │
                    │                                     import · passkeys · matching)  ◄────┘
                    └───────────────────────────────┬──────────────────────────────────┘
                                                    │ HTTPS (TLS 1.3) + WebSocket
                                                    │ ciphertext only
                                                    ▼
                              apps/server  (Rust · axum · OPAQUE auth · sync API)
                                 │                │                 │
                          PostgreSQL /       S3-compatible     SMTP / email
                          SQLite (self-host)  attachments      provider
```

The server stores ciphertext, auth records and minimal account metadata. All encryption and decryption happens in `octapass-core` on the client.

## Monorepo layout

```
/
├── apps/
│   ├── website/          Astro + Starlight: landing, docs, changelog, llms.txt  (exists)
│   ├── web/              Web vault: React + Vite, core via WASM in a Web Worker
│   ├── extension/        Browser extension: MV3, React app page in a tab, content scripts; Chrome/Edge/Firefox targets
│   ├── desktop/          Tauri 2 shell for Windows/Linux (React UI); macOS dropped 2026-11-06 (plan 19)
│   ├── macos/            Native Mac app (SwiftUI, the iPhone app's screens on OctaPassVault, plan 19)
│   ├── mobile/           Tauri 2 mobile shell (iOS/Android) + native autofill extensions
│   │   ├── ios/          Swift: AutoFill Credential Provider extension, Safari Web Extension
│   │   └── android/      Kotlin: AutofillService, CredentialProviderService
│   ├── server/           Rust (axum) sync + auth server
│   └── cli/              Rust CLI (`octapass`)
├── crates/
│   ├── octapass-core/    Crypto, vault model, item schemas, sync engine, TOTP, generators,
│   │                     URL matching, importers, passkey authenticator
│   ├── octapass-wasm/    wasm-bindgen bindings for web + extension
│   ├── octapass-ffi/     UniFFI bindings for Swift + Kotlin
│   └── octapass-api/     Shared API types (serde) used by server and clients
├── packages/
│   ├── ui/               React component library + design tokens (shared by web, extension, desktop, mobile)
│   ├── i18n/             Message catalogs (ICU MessageFormat), RTL helpers
│   └── api-client/       TypeScript client for the sync API (generated from OpenAPI)
├── docs/  plans/  changelog/  skills/
└── tools/                Test corpora (autofill pages, import fixtures), scripts
```

**Tooling:** pnpm workspaces + Turborepo for TypeScript, Cargo workspace for Rust. CI runs on GitHub Actions: `cargo test`, `cargo deny`, `cargo vet`, clippy; `pnpm lint`, `tsc`, Vitest, Playwright (extension E2E against the autofill corpus).

## Why this stack

| Choice | Reason | Alternative considered |
|---|---|---|
| **Rust core** | Memory-safe, one implementation of the crypto, audited once and used everywhere. RustCrypto crates are mature. | TS everywhere: crypto would be duplicated in Swift/Kotlin for autofill extensions. |
| **WASM in web/extension** | Same code as native. Keys stay in WASM memory, which is easier to zero than JS strings. | WebCrypto alone: missing Argon2id and XChaCha20. |
| **UniFFI** | Generates idiomatic Swift/Kotlin bindings. iOS/Android autofill extensions must be native (memory and API limits), and they call the same core. | Hand-written C FFI. |
| **Tauri 2** (desktop) | Small binaries, Rust backend links the core directly, OS keychain and biometrics via plugins. **Being replaced** by native apps on the phones' UniFFI API (plan 19, 2026-11-06): on macOS the SwiftUI app already replaced it (the Tauri app's Mac support was removed the same day); it stays on Windows and Linux until their native apps. | Electron: ~150 MB, larger attack surface. |
| **Tauri 2 mobile** (default) | One React UI everywhere. **Risk:** less mature than React Native. **Fallback:** React Native + `uniffi-bindgen-react-native`. Decide at Phase 4 kickoff with a 2-week spike. | React Native, native SwiftUI/Compose. |
| **axum + sqlx** | Same language as the core, shares `octapass-api` types; sqlx supports Postgres (hosted) and SQLite (small self-host). | Node/Fastify. |
| **Astro + Starlight** (website) | Static HTML (fast, SEO), built-in search, i18n/RTL, `llms.txt` plugin. | Next.js, Docusaurus. |

## Core modules (`octapass-core`)

| Module | Responsibility |
|---|---|
| `crypto` | KDF (Argon2id), AEAD (XChaCha20-Poly1305), HKDF-SHA256, X25519 sealed boxes, Ed25519 signatures, secure random, `zeroize` on all secrets |
| `keys` | Key hierarchy: Account Unlock Key, account keyset, vault keys, item keys; wrapping and rotation (plan 03) |
| `auth` | OPAQUE client (`opaque-ke`), device registration, session tokens |
| `model` | Item types and field schemas (versioned, forward-compatible: unknown fields preserved) |
| `vault` | Local encrypted store (SQLite via `rusqlite`; items stored as ciphertext blobs), search index (encrypted at rest, decrypted in memory after unlock) |
| `sync` | Pull/push with per-item revision numbers, conflict handling, offline queue. A `VaultBackend` trait has two implementations: `RemoteBackend` (server) and `LocalBackend` (local mode, no network) |
| `backup` | Encrypted backup files for local mode (and optional for synced accounts) |
| `totp` | RFC 6238/4226, Steam, `otpauth://` and `otpauth-migration://` parsing |
| `generator` | Passwords, passphrases (EFF wordlist), site rules |
| `matching` | URL → item matching with the Public Suffix List, equivalent domains, match modes |
| `passkey` | Software WebAuthn authenticator: ES256 (P-256), EdDSA; attestation `none`; CXF export/import |
| `health` | Strength estimation, reuse detection, HIBP k-anonymity client, 2FA/passkey directory lookups |
| `import` / `export` | Parsers and writers (plan 07) |

## Data flow: saving a new login (browser)

1. The content script detects a form submit and sends `{url, username, password}` to the extension service worker over a private runtime port.
2. The service worker asks the user (in-page prompt, isolated in a shadow DOM / extension iframe) whether to save.
3. On *Save*: WASM core creates the item → generates an item key → encrypts fields with the item key → wraps the item key with the vault key → writes to the local store → queues a sync push.
4. Sync sends `PUT /v1/vaults/{id}/items/{itemId}` with `{revision, encryptedKey, ciphertext}`. The server checks the revision, stores the item, bumps the vault revision, and notifies other devices via WebSocket.
5. The other devices pull the changed items and decrypt them locally.

## Server API (summary; full spec in plan 04)

- `POST /v1/auth/register/*`, `POST /v1/auth/login/*`: OPAQUE flows
- `GET /v1/sync?since=<rev>`: changed vaults/items since revision
- `PUT/DELETE /v1/vaults/{id}/items/{itemId}`
- `POST /v1/vaults`, `POST /v1/vaults/{id}/members`: sharing via wrapped vault keys
- `POST /v1/attachments`: presigned upload of encrypted blobs
- `GET /v1/ws`: change notifications (no payloads, just "vault X changed")
- `POST /v1/health/breach-email`: optional HIBP proxy for email breach checks (opt-in; the address is in the body, not the URL)

## Cross-cutting

- **Observability:** server logs carry no item IDs tied to IPs beyond 7 days. Metrics are aggregate only (Prometheus). Clients send no analytics; crash reports are opt-in and scrubbed.
- **Config:** 12-factor env vars for the server; one `octapass.toml` for self-hosters.
- **Versioning:** SemVer per app. The sync API is versioned (`/v1`), and the item schema has a `schemaVersion` with migrations in the core.
- **Release:** signed builds (Apple notarisation, Windows Authenticode, Linux repo GPG + Flatpak/Snap/AppImage), reproducible builds for the extension and web vault, SBOM (CycloneDX) per release.
