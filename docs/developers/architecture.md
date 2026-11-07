---
title: Architecture
description: How Octa Pass is built, with a shared Rust core compiled to WebAssembly and native bindings, TypeScript and React interfaces, Tauri apps and an axum sync server.
status: in-progress
sidebar:
  order: 1
---

:::note[In progress]
This describes the code as it is today. The core, server, web vault, extension, desktop app, native phone apps and CLI all exist. What's still to come is on the [roadmap](/docs/reference/roadmap/).
:::

## Overview

```text
 React screens (apps/web) ─► Web vault    Extension    Desktop (Tauri,     CLI
                             (WASM)       (WASM)       Windows, Linux)     (native Rust)

 SwiftUI apps ┐
 (iPhone, Mac)│
              ├─ UniFFI (octapass-mobile, octapass-ffi) ─ native autofill services
 Compose app ─┘
                                        │ every client links the same core
                                        ▼
        crates/octapass-core: crypto · keys · vault · sync · TOTP · import · passkeys · matching
                                        │ HTTPS + WebSocket, ciphertext only
                                        ▼
        apps/server (Rust, axum): OPAQUE auth · sync API · sharing · email · web vault
             │                       │                       │
       SQLite / PostgreSQL     Disk or S3-compatible      SMTP
```

All encryption and decryption happens in `octapass-core` on the client.

## Why this stack

| Choice | Reason |
|---|---|
| Rust core | One memory-safe implementation of the crypto, used everywhere |
| WebAssembly for web and extension | The same code as native, and keys stay in WASM memory where they can be zeroed |
| UniFFI for Swift and Kotlin | The phone apps and their autofill extensions call the same core |
| Tauri 2 for desktop on Windows and Linux | Small binaries; the core is linked directly. Native apps replace it, starting with the Mac ([plan 19](https://github.com/octapass/octapass/blob/main/plans/19-native-desktop-apps.md)). |
| SwiftUI and Jetpack Compose for phones, SwiftUI on the Mac | Lists, sheets, Dynamic Type and screen readers are only first-class in native UI. These replace the earlier Tauri phone apps. |
| axum + sqlx for the server | The same language as the core, with shared API types. Supports PostgreSQL and SQLite. |
| Astro + Starlight for the website | Static HTML, built-in search, i18n with RTL, `llms.txt` support |

## Repository layout

```text
apps/
  website/      Astro + Starlight: landing page, docs, changelog, llms.txt
  web/          Web vault (React + Vite, core via WASM in a Web Worker)
  extension/    Browser extension (MV3), for Chromium, Firefox and Safari
  safari/       The macOS and iOS apps that carry the extension into Safari
  desktop/      Tauri 2 desktop app, for Windows and Linux
  macos/        Native Mac app (SwiftUI), built from the iPhone app's screens
  ios/          Native iPhone and iPad app (SwiftUI) + AutoFill extension
  android/      Native Android app (Compose) + Autofill and Credential Manager services
  mobile/       Earlier Tauri 2 phone app, removed when the native apps reach parity
  server/       Sync and auth server (Rust, axum)
  cli/          octapass CLI (Rust)
crates/
  octapass-core/  octapass-wasm/  octapass-ffi/  octapass-mobile/  octapass-api/
packages/
  autofill/  core/  ui/  vault-client/
docs/  plans/  changelog/  skills/  tools/  brand/  deploy/
```

## Core modules

| Module | Responsibility |
|---|---|
| `kdf`, `keys`, `secret_key` | Argon2id, HKDF and the [key hierarchy](/docs/security/encryption/) |
| `envelope`, `stream` | XChaCha20-Poly1305 ciphertext envelopes and chunked file encryption |
| `opaque`, `credentials`, `session`, `device`, `account`, `recovery` | Sign-in, master password changes and resets, device keys |
| `item`, `environment` | Versioned item schemas that preserve unknown fields |
| `sharing` | Sealed vault keys, signed grants, share links, emergency access keys |
| `local`, `backup` | Local vaults and backup files |
| `tools` | One-time codes (RFC 6238, Steam, `otpauth://`, `otpauth-migration://`), the generator, strength, breach hashes, QR codes, SSH keys, masked email |
| `matching`, `rules` | URL matching with the Public Suffix List and equivalent domains, per-site password rules |
| `passkey` | Software WebAuthn authenticator |
| `import` / `export` | Parsers and writers, including CXF |

Sync lives one layer up: `packages/vault-client` for the web vault and extension, and `apps/desktop/crates/vault` and `crates/octapass-mobile-vault` for the native clients.

## Saving a new login, step by step

1. The content script detects a form submit and sends the URL, username and password to the extension's service worker over a private port.
2. The extension asks whether to save, in UI isolated from the page.
3. On save, the core creates the item, generates an item key, encrypts the fields and wraps the item key with the vault key. The client stores it locally and queues a push.
4. The push sends the revision, wrapped key and ciphertext to the [sync API](/docs/developers/sync-api/). The server stores it, bumps the vault revision and notifies other devices.
5. Other devices pull the change and decrypt it locally.

## Tooling

pnpm workspaces for TypeScript, Cargo workspaces for Rust. CI on GitHub Actions runs `cargo fmt`, clippy and `cargo test` (the server on SQLite and PostgreSQL), typecheck and Vitest for every package, client tests against a real server, the website build and Playwright end-to-end tests. Fuzzing runs weekly. `cargo deny` and `cargo vet` are planned.
