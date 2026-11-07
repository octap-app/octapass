---
title: A first look at the web vault
date: 2026-10-23
summary: You can now run the Octa Pass web vault locally. Create an account, save your Recovery Kit, manage items, check your passwords' health and unlock with Touch ID or Windows Hello, all on demo data for now.
tags: [security, docs]
---

The first part of milestone 1 is in the repository: the **web vault** at `apps/web`. It runs against a mock data layer until the crypto core and the sync server are connected, so everything you see works end to end in your browser, on demo data. See [development setup](/docs/contributing/development-setup/#run-the-web-vault) to run it.

## What you can do

- **Create an account**: email, a master password with a live strength meter, an email code, and a **Recovery Kit** with your Secret Key, recovery code and a QR code. Print it or save it as a PDF. It's made on your device and never uploaded.
- **Sign in** to Octa Pass or to your own server. The Secret Key is asked for only on a device that hasn't signed in before.
- **Your vault**: personal and shared vaults, categories, favourites and search, with logins, passwords, secure notes, cards and identities. Copy buttons clear the clipboard after 30 seconds. One-time codes count down live. Passkeys, [recovery info](/docs/features/recovery-info/) and password history are shown for each login.
- **Add and edit items** with the [password generator](/docs/features/password-generator/) built in, several websites per login, custom fields, tags and a warning before you lose unsaved changes. Deleted items stay in the Trash for 30 days.
- **Health**: a score out of 100 with weak, reused and breached passwords and sites where two-step sign-in is available. [Breach checks](/docs/security/breach-checks/) send only the first five characters of a hash.
- **Unlock with your device**: Touch ID, Windows Hello or your device's passcode, through a passkey with the WebAuthn PRF extension. It works per browser, and your master password is still required every 14 days. See [biometric unlock](/docs/features/biometric-unlock/#web-vault).
- **Settings**: light and dark themes (following your system by default), auto-lock, export to JSON or CSV, import from Chrome, Bitwarden, 1Password or any CSV, and **delete your account** with a final check of your email and master password.

It's keyboard friendly (`/` to search, `N` for a new item, `⌘C` or `Ctrl+C` to copy a password), works on a phone, and every string is in one catalog, ready for translation.

## Packages

- `@octapass/vault-client`: the item model, the `VaultService` interface the apps talk to, and local tools (generator, strength estimate, TOTP, breach check, health report, import and export).
- `@octapass/ui`: the brand's design tokens and accessible React components.

## Next

The integration step swaps the mock for the Rust crypto core (WASM) and the sync server, so accounts and items are stored on the server only as ciphertext.
