---
title: The browser extension, built from source
date: 2026-10-24
summary: Octa Pass now has a Manifest V3 extension for Chrome, Edge and Firefox that fills logins, saves new ones, creates and uses passkeys, unlocks through the desktop app, and works without an account. It isn't in the stores yet, but you can build it and load it unpacked.
tags: [extension, security]
---

The Octa Pass browser extension is in the repository (`apps/extension`) and works end to end against an Octa Pass server. It ships in the stores with the public alpha; until then you can [build it and load it unpacked](/docs/platforms/browser-extension/#build-it-yourself).

## What it does

- **Fills logins in the page** from an inline menu, with the [autofill engine](/docs/features/autofill/)'s safety rules: a real click on our own menu, no hidden or covered fields. Suggestions only ever come from logins for the page's own site, judged by the address the browser reports: `paypal.com.evil.io` gets nothing for `paypal.com`, and an `https` login is never offered on plain `http`.
- **Suggests strong passwords** on sign-up forms and saves them as an "Unconfirmed" login straight away, so a password can't be lost if the sign-up goes through but you miss the save prompt. Submitting the form confirms it.
- **Offers to save or update** logins you type, even when the page navigates away right after you sign in.
- **Fills one-time codes, cards and identities.** When a code doesn't fit a site's split code boxes exactly, it's copied to the clipboard (cleared after 30 seconds) instead of filled partly.
- **Creates and uses passkeys** with the core authenticator. When a site asks, an Octa Pass prompt (an extension page the site can't script) lets you save the passkey in Octa Pass or use your browser's own flow. Passkeys sync as ordinary encrypted items, and their private keys never reach the popup.
- **Popup and side panel** with the web vault's screens: sign in, unlock, logins for the current site with a Fill button, search, item details with one-time codes, the generator and settings.
- **Matches with the core:** the same Public Suffix List matching, equivalent domains and per-site password rules as every other Octa Pass app.
- **Unlocks through the desktop app** with Touch ID or Windows Hello, when the app is running and signed in to the same account.
- **Works without an account:** "Use on this device only" keeps an encrypted vault in the browser, with encrypted backups (restorable with the master password or a backup recovery code) and **Turn on sync**, which moves the vault into a new account without re-encrypting anything.
- **Imports** run the core's importers on the device and upload in batches (`POST /v1/batch`), a few hundred items per request.

## Security notes

- The unlocked vault lives in the extension's service worker. Browsers stop idle service workers, so the account key is kept wrapped with a random per-session key in memory-only session storage and never written to disk. Locking, auto-lock (15 minutes by default, and when the computer locks) or closing the browser throws it away.
- Content scripts never choose which site they're asking for: the service worker takes it from the browser. Only the extension's own pages can approve a passkey request.

## How it's tested

Unit tests cover matching, sender checks, the session keeper, auto-lock, saving, local vaults, the desktop key exchange (checked against an independent implementation of the app's side), and the WebAuthn conversions. Integration tests run the service worker's vault against a real server and the WebAssembly core: surviving a worker restart, locking, passkeys checked by an independent verifier, batch imports, Turn on sync, and desktop unlock. A Playwright suite loads the built extension in Chromium and:

- signs in from the popup, fills a login, and refuses a look-alike domain
- saves a sign-up with a suggested password
- creates and uses a passkey on a local WebAuthn page
- keeps a vault on this device only, backs it up and turns on sync
- fills every page of the autofill corpus through the real extension: 73 of 73 fills.
