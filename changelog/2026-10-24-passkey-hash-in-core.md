---
title: Passkeys on iPhone and Android use the same authenticator as the browser
date: 2026-10-24
summary: Signing a passkey request from iOS or Android now runs through the same tested code as the browser extension and the web vault, and refuses shared suffixes like github.io.
tags: [core, mobile, security]
---

On iPhone and Android the system writes the WebAuthn client data itself and hands Octa Pass only its hash to sign. That signing used to live in the mobile bindings, next to the core's own authenticator. It's now part of the core, so every app creates and uses passkeys with one implementation, checked by the same WebAuthn verifier tests.

It also closes a gap: a request from the system for a shared suffix such as `com` or `github.io` as the site was accepted. It's now refused, as it already was in the browser. Nothing changes for passkeys you already have.
