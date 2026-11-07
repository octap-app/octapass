---
title: Authentication
description: How signing in to Octa Pass works with OPAQUE so the server never sees your password, plus sessions, two-step sign-in, new-device alerts and rate limits.
status: in-progress
sidebar:
  order: 3
---

:::note[In progress]
OPAQUE sign-up and sign-in, email verification, the token lifetimes below, two-step sign-in and the device list work in the sync server and the apps. New-device emails are sent. Refresh tokens rotate on every use but aren't bound to a device key yet, and proof-of-work is planned.
:::

Octa Pass signs you in with **OPAQUE** (RFC 9807), an asymmetric password-authenticated key exchange. Your device proves it knows a secret derived from your master password and Secret Key without sending that secret, or a hash of it, to the server.

Most password managers send a hash of the password. OPAQUE goes further: even a malicious server, or someone who breaks TLS, never receives anything that can be used to log in or to crack the password offline.

## Sign-up

1. Your device generates the Secret Key, account salt, account key (ASK), key pairs and recovery key.
2. It derives `auth_secret` (see [encryption](/docs/security/encryption/)) and runs OPAQUE registration.
3. It uploads the OPAQUE record, the wrapped account key, the wrapped private keys, public keys and the recovery-wrapped account key.
4. You confirm your email with a 6-digit code.

## Sign-in

1. OPAQUE login gives your device and the server a shared session key.
2. The server issues a **15-minute access token** and a **refresh token**. The refresh token rotates on every use, and using an old one again ends the session. Binding it to a per-device Ed25519 key, so a stolen token alone is useless, is planned.

## New devices

A new device needs your email, master password and Secret Key, plus the second step if [two-step sign-in](/docs/features/two-step-sign-in/) is on. Every time one signs in, you get a **New sign-in** email with the device's name and platform and the time (in UTC). It has no location: the server doesn't look up where an IP address is. If it wasn't you, sign that device out in **Settings → Devices** and change your master password.

No email is sent when:

- a device you're already signed in on signs in again with its trusted-device token (see below),
- your first device signs in right after you create the account,
- a recovery code was used: that sign-in sends its own email instead.

## Two-step sign-in

Two-step sign-in protects **access to your encrypted data**. It's separate from the encryption itself, which depends only on your master password and Secret Key: turning it on or off changes no key, and the server can't use it to decrypt anything.

How it works:

1. OPAQUE login runs first. Only when the password is proven does the server ask for the second step, so a wrong password never reveals whether two-step sign-in is on.
2. The device proves one of:
   - a **TOTP code** (RFC 6238: SHA-1, 6 digits, 30 seconds) from an authenticator app. Each code works once.
   - a **WebAuthn security key** or passkey: the server checks the challenge, the web vault's origin, the relying party id, user presence, the signature and the signature counter. ES256 and Ed25519 keys are supported.
   - a single-use **recovery code** (10 codes of 50 random bits each).
3. The server then creates the device's session as usual, in the same transaction that uses up the code, and gives the device a **trusted-device token**. Sent with a later sign-in from the same device, it skips the second step once and is replaced. Trust belongs to the device: it ends when the device leaves your device list (signed out, or 30 days without use), and is never older than 30 days. Turning two-step sign-in on, or **Ask again** in Settings, ends it for every other device; so does a stolen refresh token being detected.

What the server stores: the authenticator secret, sealed with XChaCha20-Poly1305 under a key derived from the server's own secret (a copy of the database alone doesn't reveal it); recovery codes as HMACs; security keys' public keys; trusted-device tokens as SHA-256 hashes.

Turning it on, turning it off, adding or removing a method and making new recovery codes all need a fresh master password check (a single-use reauthentication token). Each change goes into your security log; turning it on or off, and using a recovery code, also send you an email.

## Single sign-on

An [organisation](/docs/features/organisations/) can ask members to pass its identity provider too, after the master password. It adds a step and never replaces one: the server's OPAQUE check comes first, and nothing from the provider goes into any key. The password and Secret Key still unlock the vault. See [single sign-on](/docs/features/single-sign-on/).

## Rate limiting

- Limits per account and per IP address, with exponential backoff
- Second step: five wrong tries end the sign-in attempt; ten wrong tries for an account pause the second step (one more try every 5 minutes), and are logged and emailed to the owner at most once an hour
- Proof-of-work challenges after repeated failures, instead of CAPTCHAs (planned)
- Remote sign-out of any device from the device list
