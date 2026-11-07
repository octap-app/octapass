---
title: Sharing, families, share links and emergency access on the server
date: 2026-10-24
summary: The core and the sync server now support shared vaults with signed grants, families, one-time share links and emergency access. The screens for them come next.
tags: [core, server, security]
---

Everything behind sharing is built and tested: the encryption in the Rust core, and the endpoints in the sync server. The apps get the screens for it next. See the [sync API](/docs/developers/sync-api/#sharing).

## What's in it

- **Shared vaults.** Each member gets the vault key sealed to their own public key and signed by whoever invited them; their device checks the signature before using the key. Roles are `read`, `write`, `manage` and `owner`, and the server enforces them on every write.
- **Removing someone** gives the vault a new key, re-wraps every item key and re-issues the remaining members' grants in one step. After that, the server refuses item keys still wrapped under the old key, so a member who hasn't caught up can't write items the others can't open.
- **Fingerprints** for each account: six groups of four digits, or eight emoji with names, to compare in person or on a call.
- **Invites don't reveal accounts.** Inviting an email without an Octa Pass account gets the same answer as inviting one with an account, and stores nothing. Looking up accounts is limited per user.
- **Families** of up to 6 people with a shared Family vault, invites that carry the Family vault key, and leaving or removing members.
- **One-time share links** for people without an account. The key is in the link's `#` part, which never reaches the server. Links expire after 1 hour to 30 days or after 1 to 100 views, can need a passphrase, and are deleted at the limit.
- **Emergency access.** You seal your account key, or one vault's key, to a trusted contact. They can request it; you get an email straight away and every day after, and can deny at any time. After the waiting period (1 to 30 days) the server releases it. Every step is in your new security log.
- **Account deletion** now also removes your grants, family membership, share links and emergency-access records in both directions.

## How it's tested

The server's integration tests use the real core: grants are sealed and signed, keys rotated and items decrypted exactly as clients will, on SQLite and PostgreSQL. They cover role checks, invites to unknown emails, rotation, view limits and expiry, the emergency-access timeline (on a clock the tests move forward) and what deletion leaves behind. Test vectors for the sealed box, grants, fingerprints and share links are in `crates/octapass-core/tests/vectors/sharing.json`.
