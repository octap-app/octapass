---
title: Replace your Secret Key, rotate vault keys, and real emergency takeover
date: 2026-11-02
summary: You can now replace your Secret Key and give a vault a new key whenever you want. Emergency takeover works, and family members can opt in to organiser recovery.
tags: [core, server, security, website, desktop, mobile, cli]
---

**Replace your Secret Key** in **Settings → Security**, or with `octapass rotate-secret-key`. Your master password and vaults stay as they are, you get a new Recovery Kit, and your other devices sign in with the new key. Your recovery code stays unless you choose to replace it too. See [account recovery](/docs/security/account-recovery/#replacing-your-secret-key).

**Rotate vault keys on demand**, for your personal vaults and shared vaults you own or manage, in **Settings → Security → Vault keys** or with `octapass rotate-vault-key`. Before, only removing a member did this. It re-wraps item keys rather than re-encrypting items, so it protects against someone with only the old key. Devices still on the old key catch up by themselves, and changes waiting on an offline device aren't lost.

**Emergency takeover is real.** A takeover contact can now, after your waiting period, set a new master password and Secret Key for your account. It needs their own password as well as their private key. You're signed out everywhere, two-step sign-in is turned off, and you're emailed. It can't be undone, so choose someone you'd trust with everything. See [takeover](/docs/features/emergency-access/#takeover).

**Family organiser recovery** is opt-in per member, off by default. Your organiser can reset your account after your waiting period, and can't read your vault. See [organiser recovery](/docs/features/sharing/#organiser-recovery).

Each of these is in your security log. Developers: new endpoints in the [sync API](/docs/developers/sync-api/), and test vectors in `crates/octapass-core/tests/vectors/key-rotation.json`.
