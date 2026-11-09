---
title: Breached recovery emails, backup reminders and signed site lists in Health
date: 2026-11-08
summary: Health warns about a recovery email that was in a breach, reminds you to back up a vault on this device only, and gets newer site lists between releases as a signed update.
tags: [security, server, extension, desktop, mobile]
---

Three additions to the [security dashboard](/docs/features/security-dashboard/), everywhere it runs.

- **Recovery emails in a breach.** When email breach alerts find a breach for an address that's the recovery email of other logins, Health lists it with the breaches and how many logins it can reset. Your account email and aliases are checked as before. Other recovery emails may not be yours, so they're sent only after a second switch, **Also check my other recovery emails**, which asks first; turning it off deletes what it found. See [breach checks](/docs/security/breach-checks/#email-breach-alerts-opt-in).
- **Backup reminders.** A vault on this device only has no server keeping a copy, so Health now says how long ago it was backed up ("Last backup 34 days ago"), names the folder when automatic backups are on, and warns with a **Back up** button when one is due. In the desktop app, the extension's Octa Pass tab and the phone apps. Nothing is sent.
- **Signed site lists.** The lists of sites that accept passkeys or offer two-step sign-in can now be updated between releases. Apps ask their own Octa Pass server once a day for a file signed by the project's key, which the apps carry, and use it only when the signature checks out and it's newer than what they have, so no server can change the lists or roll them back. Self-hosted servers serve the lists from their release, or newer ones from the project's site with [`OCTAPASS_HEALTH_DATA_URL`](/docs/self-hosting/configuration/#health-data). The signing tool is `tools/health-data/sign.mjs`.

Decisions are in [plan 06](https://github.com/octapass/octapass/blob/main/plans/06-health-sharing-aliases.md) and [plan 05](https://github.com/octapass/octapass/blob/main/plans/05-clients-and-autofill.md) History.
