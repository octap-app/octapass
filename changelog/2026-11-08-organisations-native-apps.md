---
title: Run an organisation from the Mac, iPhone, iPad and Android apps
date: 2026-11-08
summary: The native apps now have Organisation screens, to create one, invite people, review and give access to organisation vaults, manage groups, vaults, policies, single sign-on settings and SCIM tokens, and leave or delete. They also apply the policies that are the apps' to apply.
tags: [mobile, desktop, security, docs]
---

[Organisations](/docs/features/organisations/) ran from the web vault, the Windows and Linux app and the CLI. Now the Mac, iPhone, iPad and Android apps have **Organisation** in the sidebar (in the menu on Android), with the same sections:

- **Invitations and joining.** An invitation shows the organisation's rules before you accept.
- **Access to review.** Your device shows each person with a fingerprint it worked out itself. You tick the people you recognise, and only they get the vault's key. Someone whose keys changed since you saw them, or since you verified them on that device, gets nothing.
- **Members, groups and vaults** for admins: invite as a member or admin, change roles (owners), remove people, make groups and link them to vaults with a role.
- **Policies, single sign-on settings, SCIM tokens and the activity log** for owners.
- **Leave or delete.** Deleting the organisation, or one of its vaults, asks for your master password.

The apps apply the three policies that are theirs to apply: the auto-lock choice offers nothing longer than the organisation allows (and stay unlocked turns off), a new master password shorter than the minimum is refused, and exports leave organisation vaults out. The apps keep the last policies they saw, so this holds offline too.

Under the hood this is the desktop app's organisation engine, built again on the phones' Rust core (`crates/octapass-mobile`), so every app seals keys under the same review rules. Not yet: the single sign-on step at sign-in in the native apps, so a member whose organisation requires it signs in on the web vault or another app.
