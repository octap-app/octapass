---
title: Organisations with groups, policies and single sign-on
date: 2026-11-02
summary: Teams can now run on Octa Pass with roles, groups, server-enforced policies and OpenID Connect sign-in, with no new key and no path to anyone's vault for admins, the server or an identity provider.
tags: [security, server, core, decision]
---

[Organisations](/docs/features/organisations/) bring a team's people, shared vaults and rules together. They're built on shared vaults, with no new kind of key: being an admin opens nothing.

- **Groups** are lists of people. Adding someone only asks a key holder to review it, and their device seals the vault key after they confirm each person and fingerprint. Taking access away is immediate, and the vault's key is changed next.
- **Policies** the server enforces: two-step sign-in, single sign-on, no share links, no emergency access. Policies the apps apply, labelled as such: no organisation vaults in exports, a limit on auto-lock, a minimum master password length.
- **[Single sign-on](/docs/features/single-sign-on/)** with OpenID Connect adds a step after your master password. **It's for signing in only.** SSO unlock can't be zero-knowledge, so your master password and Secret Key still unlock your vault, and neither the identity provider nor the server gets a path to your keys.

Organisation and group names are plain metadata on the server, so don't put secrets in them. The design is in `plans/03-security-model.md`.
