---
title: Organisations get SAML, SCIM provisioning, and run from the CLI and the Windows and Linux app
date: 2026-11-08
summary: Single sign-on now speaks SAML 2.0 as well as OpenID Connect, identity providers can invite, group and remove members over SCIM 2.0, and owners can run an organisation with `octapass org` or in the Windows and Linux app. Nothing here can open a vault.
tags: [decision, server, cli, desktop, security, docs]
---

[Organisations](/docs/features/organisations/) were run from the web vault only, and could sign people in through OpenID Connect only. Now:

- **SAML 2.0 sign-in.** Owners paste their provider's metadata, or its entity ID, sign-in URL and certificate, under **Organisation → Single sign-on**. As with OpenID Connect, it's a step after the master password and Secret Key and never unlocks anything. The server checks responses strictly: one signed assertion, pinned certificates only, SHA-256 or stronger, no DTDs. See [how SAML responses are checked](/docs/features/single-sign-on/#how-saml-responses-are-checked).
- **SCIM 2.0 provisioning.** Owners make a token under **Organisation → Provisioning** and give it to Entra ID, Okta or another provider. Adding someone there sends them an invitation they accept themselves; putting them in a group puts them on the list for that group's vaults, which a key holder still reviews; removing them takes the organisation's vaults away at once and marks them for a new key. It never removes an owner. See [SCIM provisioning](/docs/features/scim/).
- **`octapass org`** runs everything from the [CLI](/docs/platforms/cli/): members, groups, vaults, policies, SSO and SCIM tokens. Giving access (`octapass org access apply`) still shows each person's fingerprint and asks, or takes `--person EMAIL=FINGERPRINT` in a script.
- **The Windows and Linux app** shows the Organisation screens, on the same engine as the CLI.

This reverses the earlier decision not to build SAML and SCIM (plan 03 History); admin account recovery and group keys stay out. Self-hosters: see [identity providers](/docs/self-hosting/identity-providers/). Not done yet: organisation screens in the Mac and phone apps, and trying SAML and SCIM against real identity providers (the tests use local stand-ins). The SAML code hasn't had an outside review.
