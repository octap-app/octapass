---
title: The docs now say what's built
date: 2026-11-02
summary: Every page marked planned was checked against the code, and claims about features that don't exist yet were corrected.
tags: [docs, security]
---

The pages still marked `planned` were written before the code existed. Each one was checked against the repository, and the [support matrix](/docs/platforms/support-matrix/) now shows what's built, with a table of what each app can do, including the native iPhone and Android apps.

Some claims were wrong, and these matter most:

- Password [breach checks](/docs/security/breach-checks/) go straight from your device to Have I Been Pwned. The proxy through our server doesn't exist yet, so HIBP sees your IP address.
- Refresh tokens rotate, but they aren't bound to a device key yet.
- Reproducible builds, signed vault manifests, Subresource Integrity, proof-of-work and email breach alerts aren't built. The [security overview](/docs/security/overview/#not-built-yet) and [threat model](/docs/security/threat-model/#not-built-yet) list what isn't.
- An emergency contact can read a vault, but can't take over the account yet.
- Local vaults exist only in the browser extension.
- Push sync, the updater, Flatpak and AUR packages, a published server image and running several server instances aren't there yet.

The repository also has issue forms and a pull request template.
