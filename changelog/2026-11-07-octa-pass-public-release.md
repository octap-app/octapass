---
title: Open Pass is now Octa Pass, open source under MIT
date: 2026-11-07
summary: The project is published as Octa Pass at octap.app, under the MIT licence, with the hosted service on PostgreSQL at vault.octap.app.
tags: [release, licence, self-hosting]
---

The project developed as "Open Pass" is published as **Octa Pass**. "OpenPass" is already the name of another product, so the public release uses the new name everywhere: the apps, the CLI (`octapass`), the crates and packages (`octapass-*`, `@octapass/*`), the server's settings (`OCTAPASS_*`) and the app identifiers (`app.octap.*`).

- **Website and docs:** [octap.app](https://octap.app).
- **Hosted service:** the sync server and the web vault on one origin, [vault.octap.app](https://vault.octap.app). The apps' "Octa Pass" server choice points there.
- **Source:** [github.com/octap-app/octapass](https://github.com/octap-app/octapass), with a fresh history. The GitHub Action is published separately as [`octap-app/octapass-action`](https://github.com/octap-app/octapass-action).
- **Licence:** [MIT](/docs/reference/license/) instead of AGPL-3.0-only. The hosted service still runs exactly the published code.

The hosted service runs on PostgreSQL with nightly backups of both the database and the server's own secrets. [`deploy/octap.app`](https://github.com/octap-app/octapass/tree/main/deploy/octap.app) is the complete setup: images are built on a workstation and copied to the server, so the server never compiles anything.
