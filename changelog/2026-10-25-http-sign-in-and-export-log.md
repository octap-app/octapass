---
title: HTTP sign-in prompts, and exports in the security log
date: 2026-10-25
summary: The browser extension can answer a site's username-and-password pop-up once you allow it, and every export now shows in your security log.
tags: [extension, server, security]
---

**HTTP sign-in prompts.** Routers, printers and admin pages often ask for a username and password in the browser's own pop-up instead of a form. In Chrome, Edge and Firefox, Octa Pass can now answer it with a login saved for that exact address. The first time, it asks which login to use; after that it signs you in by itself. A login's editor has a new **HTTP realm** field for sites that ask for different sign-ins in different areas. Octa Pass never answers for a proxy, for a frame or for a request another site started, and you can take a site back in **Settings → HTTP sign-in prompts**. Safari doesn't allow this, so it keeps its own pop-up. See [autofill](/docs/features/autofill/#http-sign-in-prompts).

**Exports in the security log.** Exporting your vault from the web vault, the browser extension, the desktop app, the CLI or the phone apps now adds an entry to **Settings → Security log**: which device, when, the format, and whether the file holds your attached files. Nothing from the vault goes to the server. See [exporting](/docs/import-export/export/).
