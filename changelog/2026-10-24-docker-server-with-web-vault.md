---
title: The Docker image serves the web vault, with invites, log codes and backups built in
date: 2026-10-24
summary: One container now runs the sync server and the web vault on one port, invites the emails you list at start, can log sign-up codes when there's no SMTP, and makes daily online backups you can restore with one command.
tags: [server, release]
---

Self-hosting needs one container and one HTTPS name:

- **Web vault included.** The image serves the web vault next to the API (`OCTAPASS_WEB_DIR`, set in the image), with a strict content security policy (this origin only, plus `wasm-unsafe-eval` for the crypto core) and cross-origin isolation. The web vault always connects to the server it came from.
- **Invites from the configuration.** `OCTAPASS_INVITES` lists emails that may sign up while `OCTAPASS_SIGNUPS=invite`. They're invited at every start until their account exists.
- **Sign-up codes without SMTP.** `OCTAPASS_EMAIL_TO_LOG=true` writes email subjects, including the sign-up code, to the server log for the operator to read. Codes never go back to the browser.
- **Backups.** `OCTAPASS_BACKUP_DIR` turns on a daily online SQLite backup (database, server secrets and attachments, keeping 14). `octapass-server admin backup` and `admin restore` do the same by hand.
- **Health check** without a shell: `octapass-server healthcheck`.

`deploy/octap.app/` is a complete Docker Compose setup using all of it. See [Run with Docker](/docs/self-hosting/docker/) and [Backups](/docs/self-hosting/backups/).
