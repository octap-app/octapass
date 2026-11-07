---
title: Run with Docker
description: Run the Octa Pass server and web vault in one Docker container behind your own HTTPS proxy, with Docker Compose, invites, backups and health checks.
status: in-progress
sidebar:
  order: 3
---

:::note[In progress]
There's no published image yet: build it from the repository. The settings below work today.
:::

The image runs the sync server and the web vault on one port: `/v1/…` is the API (including the `/v1/ws` WebSocket), everything else is the web vault. Put it behind a reverse proxy that terminates TLS; the apps refuse servers without HTTPS.

## Build the image

From the repository root:

```bash
docker build -f apps/server/Dockerfile -t octapass-server .
```

The build compiles the crypto core to WebAssembly, builds the web vault and the server, and copies them into a distroless image that runs as a non-root user. Base images are pinned by digest.

## Docker Compose

A complete example lives in [`deploy/octap.app`](https://github.com/octap-app/octapass/tree/main/deploy/octap.app): copy the folder, change the domain and the invited email, and run `docker compose up -d --build`. The essentials:

```yaml
services:
  octapass:
    build: { context: ../.., dockerfile: apps/server/Dockerfile }
    restart: unless-stopped
    ports: ["127.0.0.1:8380:8080"]      # only your proxy should reach it
    environment:
      OCTAPASS_PUBLIC_URL: https://vault.example.com
      OCTAPASS_WEB_ORIGINS: https://vault.example.com
      OCTAPASS_SIGNUPS: invite
      OCTAPASS_INVITES: you@example.com
      OCTAPASS_TRUST_PROXY: "true"
      OCTAPASS_SMTP_URL: ${OCTAPASS_SMTP_URL:-}
      OCTAPASS_EMAIL_TO_LOG: ${OCTAPASS_EMAIL_TO_LOG:-false}
      OCTAPASS_BACKUP_DIR: /backups
    volumes:
      - octapass-data:/data
      - octapass-backups:/backups
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]

volumes:
  octapass-data:
  octapass-backups:
```

Then forward `https://vault.example.com` to `127.0.0.1:8380` in your proxy (Caddy, Traefik, nginx or a Cloudflare Tunnel), with WebSockets allowed.

- **Who can sign up.** With `OCTAPASS_SIGNUPS=invite`, only the emails in `OCTAPASS_INVITES` (comma-separated) can create an account. They're invited at every start until their account exists; `octapass-server admin invite` adds more without a restart.
- **The verification code.** Sign-up needs a code sent by email. Set `OCTAPASS_SMTP_URL`, or set `OCTAPASS_EMAIL_TO_LOG=true` and read the code with `docker compose logs octapass | grep "verification code"`. The code is never returned to the browser outside dev mode.
- **The web vault** always uses the server it's served from. Its pages get a content security policy that allows only that origin plus `wasm-unsafe-eval` (the crypto core), and cross-origin isolation headers. API responses keep `default-src 'none'`.
- **PostgreSQL** instead of SQLite: add a `postgres:17` service and set `OCTAPASS_DATABASE_URL=postgres://octapass:<password>@db:5432/octapass`. Scheduled backups are SQLite only; use `pg_dump` there.

## Health checks

- `GET /healthz`: the process is alive
- `GET /readyz`: the database and storage are reachable
- `octapass-server healthcheck` exits 0 when `/healthz` answers. The image uses it as its `HEALTHCHECK`, since it has no shell or curl.

## Admin commands

Run them in the container: `docker compose exec octapass octapass-server admin …`. See [configuration](/docs/self-hosting/configuration/#admin-cli).

## Updating

```bash
git pull && docker compose up -d --build
```

Database migrations run automatically at startup, behind a lock, so only one instance migrates at a time. Back up first: see [backups](/docs/self-hosting/backups/).
