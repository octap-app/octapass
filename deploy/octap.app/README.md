# octap.app: the public Octa Pass service

How the hosted service runs. Self-hosters can copy this folder; change the hostnames, the Traefik labels and `.env`.

| URL | Container | What |
|---|---|---|
| `https://octap.app` | `octapass-website` | Website, docs, changelog (`apps/website`, static, nginx) |
| `https://vault.octap.app` | `octapass-server` | Sync API and the web vault on one origin (`apps/server`) |
| (internal) | `octapass-db` | PostgreSQL 17, reachable only from the server and backup job |
| (internal) | `octapass-backup` | Nightly `pg_dump` and a copy of the server's secrets into `./backups`, kept 14 days |

Sign-ups are **open** (`OCTAPASS_SIGNUPS=open`): anyone can create an account after confirming their email, so SMTP is required.

## Layout on the server

```
/opt/stacks/octapass/
  docker-compose.yml   copied by deploy.sh
  .env                 secrets, chmod 600, never in git
  backups/             nightly dumps
```

TLS: Cloudflare proxies both hostnames (orange cloud) to the server, where the shared Traefik terminates TLS with a Let's Encrypt certificate from its `cloudflare` DNS-challenge resolver. The Cloudflare API token Traefik uses must be allowed to edit DNS for the `octap.app` zone. Set Cloudflare SSL/TLS to **Full (strict)**.

## First deploy

1. DNS in Cloudflare (proxied): `A octap.app`, `A www.octap.app` and `A vault.octap.app` → the server's IP.
2. Brevo: verify the `octap.app` sender domain (add Brevo's DKIM and DMARC records in Cloudflare), then create an SMTP key.
3. On the server, create the stack folder and `.env`:

   ```sh
   mkdir -p /opt/stacks/octapass && cd /opt/stacks/octapass
   # paste .env.example as .env, then fill in POSTGRES_PASSWORD and OCTAPASS_SMTP_URL
   chmod 600 .env
   ```

4. From a workstation with Docker, at the repository root:

   ```sh
   deploy/octap.app/deploy.sh
   ```

   It builds `octapass-server` and `octapass-website` locally (linux/amd64), streams them to the server with `docker save | ssh … docker load`, copies `docker-compose.yml`, sets `OCTAPASS_TAG` in `.env` and runs `docker compose up -d`.

5. Check it: `curl -fsS https://vault.octap.app/health` and open `https://octap.app`.

## Updating

Run `deploy/octap.app/deploy.sh` again. Migrations run when the server starts. The three newest tags of each image stay on the server for rollback:

```sh
ssh macberry 'cd /opt/stacks/octapass && sed -i "s/^OCTAPASS_TAG=.*/OCTAPASS_TAG=<older tag>/" .env && docker compose up -d'
```

## Backups and restore

`octapass-backup` writes `backups/octapass-<UTC time>.dump` (pg_dump custom format) and `backups/server-data-<UTC time>.tgz` every 24 hours. The `.tgz` holds the server's generated secrets (`opaque-server-setup.bin`, `server-secret.bin`): **a database restored without them can't log anyone in**, so always keep the two together. Copy them off the server too: a backup on the same disk doesn't survive losing the disk.

Restore into an empty database:

```sh
cd /opt/stacks/octapass
docker compose stop server
docker compose exec -T db pg_restore -U octapass -d octapass --clean --if-exists < backups/octapass-<time>.dump
docker compose start server
```

To restore the server's secrets into a fresh volume: `docker compose run --rm -v "$PWD/backups:/b" --entrypoint sh backup -c 'tar -xzf /b/server-data-<time>.tgz -C /server-data'` (with that mount made writable), before starting the server.

The vault data in the database is end-to-end encrypted. A dump holds ciphertext, OPAQUE records and account metadata (emails), so treat it as sensitive anyway.

## Resources

The server is small and shared, so every container has a memory limit: server 384 MB, PostgreSQL 384 MB (tuned in `docker-compose.yml`), website 64 MB, backup 128 MB. Watch them with `docker stats --no-stream | grep octapass`.
