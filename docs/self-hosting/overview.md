---
title: Self-hosting overview
description: Run your own Octa Pass server with every feature of the hosted service, using a single Docker container with SQLite or PostgreSQL and S3-compatible storage.
status: in-progress
sidebar:
  order: 1
---

:::note[In progress]
The server is built and tested on SQLite and PostgreSQL, but no image is published yet: for now you [build it from the repository](/docs/self-hosting/docker/).
:::

The Octa Pass server you can self-host is **the same code** that runs the free hosted service, under MIT. Every feature is included.

## What you run

One container, built from `apps/server/Dockerfile`, that:

- Handles accounts, sign-in (OPAQUE), sync and sharing
- Serves the web vault
- Sends transactional email over SMTP
- Stores attachments locally or in S3-compatible storage

The server only ever stores ciphertext. See [what the server sees](/docs/security/what-the-server-sees/).

## Sizes

| Setup | Database | Attachments | Good for |
|---|---|---|---|
| Small | SQLite (default) | Local disk | A family or a few friends, a home server or a small VPS |
| Larger | PostgreSQL 16+ | S3-compatible (MinIO, Garage, any S3 provider) | Many users |

Rate limits are kept in each server's memory, so running several instances behind one address isn't supported yet.

## Requirements

- A domain name and TLS. The [Docker guide](/docs/self-hosting/docker/) uses Caddy for automatic certificates.
- An SMTP account for verification and alert emails
- Docker, or the server binary built with Cargo

## Next steps

1. [Run it with Docker](/docs/self-hosting/docker/)
2. [Configure it](/docs/self-hosting/configuration/)
3. [Set up backups](/docs/self-hosting/backups/)

Then [connect the apps to your server](/docs/self-hosting/connect-apps/): the same official apps work with it.
