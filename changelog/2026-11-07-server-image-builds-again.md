---
title: The server's Docker image builds again
date: 2026-11-07
summary: apps/server/Dockerfile had fallen behind the workspace; it now copies the relay crate, builds the Tools WASM core and no longer races on the cargo cache.
tags: [server]
---

`docker build -f apps/server/Dockerfile .` (and `docker compose up --build` in `deploy/octap.app`) stopped working. Three fixes:

- **The relay crate is copied in.** `apps/relay` is a workspace member, so cargo refused to load the workspace without it (`failed to load manifest for workspace member /src/apps/relay`).
- **The Tools build of the crypto core is built.** The web vault's worker imports `@octapass/core/tools` for the Tools section, and the image only built the `web` and `full` variants, so the web vault failed to type-check. The image now builds all three the way `packages/core/scripts/build.mjs` does.
- **No more cache race.** The WASM and server stages run at the same time and shared the cargo registry cache, so both could unpack the same crate at once (`failed to unpack package … File exists`). The cache is now `sharing=locked`.

The image itself is unchanged: the same server binary and web vault, served the same way. See [Run with Docker](/docs/self-hosting/docker/).
