---
title: A build command for each app
date: 2026-11-04
summary: pnpm build:desktop, build:macos, build:windows, build:linux, build:cli, build:vscode and build:jetbrains join the existing app builds, and every build asks which server the apps offer as "Octa Pass".
tags: [extension, desktop, mobile, cli]
---

Every app now builds from the repository root with `pnpm build:<app>`. The new commands are `build:desktop`, which picks the build for the system you're on, `build:macos`, `build:windows`, `build:linux`, `build:cli`, `build:vscode` and `build:jetbrains`. They join `build:extension`, `build:safari`, `build:ios` and `build:android`. See [building the apps](/docs/contributing/development-setup/#build-the-apps).

The extensions and the iPhone, Android and desktop apps offer one server as "Octa Pass" on their sign-in screen. Local builds used to offer a placeholder address there, so only "Self-hosted" reached a real server. Now the first build in a terminal asks which server to offer. It suggests `pnpm start`'s public address and the hosted service, and can save the answer in `.env.local`. Builds without a terminal still use the hosted service, and the release workflow's `VITE_SERVER_URL` still wins.

`pnpm build:ios` now also signs with the team `pnpm dev:ios:device` picked, when no other team is set.
