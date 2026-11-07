---
title: The development scripts ask instead of guessing
date: 2026-11-04
summary: pnpm start asks where people open the server and who can sign up, and the iPhone, Simulator and Android scripts pick the device, team and server or let you choose.
tags: [server, mobile]
---

The scripts that run Octa Pass locally used to apply silent defaults. Now they ask in a terminal, remember the answers in a gitignored file, and take `--setup` to ask again. Without a terminal they keep the old defaults and print them. See [development setup](/docs/contributing/development-setup/#serve-it-or-run-the-native-apps).

- **`pnpm start`** asks whether people open it through a tunnel or only on this computer, and who can create an account: invited emails, anyone, or no one new. It used to invite only your git email without saying so. The answers can be saved in `.env.local`, and the questions come before the build so you can walk away.
- **`pnpm dev:ios:device`** offers the signing teams from Xcode's accounts and the keychain's certificates, the connected iPhones and iPads, and a server the phone can reach. It used to stop when `APPLE_DEVELOPMENT_TEAM` was missing, and without a server setting the app pointed at a placeholder address.
- **`pnpm dev:ios`** uses the booted Simulator, and **`pnpm dev:android`** the only connected device. Both find which of `pnpm dev:api` and `pnpm start` is running.

Fixed:

- The iOS scripts no longer fail with `cleanup[@]: unbound variable` on the bash 3.2 that ships with macOS.
- `pnpm dev:ios:device` no longer looks for a phone named "iPhone 17 Pro", the Simulator's default, when `DEVICE` isn't set.
- A variable given on the command line now wins over the same setting in `.env.local` or `apps/ios/device.env`.
