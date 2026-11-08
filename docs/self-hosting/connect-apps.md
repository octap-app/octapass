---
title: Connect the apps to your server
description: Self-hosted Octa Pass uses the same official apps and extensions. Choose Self-hosted at sign-in, enter your server address, and optionally enable push sync.
status: in-progress
sidebar:
  order: 2
---

:::note[In progress]
The apps connect to your own server today. Push sync on phones is built but the Octa Pass push relay isn't running yet, so it needs a relay you run. The store listings, switching between several accounts and the F-Droid build on this page are planned. See the [roadmap](/docs/reference/roadmap/).
:::

There's no separate "self-hosted app". The browser extensions, desktop apps and mobile apps work with the hosted Octa Pass service **and** with your own server. You pick the server when you sign in.

## Sign in to your own server

1. Install Octa Pass. Until it's in the app stores, [build the apps from source](/docs/contributing/development-setup/).
2. On the sign-in screen, choose **Use a different server**, then **Self-hosted**.
3. Enter your server's address, for example `https://vault.example.com`. It must use HTTPS with a valid certificate.
4. Create an account or sign in as usual. Your Secret Key, master password and Recovery Kit work exactly as on the hosted service.

The app remembers the server for that account. Signing in to a different server means signing out first. Switching between several accounts is planned.

## What works the same

Everything that happens on your device is identical, because it lives in the app, not on the server:

| Feature | Self-hosted |
|---|---|
| Encryption, Secret Key, Recovery Kit | Same |
| Autofill in browsers, iOS, Android, macOS | Same |
| Passkeys | Same |
| Face ID, Touch ID, fingerprint, Windows Hello | Same |
| Offline access | Same |
| Password breach checks | Same: your device calls HIBP directly (see [breach checks](/docs/security/breach-checks/)) |
| Import and export | Same |
| Web vault | Served by your own server at its address |

## What needs setup on your server

| Feature | What you need |
|---|---|
| Verification codes and alert emails | An SMTP account, set in [configuration](/docs/self-hosting/configuration/) |
| Instant sync on phones (push) | Opt in to a push relay (below) |
| Email breach alerts (off by default) | Your own Have I Been Pwned API key, or leave the feature off |
| Website icons | Built in. Your server fetches and caches them so the apps don't contact icon services |

## Push sync on iPhone and Android

Apple and Google only deliver push notifications sent with the app publisher's credentials, so your server can't wake the Octa Pass mobile apps directly. You choose between two setups:

- **Push relay.** Set `OCTAPASS_PUSH_RELAY=true` ([configuration](/docs/self-hosting/configuration/#push-sync)). Your server registers with the relay once and gets an installation ID and key. When a vault changes, it sends the relay each affected phone's push token and the word `sync`; for sharing, family invites and emergency access, the word `alert`, which shows a notice like "Something changed in your sharing or emergency access". The relay forwards it through Apple or Google. **No vault data, item names, names or account emails pass through the relay.** The phone then syncs with your server as usual, even while it's locked: what it downloads stays encrypted until you unlock. The Octa Pass relay isn't running yet; until it is, [run your own](/docs/self-hosting/push-relay/) if you build the apps with your own Apple and Google credentials.
- **No relay** (the default). Phones sync when you open the app, and in real time while it's open.

On Android, push needs Google Play services. Builds without them sync as without a relay.

Browser extensions and desktop apps don't need the relay. They keep their own connection to your server.

## For advanced users

- **Android without Google services (planned):** an F-Droid build that syncs without Firebase (no push relay; background sync by polling).
- **Build from source:** every app can be built from the repository. See [development setup](/docs/contributing/development-setup/). Reproducible builds are planned for the extension and web vault.

## Related

- [Self-hosting overview](/docs/self-hosting/overview/)
- [Run with Docker](/docs/self-hosting/docker/)
- [Configuration](/docs/self-hosting/configuration/)
