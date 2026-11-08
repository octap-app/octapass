---
title: Push relay
description: How Octa Pass wakes phones to sync. What the push relay is, what a push contains, what the relay, Apple and Google can see, and how to run one.
status: beta
sidebar:
  order: 8
---

:::caution[Built, not yet run with Apple or Google]
Push sync and the relay are complete and tested end to end on one machine, against stand-ins for Apple's and Google's push services. Nothing has been sent through the real services yet, and the Octa Pass relay isn't running. Until it is, pushes need a relay you run with your own Apple and Google credentials, and apps you build with them.
:::

A phone app can only be woken by its publisher: Apple and Google deliver pushes sent with the credentials of whoever publishes the app. A self-hosted Octa Pass server doesn't have those, so it asks the **push relay**, a small service that holds them, to pass a wakeup on. The phone then syncs with your server as it always does.

Push is off unless you turn it on with [`OCTAPASS_PUSH_RELAY=true`](/docs/self-hosting/configuration/#push-sync). Without it, phones sync when you open the app and while it's open.

## What a push contains

One word, and nothing else:

| Word | When | What the phone does |
|---|---|---|
| `sync` | Something in a vault the account can see changed, or who can see it | Syncs, silently |
| `alert` | A vault was shared with you, a family invited you, someone added you as an emergency contact, asked for emergency access, or was denied or given it | Shows a notice ("Something changed in your sharing or emergency access. Open the app to see it.") and syncs |

The notice's words are in the app, in the phone's language. The push names no account, email, vault, item, person or number. Changes are gathered for two seconds, so an import of a thousand items wakes each phone once.

A locked phone syncs too: it downloads what changed, still encrypted, so autofill and the next unlock have it. Nothing is decrypted until you unlock.

## Who sees what

| Who | Sees |
|---|---|
| Your server | Each phone's push token, which device and account it belongs to, and when it sent a push |
| The relay | Which server is asking, and per push: a token, Apple or Google, and the word. Never an account, email, vault or item. It stores no tokens and logs counts only |
| Apple or Google | The token, the word and the time, as for any app's push |

So the relay, Apple and Google can tell how often your phones are woken, and that a token got an `alert` rather than a `sync`. They can't tell who it is or what changed. See the [security model](/docs/security/) for the rest of what a server can see.

## How the server uses it

1. With `OCTAPASS_PUSH_RELAY=true`, the server registers with the relay (`OCTAPASS_PUSH_RELAY_URL`) and keeps the installation ID and key in its database.
2. Phones that see `pushRelay: true` in `GET /v1/server-info` send their push token to `PUT /v1/devices/current/push` (see the [sync API](/docs/developers/sync-api/#push)).
3. On a change, the server sends the relay the tokens of the affected accounts' signed-in devices with the word, at most 100 a request.
4. When the relay says a token is dead (the app was removed), the server deletes it. Signing a device out deletes its token too.

Pushes are best effort. If the relay is down or limiting your server, that round is dropped and phones catch up the next time they're opened.

## Run a relay

The relay is `octapass-push-relay` in `apps/push-relay`: one binary and a small database (SQLite or PostgreSQL) of installations. Pushes only reach apps signed with the same Apple team and Firebase project as the relay's credentials, so a relay of your own is only useful with apps you build yourself.

```bash
cargo build --release -p octapass-push-relay
OCTAPASS_PUSH_RELAY_DATABASE_URL=sqlite:///var/lib/octapass-push-relay/relay.db \
OCTAPASS_PUSH_RELAY_APNS_KEY_FILE=/etc/octapass-push-relay/AuthKey.p8 \
OCTAPASS_PUSH_RELAY_APNS_KEY_ID=ABC123DEFG \
OCTAPASS_PUSH_RELAY_APNS_TEAM_ID=TEAM123456 \
OCTAPASS_PUSH_RELAY_FCM_CREDENTIALS_FILE=/etc/octapass-push-relay/firebase-service-account.json \
./target/release/octapass-push-relay
```

Put it behind a reverse proxy with HTTPS, and point your server at it with `OCTAPASS_PUSH_RELAY_URL`.

| Variable | Default | Description |
|---|---|---|
| `OCTAPASS_PUSH_RELAY_DATABASE_URL` | required | `sqlite://…` or `postgres://…`. Holds installations only. |
| `OCTAPASS_PUSH_RELAY_BIND` | `127.0.0.1:8092` | Address and port to listen on. |
| `OCTAPASS_PUSH_RELAY_TRUST_PROXY` | `false` | `true` behind a reverse proxy, so the registration limit uses the last `X-Forwarded-For` address. |
| `OCTAPASS_PUSH_RELAY_APNS_KEY_FILE` | unset | Apple's `.p8` push key. Set it, or the FCM file, or both. |
| `OCTAPASS_PUSH_RELAY_APNS_KEY_ID`, `OCTAPASS_PUSH_RELAY_APNS_TEAM_ID` | required with the key | The key's ID and your Apple team ID. |
| `OCTAPASS_PUSH_RELAY_APNS_TOPIC` | `app.octap.ios` | The iPhone app's bundle ID. |
| `OCTAPASS_PUSH_RELAY_FCM_CREDENTIALS_FILE` | unset | A Firebase service account key (JSON) allowed to send Cloud Messaging. |
| `OCTAPASS_PUSH_RELAY_PUSHES_PER_MINUTE` | `600` | Pushes one server may send a minute. |
| `OCTAPASS_PUSH_RELAY_REGISTRATIONS_PER_HOUR` | `5` | New servers that may register from one address an hour. |

The credentials are read from files, never from the environment. Keep them, and the database, private.

### Managing servers

```bash
octapass-push-relay admin list                 # every installation, active or revoked, and when it was last used
octapass-push-relay admin revoke <installation id>
```

A revoked server is refused from then on (`403`), and an Octa Pass server then stops sending and doesn't register again by itself; it tries again after a restart. A modified server could register anew, within the registration limit, so on abuse block its address at the proxy too.

## Building the apps for your relay

- **iPhone:** an Apple team with the Push Notifications capability, and the `.p8` key from that team for the relay. Development builds use Apple's sandbox, which the relay picks from what the phone tells your server.
- **Android:** a Firebase project. Build with its settings (`-PoctapassFcmProjectId`, `-PoctapassFcmAppId`, `-PoctapassFcmApiKey`, `-PoctapassFcmSenderId`) and give the relay a service account key from the same project. Without the settings, the app has no push. Only Firebase Cloud Messaging is used: no Analytics, and delivery metrics stay off.

## Related

- [Configuration](/docs/self-hosting/configuration/#push-sync)
- [Connect the apps](/docs/self-hosting/connect-apps/#push-sync-on-iphone-and-android)
- [Sync API: push](/docs/developers/sync-api/#push)
