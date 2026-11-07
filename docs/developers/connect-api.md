---
title: Octa Pass Connect API
description: The local HTTP API tools use to ask Octa Pass for a secret by reference, with per-client approval and a session token.
status: in-progress
sidebar:
  order: 3
---

Octa Pass Connect is a helper on your own computer. Any program with an HTTP client can ask it for a secret by `octapass://` reference. There's nothing product-specific about it: this page is the whole interface.

Start it with `octapass connect serve`, or turn it on in the desktop app. See [Octa Pass Connect](/docs/features/connect/) for what it does and doesn't protect.

## Finding it

There's one Connect per user. Look for it in this order:

1. `OCTAPASS_CONNECT`: `unix:/path/to/connect.sock`, `http://127.0.0.1:<port>` or `http://localhost:<port>`. Anything else is an error: don't fall through to the next step, and never send a token anywhere else.
2. The socket `connect.sock` in the Connect folder, if something answers on it. A process that died can leave the file behind.
3. The port in the file `connect.port` in the Connect folder (Windows, or `octapass connect serve --port`).

The Connect folder is `com.octapass.connect` in the system's per-user data folder:

| System | Folder |
|---|---|
| macOS | `~/Library/Application Support/com.octapass.connect` |
| Linux | `$XDG_DATA_HOME/com.octapass.connect`, by default `~/.local/share/com.octapass.connect` |
| Windows | `%APPDATA%\com.octapass.connect` |

On a socket, any `Host` header works. On loopback, `Host` must be `127.0.0.1:<port>` or `localhost:<port>`, and a request with an `Origin` header is refused, so web pages can't use Connect.

## Getting a token

```sh
curl --unix-socket "$SOCKET" http://localhost/v1/clients \
  -H 'Content-Type: application/json' -d '{"name":"My tool"}'
```

This waits while the person is asked, for up to two minutes. Show your own "waiting for approval" message. One client can be waiting at a time. To give up, close the connection: nothing is approved, and the next client can ask.

```json
{ "id": "kU2n6mN0Yk4", "token": "opc1_…", "expiresAt": 1802592000 }
```

Keep the token in the system's secret store. It lasts 30 days and can be revoked at any time. On a socket it only works from the same program that asked, so a program that moves (an update can do this) gets `401` and has to ask again. Send it as `Authorization: Bearer <token>`. Requests with a body need `Content-Type: application/json`.

## Endpoints

### `GET /v1/status`

No token needed.

```json
{ "unlocked": true }
```

### `POST /v1/clients`

`{ "name": "My tool" }`, 1 to 64 characters. Answers `201` as above.

### `DELETE /v1/clients/self`

Gives up this client's token. Answers `204`.

### `GET /v1/items`

Names only, never values. Use it to let people browse.

```json
{
  "items": [
    {
      "vault": "Work",
      "vaultId": "0192f0c8-1c2d-7a00-8000-0000000000bb",
      "item": "Stripe",
      "itemId": "0192f0c8-1c2d-7a00-8000-0000000000aa",
      "type": "login",
      "fields": [
        { "name": "username", "secret": false },
        { "name": "password", "secret": true }
      ]
    }
  ]
}
```

A reference is `octapass://<vault>/<item>/<field>`, with `%` written `%25` and `/` written `%2F` inside a part. Vaults and items can be named or given by id. Names match in any case, and a name more than one has fails as ambiguous, so use `vaultId` or `itemId` when names repeat. Every field listed can be read.

### `POST /v1/read`

Up to 100 references. Each value handed out is recorded in the security log first.

```json
{ "references": ["octapass://Work/Stripe/password", "octapass://Work/Nope/password"] }
```

```json
{
  "secrets": [
    { "reference": "octapass://Work/Stripe/password", "value": "…" },
    { "reference": "octapass://Work/Nope/password", "error": "No item called \"Nope\"." }
  ]
}
```

The field `accessToken` of an item with an OAuth2 client is a live token, fetched or refreshed as needed.

## Errors

Errors have a status and this body:

```json
{ "error": { "code": "locked", "message": "Octa Pass is locked. Unlock it, then try again." } }
```

| Status | `code` | Meaning |
|---|---|---|
| 400 | `bad-request` | The name or the list of references is out of range, or the body isn't valid JSON |
| 401 | `unauthorized` | No token, an unknown or expired one, or a different program |
| 403 | `denied` | The person said no, or didn't answer |
| 403 | `forbidden` | A request from a web page, or from another user |
| 404 | `not-found` | Not in the vault, or no such path |
| 405 | `bad-request` | Wrong method |
| 413 | `bad-request` | The body is over 64 KiB |
| 415 | `bad-request` | The body isn't `application/json` |
| 423 | `locked` | The vault is locked. Connect never unlocks it |
| 429 | `busy` | Another client is waiting for approval |
| 500 | `failed` | The entry couldn't be recorded, so the secret wasn't handed out; or another failure |
