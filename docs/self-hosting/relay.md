---
title: Masked email relay
description: Run the Octa Pass masked email relay, an optional mail forwarder that passes mail through without storing it. Setup, DNS records, limits and what it can see.
status: in-progress
sidebar:
  order: 7
---

:::caution[Built, not yet run on real mail]
The relay is complete and tested with real SMTP on one machine, against a stand-in for the outgoing mail provider and fixed DNS answers. It has not yet been run on the internet, with real DNS, a real provider or a real inbox. The hosted Octa Pass service doesn't run it. It stays off unless you set it up.
:::

`octapass-relay` gives your server its own [masked email](/docs/features/masked-email/) service. Aliases such as `k3j9x2m7q4tz@alias.example.com` forward to the email address of the Octa Pass account that made them, and replies go back out through the alias, so the other side never learns the real address.

It's a separate program with its own database, so the vault server stays small. Running a public mail service is real work: it needs a domain, a sending provider and someone reading abuse reports. Most self-hosters are better off [connecting an existing provider](/docs/features/masked-email/#providers).

## How it works

- **No queue.** A message is held in memory while it's received, passed to your outgoing provider inside the same SMTP conversation, and forgotten. The sender gets `250` only after the provider has taken it, `451` to try again later, or `550` when it will never work. **No message ever reaches a disk or a log**, and there's no queue to fill up or leak.
- **One recipient per transaction.** Sending systems retry further recipients on their own, so the answer to a message is always the fate of that one message.
- **Forwarding.** From and Reply-To become a *reverse alias* (`r-…@alias.example.com`), one per alias and sender. The sender's name stays visible, and their real address is in `X-Original-From`. The original To and Cc move to `X-OctaPass-Original-To` and `-Cc`, so Reply All can't reach them from your real address. Read receipts and mailing-list `mailto:` links are removed for the same reason.
- **Replies.** Mail to a reverse alias is accepted only from the account's own email, and only when SPF or DKIM proves it. It goes out from the alias, with only the subject, threading and content headers kept. `Received`, `X-Originating-IP`, `User-Agent`, your DKIM signature, your time zone and everything else your mail provider added are gone. **The body isn't changed**, so a signature with your name in it still goes out.
- **Bounces.** The return path of forwarded mail is signed and names the alias, not the sender. A bounce is read, sorted as hard or soft, and counted. It is **never passed on** to the original sender, because it would contain your real address. Forged return paths are refused, and no bounce is ever generated.
- **Complaints.** Abuse reports (RFC 5965) sent to the return path or to `abuse@` count too.
- **Pauses.** Too many hard bounces or complaints stop an alias, or everything on the account, with one email saying so. Turning the alias back on ends the pause.

Mail to an unknown, disabled, paused or blocked address gets the same refusal, so a sender can't tell them apart.

## What it stores

| Stored | How |
|---|---|
| Each alias, its account id, whether it's on, and counters | In the clear |
| The account's email | Sealed with XChaCha20-Poly1305 under a key from the relay's secret; found through a keyed hash |
| The address of each sender you've had mail from on an alias | Sealed the same way, with its reverse alias |
| Blocked senders | A keyed hash only |

It stores no subjects, no bodies and no site names. The site an alias is for stays in your encrypted vault.

**What this changes.** Your vault stays end-to-end encrypted and the relay can't read it. But email isn't: **while a message is being forwarded, it passes through the relay in plaintext**, in memory. Whoever runs a relay could read mail as it goes by, as with any mail forwarder. With the relay's secret, they can also open the stored addresses, which show who has written to your aliases. See [what the server sees](/docs/security/what-the-server-sees/).

## Set it up

You need a domain or subdomain just for aliases, and an outgoing provider that accepts mail with your domain as the sender, including forwarded mail. Check its terms: many forbid forwarding.

```bash
# The DKIM key
openssl genrsa -out dkim.pem 2048
openssl rsa -in dkim.pem -pubout -outform DER | base64 | tr -d '\n'   # the p= value below

# Two secrets
openssl rand -base64 48   # OCTAPASS_RELAY_SECRET; keep it safe, it opens the stored addresses
openssl rand -base64 48   # OCTAPASS_RELAY_API_TOKEN, the same on the vault server
```

### DNS records

```text
alias.example.com.                     MX  10 mx.alias.example.com.
mx.alias.example.com.                  A   <the relay's public IP>
alias.example.com.                     TXT "v=spf1 include:<your provider's SPF> -all"
relay2026._domainkey.alias.example.com. TXT "v=DKIM1; k=rsa; p=<the public key>"
_dmarc.alias.example.com.              TXT "v=DMARC1; p=reject; rua=mailto:postmaster@alias.example.com"
```

The relay's outgoing mail is signed for the alias domain, and its return paths are on that domain, so SPF and DKIM both line up with it.

### The relay

Without configuration, `octapass-relay` says it's off and exits. These are all required:

| Variable | Description |
|---|---|
| `OCTAPASS_RELAY_DOMAIN` | The domain aliases live on. |
| `OCTAPASS_RELAY_SECRET` or `OCTAPASS_RELAY_SECRET_FILE` | At least 32 bytes. Everything sealed depends on it, so back it up with the database. |
| `OCTAPASS_RELAY_API_TOKEN` | At least 32 characters. The vault server sends it to the internal API. |
| `OCTAPASS_RELAY_DATABASE_URL` | `sqlite:/path/relay.db` or `postgres://…`. |
| `OCTAPASS_RELAY_SMART_HOST` | The outgoing provider, as `smtps://user:password@host:465` or `smtp://user:password@host:587?tls=required`. |
| `OCTAPASS_RELAY_DKIM_SELECTOR` | The selector in your DNS record, such as `relay2026`. |
| `OCTAPASS_RELAY_DKIM_KEY_FILE` | The RSA private key, in PEM. |

| Optional | Default | Description |
|---|---|---|
| `OCTAPASS_RELAY_HOSTNAME` | the domain | The name in the SMTP banner. |
| `OCTAPASS_RELAY_SMTP_BIND` | `0.0.0.0:25` | Where mail arrives. |
| `OCTAPASS_RELAY_API_BIND` | `127.0.0.1:8025` | The internal API. It speaks for every account, so keep it off the internet. |
| `OCTAPASS_RELAY_TLS_CERT_FILE`, `OCTAPASS_RELAY_TLS_KEY_FILE` | unset | PEM files for STARTTLS. Without them, inbound mail arrives in plaintext. |
| `OCTAPASS_RELAY_OPERATOR_EMAIL` | unset | Where `postmaster@` and `abuse@` go. Without it they're refused, which breaks RFC 5321's rule that `postmaster` must work, so set it on a public relay. |

Limits, all optional:

| Variable | Default |
|---|---|
| `OCTAPASS_RELAY_MAX_MESSAGE_BYTES` | `26214400` (25 MiB) |
| `OCTAPASS_RELAY_MAX_CONNECTIONS` | `256` |
| `OCTAPASS_RELAY_CONNECTIONS_PER_IP_MINUTE` | `60` |
| `OCTAPASS_RELAY_MESSAGES_PER_ALIAS_HOUR` | `60` |
| `OCTAPASS_RELAY_MESSAGES_PER_SENDER_HOUR` | `120` |
| `OCTAPASS_RELAY_MESSAGES_PER_ACCOUNT_HOUR` | `300` |
| `OCTAPASS_RELAY_REPLIES_PER_ACCOUNT_HOUR` | `60` |
| `OCTAPASS_RELAY_ALIASES_PER_ACCOUNT` | `200` |
| `OCTAPASS_RELAY_ALIASES_PER_DAY` | `25` |
| `OCTAPASS_RELAY_CONTACTS_PER_ALIAS` | `2000` |
| `OCTAPASS_RELAY_FEEDBACK_WINDOW_DAYS` | `30` |
| `OCTAPASS_RELAY_ALIAS_HARD_BOUNCES` | `3` |
| `OCTAPASS_RELAY_ALIAS_COMPLAINTS` | `3` |
| `OCTAPASS_RELAY_ACCOUNT_HARD_BOUNCES` | `10` |
| `OCTAPASS_RELAY_ACCOUNT_COMPLAINTS` | `10` |

Rate limits are kept in memory, so run one relay, not several.

### The vault server

Point the server at the internal API:

| Variable | Description |
|---|---|
| `OCTAPASS_RELAY_API_URL` | For example `http://127.0.0.1:8025`. Unset, `/v1/masked-email` answers 404 and server info says `maskedEmailRelay: false`. |
| `OCTAPASS_RELAY_API_TOKEN` | The same token as the relay's. |

The vault server sends the signed-in account's id and verified email, and mail can only ever be forwarded to that address. When an account is deleted, the relay deletes everything it has for it. If the relay is down at that moment, the server keeps trying until it succeeds.

## Abuse protection

- SPF, DKIM, DMARC and ARC are checked on every message by [`mail-auth`](https://crates.io/crates/mail-auth). Mail that fails DMARC from a domain asking for `p=reject` is refused. The result is added as `Authentication-Results`, and forwarded mail gets an ARC seal.
- A message with several From addresses, or none, is refused: DMARC doesn't apply to those, so they'd be a way around it.
- Only the addresses the relay issued are accepted. Other domains, source routes, `%` and `!` routing, quoted local parts and address literals are refused, so it can't be used as an open relay.
- Messages ending in a bare CR or LF are refused, which stops SMTP smuggling. Anything sent along with `STARTTLS` ends the connection.
- `VRFY` and `EXPN` aren't offered.
- Loops stop at a marker header and at 25 `Received` headers. Automatic replies from your mailbox (`Auto-Submitted`, `Precedence: bulk`) never go out through a reverse alias.
- There's no content filtering. Spam that passes these checks is forwarded, and every complaint counts against the alias.
