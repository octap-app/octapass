---
title: Key log witnesses
description: How independent witnesses stop an Octa Pass server from showing different people different key logs, how to point your server at witnesses, and how to run one for someone else.
status: in-progress
sidebar:
  order: 9
---

:::caution[Built, not yet reviewed]
Witnesses are built and tested end to end on one machine, and the formats are checked against the Go reference implementations of the C2SP specs. Like the rest of the [key log](/docs/security/post-quantum-and-key-log/#the-key-log), they haven't had the outside cryptographer's review yet. Nobody has been chosen to witness the hosted service, so it isn't witnessed yet.
:::

The [key log](/docs/security/post-quantum-and-key-log/#the-key-log) shows a swapped public key to the key's real owner. One attack gets past it: a server that shows you one log and your contact another. Each of you sees a log that hangs together, so neither of you notices.

**Witnesses** close that gap. A witness is someone other than the server's operator who runs a small service that signs ("cosigns") the log's current state, but only after checking that it extends the last state it cosigned. A server can then fork its log only by getting the witnesses to cosign both forks, and an honest witness never does.

## What clients do

When a server has witnesses, every head it sends comes with the newest checkpoint they cosigned and a proof that the head extends it. Your device:

1. **Pins the witnesses** the first time, alongside the log's own keys, and from then on holds the server to them. A server can add witnesses or ask for more cosignatures, but it can't drop a witness or lower the number for a device that has pinned them.
2. **Needs a quorum of fresh cosignatures.** By default that's a majority of the witnesses, so any two people's devices rely on at least one witness in common. A cosignature older than 7 days doesn't count.
3. **Refuses a head that doesn't extend the witnessed checkpoint.** That's an alert in **Sharing**, like any other sign the log was rewritten.

If the witnesses can't be reached for more than 7 days, devices that pinned them refuse key log checks, and with them new shares, until they can. That's the point: a server that cuts its witnesses off could otherwise fork the log behind them.

A server's devices learn its witnesses from the server. A device that has never connected could be given fake ones, just as it could be given a fake log. Witnesses protect everyone who pinned the real ones.

## What a witness sees

Only checkpoints: the log's name, its size and its root hash, signed by the server. No emails, no keys, no accounts and nothing about who uses the server. Your devices never talk to a witness, so witnesses don't learn anything about your users either. A witness does learn your server's address and how fast its log grows.

## Use witnesses on your server

Witnesses speak the standard [C2SP tlog-witness](https://c2sp.org/tlog-witness) protocol, so you can use the [Octa Pass witness](#run-a-witness), or any other witness that accepts Ed25519 checkpoints.

1. **Give each witness operator your log's verifier key.** Your server prints it:

   ```bash
   octapass-server admin key-log
   ```

   ```text
   origin   octapass-key-log/9oQ…
   vkey     octapass-key-log/9oQ…+1a2b3c4d+AXJ…
   ```

   The origin is derived from your log's keys, so it can't be changed, and it changes only if you lose the server secret.

2. **List the witnesses** once their operators have added your log:

   | Variable | Default | Description |
   |---|---|---|
   | `OCTAPASS_KEY_LOG_WITNESSES` | unset | Witnesses, separated by commas or newlines. Each is the witness's submission URL and its verifier key, separated by a space. At most 16. |
   | `OCTAPASS_KEY_LOG_WITNESS_QUORUM` | a majority | How many must cosign. Lower it only if you accept that two groups of users could rely on different witnesses. |
   | `OCTAPASS_KEY_LOG_WITNESS_INTERVAL` | `600` | Seconds between rounds. Each round sends the current checkpoint to every witness, even if nothing changed, so cosignatures stay fresh. |

   ```bash
   OCTAPASS_KEY_LOG_WITNESSES="https://witness.example.org witness.example.org/octapass+5d2f…+BEk…,https://w2.example.net w2.example.net+81c0…+BFa…"
   ```

3. **Check it works:**

   ```bash
   octapass-server admin key-log witness
   ```

   This sends a checkpoint to every witness now and says which cosigned. Once a quorum has, clients are offered the witnesses with every head. Until then, nothing changes for them, so it's safe to set the variable before every witness is ready.

Pick witnesses run by people who don't answer to you, on infrastructure you don't control. Three witnesses with the default quorum of two keeps working through one outage.

### Restoring an old backup

A backup taken before newer accounts published their keys has a shorter log. New keys then go where the newer ones were, which is a fork. Witnesses refuse it, and devices that saw the newer log raise an alert. This is the key log working as designed: a restore can't quietly rewrite history. If you must restore an old backup, say so to your users before they see the alert.

## Run a witness

`octapass-witness` is a small, standalone server. It keeps one JSON file of the newest checkpoint it cosigned for each log, and its signing key.

```bash
OCTAPASS_WITNESS_NAME=witness.example.org/octapass \
OCTAPASS_WITNESS_LOGS="octapass-key-log/9oQ…+1a2b3c4d+AXJ…" \
OCTAPASS_WITNESS_DATA_DIR=/var/lib/octapass-witness \
OCTAPASS_WITNESS_BIND=127.0.0.1:8090 \
octapass-witness
```

| Variable | Default | Description |
|---|---|---|
| `OCTAPASS_WITNESS_NAME` | required | Your witness's name, a URL without the scheme. Log operators see it, and it goes in every cosignature. |
| `OCTAPASS_WITNESS_LOGS` | none | The verifier keys of the logs you witness, separated by commas or newlines. Checkpoints from any other log are refused. |
| `OCTAPASS_WITNESS_DATA_DIR` | `./witness-data` | Holds `state.json` and, by default, the key. |
| `OCTAPASS_WITNESS_KEY_FILE` | `<data dir>/witness.key` | Your signing key, 32 random bytes made on first start and readable only by its owner. |
| `OCTAPASS_WITNESS_BIND` | `127.0.0.1:8090` | Where to listen. Put it behind a reverse proxy with HTTPS. |

`octapass-witness vkey` prints your verifier key for log operators to add. The witness answers:

- `POST /add-checkpoint`: the tlog-witness endpoint servers send checkpoints to.
- `GET /<SHA-256 of the origin, hex>/checkpoint`: the newest checkpoint it cosigned for a log, for anyone who wants to compare.
- `GET /`: its verifier key.

**Keep the key and `state.json` safe, and back them up together.** If you lose `state.json`, you'll accept a fork you would have refused. If you lose the key, you need a new one, and every log operator has to replace your verifier key. Don't run the same key in two places: two copies with separate state could each cosign a different fork.

A witness is only worth something if it's independent. Run one for a server you don't operate.
