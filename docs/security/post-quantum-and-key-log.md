---
title: Post-quantum sharing and the key log
description: How Octa Pass seals shared keys with hybrid X25519 and ML-KEM-768, how the key log shows a swapped public key, and what neither protects against.
status: in-progress
sidebar:
  order: 8
---

:::caution[Not yet reviewed]
Both of these are built but haven't had the outside cryptographer's review the project requires. Don't rely on them yet, and keep comparing fingerprints with the people you share with.
:::

## Post-quantum sharing

Everything in your vault is protected by 256-bit symmetric keys, which quantum computers aren't expected to break. The exposure is in sharing: a key sealed with X25519 today could be recorded and opened by a future quantum computer.

So new shares are sealed with a **hybrid** box that combines X25519 with ML-KEM-768. It stays safe as long as either one holds. Octa Pass never uses ML-KEM alone.

- **It happens by itself.** The first time you unlock, your device makes an ML-KEM key and publishes it. There's nothing to set up.
- **Existing shares keep working.** They stay classical until the vault's next key rotation, which reseals them. A recording of an old share has the old exposure.
- **Emergency contacts** added before this keep their X25519 seal until you add them again.
- **Someone who hasn't unlocked since this shipped** has no ML-KEM key yet, so shares to them use X25519.

## The key log

To share with someone, your device asks the server for their public keys. A malicious server could hand out its own keys instead. [Comparing fingerprints](/docs/features/sharing/#shared-vaults) catches that, but only if you do it.

The key log catches it without a call. It's an append-only Merkle log of account public keys, one per server. Your device:

1. **Checks a proof** that the keys it was given are in the log under that person's email, before sealing anything to them. A failed check stops the share.
2. **Pins the log** and checks that each new version extends the last one, so history can't be rewritten without your device noticing.
3. **Watches for your own email.** At most hourly, each of your devices reads what's new in the log. A key under your email that you didn't make shows as an alert in **Sharing**.

Each person shows as **In key log**, **Not in key log yet** or **Key log check failed**.

The log holds no emails and no keys, only hashes. An email is turned into a label with an [OPRF](https://www.rfc-editor.org/rfc/rfc9497), so nobody can test a list of emails against the log offline, and getting a label is rate limited like looking up an account. The server does see which labels your device asks about. When an account is deleted its key record goes, and its entry stays as two meaningless hashes.

### What the key log can't catch

- **Different logs for different people.** A server that shows you one log and your contact another isn't caught by either of you alone. Catching that needs independent witnesses, which don't exist yet. Until then, comparing fingerprints is the only check against a server willing to do this.
- **"Not in key log yet".** Until someone's device publishes, there's nothing to check, and a server could claim that of anyone your device hasn't seen before. That's why it shows as a warning, not a pass.
- **The newest key.** A proof shows a key was logged, not that it's the latest. This holds up while account keys don't change, and your device refuses to step back to an older entry for someone it has seen.
- **Keys on incoming shares.** The members screen checks everyone against the log, but opening a vault shared with you doesn't check the sharer's key.
- **While you're offline.** Nothing watches for your email when none of your devices is online.
- **Self-hosted servers** have their own log. If a server loses its secrets it starts a new log, which your device reports as an alert.
