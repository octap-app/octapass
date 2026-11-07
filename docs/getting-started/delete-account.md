---
title: Delete your account
description: How to permanently delete your Octa Pass account, every password and item in it, and all your devices, plus what happens to backups and shared vaults.
status: in-progress
sidebar:
  order: 4
---

:::note[In progress]
Account deletion works in the web vault preview against the sync server: the steps below, the server-side deletion and the wipe on this and other devices. The device count shows only this browser until the server has a device list, and shared vaults don't exist yet. See the [roadmap](/docs/reference/roadmap/).
:::

You can delete your Octa Pass account at any time. This permanently removes **the account and everything in it**: every password, passkey, one-time code, card, identity, note and file, all your vaults, and all your devices. It can't be undone, and no one, including Octa Pass, can recover it afterwards.

## Before you delete

- **Export your vault** if you want to keep your data: Settings → Export. See [export](/docs/import-export/export/).
- **Shared vaults you own** are deleted too, so other members lose access to them. Octa Pass lists them before you confirm.
- **Change your recovery details** on websites that use an Octa Pass [masked email](/docs/features/masked-email/) you plan to stop using.

## Delete your account

1. Open **Settings → Account → Delete account**.
2. Review what will be deleted: the number of items, vaults and devices.
3. Type your account email and enter your master password.
4. Choose **Delete account permanently**.

You're signed out, and the vault data stored on that device is wiped. Your other devices are signed out the next time they connect, and they wipe their local copy too. You'll get an email confirming the deletion.

## What happens to your data

| Data | When it's gone |
|---|---|
| Account, keys, vaults, items, files, devices, sessions | Immediately, in one step |
| Local copies on your other devices | The next time each device connects |
| Encrypted server backups | Within 30 days, as backups rotate out |
| Your email address | Free to register again immediately |

Octa Pass keeps only an anonymous count of how many accounts were deleted each day. Because your vault was end-to-end encrypted, its contents could never be read, not even in backups.

## Self-hosted servers

On your own server, the same option is in Settings. An administrator can also delete an account with `octapass-server admin delete-account <email>`.
