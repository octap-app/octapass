---
title: Offline access and sync
description: How Octa Pass keeps an encrypted local copy of your vault for offline use, syncs changes across devices in real time, and handles edit conflicts safely.
status: in-progress
sidebar:
  order: 12
---

:::note[In progress]
Every app keeps an encrypted copy of your vaults on the device, so you can unlock and read them offline. The web vault and the browser extension hear about changes over the WebSocket within moments; while it's down, the web vault's tab syncs on focus and every 30 seconds. Push to phones isn't built yet, so the phone apps sync when you open them, while they're open and in background refresh. The iPhone, iPad, Mac and Android apps save changes made offline and upload them later. The web vault, the browser extension and the Windows and Linux app need a connection to save. An edit that clashes with another device's is kept as a conflicting copy: merging edits field by field isn't built yet.
:::

## Offline first

Every app keeps an **encrypted local copy** of your vaults (SQLite storing ciphertext blobs). You can unlock, search, view and edit items without a connection. Changes queue up and sync when you're back online.

Search uses an index that is encrypted at rest and decrypted in memory only while the vault is unlocked.

## How sync works

- Each vault has a revision number that increases with every change.
- Devices pull "everything changed since revision N" and push individual encrypted items.
- A WebSocket connection tells your other devices that a vault changed. It carries no data, only the fact that something changed.
- Deleted items go to the trash for 30 days. Deletion markers are kept for 90 days so offline devices catch up.

Protocol details: [sync API](/docs/developers/sync-api/).

## Conflicts

If two devices edit the same item while offline:

1. If the edits touch different fields, Octa Pass merges them.
2. If they touch the same field, the server's version wins, and your device's version is saved as a **conflict copy** in the same vault with a banner so you can choose.

Octa Pass never silently drops your data.

## Version history

Each item keeps its last 10 versions. Open an item and choose **Version history** to see them, and **Restore** to go back to one.

- Versions are encrypted with the item's own key, like the item. The server keeps them as ciphertext and can't read them. They count against your storage quota.
- Restoring is an ordinary edit, so the version it replaces joins the list and you can go back again.
- A version covers what the item says, not its files. Restoring keeps the item's current files and passkeys, keeps its password history growing, and never moves a counter-based code backwards.
- Reading the history needs a connection. Vaults on this device only keep no history yet.
- Moving an item to another vault starts its history again, because its encryption is tied to the vault.
