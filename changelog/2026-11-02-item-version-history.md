---
title: Items keep their last 10 versions
date: 2026-11-02
summary: Open an item's version history to see what it used to say and restore an older version, encrypted like the item itself.
tags: [core, server, security]
---

Every item now keeps its last 10 versions. **Version history** on an item lists them, and **Restore** brings one back as an ordinary edit, so you can undo that too.

Versions are stored on the sync server as ciphertext under the item's own key, so the server can't read them. They count against your storage quota. Restoring keeps the item's current files and passkeys, and never moves a counter-based code backwards. Vaults on this device only don't keep versions yet.

Details are in [Offline and sync](/docs/features/offline-and-sync/#version-history) and the [sync API](/docs/developers/sync-api/).
