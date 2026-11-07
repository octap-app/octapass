---
title: Importing your own backup no longer makes copies
date: 2026-11-04
summary: An Octa Pass export imported into a vault that already has its items updates them or leaves them alone instead of adding every item again, and saving a login you already have asks first.
tags: [decision, core, extension, desktop, mobile, cli]
---

Importing a file from another password manager twice already updated the items it brought in the first time. Octa Pass's own exports were the exception: importing a backup into the vault it came from added every item a second time. Now they're matched too (the decision is in `plans/07-import-export.md`):

- **By the item's own id first, in any of your vaults.** An export holds every vault and an import goes into one, so your family vault's items are no longer copied into Personal. When the ids don't match (an export imported into another account), the usual rules for a duplicate apply in the vault you import into.
- **The newer version wins.** An item you changed after the export was made is kept as it is, so restoring an old backup to get one deleted item back doesn't undo the passwords you've changed since. The summary says how many were kept.
- **Files come back only where they're missing**, and links between items (a login's recovery email from an Identity) point at the items already in your vault.

More kinds of item now match as duplicates too: documents by title and notes, SSH keys and keys by their public key, certificates by the certificate, and environments by project and stage.

Saving a **new login for a website and username you already have** now asks first, in the web vault, the desktop app and the phone apps: keep editing or save a copy, and in the web vault and desktop app, open the one you have. See [item types](/docs/features/item-types/#fields-every-item-has) and [importing again](/docs/import-export/overview/#importing-again).

The phone apps' part of this hasn't been built or run on a device yet.
