---
title: Octa Pass exports import back as they were
date: 2026-11-08
summary: Wi-Fi networks in a CSV or CXF export come back as Wi-Fi networks, and importing a file whose items are all already there says so.
tags: [core]
---

Importing an Octa Pass export back into Octa Pass now keeps each item's type:

- **CSV.** Import → Other app (CSV) recognises Octa Pass's own CSV and reads its `type` column. Wi-Fi networks, cards, identities, notes, bank accounts, licences, ID documents, databases and wallets come back as what they were, and the `Label: value` lines the export writes at the top of the notes go back into their fields. Before, every row became a login, or a secure note when it had no website. Types a CSV can't hold in full (SSH keys, documents, certificates) become notes with every line kept, and the import says so.
- **CXF.** A `wifi` credential becomes a Wi-Fi network instead of a secure note, with the Enterprise settings Octa Pass exports as custom fields back in their places.
- **Importing into the same account.** An export's items are found by their ids in any of your vaults, so importing it into the account it came from, even into a new vault, adds nothing. The import now says "All 25 items are already in your vaults, so nothing was added." instead of a row of counts that looked like a failure. An address written as one line (CSV) no longer replaces the one in the vault when they say the same thing.

- **Between Octa Pass and Open Pass.** Octa Pass reads the JSON and encrypted exports of Open Pass, the project it's a fork of (`.openpass` files, `"format": "openpass-export"`), and Open Pass reads Octa Pass's. Before, each refused the other's file as not its own export.

The JSON and encrypted exports were already complete; they're still the ones to use for a backup. See [export](/docs/import-export/export/) and [import](/docs/import-export/overview/#other-apps-csv).
