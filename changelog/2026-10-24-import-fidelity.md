---
title: Imports keep every field, and importing again updates instead of copying
date: 2026-10-24
summary: Imported items keep the other app's dates, ids, HTTP realms and auto-type settings, and importing the same file again updates your items instead of adding copies.
tags: [core, cli, desktop, mobile, extension, docs]
---

**Every field where it belongs.** Importers now read every field the other apps export, not just the URL, username and password. Created, last-changed, last used and password-changed dates come across. So does each app's own id for the item, and Firefox's HTTP realm for logins saved from a site's sign-in pop-up. KeePass auto-type settings and KeePassXC passkeys come across too. Only fields Octa Pass has no place for become custom fields. Each source's page in the [import docs](/docs/import-export/overview/) has a table of what goes where.

**Dates you recognise.** An imported item shows when it was created, when it last changed, when it was last used and when its password changed, as the other app recorded them. These dates are encrypted with the rest of the item.

**Import again without copies.** Import the same file again, or a newer export, and items already in your vault are updated instead of copied. They're matched by the other app's id, or as duplicates (same website and username). A changed password keeps the old one in the password history. The import summary says how many items are new, updated and unchanged. The [CLI](/docs/platforms/cli/) shows the same counts, also with `--dry-run`.

**Any CSV.** A Firefox, Chrome, LastPass or other known export chosen as "Other app (CSV)" is now read by that app's importer. Bitwarden's CSV export works too, with its custom fields. Date and id columns are recognised by name.

Everything is in Arabic too.
