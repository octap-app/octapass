---
title: Pinned, recent and frequently used lists in the sidebar
date: 2026-11-04
summary: The sidebar's Vaults section now starts with Recently created, Pinned, Favourites, Frequently used, Recently used and Recently modified, with Nearby coming soon, on the web, the desktop app and both phone apps.
tags: [decision, core, extension, desktop, mobile]
---

The **Vaults** part of the sidebar has new lists between **All items** and your vaults:

- **Recently created** and **Recently modified**: the 50 items added or changed last.
- **Pinned**: a list of its own, apart from your favourites. Pin an item from its page (the pin next to the star on the web and desktop, the **More** menu on a phone), or with the editor's new **Pinned** switch. Pinned items show a small pin in every list.
- **Frequently used** and **Recently used**: the items you use most and last. Copying from an item, filling it with the browser extension, or opening its website counts as a use.
- **Nearby** shows as coming soon. It needs places saved with items, which isn't built yet.

Uses are kept in one hidden item in your personal vault, encrypted on your device like everything else, so they follow you to your other devices and the server can't tell which items you use. It does see when that item is saved. Using an item never changes the item itself. See [pinned, recent and frequently used items](/docs/features/quick-lists/) and [what the server sees](/docs/security/what-the-server-sees/). The decisions are in `plans/01-product-spec.md` and `plans/03-security-model.md`.

The phone apps' part of this hasn't been built or run on a device yet. Autofill from the iOS AutoFill extension and the Android Autofill service doesn't count uses yet.
