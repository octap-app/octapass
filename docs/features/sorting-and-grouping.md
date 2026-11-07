---
title: Sorting and grouping items
description: Sort item lists by name or date, group them by type, first letter or vault, and show several logins for one website as one row. Each list remembers its choice on each device, in English and Arabic.
status: beta
sidebar:
  order: 16
---

Item lists in the web vault, the desktop app, the phone apps and the browser extension's **All items** view can be sorted and split into sections. Open the **Sort and group** menu (the arrows button at the top of the list). On a phone it opens as a sheet from the bottom of the screen.

## Sort by

| Choice | Order |
|---|---|
| **Name, A to Z** | The default. Follows your app language: accents and capitals don't matter, and "Item 2" comes before "Item 10". |
| **Name, Z to A** | The same, backwards. |
| **Date added, newest first** / **oldest first** | When the item was created. |
| **Last changed** | Most recently edited first. |

Items with the same name or date always come in the same order.

## Group by

| Choice | Sections |
|---|---|
| **Type** | Logins, Passwords, Cards, Identities, Secure notes, Documents, in that order. The default for **All items**, **Pinned**, **Favourites** and a vault. |
| **First letter** | A to Z for Latin titles, the Arabic letter for Arabic titles (أ, إ and آ are filed under ا), and **#** for titles that start with a digit or a symbol. In Arabic, Arabic letters come first. The default for a list of one type, such as **Logins**. |
| **Vault** | One section per vault. Offered when you have more than one vault. |
| **None** | One list. |

Each section has a header with its item count, and the header stays at the top while you scroll through it. A list of one type doesn't offer grouping by type.

## Several accounts on one website

When two or more logins are for the same website, the list shows one row for that website instead of one per login. The row has the website's address and the number of accounts, such as **a.example.com · 3 accounts**. Click or tap it to open it: the logins appear indented right under it, in the list's order. Click or tap it again to close it. It works the same on every device, in the list itself.

- **Which website**: the login's first website address. Logins without an address are never combined, and other kinds of items aren't either.
- **Same website** means the same address after these are ignored: `https://` or `http://`, capitals, a leading `www.`, and the path. So `https://www.a.example.com/login` and `a.example.com` are one website, but `a.example.com` and `b.example.com` are two. A port is kept when it isn't the usual one (`nas.local:5000` and `nas.local:8080` are usually different apps on one server).
- **Where it sits**: inside the current section (for example under **Logins**, or in its vault). In name order it's filed by its address; when you sort by date it sits where its newest (or last changed) login would. Grouped by first letter, it goes under the address's first letter.
- A website with only one login stays a normal row.
- A website row stays open while your vault is unlocked, and opens by itself when one of its logins is the item you're looking at. Which rows are open is kept in memory only, never saved.
- To list every login on its own, turn off **Combine accounts for the same website** in the **Sort and group** menu. That choice is for the whole device, not one list.
- **Search results**, the **One-time codes** list, the extension's **This site** view and autofill menus always show each login on its own.

## What the choice applies to

- Each list remembers its own choice: **All items**, **Pinned**, **Favourites**, **Passkeys**, **One-time codes**, each type, and vaults (one choice for all vaults).
- **Recently created**, **Frequently used**, **Recently used** and **Recently modified** keep an order of their own and have no menu. See [pinned, recent and frequently used items](/docs/features/quick-lists/).
- The choice is a preference of that device, kept by the app or browser. It isn't synced and isn't part of your vault.
- **Search results** aren't grouped: they're listed by name, and a note under the search box says so.
- The **Trash** keeps the most recently deleted items first.
- The extension's **This site** view keeps its own order: the logins that match the page best come first.

Sorting happens on your device, after your items are decrypted. Dates come from the item itself (the date added is part of the item's id), so sorting doesn't decrypt anything beyond what the list already shows. See [what the server sees](/docs/security/what-the-server-sees/).
