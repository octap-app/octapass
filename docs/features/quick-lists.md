---
title: Pinned, recent and frequently used items
description: The lists above your vaults in the sidebar, Recently created, Pinned, Favourites, Frequently used, Recently used and Recently modified, and how Octa Pass counts a use without the server knowing.
status: beta
sidebar:
  order: 16
---

The **Vaults** part of the sidebar starts with lists that cut across every vault you can open. They're in the web vault, the desktop app and the phone apps, in this order:

| List | What it shows |
|---|---|
| **All items** | Everything, sorted and grouped as you choose. |
| **Recently created** | The 50 items added most recently, newest first. |
| **Nearby** | Your places and the items saved with each, the place you're at first. See [Nearby](/docs/features/nearby/). |
| **Pinned** | The items you pinned, with a count. |
| **Favourites** | The items you starred, with a count. |
| **Frequently used** | The 50 items you use most, the most uses first. |
| **Recently used** | The 50 items you used last, the latest first. |
| **Recently modified** | The 50 items changed most recently, the latest change first. |

Your vaults and **New shared vault** come after them.

## Pinned and favourites

Pinning is a list of its own, apart from your favourites: use Favourites for the items you reach for every day and Pinned for anything else you want to keep at hand, such as the logins for a project you're working on this month.

- **To pin an item**, open it and choose **Pin** (in the web vault and the desktop app, the pin button next to the star; on a phone, in the item's **More** menu, or swipe the row on iPhone). Choose **Unpin** to take it off. The editor has a **Pinned** switch too, next to **Favourite**.
- A new item made while **Pinned** is showing starts pinned.
- Pinned items have a small pin next to their title in every list.
- Like a favourite, the pin is part of the item, so it follows the item to your other devices. In a shared vault, everyone sees the same pin, and people who can only view the vault can't pin its items.
- A copy of an item in another vault, and a share link, don't keep the pin.

**Pinned** and **Favourites** are filters: you can sort and group them like any other list. See [sorting and grouping](/docs/features/sorting-and-grouping/).

## The lists with their own order

**Recently created**, **Frequently used**, **Recently used** and **Recently modified** put your items in an order of their own, so they have no **Sort and group** menu. Search looks through what the list shows. Items in the trash aren't in them.

The dates are the ones Octa Pass keeps for each item: when it was first saved here, and when it last changed.

## What counts as using an item

Octa Pass counts a use when you:

- **copy** something from the item: its username, password, one-time code, any other field, a `.env` file or an SSH private key;
- **fill** it into a page or an app with the browser extension (from a field's menu or the **Fill** button in **This site**);
- **open its website** from the item.

Looking at an item, or revealing a password, isn't a use. A use shows in **Frequently used** and **Recently used** right away.

The autofill built into iOS and Android (the AutoFill extension and the Autofill service) doesn't count uses yet.

### How uses are kept

Uses are kept in one hidden item in your personal vault: for each item, how many times you used it and when you last did. That item is encrypted on your device like the rest of your vault, so the server can't read which items you use or how often, and the uses follow your account to your other devices.

- Uses wait a few seconds and are saved together, so copying a username and then a password is one save. Leaving the tab or the app saves them at once. Locking the vault forgets uses that weren't saved yet.
- Using an item never changes the item itself: it gets no new version, and it works in vaults shared with you read-only.
- The hidden item keeps the 500 items you used most recently.
- If two devices save their uses at the same moment, each item keeps the higher count and the later use. Uses both devices counted since they last synced count once.
- Usage isn't part of exports: it names items by ids that an import changes.

The server does see that an item in your personal vault changed, and when, as it does for any item. See [what the server sees](/docs/security/what-the-server-sees/).
