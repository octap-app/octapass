---
title: Nearby
description: Save places like home or the office, add items to them, and Nearby lists the place you're at first, worked out on your device with nothing sent anywhere.
status: beta
sidebar:
  order: 17
---

**Nearby** is a list in the sidebar, under **Recently created**. It shows the things that belong to the places you go: the Wi-Fi password and the alarm code at home, the door code, the printer's login and the VPN at the office. The place you're at comes first.

- **Now nearby: Office** (on its Wi-Fi)
  - Logins: Printer, VPN
  - Secure notes: Alarm code, Door code
  - Wi-Fi networks: Office 5G
- **Your other places**
  - **Home**, 1.2 km away
    - Secure notes: Alarm code
    - Wi-Fi networks: Home
  - **The cabin**, 37 km away
    - Documents: Lease

Each place lists its items in a section per type, in the same type order as your other lists, and each section by name.

## Places

A place is a name and up to two ways of telling that you're there:

- **Wi-Fi networks**: the names of its networks (SSIDs), exactly as your devices show them. Being connected to one of them means you're at the place. A Wi-Fi item you add to a place counts as one of its networks too, and a Wi-Fi item whose network is one of the place's is listed there without adding it.
- **A location**: a point (latitude and longitude) and a radius around it, 150 metres unless you choose another, from 25 m to 10 km. Use **Use my current location** while you're there, or copy the coordinates from a map app. Octa Pass never looks an address up: you name places yourself.

A place can have both, either or neither. A place with neither is never marked as nearby, but its items are still listed under it. A place can also have a note.

To make one, choose **New place** in Nearby (the plus button). **Places** (the settings button) lists them all, to edit or delete. Deleting a place doesn't delete its items: they just aren't listed under it any more.

## Adding items to a place

- On an item's page, under **Places**, choose **Add to a place**, or the cross next to a place to take the item off it. An item can be at several places.
- In Nearby, the plus button on a place makes a new item that starts at that place.
- When you save a new item while you're at one of your places, Octa Pass asks **You're at Office. Add this item to it?** with **Add** and **Not now**. It asks once for each item, only when your device can tell where it is, and never offers a place that someone who can see the item couldn't see (see [shared vaults](#shared-vaults)). Turn it off in **Settings → Nearby → Suggest a place when saving**.

## How your device knows where it is

Octa Pass compares where your device is with your places **on the device**, with the same Rust code in every app.

| | Wi-Fi | Location |
|---|---|---|
| **Mac app** | Not read on a Mac yet | One reading, with your permission, when you open Nearby |
| **Windows and Linux app** | The network the computer is on | One reading from the system's web view, where it offers one, after you turn it on |
| **iPhone and iPad** | The network the phone is on, with location access | One reading, with your permission, when you open Nearby |
| **Android** | The network the phone is on, with location access | One reading, with your permission, when you open Nearby |
| **Web vault** | Browsers can't see Wi-Fi | One reading from your browser, with your permission |
| **Browser extension** | Not visible to extensions | Not asked for: Nearby lists your places, none marked as nearby |

The location is read **once**, when you open Nearby or come back to it, and only while the app is open. There is no background location, no geofencing and no location history: the reading is compared with your places and then forgotten.

On the web and in the Windows and Linux app, using your location is off until you turn it on, with **Use my location** in Nearby or **Settings → Nearby → Use my location for Nearby**. On a phone, a tablet or a Mac, Nearby asks the first time you open it.

If your device can't tell where it is, because location is off or blocked, or you're not on one of your places' networks, Nearby still lists every place, none of them marked as nearby, and says why. When the location is known, your other places are in order of distance, nearest first, each with a rough distance ("1.2 km away"). Places without a location come after them, by name; without a location reading every place is in name order.

The extension doesn't ask for location: Chrome and Firefox would ask everyone for that permission when they install the extension, for a list the web vault and the apps already show with it.

## Privacy

Places are items in your vault, encrypted on your device like every other item. The server stores them as ciphertext: it can't see a place's name, its location, its radius, its networks, its note, or which items belong to it. It sees what it sees for any item: that an item exists, its size and when it changes. See [what the server sees](/docs/security/what-the-server-sees/).

Octa Pass never sends your location or a network name anywhere, and uses no map, geocoding or location service of its own. To work out a location, your phone's or computer's own location service may use nearby Wi-Fi and mobile networks, the same as for any app you allow location: on Apple devices that's Apple's location service, on Android Google's, and in a browser the browser's own.

### Shared vaults

A place in a shared or family vault is seen by everyone in the vault, like any item there. When you save a place with a location in one, Octa Pass warns: **Everyone in this vault will see where this place is.**

Items in your personal vault can be added to a place in a shared vault: only you see that link. An item in a shared vault is only offered places in the same vault, so everyone who sees the item can see its place.

## Import and export

Places are part of the Octa Pass JSON and encrypted exports, and come back when you import one, with your items still added to them. CSV exports leave them out, like your other settings-like items.
