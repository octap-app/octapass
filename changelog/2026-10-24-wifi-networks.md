---
title: Wi-Fi networks get their own item type
date: 2026-10-24
summary: Wi-Fi networks are their own item type and category, with Enterprise settings; the apps mark the network you're on and those in range, import a computer's saved networks and offer to save new ones.
tags: [core, desktop, mobile]
---

Wi-Fi networks are now a **Wi-Fi network** item with its own category in the sidebar, editor and view:

- **Network name** and **hidden network**, and the **security** in full: open, WEP, WPA, WPA/WPA2, WPA2, WPA2/WPA3 and WPA3 Personal, and WPA2 or WPA3 **Enterprise** with the EAP method, inner sign-in, username, anonymous identity, server domain and CA certificate.
- **Has a sign-in page** (captive portals), **Managed by an organisation** and **Personal Hotspot**, with what "Managed" means on Apple devices explained in the editor.
- **Show as QR code** uses the right `WIFI:` type (`WPA`, `WEP` or `nopass`, `H:true` for hidden networks), now in the web vault too, and phones' **Connect** joins WPA3 and Enterprise networks.

Older Wi-Fi items (a password item with an SSID field, which QR scans and importers used to make) move to the new type the next time you unlock, losing nothing.

In the desktop and phone apps:

- **Connected** and **In range** marks with the signal strength, networks in range first in the Wi-Fi category, refreshed while the screen is open. iPhones show only **Connected**: iOS doesn't let apps see the networks around them. Location access is asked for only when you open Wi-Fi.
- **Import saved networks** on a Mac, Windows PC or Linux computer, after you choose which; macOS asks for an administrator's password for each in its own window. Phones can't do this, and the app says how to bring a network in instead (on Android, the system's **Share** QR code).
- **Save this network?** when you join one that isn't in your vault, once per network, with **Never for this network** and a switch in Settings.

See [Wi-Fi networks](/docs/features/wifi/) for what each platform allows and why.
