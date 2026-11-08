---
title: Wi-Fi networks
description: Keep Wi-Fi networks in Octa Pass, see which one you're on and which are in range, import the networks your computer saved, and what each platform allows.
status: in-progress
sidebar:
  order: 17
---

:::note[In progress]
Wi-Fi items work in the web vault, the browser extension, the desktop apps and the phone apps. The Windows and Linux app and the phone apps show the **Connected** and **In range** marks where the system allows and offer to save networks, and the Windows and Linux app imports the networks the computer saved. The Mac app doesn't have these yet: it keeps and shows networks, without the marks, **Import saved networks** or the save offer. The iPhone, iPad, Android and Mac apps also show [older Wi-Fi items](#older-wi-fi-items) as they are, and don't move them to the Wi-Fi type yet.
:::

A **Wi-Fi network** is its own item type, with its own category in the sidebar and its own section when a list is grouped by type. Like every item, it's encrypted on your device; network names never reach the server unencrypted.

## What a network holds

| Field | Notes |
|---|---|
| **Network name** | The SSID, exactly as the network list shows it. |
| **Hidden network** | The network doesn't broadcast its name; devices join it by name. |
| **Security** | **WPA2 Personal**, **WPA2/WPA3 Personal**, **WPA3 Personal**, **WPA/WPA2 Personal**, **WPA Personal**, **WPA2 Enterprise**, **WPA3 Enterprise**, **WEP**, or **None** for an open network. The transition modes (WPA/WPA2, WPA2/WPA3) are what routers offer so older devices can still join. |
| **Password** | Personal and WEP networks. Open networks have none. Octa Pass checks the length: 8 to 63 characters for WPA (or 64 hexadecimal digits), 5 or 13 characters (or 10 or 26 hexadecimal digits) for WEP. Old passwords are kept in the password history. |
| **Enterprise sign-in** | Enterprise networks sign each person in: EAP method (PEAP, TTLS, TLS, PWD, LEAP, EAP-FAST), inner sign-in for PEAP and TTLS (MSCHAPv2, GTC, PAP, CHAP, MSCHAP), username, password, anonymous identity, server domain and CA certificate. |
| **Has a sign-in page** | A captive portal: after you join, a page asks you to accept terms or sign in, as in hotels and airports. |
| **Managed by an organisation** | A work or school network your organisation set up. This is your own note. On iPhone, iPad and Mac, **Managed** in the Wi-Fi settings means something narrower: a configuration profile (MDM) installed the network. That comes from the organisation, and Octa Pass doesn't change it. |
| **Personal Hotspot** | A phone or tablet sharing its mobile data. |
| **Notes** and fields | Like any item. |

The list shows each network's name under its title. Leave the title empty and the network's name becomes the title.

### Older Wi-Fi items

Before this type, a network was a **Password** item with an **SSID** field (and maybe **Security** and **Hidden**). Scanning a Wi-Fi QR code made those, and importers wrote Wi-Fi entries from other apps the same way. When you unlock, the web vault and the apps move such items in the vaults you can edit to the Wi-Fi type. Nothing is lost: a security type Octa Pass can't read and any other fields stay as fields. A login that has a username, website, one-time code, passkey or recovery info stays a login.

## Join and share

- **Show as QR code:** the `WIFI:` code phone cameras join from. Every WPA kind is `T:WPA` (the joining device works out WPA2 or WPA3), WEP is `T:WEP` and open networks `T:nopass`; hidden networks add `H:true`. Enterprise networks have no join code, because each person signs in. See [QR codes](/docs/features/qr-codes/).
- **Connect** (phone apps): iPhone joins Personal, WEP, open and Enterprise (PEAP, TTLS, EAP-FAST) networks. Android saves Personal, WPA3, open and Enterprise (PEAP, TTLS, PWD) networks after it asks you once; that needs Android 11 or later, and Android doesn't let apps add WEP networks. Android also needs the server domain or the CA certificate for an Enterprise network. TLS networks sign in with a client certificate, which Octa Pass doesn't keep, so set those up in the system's settings.
- **Scanning** a Wi-Fi QR code adds a Wi-Fi item, Enterprise fields included when the code has them (Android writes `WPA2-EAP` codes).

### NFC tags on Android

On Android, **Write to NFC tag** on a Wi-Fi item puts the network on a tag, so a guest with an Android phone taps it and confirms to join.

- **A tag isn't encrypted.** Anyone who taps or reads it gets the network's name and password. Octa Pass says so before writing. Put it where only your guests can reach it.
- WEP, WPA3-only and Enterprise networks can't go on a tag, because Android's tap-to-join doesn't read them. A network offering both WPA2 and WPA3 is written as WPA2.
- iPhones don't join networks from tags. Show them the QR code instead.

## Connected and in range

Where the system tells apps, the Wi-Fi list and each network show **Connected** on the network the device is on, and **In range** with the signal strength on the ones it sees. In the Wi-Fi category, the networks in range come first, the connected one at the top. The marks refresh every 15 seconds while a Wi-Fi screen is open, never in the background, and **Look for networks again** scans now.

Network names are read on the device and never stored or sent anywhere.

| Platform | Connected | In range | How |
|---|---|---|---|
| **iPhone, iPad** | Yes | No | `NEHotspotNetwork.fetchCurrent`, with location access and the Access Wi-Fi Information entitlement. iOS gives apps no way to see the networks around them (`NEHotspotHelper` is only for hotspot operators, with a special entitlement), so only **Connected** shows. |
| **Android** | Yes | Yes | `WifiManager`, with location access. Android allows four scans every two minutes; between them Octa Pass shows the last results. |
| **Mac** | Yes | Yes | CoreWLAN, with location access (macOS 14 and later give apps network names only with it). |
| **Windows** | Yes | Yes | The Native Wi-Fi API (`WlanAPI`). Windows 11 24H2 and later need location access for Octa Pass in Settings → Privacy & security → Location. |
| **Linux** | Yes | Yes | NetworkManager over D-Bus. |
| **Web vault, browser extension** | No | No | Browsers can't see Wi-Fi at all. |

Location access is asked for only when you open Wi-Fi in Octa Pass, never when the app starts. Phones and Macs require it because network names can reveal where you are; Octa Pass uses it only to read network names and never reads your location.

## Import the networks a computer saved

On a computer, the Wi-Fi category's **Import saved networks** lists the networks the computer has saved. Choose the ones to keep, then Octa Pass gets their passwords in one batch:

| Platform | What happens |
|---|---|
| **Mac** | The list comes from `networksetup -listpreferredwirelessnetworks` (no prompt). The passwords are in the System keychain as "AirPort network password" items, and macOS asks for an administrator's name and password before it gives each one, in its own window. Octa Pass never sees or keeps what you type there. |
| **Windows** | The WLAN profiles. Windows gives a profile's key in plain text only to apps running as an administrator; otherwise the network comes in without its password and you can type it later. |
| **Linux** | NetworkManager's Wi-Fi connections. Their passwords come from NetworkManager's secrets, and polkit may ask for your password for networks shared by all users. |
| **iPhone, iPad** | Not possible: iOS has no way for apps to read the networks it saved. Type a network in, or scan its QR code. |
| **Android** | Not possible: since Android 10, apps can't read saved Wi-Fi passwords. Open the network in Settings and tap **Share**: Android shows its QR code, which you scan in Octa Pass with **Scan a QR code**. |

Networks already in your vault are marked and start unselected.

## Save networks you join

When the device is on a network that isn't in your vault, Octa Pass offers **Save "network" in Octa Pass?**:

- **Computers** notice when they join a network, and read its password from the system, which may ask first (the same prompts as importing).
- **Phones** check when the app opens or comes back to the front, because they don't tell apps when they join. You type the password once.

Each network is offered once. **Not now** leaves it; **Never for this network** stops it for good. Turn the offers off in Settings → Wi-Fi, which also lets you clear your "Never" list. These choices stay on the device.
