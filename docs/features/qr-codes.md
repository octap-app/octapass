---
title: QR codes
description: Show Wi-Fi passwords, contacts, one-time codes and other items as QR codes for other devices to scan, and scan QR codes to add items, all on your device.
status: in-progress
sidebar:
  order: 14
---

:::note[In progress]
The iPhone, iPad, Mac and Android apps show items as QR codes. The web vault and the Windows and Linux app show Wi-Fi codes only, and the browser extension shows none. Every app can scan one-time codes. Rows marked *planned* below aren't built. See the [roadmap](/docs/reference/roadmap/).
:::

Octa Pass can turn items into QR codes that other phones and apps understand, and read QR codes to add items. QR codes are created on your device. Nothing is sent to a QR service.

## Show an item as a QR code

Open the item and choose **Show as QR code**. The code fills the screen (phones raise the brightness) and disappears after 60 seconds or when Octa Pass locks.

| Item | What scanning it does |
|---|---|
| **Wi-Fi network** | Joins the network straight away. Guests point their camera at it, with no typing. Enterprise networks have none: each person signs in. See [Wi-Fi networks](/docs/features/wifi/). |
| **Contact or identity** | Adds a contact card with the fields you choose |
| **One-time code** | Moves the 2FA code to another authenticator app |
| **Website** | Opens the login page on the other device |
| **Bank account** | Opens a bank transfer to you in the other person's banking app (EPC QR, the SEPA standard). You can add an amount in euros and a reference. It needs an IBAN in a SEPA country and the account holder's name; other accounts can show the IBAN as text. The PIN is never included |
| **Crypto wallet** | A `bitcoin:` or `ethereum:` link to your receiving address, or the plain address on other networks. Never your seed phrase or passphrase, and never a field you added yourself, since a seed could be in one. Anything with a space in it isn't treated as an address |
| **Any login** | Shows **the password** as text the other phone can copy, for a TV, game console, smart device or someone else's computer. You can add the username too. |
| **Notes and other fields** | Shows the field you choose as text |
| **Share link** (planned) | Hands someone a one-time link to an item, in person |

If an item has no scan-to-join format, its QR code simply **shares the password**. Every QR code also has a **Password only** switch, for example for a device that can't join Wi-Fi from a QR code: scanning then shows just the password, ready to copy.

For anything secret, such as one-time codes or a password, Octa Pass asks for your master password or device unlock first, unless unlocking already did (see [Revealing and copying](/docs/features/biometric-unlock/#revealing-and-copying)), and reminds you that cameras nearby can see the screen.

Card numbers, security codes, seed phrases, your master password and recovery codes are **never** shown as QR codes.

### Share Wi-Fi with guests

1. Open your Wi-Fi item and choose **Show as QR code**.
2. Your guest points their phone camera at the screen and taps **Join**.

Their phone joins the network directly. The password is never shown to them or typed. iPhones, Android phones and recent Windows and Mac cameras all understand Wi-Fi QR codes.

For longer visits, choose **Share for a day**. Octa Pass makes a [one-time share link](/docs/features/sharing/) that opens once within 24 hours, and shows it as a QR code to scan or copy. The link holds a copy of the network's name and password; your item stays yours. You can cancel it under Sharing. It needs an account, so vaults on this device only don't offer it.

### Join on your own devices

Your own phones don't need a QR code. Open the Wi-Fi item and choose **Connect**, and Octa Pass joins the network for you. See [Wi-Fi networks](/docs/features/wifi/) for what each platform allows. **Add to all my devices**, which would send the network to every phone and computer you're signed in on, is planned. Browsers can't join Wi-Fi networks, so the web vault shows the QR code instead.

## Scan a QR code to add an item

Use your phone's camera or a photo, or on a computer a QR code on screen (the browser extension reads the page), an image file or a pasted screenshot.

- **2FA setup QR code**, or a Google Authenticator export: adds one-time codes to the logins you choose. This works in every app; see [adding a code](/docs/features/totp/#adding-a-code).
- **Wi-Fi QR code** (on a router sticker, or Android's **Share** for a saved network): creates a Wi-Fi item (phone apps)
- **Contact QR code (vCard)**: creates an identity (phone apps)
- **Recovery Kit QR code** (planned): fills in your sign-in details on a new device

Scanned codes are read on your device and never uploaded.
