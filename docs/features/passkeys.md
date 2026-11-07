---
title: Passkeys
description: How Octa Pass creates, stores, syncs and uses passkeys in browsers, iOS, macOS, Android and Windows, and how to move passkeys with the FIDO CXF format.
status: in-progress
sidebar:
  order: 3
---

:::note[In progress]
The passkey authenticator in the Octa Pass core is built and tested. The browser extension that puts it in front of websites is in progress for the public alpha. System-wide passkeys on mobile and desktop come with those apps.
:::

A passkey is a key pair tied to one website (its *relying party ID*). The website stores only the public key. Octa Pass stores the private key encrypted in your vault and syncs it to your devices like any other item.

## Where it works

| Platform | Mechanism |
|---|---|
| Chromium browsers, Firefox | The extension handles `navigator.credentials.create()` and `.get()` |
| iOS 17+, macOS 14+ | System AutoFill credential provider (`ASCredentialProviderViewController`) |
| Android 14+ | Credential Manager provider (`CredentialProviderService`) |
| Windows 11 | Passkey plugin provider in the desktop app, off by default ([details](#windows-11)). Not yet tried on real Windows |
| Linux | In browsers, through the extension |


## Windows 11

:::note[In progress]
The provider is built and tested against a stand-in for Windows, but it hasn't run on real Windows yet, and the signed package it needs isn't released. On the installer you can download today the setting doesn't appear, and passkeys work through the browser extension.
:::

With the desktop app installed from its MSIX package, on Windows 11 24H2 (build 26100.6725) or 25H2 (build 26200.6725) or newer, Octa Pass can be a passkey provider for Windows, so sites and apps offer your Octa Pass passkeys in Windows' own dialog and in browser autofill.

1. In the app, open **Settings** and turn on **Use Octa Pass as a passkey provider**. It's off until you do, and it applies to this device only.
2. Windows asks for one more step: select **Open Windows Settings**, then turn on Octa Pass under **Accounts → Passkeys → Advanced options**.

Each time you create or use a passkey, **Windows Hello** asks for your face, fingerprint or PIN. Nothing skips this, not even an unlocked vault or the autofill setting, and a site can't ask for it to be skipped. If the vault is locked, it unlocks first, with Windows Hello where you've turned on device unlock, otherwise at the lock screen. If several accounts match, you pick one first.

Windows keeps a list of your passkeys' sites and user names on this device so it can offer them. The list holds no keys, it stays on this computer, and turning the provider off or signing out clears it. Turning the provider off doesn't delete any passkey.

## How the browser flow works

1. A small script in the page wraps `navigator.credentials.create/get` and forwards the request to the extension.
2. If you choose Octa Pass, the core checks that the requested `rpId` belongs to the page's origin: it must be the page's own domain or a parent domain you could register (so `login.example.com` can use `example.com`, but no page can use `co.uk` or `github.io`). Pages must use `https` (`http://localhost` is allowed for development), and a site embedded in another site's frame needs your permission first. It never signs for another site.
3. The core signs the challenge with the stored key (ES256 on P-256, or EdDSA) and returns a standard credential response. Attestation is `none`.
4. If you pick "use another device" or a hardware key, the request goes to the browser's built-in handler.

Passkeys are synced, so they're reported as backup-eligible and backed up (the WebAuthn BE and BS flags are set).

### The passkey prompt

When a site asks to make or use a passkey, the extension shows its prompt in the page. The site frames it but can't script it.

- **Header:** the site the passkey is for, by its relying party ID once that's been checked against the page's address, not whatever the page calls itself. **×** or **Escape** cancels.
- **Accounts:** to sign in, you see your accounts for that site, each with an avatar, the display name, the username and the title of the login the passkey is in. Use the arrow keys and **Enter**, or click. The account you picked shows a spinner while Octa Pass signs.
- **Footer:** **Use another device or security key** hands the request to your browser. **Cancel** ends it.
- While it loads, it shows the outline of what's coming. Then it fits its height to what it shows, between 200 and 520 pixels. It reports its size over a private channel the page can't read.
- It shows on top of a dialog the site has open, too.
- If Octa Pass is locked, the prompt asks for your master password first.

## What websites see

| Property | Value |
|---|---|
| Algorithm | ES256 (P-256), or EdDSA (Ed25519) when the site prefers it |
| Attestation | `none`, with the Octa Pass AAGUID `c9a07734-1d0b-4c72-8ff5-45e0daa2064f` so the site can label the passkey "Octa Pass" |
| Flags | User present, user verified, backup eligible, backed up |
| Signature counter | Always 0, like every synced passkey |
| Credential ID | 16 random bytes |
| Extensions | `credProps`, and `prf` (WebAuthn PRF) for passkeys made from November 2026 |

A new passkey is saved in the login for that site, or in a new login named after the site. The private key is stored only inside the login's encrypted details, in the standard PKCS#8 format, so it can be exported later.

## Unlocking Octa Pass with a passkey

Browsers that support the WebAuthn **PRF** extension can unlock your vault with an Octa Pass account passkey instead of typing your master password. This is planned for 1.0. See [biometric unlock](/docs/features/biometric-unlock/).

## PRF: keys a site derives from its passkey

Some sites use the WebAuthn **PRF** extension to get a secret from your passkey, for example to encrypt your data with it. Every passkey Octa Pass makes from November 2026 has its own PRF secret, kept in the login's encrypted details with the private key, so those sites work with a passkey kept in Octa Pass. Older passkeys sign in as before, without PRF.

The Octa Pass browser extension's own **Unlock with Touch ID** uses this too. On a Mac (macOS 15 or later) or an iPhone (iOS 18 or later), you can choose Octa Pass when the browser asks where to save that passkey. Octa Pass's AutoFill opens with Touch ID, Face ID or your master password, so it can still answer when the extension is locked. On a device where Octa Pass can't open by itself, save that passkey in Passwords or on a security key instead. On a computer with the Octa Pass app, the extension can also unlock through the app, with no passkey at all.

When you export to CXF, the PRF secret goes with the passkey as `hmacCredentials`, so it keeps working in another app that supports PRF.

## Moving passkeys between managers

Octa Pass imports and exports passkeys in the FIDO **Credential Exchange Format (CXF)**, as a file, so they keep working in the other app. The Credential Exchange Protocol (moving them app to app on Apple and Android, without a file) comes later. See [CXF](/docs/import-export/from-cxf/) and [export](/docs/import-export/export/). The Octa Pass encrypted export keeps passkeys too.

## Security dashboard

The [security dashboard](/docs/features/security-dashboard/) tells you when a site in your vault supports passkeys but you haven't created one. It uses the passkeys.directory dataset bundled with the app.
