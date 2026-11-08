---
title: Biometric unlock
description: Unlock Octa Pass with Face ID, Touch ID, fingerprint, Windows Hello, or your device passcode, PIN or password, using hardware-backed keys on trusted devices.
status: in-progress
sidebar:
  order: 11
---

:::note[In progress]
Device unlock is built in the web vault, the browser extension, the desktop apps and the iPhone, iPad and Android apps. Still missing: the **Ask on every fill** switch in the phone apps (see [two device-auth settings](#two-device-auth-settings)).
:::

Biometrics **unlock a key stored on that device**. They never replace your master password on a new device, and your fingerprint or face data never reaches Octa Pass.

## How it works

When you turn on biometric unlock, your device wraps your account key with a **hardware-backed key** that can be used only after a successful biometric check. Unlocking with biometrics releases that key; locking erases the unwrapped account key from memory.

| Platform | Protection |
|---|---|
| iOS, macOS | Secure Enclave key that requires the current biometric set. Enrolling a new face or fingerprint invalidates it, so you'll need your master password once. |
| Android | Android Keystore key that requires user authentication and is invalidated by new biometric enrolment. Uses StrongBox when available. Class 3 biometrics only. On Android 9 and 10 the key is usable for a few seconds after your fingerprint or screen lock, because those versions can't tie both to a single use. |
| Windows | Windows Hello key in the TPM |
| Linux | Master password. The desktop app can optionally use the system keyring with polkit. |

## Web vault

In the web vault, **Settings → Security → Unlock with this device** uses the lock your device already has: Touch ID on a Mac, Windows Hello on Windows (face, fingerprint or its PIN), Face ID or the passcode on an iPhone or iPad. If there's no biometric, your device's own PIN, passcode or computer password works.

- It creates a **passkey on this device** for the web vault and uses the WebAuthn **PRF** extension to get a secret that only that passkey can produce. Your account key is wrapped with a key derived from it and stored in this browser. Nothing new is sent to the server.
- It works **per browser** and is never synced. Turning it off, signing out or deleting your account removes it.
- The lock screen starts the device prompt by itself, and **Use master password** is always there.
- Your **master password is still required every 14 days**, so you don't forget it.
- Browsers without PRF support keep using the master password. Chrome, Edge, Safari 18+ and Firefox 139+ on macOS 15+ have it; see [device unlock in each browser](/docs/platforms/browser-extension/#device-unlock-in-each-browser).
- Turning it on takes one prompt where the browser gives the key while creating the passkey (Safari, Firefox), and two elsewhere. If the browser turns the second down, **Finish with** finishes it with one more click.
- When a prompt fails, the message shows what your browser said, so you can tell a dismissed prompt from a real problem.

## Browser extension

The extension can unlock with:

- Your master password
- The [desktop app](/docs/platforms/desktop/) over native messaging, which then handles Touch ID or Windows Hello
- A passkey with the WebAuthn PRF extension, in Chrome and Edge. Not in Firefox yet: see below.

## Device passcode, PIN or password

No Face ID or fingerprint reader? Octa Pass uses **the same lock you already use for your device**:

| Device | Quick unlock options |
|---|---|
| iPhone, iPad | Face ID or Touch ID, or your **device passcode** |
| Mac | Touch ID or Apple Watch, or your **Mac login password** |
| Android | Fingerprint or face, or your **screen-lock PIN, pattern or password** |
| Windows | Windows Hello face or fingerprint, or your **Windows Hello PIN** |
| Linux | Your **system password** (or fingerprint where set up) |
| Web vault and browser extension | A passkey for this device, which uses any of the above |

There's no separate Octa Pass PIN to remember. Your device already limits wrong attempts with its security chip, which makes this safer than an extra app PIN would be.

- In the phone and desktop apps, Octa Pass offers it right after you sign up or sign in ("Use Face ID to unlock Octa Pass?"). **Turn on** runs your device's check once. If you choose **Not now**, it asks once more the next time you unlock with your master password, and then never again.
- You can always turn it on or off in **Settings → Security** after unlocking with your master password. It works per device and isn't synced.
- On a phone, AutoFill uses it too: with it on, the AutoFill sheet asks for Face ID, your fingerprint or your passcode instead of your master password.
- Your master password is still needed every 14 days, and after you change it.
- If a device has no screen lock at all, see the next section.

## Stay unlocked while you're logged in

**Settings → Security → Device auth → Stay unlocked while you're logged in to this device.** On by default in the desktop app, the iPhone and Android apps and the browser extension. It's per device and never synced, and the web vault doesn't have it.

While it's on, Octa Pass opens unlocked whenever your device is unlocked, the way your browser's saved passwords do:

- **Opening and filling don't ask.** AutoFill on your phone, auto-type and AutoFill on your computer, and the extension's fills work without a prompt. There's no lock timer, and Octa Pass doesn't lock when it goes to the background or your computer locks.
- **Revealing and copying don't ask** while Octa Pass is unlocked ([Revealing and copying](#revealing-and-copying)).
- **Some things always ask:** exporting, saving a private key or `.env` file, your Secret Key, your Recovery Kit and recovery code, changing or resetting your master password, rotating keys and deleting your account.
- **Your master password every 14 days stays.** When it's due, Octa Pass asks for it once, then stays unlocked again.
- **Lock now** still locks. Octa Pass stays locked until you unlock it, or until the app or browser starts again.

Under the switch, Settings says what it means: "Anyone who can use this device while it's unlocked can open Octa Pass, fill your logins and see your passwords." The two settings below show greyed out while it's on, and come back as you left them when you turn it off.

It needs a lock on your device. Without one, Octa Pass locks as before and Settings says why:

| Device | Where Octa Pass keeps the key | Locks as usual when |
|---|---|---|
| iPhone, iPad | The Keychain, only while the phone has a passcode, shared with AutoFill | There's no passcode ("Set a passcode on this device to stay unlocked.") |
| Android | The Android Keystore, usable only while the phone is unlocked | There's no screen lock ("Set a screen lock on this device to stay unlocked.") |
| Mac | The Keychain, for this app | Never in practice |
| Windows | Windows' own data protection for your user account | Never in practice |
| Linux | The system keyring (Secret Service) | No keyring is running ("No system keyring found, so Octa Pass locks as usual.") |
| Browser extension | Nowhere on disk. With the desktop app staying unlocked, the extension opens through it. On its own, it stays unlocked in memory until the browser closes | After a browser restart without the desktop app: one normal unlock |

Changing your master password, rotating your Secret Key, resetting your password or signing out deletes the key; the next time you unlock, Octa Pass makes a new one. A locked or switched-off device still holds only encrypted data. See [what this means for security](/docs/security/threat-model/).

**If you already used Octa Pass:** if you had kept any lock settings on that device (Octa Pass can't tell whether you picked the defaults yourself), it keeps locking as before, and you can turn this on in Settings. The extension can tell, so it only keeps locking if you changed its lock settings.

## Two device-auth settings

Device auth has its own gates, both **per device** and never synced, in **Settings → Security → Device auth**. They apply when **Stay unlocked** is off:

- **Use device auth when Octa Pass opens** (on by default). Where your device has a lock, opening asks for it. Off, opening asks for your master password instead.
- **Ask on every fill** (on by default). Each autofill asks for your device's lock. Off, Octa Pass fills directly while the vault is unlocked, with a warning that anyone using the device can fill your logins. A locked vault always asks at least once.

### Revealing and copying

An open vault is enough. While Octa Pass is unlocked, revealing and copying a password or another field, showing an item as a QR code, and showing an SSH key or an environment's values don't ask, however Octa Pass was opened: with your device's lock, your master password, or **Stay unlocked**, and whatever the switches below say. Once Octa Pass locks (by auto-lock, by locking when it goes to the background, or with **Lock now**), unlocking it again is the only prompt.

Some things always ask, however you unlocked: exporting your vault, saving a private key or an `.env` file, showing your Secret Key or recovery code, changing or resetting your master password, rotating keys, and deleting your account. Asking means your device's lock where it's set up, your master password otherwise.

In the native iPhone, iPad and Android apps the first switch is there too, and the same rules apply. The **Ask on every fill** switch isn't in the phone apps yet: there, with **Stay unlocked** off, AutoFill keeps asking for your device's lock or your master password each time.

On a device with no lock Octa Pass can use, there is nothing to verify with, so opening an already-unlocked vault and filling don't ask (the same behaviour as Chrome's password manager). After a restart or a lock, the master password opens the vault. Exporting and your Secret Key still need the master password each time, and the web vault never offers a gateless mode.

## Browser extension PRF

In Chrome and Edge, **Settings → Security → Unlock with this device** in the extension makes **a passkey for the extension itself** and uses its WebAuthn PRF output, as the web vault does. The PRF output unwraps the account key inside the service worker. It's there for a signed-in account, not for a vault on this device only, and it hasn't been tested on a real device yet.

**Firefox can't do this yet.** Firefox lets an extension use passkeys only for a website it has access to, not for the extension itself, so the same request fails there with "SecurityError: The operation is insecure". In Firefox, Settings → Security says so and links to the [desktop app](/docs/platforms/desktop/), which unlocks the extension with Touch ID or Windows Hello. Touch ID still works in the [web vault](#web-vault) in Firefox.

The desktop app over native messaging is the fallback in every browser, then the master password.

## Auto-lock

With **Stay unlocked** off, choose a lock timer, and lock on sleep or screen lock. While it's on, those settings show greyed out. The clipboard is cleared automatically after copying a secret either way. An organisation's maximum lock time turns **Stay unlocked** off on that device.
