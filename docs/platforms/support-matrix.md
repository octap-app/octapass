---
title: Platform support matrix
description: Which browsers, operating systems and devices Octa Pass supports today, with autofill, passkey, one-time code and unlock capabilities, and what each app can do.
status: in-progress
sidebar:
  order: 1
---

:::note[In progress]
This page shows what's built, as of 2026-11-11. Built doesn't mean released: the browser extension is in the [Chrome Web Store](https://chromewebstore.google.com/detail/octa-pass/jainmncaocgdhknhcjkdbbbmahllbjol) and on [Firefox Add-ons](https://addons.mozilla.org/firefox/addon/octa-pass/), and the other apps aren't in a store yet. The web vault is open as a public alpha at [vault.octap.app](https://vault.octap.app). See the [roadmap](/docs/reference/roadmap/).
:::

## Platforms

| Platform | App | Password autofill | Passkeys | One-time codes | Unlock | State |
|---|---|---|---|---|---|---|
| Chrome, Edge, Brave, Opera, Vivaldi, Arc | [Browser extension](/docs/platforms/browser-extension/) (MV3) | Yes, in the page | Yes, WebAuthn | Fill and copy | Password, device passkey, desktop app | In the Chrome Web Store (Edge installs from it too) |
| Firefox 140+ (142+ on Android) | Browser extension (MV3) | Yes | Yes | Fill and copy | Password, desktop app | On Firefox Add-ons |
| Safari 18+ (macOS, iOS, iPadOS) | Safari Web Extension inside its own app | Yes | Yes, with the [system provider](/docs/features/passkeys/) | Yes | Password | Built. Not yet checked in Safari itself, only in WebKit's extension runtime |
| Web vault | Web app | No (view and copy) | No | View and copy | Password, device passkey | Built |
| macOS 14+ | Native [Mac app](/docs/platforms/desktop/#the-mac-app) + AutoFill provider | Yes, system-wide | Yes, system provider | Yes (macOS 15+) | Touch ID, Mac password | Built, development builds only, not notarised |
| Windows 10/11 | Desktop app (Tauri) | Partial: extension + auto-type | In the browser. System-wide on Windows 11 with the MSIX package: [built, off by default](/docs/features/passkeys/#windows-11), not yet tried on real Windows | Auto-type and copy | Windows Hello, including its PIN | Built, not signed |
| Linux (X11, Wayland) | Desktop app (Tauri): AppImage, .deb, .rpm | Partial: extension + auto-type | In browsers only | Yes | polkit, otherwise password | Built. Flatpak and AUR planned |
| iOS / iPadOS 17+ | Native [iPhone and iPad app](/docs/platforms/mobile/) + AutoFill provider | Yes, system AutoFill | Yes | Yes (iOS 18+) | Face ID, Touch ID, passcode | Built, Simulator and development builds only |
| Android 9+ | Native Android app + Autofill and Credential Manager services | Yes, with inline keyboard suggestions on 11+ | Yes (Android 14+) | Yes | Fingerprint, face or screen lock | Built, emulator and development builds only |
| Apple Watch (watchOS 10+) | [Watch app](/docs/features/watch/), with the iPhone app | n/a | n/a | Shows codes the iPhone sends | The watch's passcode | Built, not tried on a watch |
| Wear OS 3+ | [Watch app](/docs/features/watch/), with the Android app | n/a | n/a | Shows codes the phone sends | The watch's screen lock | Built, not tried on a watch |
| Terminal | [CLI](/docs/platforms/cli/) | n/a | n/a | `octapass totp` | Password, keyring session | Built, preview |

"Partial" means the operating system has no general autofill API for third-party password managers, so Octa Pass uses the best available workaround. See [autofill](/docs/features/autofill/).

The phone apps are native: SwiftUI on the iPhone and iPad, Jetpack Compose on Android. They replaced the earlier Tauri phone apps, which showed the web vault's screens in a web view and were removed on 2026-11-05. On a Mac, Octa Pass is a native SwiftUI app too, built from the iPhone and iPad app's screens; it replaced the Tauri app there on 2026-11-06. The Tauri desktop app stays on Windows and Linux.

## What each app can do

The two native columns are the apps that will ship in the stores. The Mac app is built from the iPhone and iPad app's screens; what it doesn't have yet is listed under [the Mac app](/docs/platforms/desktop/#the-mac-app).

| Feature | Web vault | Extension | Desktop (Windows, Linux) | Native iPhone, iPad | Native Android | CLI |
|---|---|---|---|---|---|---|
| Logins, cards, identities, notes, documents, Wi-Fi | Yes | Yes | Yes | Yes | Yes | Read, except [environments](/docs/features/environments/) |
| [Environments](/docs/features/environments/) | Yes | Yes | Web screens | Yes | Yes | Yes |
| [SSH keys](/docs/features/ssh-keys/) | Yes | Public key only | Yes, with the SSH agent | Yes | Yes | Yes |
| [Attachments](/docs/features/attachments/) | Yes | Yes, with an account | Yes | Yes | Yes | No |
| Add one-time codes from a [QR code](/docs/features/qr-codes/) | Image file | Page, image | Image | Camera, photo, file | Camera, photo, file | No |
| Show items as QR codes | Wi-Fi only | No | Wi-Fi only | Yes | Yes | No |
| [Wi-Fi](/docs/features/wifi/) Connect | No | No | No | Yes | Yes | No |
| [Security dashboard](/docs/features/security-dashboard/) | Yes | Yes | Yes | Yes | Yes | No |
| [Masked email](/docs/features/masked-email/), with turning aliases off and deleting them | 4 of 6 providers | Yes | Yes | Yes | Yes | No |
| [Sharing and families](/docs/features/sharing/) | Yes | Yes | Yes | Yes | Yes | Read |
| [Emergency access](/docs/features/emergency-access/) | Yes | Yes | Yes | Yes | Yes | No |
| [Two-step sign-in](/docs/features/two-step-sign-in/) settings | Yes, with security keys | Yes | Yes | Yes | Yes | Sign-in only |
| Change the master password | Yes | Yes | Yes | Yes | Yes | Yes |
| Reset it with the recovery code | Yes | Yes | Yes | Yes | Yes | Yes |
| [Import](/docs/import-export/overview/) and [export](/docs/import-export/export/) | Yes | Yes | Yes | Yes | Yes | Yes |
| [Use without an account](/docs/features/local-vault/) | No, by design | Yes | Yes | Yes | Yes | No |
| Arabic, right to left | Yes | Yes | Yes | Yes | Yes | No |
| [Apple Watch and Wear OS codes](/docs/features/watch/) | n/a | n/a | n/a | Yes, off by default | Yes, off by default | n/a |
| [Developer toolkit](/docs/features/developer-toolkit/) | Yes | Yes | Yes | Some tools | Some tools | Yes |
| [Octa Pass Safe](/docs/features/octa-pass-safe/) | No | No | Yes | Yes | Yes | Yes |

The Windows passkey provider is built and off by default, but hasn't run on real Windows yet. What's still missing before 1.0 is on the [roadmap](/docs/reference/roadmap/#not-built-yet).
