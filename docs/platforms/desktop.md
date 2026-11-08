---
title: Desktop apps
description: The Octa Pass desktop apps, a native app on macOS with system AutoFill and a Tauri app on Windows and Linux with auto-type, device unlock, quick access, a tray icon and sharing.
status: in-progress
sidebar:
  order: 3
---

:::note[In progress]
The desktop apps are built for macOS, Windows and Linux, but they aren't released: there are no signed public downloads yet. You can [build them from source](/docs/contributing/development-setup/#build-the-apps). The native Mac app doesn't have auto-type, Wi-Fi or single sign-on yet, and Windows and Linux will move to native apps too.
:::

There are two desktop apps on the same Rust core:

- **On a Mac**, Octa Pass is a native SwiftUI app, built from the same screens as the iPhone and iPad app. See [the Mac app](#the-mac-app).
- **On Windows and Linux**, it's a Tauri 2 app that shows the web vault's screens. Its Rust side links the Octa Pass core directly, and the interface never holds encryption keys: it only receives the decrypted fields it asks for. Native apps will replace it there too ([plan 19](https://github.com/octapass/octapass/blob/main/plans/19-native-desktop-apps.md)).

The rest of this page, from [Features](#features), is about the Windows and Linux app unless it says otherwise.

## Platforms and packages

| OS | Package | Unlock |
|---|---|---|
| macOS 14+ | Native app and disk image, signed for development. Developer ID signing and notarising for public downloads aren't set up yet. | Touch ID or your Mac password |
| Windows 10/11 | NSIS installer. Code signing is planned. | Windows Hello |
| Linux | AppImage, .deb, .rpm. Flatpak and AUR packages are planned. | polkit (your system password or fingerprint), otherwise the master password |

## The Mac app

The Mac app has the iPhone and iPad app's screens in a Mac window: a sidebar, the item list and the item, with the editor in the window rather than a sheet. Settings is its own window (**Cmd+,**), and the menus have New login (**Cmd+N**), Search (**Cmd+F**), copying the username, password or code of the open login, and Lock (**Ctrl+Cmd+L**).

- **Unlock** with Touch ID or your Mac password, or the master password. **Stay unlocked while you're logged in** works as on the iPhone.
- **[AutoFill](#macos-autofill)** of passwords, passkeys and one-time codes in Safari and other apps, even when the app is closed.
- **[Safes](/docs/features/octa-pass-safe/) in Finder**, under Locations, while the vault is unlocked.
- **[One-time code links](#setting-up-one-time-codes-on-the-mac)** and **[Credential Exchange](#moving-from-another-password-manager-on-the-mac)** with other password managers.
- **Quick access** from the menu bar, and **open at login** (Settings → Running in the background).

- **The browser extension and the CLI unlock through the app**, with Touch ID or your Mac password: **Settings → Browser extension → Connect browser extension** once (see [supported browsers](#supported-browsers)), and a locked [`octapass`](/docs/platforms/cli/#unlocking-through-the-desktop-app) asks the app by itself.
- **The [SSH agent](/docs/features/ssh-keys/#ssh-agent)**, turned on in **Settings → SSH agent**. The app is sandboxed, so you point SSH at it yourself: Settings shows the lines for `~/.ssh/config`.

These three are new in the Mac app and haven't been tried with a real browser, terminal and SSH server yet.

Not in the Mac app yet: auto-type, Wi-Fi and single sign-on. They're being added ([plan 19](https://github.com/octapass/octapass/blob/main/plans/19-native-desktop-apps.md)).

The Mac app keeps its own vault store. If you used the earlier Tauri app on a Mac, sign in again in the new app: your account's items sync back. A [vault without an account](/docs/features/local-vault/) isn't moved over: export it from the old app first, and import it in the new one.

## Features

- **Quick access:** a global shortcut opens a search box to copy, fill or auto-type.
- **Runs in the background:** closing the window doesn't quit Octa Pass. An icon in the menu bar or system tray opens it, and it opens when you sign in to the computer. See [running in the background](#running-in-the-background).
- **Auto-type:** types your username and password into the focused app after checking that the window matches the item. See [auto-type](#auto-type).
- **One-time codes from QR codes:** on a login, **Add one-time code** reads a QR code from an image file or a pasted screenshot. See [adding a code](/docs/features/totp/#adding-a-code).
- **HTTP sign-in prompts** (a site's username-and-password pop-up) are filled by the [browser extension](/docs/features/autofill/#http-sign-in-prompts), not the desktop app: the app doesn't show websites.
- **[Wi-Fi](/docs/features/wifi/):** marks the network the computer is on and the ones in range, imports the networks it saved (with their passwords where Windows or NetworkManager give them), and offers to save a network when you join one.
- **[Sharing](/docs/features/sharing/) and [emergency access](/docs/features/emergency-access/):** the same screens as the web vault. See [sharing in the app](#sharing-in-the-app).
- **Stay unlocked while you're logged in** (on by default, Settings → Device auth): the app opens unlocked while you're logged in to the computer, keeping its key in Windows' data protection or the system keyring (Linux). No lock timer, and filling, revealing and copying don't ask. Without a running keyring on Linux it locks as usual. See [Stay unlocked](/docs/features/biometric-unlock/#stay-unlocked-while-youre-logged-in).
- **Browser unlock:** the app acts as a native messaging host, so the [browser extension](/docs/platforms/browser-extension/) can unlock with Windows Hello or polkit and share one unlock session. While the app stays unlocked, the extension opens through it without a prompt.
- **[SSH agent](/docs/features/ssh-keys/#ssh-agent):** serves SSH keys from your vault to `ssh`, Git and IDEs, asking you for each use. Off until you turn it on in Settings. The key editor also reads keys from `~/.ssh` and writes them back.
- **[CLI unlock](/docs/platforms/cli/#unlocking-through-the-desktop-app):** a locked `octapass` asks the running app, which confirms with Windows Hello or polkit. Locking the app locks it too.

- **[Windows 11 passkeys](/docs/features/passkeys/#windows-11):** a passkey provider for Windows, off by default. It needs the MSIX package, asks for Windows Hello for every passkey, and hasn't been tried on real Windows yet.

## Without an account

**Use on this device only**, on the first screen, keeps a vault on this computer with no account. See [use without an account](/docs/features/local-vault/) for backups, several vaults and Turn on sync.

**Ask on every fill** (Settings → Device auth) applies when **Stay unlocked** is off, and decides whether auto-type asks for Windows Hello or your system password each time. With it off they fill directly while the vault is unlocked; a locked vault always asks. A computer with no lock Octa Pass can use fills without a prompt while unlocked, and asks for the master password after a restart or a lock. Quick access copying isn't covered by this switch yet.

## Sharing in the app

Under **Sharing** you can make shared vaults, add people after comparing their fingerprint, change their role and remove them, run a family, make one-time share links, and choose emergency contacts. **Settings** lists your signed-in devices and your security log.

Everything is done in the app's own process, never in its window: vault keys are sealed to each person and signed there, a removed member's vault gets a new key there, and a released emergency key opens the other person's vaults there, read-only. The fingerprints you compare are computed from the keys the server returned, so a server that swapped someone's keys would show a different fingerprint, and a member whose keys change after you compared shows as not verified again.

A share link made in the app opens in the hosted web vault, or, on a self-hosted server, in the web vault that server serves (it names the server in the link). The key is only in the part after `#`, which browsers never send.

## Running in the background

Closing the vault window doesn't quit Octa Pass. It keeps running, so quick access, auto-type, the browser extension, the SSH agent and the CLI keep working. Locking works as before: with **Stay unlocked** off, the vault locks on your auto-lock timer whether the window is open or not; with it on, there's no timer.

- **Tray icon:** the Octa Pass icon in the system tray has **Show Octa Pass**, **Quick access**, **Lock** (while the vault is unlocked) and **Quit Octa Pass**. On Windows, clicking the icon shows the vault window. GNOME shows tray icons only with the AppIndicator extension, which Ubuntu includes.
- **Open at login:** Octa Pass starts when you sign in to the computer, in the background and without its window (locked, unless it stays unlocked). Opening it again from the Start menu or your app launcher shows the window of the copy that's running; it never starts a second one.
- **Quitting:** **Quit Octa Pass** in the icon's menu, or File → Quit on Windows, Vault → Quit Octa Pass on Linux.

Both are on by default. Turn either off in **Settings → Running in the background**; the choice is for this computer only. Opening at login is an entry in the system's own list, so you can turn it off there too:

| OS | Where the system lists it |
|---|---|
| Windows | Task Manager → Startup apps, or Settings → Apps → Startup |
| Linux | Your desktop's startup applications (the entry is `~/.config/autostart/app.octap.desktop.desktop`) |

Octa Pass turns opening at login on the first time an installed copy starts. If you turn it off, here or in the system, it stays off. If you move the app later, the entry follows it the next time Octa Pass starts.

On a Mac, **Settings → Running in the background → Open when I sign in to this computer** is offered once Octa Pass is in Applications. macOS lists it under System Settings → General → Login Items.

## Auto-type

Auto-type types a login into another app's window, for apps the browser extension can't reach. It's in the Windows and Linux app; the Mac app doesn't have it yet.

- **From quick access:** open it with **Ctrl+Shift+Space**, pick a login and press **Ctrl+Enter**, or click its keyboard button. Octa Pass goes back to the window you were in and types there.
- **With the auto-type shortcut:** in the app you want to sign in to, press `Ctrl+Shift+\`. If one login belongs to that window, Octa Pass types it. If none or several do, quick access opens with the matching logins; press Enter to type one.

By default Octa Pass types the username, Tab, the password and Enter. Password items type the password and Enter. You can change what's typed in the item's **Auto-type** section, with `{USERNAME}`, `{PASSWORD}`, `{TOTP}` (the current one-time code), `{TAB}`, `{ENTER}` and `{DELAY 500}` (wait 500 milliseconds, for slow apps). Other text is typed as it is.

Octa Pass types only into a window that belongs to the login:

- **In a browser,** the page must be on one of the login's websites, matched [like autofill](/docs/features/autofill/#domain-matching). Page titles don't count, because a phishing page can copy them. Windows and Linux don't tell Octa Pass the page's address, so add the window to the login's auto-type windows instead, or use the [browser extension](/docs/platforms/browser-extension/).
- **In other apps,** the window title or the app's name must contain the login's title, or the name of its website (`slack` for slack.com).
- **Auto-type windows** you list on the login always count. A rule like `Slack` matches any window whose title or app name contains it; `*` stands for any text, as in `*Remote Desktop*`.

It never types into Octa Pass itself or while the screen is locked, it waits until you let go of the shortcut's keys, and it stops if another window takes focus while it types. Characters that aren't on your keyboard, like `é` or `ب`, are typed too.

| OS | How it types | What you need |
|---|---|---|
| Windows | `SendInput` | Nothing. Windows doesn't let apps type into apps running as administrator. |
| Linux (X11) | XTest | Nothing |
| Linux (Wayland) | The RemoteDesktop portal | Allow Octa Pass in the desktop's dialog, once each time Octa Pass starts. Wayland doesn't say which window is focused, so only a login you pick in quick access is typed, and the auto-type shortcut opens quick access. Without the portal, Octa Pass copies the password instead and clears the clipboard after 30 seconds. |

## macOS AutoFill

This and the next two sections are about the [Mac app](#the-mac-app).

On macOS 14 and later, Octa Pass fills passwords and passkeys in Safari and other apps through the system's AutoFill, and one-time codes on macOS 15. Turn it on in System Settings → General → AutoFill & Passwords → **AutoFill from** (on macOS 14: Passwords → Password Options). If Octa Pass isn't in that list, move the app to Applications and open it once. The app's **Settings → AutoFill** turns it on too (on macOS 15 it asks in place). A build you make yourself needs to be signed by an Apple developer team (see [building the apps](/docs/contributing/development-setup/#build-the-apps)); `pnpm build:macos` uses the team your iPhone builds sign with.

The AutoFill extension works as on the iPhone: it opens the vault the app keeps on this Mac, so it fills even when the app is closed, and it never uses the network. It asks for Touch ID, your Mac password or the master password, or nothing while **Stay unlocked** is on. It gets only the password, code or passkey you picked. New passkeys are saved to your vault before the site gets them.

### Setting up one-time codes on the Mac

On macOS 15 and later, Octa Pass can be the app that opens one-time code setup links (`otpauth://`) and their QR codes. In System Settings → General → AutoFill & Passwords → **Set up codes in**, choose **Octa Pass**. After that, a site's "set up authenticator" link opens Octa Pass, and so do Google Authenticator exports (`otpauth-migration://`).

Octa Pass asks before it adds anything, because any website can open such a link. When the vault is locked, it asks you to unlock first. Then you choose where each code goes, as for a scanned QR code: a code that matches a login joins it, and for the others you search your logins or keep the code as an item of its own (see [linking a code to a login](/docs/features/totp/#linking-a-code-to-a-login)). Several links opened together, like the parts of a Google Authenticator export, are reviewed together. AutoFill then offers the code in verification-code fields.

### Moving from another password manager on the Mac

On macOS 26, password managers can hand their items to each other directly through Credential Exchange, in the [FIDO Credential Exchange Format](/docs/import-export/from-cxf/), with no file. In the other app (for example the Passwords app's **File → Export Data to Another App**), choose **Octa Pass**. Octa Pass comes forward, asks you to unlock if it's locked, and shows how many items the app sent. Nothing is saved until you choose **Import**; the items go into your Personal vault. Cancel, or lock Octa Pass, and they're forgotten.

If the other app says no app can receive your data, open Octa Pass once from Applications, so macOS knows about it.

## Supported browsers

The browser extension can unlock through the app in these browsers, installed from their makers:

- Google Chrome (and Beta, Dev, Canary)
- Microsoft Edge (all channels)
- Brave (all channels)
- Firefox (all channels)
- Vivaldi
- Opera
- Arc

The app checks which program asks before it answers: only the `octapass-native-host` inside the app, signed by the same developer team, started by one of these browsers. On the Mac and on Windows the browser must carry its maker's code signature; on Linux it must be installed system-wide (owned by root), so browsers installed in your home folder, and Snap or Flatpak browsers, aren't accepted. Chromium has no maker's signature, so it isn't accepted on the Mac or Windows.

In any other browser the extension says *The Octa Pass app doesn't recognise this browser, so it can't unlock it*. Unlock with your master password there instead. Safari's extension can't reach the app at all (see [Safari](/docs/platforms/browser-extension/#safari)).

## Updates

There's no automatic update yet: install a new build over the old one. Signed updates inside the app, and package repositories on Linux, are planned for 1.0.

## Master password

**Settings → Security → Master password** changes it: enter the current password and the new one. Your Secret Key and recovery code stay the same, your other devices are signed out, and Touch ID, Windows Hello or polkit unlock has to be turned on again.

Changed it on another device? On the Mac, unlock with the new password: the app signs in again by itself, with nothing to sign out of first. The old password no longer opens it while the Mac is online.

Forgot it? **Forgot your master password?** on the sign-in and lock screens resets it with the recovery code from your [Recovery Kit](/docs/getting-started/recovery-kit/): we email you a code, then you enter your recovery code and a new password and save the new Recovery Kit. See [account recovery](/docs/security/account-recovery/).
