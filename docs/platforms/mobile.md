---
title: Mobile apps
description: The Octa Pass apps for iPhone, iPad and Android, with system autofill, passkey providers, Wi-Fi Connect, QR codes and Face ID or fingerprint unlock.
status: in-progress
sidebar:
  order: 4
---

:::note[In progress]
The iPhone and Android apps are built but not released (the public beta isn't open yet). They run in the iOS Simulator and the Android emulator; there are no App Store or Google Play builds yet.
:::

## iPhone app preview

- **The native app:** the iPhone and iPad app is being rebuilt in SwiftUI with the same screens and words as the Android app. On iPad, the vault's lists sit in a sidebar next to the list and the open item.
- **Your vault:** sign up or sign in, add and edit every item type, one-time codes, the password generator, the security dashboard and the trash, synced with your server and usable offline.
- **Unlock with Face ID, Touch ID or your passcode** after you've unlocked once with your master password: Octa Pass offers it right after you sign up or sign in, and AutoFill uses it too. Octa Pass still asks for the master password every 14 days.
- **Stays unlocked while your iPhone is unlocked** (on by default): the app and AutoFill open without Face ID; revealing and copying don't ask while the app is unlocked. It needs a passcode. See [Stay unlocked](/docs/features/biometric-unlock/#stay-unlocked-while-youre-logged-in).
- **AutoFill:** passwords, passkeys and one-time codes in Safari, Chrome and other browsers and apps, from the QuickType bar or the key icon. With Stay unlocked on, a password or code you pick in the QuickType bar fills straight away; with it off, the extension unlocks with Face ID or your passcode. If the login you picked is gone, it shows the logins for that site instead. It works offline; passkeys you create there reach your other devices the next time you open the app.
- **[Wi-Fi](/docs/features/wifi/):** Wi-Fi networks have their own category. **Connect** joins one from the app, **Show as QR code** shows a code other phones join from, and scanning a router's Wi-Fi QR code adds the network. With location access (asked when you open Wi-Fi), the network you're on shows **Connected**; iOS doesn't let apps see the networks in range. When you open the app on a network that isn't in your vault, Octa Pass offers to save it. iOS doesn't let apps read the networks it saved.
- **[QR codes](/docs/features/qr-codes/):** show logins, contacts, notes and Wi-Fi as QR codes, and scan QR codes to add Wi-Fi networks, one-time codes and contacts.
- **[Files](/docs/features/attachments/#on-your-phone):** attach files, photos and camera shots to any item, or make Document items, offline too. Files open in Quick Look, which can share them.

## Android app preview

- **Your vault:** the same screens and features as the iPhone app, synced with your server and usable offline.
- **Stays unlocked while your phone is unlocked** (on by default): the app and autofill open without a prompt; revealing and copying don't ask while the app is unlocked. It needs a screen lock. See [Stay unlocked](/docs/features/biometric-unlock/#stay-unlocked-while-youre-logged-in).
- **Unlock with your fingerprint or face, or your screen-lock PIN, pattern or password** after you've unlocked once with your master password. Octa Pass still asks for the master password every 14 days, and enrolling a new fingerprint or face stops device unlock until you turn it on again with your master password.
- **Autofill in other apps and browsers:** tap a sign-in field and pick **Octa Pass** in the keyboard's suggestions (Android 11+) or the dropdown. With Stay unlocked on (the default), Octa Pass fills the login saved for that app or website without asking; with it off, it asks for your fingerprint or screen lock first. Sign-up and change-password forms also get a **Suggested password**, made on your phone, and Android offers to save passwords you type. Saving doesn't ask you to unlock: Octa Pass shows **Saved to Octa Pass**, keeps the login sealed on your phone, and adds it to your vault the next time you unlock the app or autofill ([how](/docs/features/autofill/#saving-while-octa-pass-is-locked)).
- **Credential Manager (Android 14+):** apps that use Credential Manager show your Octa Pass logins and passkeys in the system sheet. An app can use a website's passkeys only when that website lists the app in its [Digital Asset Links](https://developers.google.com/digital-asset-links); browsers vouch for the website themselves.
- **[Wi-Fi](/docs/features/wifi/):** **Connect** saves the network to your phone after Android asks you to confirm (Android 11+; Android doesn't let apps add WEP networks). With location access, the list shows **Connected** and **In range** with the signal, the networks in range first. Android doesn't let apps read saved Wi-Fi passwords: open a network in Settings, tap **Share**, and scan the QR code Android shows. **Show as QR code** and the QR scanner work as on the iPhone.
- **Other password managers:** import from, or export to, another password manager on the phone without a file. See [below](#moving-between-password-managers-on-android).
- **[Files](/docs/features/attachments/#on-your-phone):** as on the iPhone, from the document picker, the system photo picker or the camera. Files open in the app you choose for them, or the share sheet when none views them.
- **Screenshots are blocked** in the app and on its autofill screens, and the app shows as a blank card in Recents.

Passkeys, logins and passwords you save from autofill are stored on your phone first and reach your other devices the next time you open the app.

## On both phones

The apps behave like the other apps on your phone, not like a web page:

- **Your master password:** change it in **Settings → Security → Master password**. If you forget it, **Forgot your master password?** on the sign-in and lock screens resets it with the recovery code from your [Recovery Kit](/docs/getting-started/recovery-kit/) and shows your new kit. Your vault stays as it is, and your other devices are signed out.
- **Text size follows your phone's setting** (Dynamic Type on iPhone, Font size on Android) instead of pinch-zooming. The screens never zoom, also not when you tap into a field.
- **Screens slide** in when you go deeper (an item, its editor, a Settings page) and back out when you go back, unless you've turned on Reduce Motion, which fades them instead. On iPhone, swipe from the left edge (the right in Arabic) to go back; on Android, use the system's back gesture or button.
- **Menus and dialogs open as sheets** from the bottom of the screen. Tap outside a sheet to close it.
- **The keyboard** pushes the screen up instead of covering the field you're typing in, and the tab bar hides while it's open.
- **You feel copies, saves and deletes** as a short vibration, when your phone's haptics are on.
- **Exports** open the share sheet, so you can save the file to Files (iPhone), your downloads or Drive (Android), or send it to another app. The file is removed from the app's own storage when the sheet closes. A plain JSON or CSV export isn't encrypted: keep it somewhere safe and delete it when you're done.
- **The status bar** follows the app's theme (Settings → Appearance), also when it differs from your phone's.
- Only text you'd want to copy, such as an item's values and notes, can be selected. Buttons and lists don't select or show the long-press menu.

## On your watch

Apple Watch and Wear OS apps show the one-time codes your phone sends them, off until you turn them on in Settings. The watch never holds your secrets: see [one-time codes on a watch](/docs/features/watch/).

## Requirements

| Platform | Minimum | Autofill | Passkeys | One-time codes |
|---|---|---|---|---|
| iOS / iPadOS | 17 | System AutoFill provider | Yes | iOS 18+ |
| Android | 9 | Autofill Framework, inline keyboard suggestions on 11+ | Android 14+ (Credential Manager) | Yes |
| Apple Watch | watchOS 10, with the iPhone app | n/a | n/a | [Shows codes from the iPhone](/docs/features/watch/) |
| Wear OS | Wear OS 3, with the Android app | n/a | n/a | [Shows codes from the phone](/docs/features/watch/) |

## How the apps are built

- The apps are fully native: SwiftUI on the iPhone and iPad, Jetpack Compose on Android, with the same screens and words as the web vault, on one Rust API (`OctaPassVault`) that does all the vault's work. They replaced the earlier Tauri 2 apps, which showed the web vault's screens in a web view.
- **The native Android app** (`apps/android` in the repository, not released yet) has every feature the earlier app had: sign-up with the Recovery Kit, sign-in with two-step sign-in, unlock with your fingerprint, face or screen lock, the item list with its Sort and group menu and website rows, every item type, files, Wi-Fi Connect, QR codes, the generator, Health, masked email, settings in English and Arabic, sharing, families, share links and emergency access, [SSH keys](/docs/features/ssh-keys/) and [environments](/docs/features/environments/), and QR scanning where one-time codes are reviewed before they join a login. It uses the brand's fonts (Mona Sans, and Monaspace Neon for passwords and codes), follows Android's font size, dark theme and right-to-left layout, uses predictive back, and puts the item beside the list on tablets. Other apps' autofill services can't see its fields.
- The **autofill extensions are native and small**, written in Swift and Kotlin, and call the same Rust core. iOS gives credential extensions only about 120 MB of memory, so they have to be lightweight.
- The app and its extension share the encrypted store through an App Group on iOS, and the app's private storage on Android.

## Without an account

**Use on this device only** keeps a vault on the phone with no account. Autofill works from it as from an account. See [use without an account](/docs/features/local-vault/) for backups, several vaults and Turn on sync.

## Turning on autofill

Octa Pass shows **Turn on AutoFill** on the item list until it's on, and **Settings → AutoFill** shows whether it's on.

- **iOS:** on iOS 18 and later, **Turn on** asks right there. On iOS 17 it opens Settings → General → AutoFill & Passwords, where you turn on **Octa Pass**.
- **Android:** **Turn on** opens the system's choice of Autofill service with Octa Pass selected. On Android 14+, the **Passwords and passkeys** row opens Settings → Passwords, passkeys & accounts, where you turn on **Octa Pass** for passkeys and Credential Manager.

## Setting up one-time codes on the iPhone

Octa Pass can be the app that opens one-time code setup links (`otpauth://`) and their QR codes. Go to Settings → General → AutoFill & Passwords → **Set Up Codes In** and choose **Octa Pass**, or tap **Open Settings** next to **Set up codes in Octa Pass** in Octa Pass's Settings. After that:

- tapping a site's "set up authenticator" link, or the Camera app's button on its QR code, opens Octa Pass;
- Google Authenticator export QR codes (`otpauth-migration://`) open Octa Pass too.

Octa Pass asks before it adds anything, because any website can open such a link. Then you choose where each code goes, as for a scanned QR code: a code that matches a login joins it, and for the others you search your logins or keep the code as an item of its own (see [linking a code to a login](/docs/features/totp/#linking-a-code-to-a-login)). Several links opened together, like the parts of a Google Authenticator export, are reviewed together. AutoFill then offers it in verification-code fields (iOS 18+).

## Moving between password managers on Android

Android lets password managers hand their items to each other directly, through Credential Manager and the [FIDO Credential Exchange Format](/docs/import-export/from-cxf/). Google Play services shows the list of apps and passes the items between the two apps; no file is saved.

- **Import into Octa Pass:** go to **Settings → Other password managers → Import from another app** and tap **Choose app**. Pick the app (for example Google Password Manager) and confirm in that app. Octa Pass then shows what it sent, by kind (logins, passkeys, cards, …), and what can't come across. Nothing is saved until you tap **Import**; the items go into your Personal vault. Cancel, or lock Octa Pass, and they're forgotten.
- **Export from Octa Pass:** start the import in the other app and pick **Octa Pass** (it shows the email of the account you're signed in to). Octa Pass names the app that asked and asks for your **master password**, as every export does. The other app only gets the kinds of items it asked for. Octa Pass is on that list while you're signed in, and leaves it when you sign out.

What comes across is what CXF holds: logins with their passkeys and one-time codes, notes, cards, identities and Wi-Fi networks. Password history, recovery info and attached files stay behind.

This needs Google Play services 25.38 or later; Octa Pass doesn't offer it on phones without them. Android's credential transfer works from Android 8, and Octa Pass from Android 9. Both directions were checked on the Android 17 emulator (Google Play image) between Octa Pass and a test app; moving to and from Google Password Manager itself needs a phone signed in to a Google account and hasn't been tried yet.

## Moving between password managers on the iPhone

On iOS 26, password managers hand their items to each other directly through Credential Exchange, in the [FIDO Credential Exchange Format](/docs/import-export/from-cxf/). The system shows the list of apps and passes the items between them; no file is saved.

- **Import into Octa Pass:** in the other app (for example Settings → Apps → Passwords), choose **Export Data to Another App**, then **Octa Pass**. Once you unlock, Octa Pass shows what the app sent, by kind (logins, passkeys, cards, …). Nothing is saved until you tap **Import**; the items go into your Personal vault. Cancel, or lock Octa Pass, and they're forgotten.
- **Export from Octa Pass:** go to **Settings → Other apps → Export to another app**, enter your **master password**, as every export asks, and pick the app in the system's list. The other app gets everything in your vault except attached files.

The same Rust code reads what comes in on the iPhone and on Android, so both show the same review.


## More in both apps

- Add one-time codes from a QR code with the camera or from a photo, including every account in Google Authenticator's export QR codes (see [adding a code](/docs/features/totp/#adding-a-code))
- "Save to Octa Pass" from the share sheet
- Screenshots blocked on sensitive screens (Android), and the app is blurred in the app switcher (iOS)
- [Face ID, Touch ID and Android biometrics](/docs/features/biometric-unlock/)
- Safari extension on iOS
- Apple Watch and Wear OS apps for TOTP codes (planned for 1.0)
