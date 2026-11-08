# 18 — Stay unlocked while you're logged in

**Status: built (2026-11-05)** in the desktop app, the browser extension and the iPhone and Android apps (with their AutoFill extension and services). Plan 03 is updated (*Stay unlocked while logged in*, the unlock table, the two gates, the threat table). The History below lists every rule decided while building.

**Decision (maintainer, 2026-11-05):** Octa Pass gets a per-device setting, **"Stay unlocked while you're logged in to this device"**, **on by default**. When the device is unlocked (logged in to the computer, phone unlocked), Octa Pass opens unlocked with no prompt, the way Chrome's saved passwords work. Revealing and copying don't ask while the vault is open (2026-11-06, replacing "ask once", History); the high-risk actions keep asking every time; the 14-day master password check stays.

**Why:** a locked vault gets in the way of everyday use. The extension locks after 15 idle minutes and whenever the computer locks (`apps/extension/src/background/autoLock.ts`). While it's locked it can't offer to save, update, or notice that a login is already saved (plan 05 History, 2026-11-05: the locked-save inbox), and every unlock is one more prompt. Google Password Manager has no lock of its own and is unlocked whenever the user is logged in. 1Password locks, but unlocking costs one touch through its desktop app.

## The rules

1. **Stay unlocked (default on, per device, never synced).**
   - **On:** a logged-in, unlocked device opens Octa Pass unlocked, and filling doesn't ask.
   - **Off:** today's behaviour comes back: the lock timer, locking on system lock, and the two device-auth gates in plan 03.
2. **Reveal and copy don't ask** while the vault is open (maintainer decision, 2026-11-06, plan 03). This replaced "reveal and copy ask once" (the first reveal asking for the device lock, reset by a device lock or sleep), which was built on 2026-11-05.
3. **High-risk actions ask every time,** however the vault was unlocked:
   - export
   - saving a secret to a file
   - the Secret Key, the Recovery Kit and the recovery code
   - master password change and reset
   - key rotation
   - account deletion
4. **The master password every 14 days stays.**
   - When it's due, the automatic unlock stops until the master password is typed once.
   - Master password change, key rotation, "sign out other devices" and a key-format update delete the stay-unlocked key, as they delete device-unlock keys today.
5. **It needs a device lock.**
   - A phone with no passcode, or a computer with no usable system key store, can't stay unlocked. It falls back to today's behaviour, and Settings says why.
6. **Existing installs get the new default.**
   - **Lock settings never changed:** the install moves to stay-unlocked.
   - **Lock settings changed from the defaults:** the user keeps their choice.
   - **Stored settings can't tell "never set" from "set to the default":** take the reading that doesn't relax a lock the user picked, and record which one was used.

## Per platform

The setting reuses the device-unlock paths in plan 03, "Unlocking on a device", with the user-presence check removed. The CLI's `octapass unlock` session already keeps ASK wrapped by a secret in the system keyring with no presence check; that's the model.

| Platform | Where the key lives | Falls back when |
|---|---|---|
| **iOS / iPadOS** (app and AutoFill extension) | Keychain item, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, no biometry flag, shared through the app group the AutoFill extension already uses | No passcode set |
| **Android** (app and Autofill / Credential Manager services) | Keystore key, StrongBox where available, `setUnlockedDeviceRequired(true)`, no user-authentication requirement | No secure lock screen |
| **macOS desktop app** | Keychain item for this app, no access-control flags | Never in practice |
| **Windows desktop app** | DPAPI (user scope), or a TPM key with no Hello prompt | Never in practice |
| **Linux desktop app** | Secret Service keyring | No keyring running |
| **Extension, with the desktop app** | The desktop app. The extension unlocks through native messaging at browser start and whenever it's locked, while the desktop app is stay-unlocked | The desktop app is missing or has the setting off |
| **Extension, on its own** | Nowhere on disk: extensions can't reach the system key store, and extension storage is readable on disk. The vault stays unlocked in memory until the browser closes, with no idle timer and no lock on system lock. A computer lock or sleep only resets the "reveal asked once" state | After a browser restart: one normal unlock (passkey or master password) |
| **Web vault** (a browser tab) | Unchanged: a web page can't tell who is at the keyboard | Always |
| **CLI** | Unchanged | — |

## What this costs

These change plan 03's threat table when built.

| Who | Today | With stay-unlocked |
|---|---|---|
| **Malware running as the user** | Out of scope. When the vault is locked, it finds only ciphertext | Out of scope. It can open the vault as it can with Chrome's passwords. Revealing and exporting still go through the device lock prompt, but that doesn't stop malware that can read memory |
| **Someone at the unlocked device** | Needs the device lock or the master password to open Octa Pass | Can open Octa Pass and fill logins. Can't reveal, copy or export without the device lock |
| **A stolen, locked or powered-off device** | Ciphertext only | Unchanged. The key needs the device unlocked (iOS, Android) or the user logged in (desktop) |
| **The server** | Zero-knowledge | Unchanged |

Plan 03 currently says "no long-lived unguarded key copy" (lockless devices). This setting is exactly such a copy, guarded by the device's own lock. The rule is rewritten when this is built.

## Interaction with other plans

- **Locked saves (plan 05, the inbox):** still needed when the mode is off, on a device without a lock, and for the extension without the desktop app after a browser restart. No locked "lookup list" is built. With the vault unlocked, "update" and "already saved" work normally.
- **Plan 03's two device-auth gates:** they apply only when the setting is off. Settings shows them under the switch, greyed out while it's on.
- **Plan 17a parity:** each phone platform gets a row for the setting, the reveal-once state and the fallbacks.

## Settings text

- **Switch:** "Stay unlocked while you're logged in to this device."
- **Shown while on:** "Anyone who can use this device while it's unlocked can open Octa Pass and fill your logins. Exporting and showing your Secret Key still ask for Face ID / your device password."
- **Shown when unavailable:** "Set a passcode on this device to stay unlocked." or "No system keyring found, so Octa Pass locks as usual."

## Build order

1. **Core and the plan 03 rewrite:** the stay-unlocked key, its deletion events, the 14-day stop and the reveal-once state.
2. **Desktop app,** then the **extension** (through the desktop app, then on its own).
3. **iOS and Android,** including their autofill extensions and services.
4. **Settings and migration** on every platform; docs (`docs/features/biometric-unlock.md`, the security docs, every platform page, in English and Arabic); a changelog entry.

## Tests

On each platform:
- Auto-unlock happens when the setting is on and doesn't when it's off.
- Reveal and copy don't ask, before or after a device lock.
- Export asks every time.
- The 14-day rule stops the auto-unlock.
- Each deletion event removes the key.
- No passcode or no keyring falls back.
- Migration keeps a lock setting the user picked.

## History

- 2026-11-05: planned (maintainer decisions above). Not built. Every high-risk action keeps asking, and the 14-day master password check stays.
- 2026-11-05: **built.** Rules decided while building, where the spec left them open:
  - **The key is the device-unlock wrapping of ASK** (`octapass_core::device`, context `device-unlock`) under a random 32-byte secret, per account. Phones: `LocalStore.stayUnlockedKey(session)` returns opaque bytes (`0x01 ‖ secret ‖ salt ‖ wrapped ASK`) the app keeps in one platform item (`NativePlatform.storeStayUnlockedKey`, name `stayUnlocked.<account tag>`), and `LocalStore.unlockStayUnlocked(key)` opens the store with it, so the app and the AutoFill extension or Android services use the same item and nothing changes in the store file. Desktop: the secret goes in the key store `DeviceUnlock::store_unprotected` already had (no caller since 2026-10-27), renamed from `fill-without-unlock` to `stay-unlocked`; the wrapped ASK is in `state.json` (`stayUnlockedKeys`, by account id). Local vaults (no account) work the same way.
  - **Deletion events:** master password change and reset, Secret Key rotation, a local vault's password change, forgetting the account (sign-out, deleting a local vault) and, on the phones, a new store for the account at sign-in. Turning the switch off deletes it (on the desktop, every account's). "Sign out other devices" only happens through a password change, reset or rotation in these apps, and **there is no key-format update yet**; when one ships it must delete the key the same way. Turning **device unlock** off doesn't touch it: they're separate switches. After a deletion, the next unlock (any kind) makes a new key while the switch is on.
  - **Enrolment:** whenever the vault unlocks with the switch on and the account has no key yet (sign-in, sign-up, a password change, a new device). No extra prompt: the user just unlocked.
  - **Opening:** the lock screen tries the key first; only if it can't does today's unlock screen, with its automatic device prompt, appear. Phones also try at launch and on coming back. The extension tries through the desktop app at browser start and when its lock screen shows ("whenever it's locked" read as "whenever the user meets the lock"; it doesn't re-unlock on its own after the user locked it).
  - **"Lock now" holds** until the user unlocks once (the device lock or the master password). The hold is in memory on the phones and desktop and in `chrome.storage.session` in the extension, so a restart of the app or browser opens unlocked again.
  - **The 14-day check:** the key opens nothing while it's due (`passwordRequired`); Settings says "Enter your master password once to keep staying unlocked."; the key isn't deleted, so typing the password once restarts it.
  - **Fallbacks, detected:** iOS no passcode (`LAContext` `.deviceOwnerAuthentication` can't evaluate; iOS also deletes `WhenPasscodeSet` items itself); Android no secure lock screen (`KeyguardManager.isDeviceSecure`); desktop a key store that fails a read (Linux with no Secret Service running: "No system keyring found, so Octa Pass locks as usual."). A phone key found without a passcode is deleted unused. A key that no longer opens the account is deleted.
  - **Reveal once:** a session stay unlocked opened isn't `confirmed`. The first reveal or copy asks; its success marks the session confirmed (desktop: `confirm_master_password` / `confirm_with_device` in Rust; extension: the worker's `confirm*` calls, kept in the session wrap; phones: `confirmedUnlock`). The open gate is ignored while staying unlocked. A device lock or sleep clears the mark **only while staying unlocked**; with the switch off, plan 03's once-per-unlock rule is unchanged. Desktop detection: a 2-second poll of the system's own lock state (macOS `CGSessionCopyCurrentDictionary` `CGSSessionScreenIsLocked`, Windows `OpenInputDesktop` failing on the secure desktop, Linux logind `LockedHint`), and a gap of over 30 seconds between polls read as sleep. Extension: `chrome.idle` `locked`. iOS: `protectedDataWillBecomeUnavailable`. Android: `ACTION_SCREEN_OFF`.
  - **Filling:** no prompt while staying unlocked, whatever the greyed-out autofill gate says. The extension's card security-code re-prompt (`requireReauthForCvv`) is its own switch and still asks.
  - **The extension with the desktop app:** the app answers `get-session-key-wrap` without its device-lock prompt when it stays unlocked, is unlocked, and the extension asks for the same account (the extension checks `unlock-status`, which now has `stayUnlocked`). The extension's own switch must be on too: it's per device like every other.
  - **An organisation's auto-lock policy wins:** while a policy sets a maximum lock time, the desktop app and extension turn the switch off on that device (the timer applies).
  - **Migration (rule 6), the reading used:** where settings are stored only when the user changes one, "none stored" means none picked: the extension's `lock-settings` (absent → stay unlocked; present without the new field → keep the lock). Where settings are stored whole, a value at its default can't be told from a picked one, so **the reading that doesn't relax a lock wins: any stored settings keep the lock**. That's the phones' `settings.json` (written whole on any change, the list order included) and the desktop app's web-view settings (written whole at first start). So on the phones and the desktop, only installs that never saved settings move to stay unlocked; others keep their lock and can turn it on in Settings. A damaged phone settings file reads as stored. The desktop records the decision in `state.json` (`stayUnlocked`) at its first start with this version.
  - **What the first reveal asks for:** "Confirm it's you", as for every other check: the device lock where device unlock is on, the master password where it's off (it's never weaker than the device lock). The switch's text names the one it will be ("…still ask for your master password" when device unlock is off).
  - **iOS:** the key is a Keychain item (service `app.octap.stayUnlocked`, the shared access group) with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and no access-control flags; a read while the phone is locked (`errSecInteractionNotAllowed`) is treated as no key, so the app asks as before. The AutoFill extension finds it by the current account in `accounts.json`; an item there means the switch is on. It fills with no prompt and, when the 14-day check is due, shows its existing master password message. iOS has no autofill gate, so only the open gate shows greyed out (both do since 2026-11-08, below). Vault-key rotation now asks every time (before this it didn't ask at all), which rule 3 requires.
  - **Android:** the key is AES-GCM under a Keystore key per account (`octapass.stayUnlocked.<name>`, `setUnlockedDeviceRequired(true)`, StrongBox where there is one, the TEE otherwise; minSdk 28 so there's no older path). The app opens itself on `ProcessLifecycle` start, which also covers autofill starting the process. Exporting stays master-password-only (`passwordOnly`). Saving a new login from autofill saves straight into the vault when the key can open it, and falls back to the save-while-locked inbox otherwise.
  - **Not built:** the Windows TPM key alternative (DPAPI, user scope, is used); a "Stay unlocked" switch in the web vault and CLI (not offered, per the spec).
- 2026-11-06 (maintainer decision, plan 03 History): **reveal and copy don't ask while the vault is open**, in this mode and with it off, replacing rule 2's "ask once". The reveal-once state built above (`confirmed`, `confirmedUnlock`, `RevealCover`, the screen-lock reset) no longer decides anything: `unlockCoversReveal` is "the vault is unlocked". The high-risk actions still ask every time.
- 2026-11-08 (plan 03 History): **the autofill gate on the phones.** With this switch off, "Ask on every fill" now applies on the iPhone, iPad and Android too, greyed out under this switch as on the desktop. Off, the app keeps a separate fill key (`unlockedFill.<account tag>`, the same wrapping and the same kind of item as this one) only while its vault is unlocked, expiring with its lock timer; turning this switch on deletes it, since this key fills then. The extensions try this key first, then the fill key (`unlockWithoutPrompt`).
