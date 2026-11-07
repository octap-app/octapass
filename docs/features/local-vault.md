---
title: Use without an account
description: Use Octa Pass on one device with no account, no email and no server. Your vault stays on the device, with encrypted backup files and an option to turn on sync later.
status: in-progress
sidebar:
  order: 13
---

You don't need an account to use Octa Pass. Choose **Use on this device only** when you first open the extension or app, and your vault lives only on that device. Nothing is sent anywhere, not even an email address.

## What works

Everything that runs on your device:

- Autofill, suggested passwords and the password generator
- One-time codes (TOTP) and passkeys
- The health check. The breach check needs the internet but only sends the first 5 characters of a hash; see [breach checks](/docs/security/breach-checks/)
- Import and export
- Unlocking with your master password. Device unlock in a local vault is planned.

These need sync, so they're not available in local mode: syncing between devices, sharing, families, emergency access, masked email, email breach alerts and the web vault.

## Back up your vault

With no server, losing the device means losing the vault, unless you have a backup.

- Octa Pass asks you to save an **encrypted backup file** when you set it up, and reminds you every 30 days.
- Backing up automatically to a folder you choose, such as iCloud Drive, Dropbox or OneDrive, is planned for the apps.
- Restore a backup on any device with your master password.
- Your **Recovery Kit** includes a backup recovery code that opens your backups if you forget your master password.

If you lose the device, every backup and the Recovery Kit, the data can't be recovered.

## A strong master password matters more here

With an account, your Secret Key protects you if our servers are ever breached. In local mode there's no server, so the risk is someone copying the vault file off your device. In the apps, Octa Pass will tie the vault to your device's security chip where there is one. A browser has no such chip, so the extension asks for a strong master password, which keeps backups safe too.

## Turn on sync later

Choose **Turn on sync** at any time. Octa Pass creates your free account and uploads your vault, already encrypted, without you re-entering anything. From then on the device works like any other synced device.

## Several vaults on one device

The desktop app and the phone apps can keep several local vaults, each with its own master password and backups: for example one for home and one for work. Open the others from the lock screen or from Settings → This device. Their names show on the lock screen before anything is unlocked, so they're stored on the device unencrypted. Don't put a secret in a vault's name.

The AutoFill extensions on your phone fill from the vault that's open in the app. The browser extension keeps one local vault.

## Automatic backups

In Settings → This device, pick a folder and each change is backed up there; the newest seven stay. On a computer a backup follows a quiet minute or locking the vault; on a phone, leaving the app or locking it. File names carry a code for the vault, never its name, so a cloud drive doesn't learn what you call it. If the folder stops working, your vault stays safe on the device and the 30-day reminder comes back.

## The security chip

Where the device has a chip Octa Pass can use (the Secure Enclave, the Android Keystore, a Windows TPM), a local vault is bound to it, so a copy of its file is useless anywhere else. If that key is lost, for example with a new logic board or a reset phone, the master password alone no longer opens the vault: restore a backup. That's one more reason to keep one.

With a chip, a master password must score at least 3 of 4 for strength; without one, 4 of 4. Backups are protected by the password alone, so they need a strong one either way. The browser extension has no chip of its own, but it uses the desktop app's when the app is installed. That vault then needs the app to open.

## Turn on sync

**Turn on sync** creates an account and moves the vault into it. Items go up exactly as they are, encrypted, and nothing is typed in again. You'll get a Recovery Kit with a Secret Key and an account recovery code; the backup recovery code doesn't apply any more.

## Not yet in local vaults

Files can't be attached to items in a local vault.
