---
title: Account recovery
description: How to change your Octa Pass master password, or reset a forgotten one with the recovery code from your Recovery Kit, without any backdoor.
status: beta
sidebar:
  order: 4
---

:::note[Where it works]
Changing the master password and resetting it with the recovery code work on the sync server, in the web vault, the browser extension (reset only), the desktop app, the native iPhone and Android apps, and the [command-line tool](/docs/platforms/cli/). So do replacing the Secret Key and rotating vault keys, except in the browser extension, which only follows changes made elsewhere. Recovering through an emergency contact or family organiser works in the web vault, the desktop app and the native apps.
:::

Octa Pass can't reset your password for you: the server doesn't have your keys. Instead, recovery uses things only you or people you trust hold.

## Recovery paths

| You lost | Recover with | What happens |
|---|---|---|
| Master password | **Recovery code** | Verify your email → enter the recovery code → your device unwraps your account key → choose a new master password. |
| Secret Key | **Recovery Kit**, or any signed-in device | The kit has the key printed and as a QR code. Signed-in devices can show it after unlock. |
| Password and Secret Key | **Recovery code** | As above, on a device that doesn't know your Secret Key: you get a new one too. |
| Everything | **Emergency contact** with takeover, or **family organiser** (if set up) | They hold a sealed copy of your account key. After the waiting period they can set a new password and Secret Key and give you the new kit. See [takeover](/docs/features/emergency-access/#takeover). |
| Everything, with no contacts | Nothing | Your vault can't be recovered. You're told this clearly at sign-up. |

## Resetting a forgotten master password

Choose **Forgot your master password?** on the sign-in or lock screen.

1. Enter your account email. We email you a 6-digit code (the same answer shows whether or not the email has an account).
2. Enter the code.
3. Enter the recovery code from your Recovery Kit and choose a new master password.
4. Save your **new Recovery Kit**: the reset always replaces the recovery code, and the old one stops working. If this device didn't know your Secret Key, you get a new Secret Key too.

On the command line, `octapass reset-master-password` does the same steps and prints the new kit, including the new Secret Key and recovery code.

Your vault stays exactly as it was: nothing is re-encrypted. Every device is signed out; sign in on them with the new master password. If [two-step sign-in](/docs/features/two-step-sign-in/) is on, signing in still asks for the second step: a reset never skips it. You get an email, and the reset shows in your security log.

## Changing your master password

In the web vault or desktop app, open **Settings → Security → Master password → Change**. On iPhone and Android, open **Settings → Security → Master password**. In the [CLI](/docs/platforms/cli/), run `octapass change-master-password`. Enter your current master password and a new one. Your Secret Key and recovery code stay the same. Your other devices are signed out, and unlock with Face ID, Touch ID, your fingerprint or screen lock, Windows Hello or a passkey has to be turned on again. You get an email, and the change shows in your security log.

## Replacing your Secret Key

If your Secret Key or a Recovery Kit may have been seen, open **Settings → Security → Replace Secret Key**. On the command line, run `octapass rotate-secret-key`. Enter your master password; it doesn't change. You get a new Secret Key and a new Recovery Kit. Your recovery code stays unless you ask to replace it too, which you should if a kit may have been seen, because the code is on the same kit.

Your other devices are signed out and need the new key to sign in: choose **My Secret Key changed** on a device that remembers the old one. Device unlock is turned off until you turn it on again. You get an email, and the change shows in your security log.

**What this can't do:** it stops the old key working from now on. Your account key doesn't change, so someone who already has your master password, your old Secret Key and a copy of your old wrapped keys can still derive it. If you think that happened, change the passwords stored in your vault.

## Rotating vault keys

**Settings → Security → Vault keys** gives a vault a new key, on demand: `octapass rotate-vault-key <vault>` on the command line. You can do this for your own vaults and for shared vaults you own or manage. Every item moves to the new key, and your other devices pick it up by themselves. A change waiting on a device that was offline isn't lost: an edit to an existing item comes back as a conflicting copy next to the current version.

**What this can't do:** it wraps item keys again and doesn't re-encrypt items, as when a member leaves. It protects against someone who has only the old vault key. Someone who kept the old key and the old wrapped item keys can still open item ciphertext they can get hold of, and passwords someone already read stay known to them. Change the ones that matter. Rotating doesn't protect against someone who has your account key, which opens the new vault key.

A [contact for a single vault](/docs/features/emergency-access/#after-a-vault-key-changes) has to be renewed afterwards.

## How the recovery code works

At sign-up your device creates a random 256-bit **recovery key** and shows it once as the recovery code. It uses this key to wrap your account key (ASK) and stores the wrapped copy on the server. Only the recovery code can unwrap it, so the server can store it safely without being able to use it.

A reset works like this:

- The server hands out your account bundle (the wrapped copies of your keys, all ciphertext) only after you enter the emailed code.
- Your device unwraps the account key with the recovery code, then wraps it again for the new master password (and a new recovery code), with a fresh salt. Nothing in your vault is decrypted or re-encrypted.
- Your device proves it really opened the account key by signing the new credentials with your account's signing key, which only the account key unwraps. So someone who can read your email but doesn't have your recovery code can't replace your password.
- The server swaps in the new password record and wrapped keys in one step and signs every device out.

A password change is the same, except that the server checks your current master password first (a fresh OPAQUE login) instead of a signature.

## The Recovery Kit

The kit is a PDF made **on your device**. It contains your email, server URL, Secret Key (as text and QR code), a space to write your master password and your recovery code. See [Recovery Kit](/docs/getting-started/recovery-kit/).

## Two-step sign-in recovery

If you lose your authenticator app, use one of the recovery codes shown when you turned on [two-step sign-in](/docs/features/two-step-sign-in/). Keep them with your Recovery Kit. They don't decrypt anything; they only let you pass the second step. A device that's still signed in can set up a new authenticator or make new codes.
