---
title: Recovery Kit
description: What the Octa Pass Recovery Kit contains, why your Secret Key and recovery code matter, and how to store the kit safely so you never lose your vault.
status: in-progress
sidebar:
  order: 3
---

:::note[In progress]
The sign-up flow and Recovery Kit (with QR code and print stylesheet) work in the web vault preview (milestone 1), which runs on demo data in your browser until the sync server is connected. The final recovery code format comes from the crypto core.
:::

Octa Pass is [zero-knowledge](/docs/security/overview/): nobody, including the Octa Pass team, can reset your master password or read your vault. The **Recovery Kit** is how you get back in if you forget your password or lose your devices.

## What's in the kit

| Item | What it is | Used for |
|---|---|---|
| Account email | Your sign-in email | Identifying your account |
| Server URL | Octa Pass Cloud or your self-hosted server | Signing in on new devices |
| **Secret Key** | A random 128-bit key, shown as `OP1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`, also printed as a QR code | Signing in on a new device, together with your master password |
| A blank line for your master password | Write it by hand if you choose to | Your own memory aid. Never type it into a file. |
| **Recovery code** | A 256-bit recovery key, shown once | Resetting your master password without anyone else's help |

If you turn on [two-step sign-in](/docs/features/two-step-sign-in/), you also get 10 recovery codes for it. They're shown once, in Settings: write them on your kit or keep them with it. They let you sign in on a new device if you lose your authenticator app.

The kit is generated as a PDF **on your device**. The server never creates or sees it.

## Why there are two secrets

Your encryption keys are derived from your master password **and** your Secret Key. The Secret Key never leaves your devices or the kit. If the server's database were stolen, an attacker would need to guess both. 128 random bits can't be guessed, so even a weak master password stays safe against a server breach. Details: [encryption](/docs/security/encryption/).

## Storing it safely

- Print it and keep it with other important papers, or in a safe.
- Keep a second copy somewhere else, such as with a trusted family member.
- Don't store it unencrypted in cloud drives or email.
- Signed-in devices can show your Secret Key again after unlock, but **the recovery code is shown only once**. Resetting your master password with it gives you a new recovery code (and a new kit), and the old code stops working.

## What happens if you lose things

| You lost | You can recover with |
|---|---|
| Master password | Recovery code |
| Secret Key | Recovery Kit, or any device that's still signed in |
| Master password and Secret Key | Recovery code (a new Secret Key is issued) |
| Everything | An [emergency contact](/docs/features/emergency-access/) or a family organiser, if you set one up |
| Everything, and no contacts | **Nothing.** Your vault can't be recovered. This is the cost of zero-knowledge encryption. |

To use the recovery code, choose **Forgot your master password?** on the sign-in or lock screen. See [account recovery](/docs/security/account-recovery/) for how it works.
