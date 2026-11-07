---
title: Quick start
description: The first-run flow for Octa Pass, from creating an account and saving your Recovery Kit to installing the browser extension and importing passwords.
status: in-progress
sidebar:
  order: 2
---

:::note[In progress]
The public alpha is open: you can create an account today in the web vault at [vault.octap.app](https://vault.octap.app). The apps in step 3 aren't in the stores yet; they're coming soon. Until then you can [build them from source](/docs/contributing/development-setup/). Follow the [changelog](/changelog/) for store releases.
:::

## 1. Create an account

1. Open the web vault or any Octa Pass app and choose **Create account**. The free Octa Pass service is selected by default. (Running your own server? Choose **Use a different server**, then **Self-hosted**, and enter its address; see [connect the apps](/docs/self-hosting/connect-apps/).)
2. Enter your email and choose a master password. A long passphrase works well; the [generator](/docs/features/password-generator/) can suggest one.
3. Enter the 6-digit code sent to your email to verify the address.

Your device generates your Secret Key, encryption keys and recovery code. None of these are sent to the server in readable form. See [encryption](/docs/security/encryption/).

## 2. Save your Recovery Kit

Octa Pass creates a PDF **Recovery Kit** on your device. It contains your Secret Key and recovery code. Print it or store it somewhere safe and offline. Without it, a forgotten master password can mean a lost vault. Read [Recovery Kit](/docs/getting-started/recovery-kit/).

## 3. Install the apps you need

| Where | What to install |
|---|---|
| Chrome, Edge, Brave, Firefox… | The [browser extension](/docs/platforms/browser-extension/) |
| macOS, Windows, Linux | The [desktop app](/docs/platforms/desktop/) |
| iPhone, iPad, Android | The [mobile app](/docs/platforms/mobile/), then turn on Octa Pass in the system autofill settings |
| Terminal | The [CLI](/docs/platforms/cli/). Sign up in another app first: the CLI signs in, but doesn't create accounts. |

Signing in on a new device needs your email, master password and Secret Key once. Scanning your Recovery Kit's QR code to fill these in is planned; for now, type the key.

You can skip the account altogether in the browser extension: see [use without an account](/docs/features/local-vault/).

## 4. Import your passwords

Export from your old password manager or browser, then use **Import** in Octa Pass. Parsing happens on your device. See the [import overview](/docs/import-export/overview/). Afterwards, delete the export file: it isn't encrypted.

## 5. Check your vault's health

Open the [security dashboard](/docs/features/security-dashboard/) to find breached, reused and weak passwords and accounts without two-factor authentication.

## 6. Turn on biometric unlock

On trusted devices, enable Face ID, Touch ID, Android biometrics or Windows Hello. See [biometric unlock](/docs/features/biometric-unlock/).
