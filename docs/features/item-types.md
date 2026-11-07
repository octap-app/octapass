---
title: Item types
description: Every item type Octa Pass can store, from logins, passkeys and payment cards to SSH keys, Wi-Fi networks, environments and ID documents, and the fields each one holds.
status: in-progress
sidebar:
  order: 1
---

:::note[In progress]
Logins, passwords, secure notes, cards, identities, documents, Wi-Fi networks, SSH keys and environments are built, and so are the types marked "built in every app": those work in the web vault, the extension, the desktop app, the phone apps and, for reading, the CLI. The apps differ in places: see the [support matrix](/docs/platforms/support-matrix/#what-each-app-can-do). Priorities show when the other types arrive: **P0** for the public alpha, **P1** for 1.0, **P2** after 1.0.
:::

## Fields every item has

Title, tags, favourite flag, vault, notes, custom fields (text, hidden, URL, date, email, phone, TOTP), attachments, password history, and created/updated times. **All of them are encrypted**, including titles and tags. See [what the server sees](/docs/security/what-the-server-sees/).

An item brought in from another app keeps that app's dates: when it was created, when it last changed, when it was last used and, for logins, when the password last changed. The item shows these instead of the date it reached Octa Pass. Editing it here makes "Last changed" today's date again. It also keeps the other app's id for the item, so [importing the same file again](/docs/import-export/overview/#importing-again) updates it instead of adding a copy. These are encrypted with the rest of the item: the server only has its own sync dates.

Saving a **new login for a website and username you already have** asks first, in the web vault, the desktop app and the phone apps: it names the login you have and where it is, and you can keep editing or save a copy anyway. The web vault and desktop app can also open the one you have (they still ask before dropping what you typed). Websites count as the same when the scheme, host without `www.` and port match, the same rule [importing](/docs/import-export/overview/#importing-again) uses; logins without a website aren't compared. The browser extension's save prompt already offers to update the login it finds instead.

Logins saved from a site's HTTP sign-in prompt (the browser's own pop-up, not a form on the page) keep the prompt's **HTTP realm**, shown with the login. You can add or change the realm in the login's editor; the browser extension then [answers that prompt](/docs/features/autofill/#http-sign-in-prompts) only when the site names the same realm.

[Attachments](/docs/features/attachments/) work in the web vault, the desktop app and the mobile apps. The free hosted service allows 1 GB per account and 100 MB per file.

### One website, listed once

A login shows each website once. Two addresses are the same website when [autofill](/docs/features/autofill/#domain-matching) would offer the login on the same pages for both, read with the first one's match rule:

- **This site and its subdomains** (the default) and **Every part of this domain**: the same host, whatever the case, `http` or `https`, port, path, query or a leading `www.`. `https://example.com/`, `http://www.example.com/login` and `https://example.com` are one website; `a.example.com` and `b.example.com` stay two.
- **This exact host**: the same host and port.
- **Pages that start with this address** and **Never fill here**: the same address, once written the standard way (`/` after the host counts as nothing, a trailing `/` after a path counts).
- **Regular expression**: the same text.

The first address stays, with its match rule. Repeats that are already in an item stay saved until you edit it: the item shows each website once, and saving the item drops the repeats. [Importing](/docs/import-export/overview/#importing-again) and saving a login from autofill don't add a website the login already has.

## Types

| Type | Key fields | Priority |
|---|---|---|
| **Login** | Username, password, website URLs (several, each with a [match rule](/docs/features/autofill/#domain-matching)), TOTP secret, passkeys, linked masked email, [recovery info](/docs/features/recovery-info/) | P0 |
| **Passkey** | Relying party ID, credential ID, user handle, private key, counter. Stored inside a Login or on its own. See [passkeys](/docs/features/passkeys/). | P0 in browsers, P1 on mobile and desktop |
| **Secure note** | Markdown text | P0 |
| **Payment card** | Cardholder, number, expiry, CVV, PIN, brand (detected), billing address | P0 |
| **Identity** | Name, birth date, emails, phones, addresses, company, job title, national ID numbers | P0 |
| **Address** | Address book entries for form filling | P0 |
| **Bank account** | Bank, account holder, account type, IBAN, account number, routing or sort code, SWIFT code, branch, PIN. IBANs and SWIFT codes are checked when you save. Shows a [payment QR code](/docs/features/qr-codes/). | Built in every app |
| **Document** | A file plus notes; the file is encrypted on your device. Works in the web vault, the desktop app and the mobile apps. See [attachments](/docs/features/attachments/). | P1 |
| **SSH key** | Private and public key, key type, SHA256 fingerprint, comment, optional export passphrase. Generate Ed25519, ECDSA P-256/P-384 or RSA 3072/4096; import OpenSSH, PEM and PKCS#8; export the private key or the `authorized_keys` line. Built in the web vault, desktop app and CLI, with an [SSH agent](/docs/features/ssh-keys/#ssh-agent) in the desktop app; the extension shows the public key and fingerprint only. See [SSH keys](/docs/features/ssh-keys/). | P1 |
| **Certificate** | TLS certificate, chain, private key, names, issuer, expiry, key type, fingerprint, and what's needed to renew it through ACME. Made in the [developer toolkit](/docs/features/developer-toolkit/); the private key is shown or exported only after you confirm it's you. | P2 |
| **Key** | JWT signing keys, OpenPGP and age keys: private and public parts, JWK and JWKS, algorithm, key ID, fingerprint. Made in the [developer toolkit](/docs/features/developer-toolkit/), with the same confirmation as SSH keys. | P2 |
| **API credential** | Type, username, key, secret, host, expiry date. The extension also saves pasted keys as `credential`/`hostname` and holds live OAuth2 tokens (`oauth2`). | Built in every app |
| **Wi-Fi network** | Network name (SSID), hidden flag, security (open, WEP, WPA to WPA3 Personal and their transition modes, WPA2/WPA3 Enterprise with EAP settings), password, sign-in page, managed and Personal Hotspot flags. Shows as a QR code; the apps mark the network you're on and the ones in range. See [Wi-Fi networks](/docs/features/wifi/). | P1, in the web vault and apps |
| **Environment** | Project and stage, an ordered list of variables (name, value, concealed flag, note). One variable is an environment with one entry. Values can be `octapass://` references. The CLI loads them into commands, writes `.env` files and runs a shell hook. See [environments](/docs/features/environments/). | P1, in the web vault, extension and CLI |
| **Software licence** | Product, version, licence key, licensed to, email, publisher, order number, purchase and expiry dates | Built in every app |
| **ID documents** | Passport, driver's licence, national ID or another document: number, full name, birth date, issuer, country, issue and expiry dates. Scans are the item's [attachments](/docs/features/attachments/). | Built in every app |
| **Crypto wallet** | Wallet name, seed phrase (hidden), optional passphrase, addresses by network. Each address shows as a QR code; the seed phrase and passphrase never do. | Built in every app |
| **Database / server** | Type, host, port, database, username, password (with its history), connection string (hidden, since it usually holds the password) | Built in every app |
| **Custom item and template** | Fields you define: text, hidden, several lines, web address, date, email, phone or one-time code. Save an item's field names as a template, then choose it for a new item. A template holds names and kinds, never values, and items keep their fields if you change or delete it. | Built in every app |

Every type from Bank account onwards that's marked "built in every app" can hold more fields of your own and notes. A value another app wrote that doesn't fit a list, like an account type, is kept and shown as written. Lists search titles and subtitles only, never secrets, and a subtitle is never taken from a secret field.

## Payment info and PCI

Cards and bank accounts are ordinary encrypted items. Octa Pass doesn't process payments, so PCI-DSS doesn't apply. The [browser extension](/docs/platforms/browser-extension/) fills card forms. You can require re-authentication before the CVV is filled.

## Forward compatibility

Item schemas are versioned. When an older app opens an item with fields it doesn't understand, it keeps those fields untouched instead of dropping them.
