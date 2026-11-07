---
title: Security dashboard
description: The Octa Pass security dashboard finds breached, reused and weak passwords, missing 2FA and passkeys, insecure URLs and expiring cards, entirely on your device.
status: in-progress
sidebar:
  order: 6
---

:::note[In progress]
Every check below works in the web vault, the desktop app, the phone apps and the extension, except the two marked otherwise. The native iPhone and Android screens haven't been run on a device yet.
:::
The security dashboard (called **Health** in the apps) reviews your vault and gives it a score out of 100. **Every check runs on your device after unlock**, and its results are never uploaded. The one exception is opt-in [email breach alerts](#email-breach-alerts), which you have to turn on. In the browser extension, open it from **Settings → Security dashboard**; it opens in a tab.

Health opens on your score and a tile for each check, with how many items it found. Choose a tile to open that check's list, where you fix or dismiss each item; **Health** at the top takes you back. Weak, reused and breached passwords, two-step sign-in and recovery emails always have a tile; the other checks get one when they find something. On the phones it's the same: a row per check on Health, each opening its own list.

## Checks

| Check | How it works | Severity | Counts towards the score |
|---|---|---|---|
| Password found in a breach | Pwned Passwords range API with k-anonymity and padding. See [breach checks](/docs/security/breach-checks/). | High | Yes |
| Reused password | The same password on two or more items | High | Yes |
| Weak password | A zxcvbn-style strength estimator in the core | Medium | Yes |
| Site supports 2FA but no code or passkey is stored | A list of sites that offer it | Low | Yes |
| Login URL uses `http://` | Local. Addresses on this device or your local network (`localhost`, `192.168.x.x`, `*.local`) don't count, because they can't get a public certificate. | Low | Yes |
| Recovery email has no 2FA | The [recovery map](/docs/features/recovery-info/#recovery-map) finds the email account's own login in your vault | Medium | No |
| Old password | Not changed for a year. See below. | Info | No |
| Site supports passkeys but none is stored | The passkeys directory dataset | Info | No |
| Card, ID or passport expiring | Expired, or expiring within 60 days. A card is valid to the end of its expiry month. | Info | No |
| Two or fewer backup codes left | Your saved [backup codes](/docs/features/recovery-info/) | Info | No |
| Account email or alias in a breach (opt-in) | Have I Been Pwned through your server. See below. | Medium | No |
| Recovery email is breached (not built) | See [recovery info](/docs/features/recovery-info/#dashboard-checks) | Medium | No |

**Old passwords** are a reminder, not a rule. Changing a strong, unique password on a schedule doesn't make it safer, so these are listed but never lower your score. The age counts from the last time the password changed, not the last time the item was edited.

## Email breach alerts

Unlike every other check, this one sends something off your device, so it's off until you turn it on. Its switch is on the **Email breach alerts** page in Health, and it asks first.

While it's on, your account email and your [masked email](/docs/features/masked-email/) aliases go to your Octa Pass server, which asks [Have I Been Pwned](https://haveibeenpwned.com) about each one. This happens at most once a day, or when you choose **Check now**. The server doesn't store the addresses or the answers. The results are kept in your encrypted vault, and turning alerts off deletes them.

Aliases exist so that sites can't connect them to you, and this check tells your server which aliases are yours. If that matters to you, leave it off. Details are in [breach checks](/docs/security/breach-checks/#email-breach-alerts-opt-in).

The switch appears only when your server has an HIBP key: on a [self-hosted server](/docs/self-hosting/configuration/#email-breach-alerts) that's the operator's choice, and it's off by default. Local vaults have no server, so they don't have it.

There is no email or push notification: a new breach shows at the top of Health in your apps, the next time one of them checks.

## Datasets without lookups

Lists of sites that support two-step sign-in and passkeys ship with each release. Octa Pass never looks up your sites one by one, so nobody learns which sites you use.

Passkey data comes from the [passkeys directory](https://passkeys.2fa.directory/) by 2factorauth, licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), reduced to registrable domains.

## Fixing problems

**Change password** on a weak, reused, breached or old password opens the site's change-password page in a new tab, using the standard `/.well-known/change-password` address, and starts the [generator](/docs/features/password-generator/) in Octa Pass. Make a password, copy it to the site, and save it. The old password stays in the item's password history, so saving doesn't lose anything if the site's change didn't finish. Not every site has that address: if yours doesn't, sign in and look in its account settings.

### On the login itself

A login whose password is also on other logins says so at the top of its page, in the web vault, the desktop app, the extension's Octa Pass tab and the phone apps: **Password used on 3 other logins**. It's the same password whatever the username, as in Health's reused check. **See them** lists those logins with their username and website; each opens its login, and **Change password** works as it does in Health. The warning comes from the report Health already made, so opening a login doesn't check anything again. A reused group you dismissed in Health shows no warning.

## Dismissing warnings

**Dismiss** hides one warning. It leaves the list and stops counting against your score, so dismiss only what you've decided to accept. Dismissed warnings stay in a list of their own, at the bottom of Health, where **Show again** brings them back.

A reused password is dismissed for the whole group of items. A warning comes back by itself when what it's about changes: a new password, a new expiry date, fewer backup codes, or another item joining a reused group.

Dismissals follow your account to your other devices. They're stored in your vault as one encrypted item, which the server can't read and your item lists don't show.
