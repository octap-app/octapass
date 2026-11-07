---
title: TOTP codes
description: How Octa Pass stores and generates two-factor authentication codes (TOTP, Steam Guard), adds them from QR codes and Google Authenticator exports, links them to logins, and fills them after the password.
status: in-progress
sidebar:
  order: 4
---

:::note[In progress]
Live codes (RFC 6238, SHA-1/256/512, 6–8 digits), counter-based codes (HOTP) and adding them from QR codes work in the web vault, the extension and the desktop and phone apps. Steam Guard codes come later: imported ones are kept as hidden fields.
:::

Octa Pass can replace your authenticator app. The TOTP secret is stored encrypted in the Login it belongs to, and codes are generated on your device.

## Supported formats

| Standard | Details |
|---|---|
| TOTP (RFC 6238) | SHA-1, SHA-256 or SHA-512; 6–8 digits; any period |
| Steam Guard | Steam's 5-character codes |
| `otpauth://` URIs | Single accounts |
| `otpauth-migration://` | Google Authenticator export QR codes, including multi-QR batches |
| HOTP (RFC 4226) | SHA-1, SHA-256 or SHA-512; 6–8 digits; `otpauth://hotp/` links, imports and QR codes |

An Apple Watch or Wear OS watch can [show your codes](/docs/features/watch/) too, without holding the secret.

## Adding a code

Open a login and choose **Add one-time code**. You don't need to edit the login first. Then use whichever of these your app offers:

| Where | How |
|---|---|
| Browser extension | **Scan QR code on this page** reads the page you opened the Octa Pass tab from: it brings that page to the front for a moment, takes a screenshot, then comes back. Right-click a QR code image on any page and choose **Add one-time code from QR**. |
| iPhone and Android | **Scan with the camera**, or **Choose a photo** of a QR code (a screenshot works too). |
| Everywhere | Choose an image file, drop one on the window, or paste a screenshot. Or paste the setup link (`otpauth://…`) or the secret key the site shows under its QR code. |

QR codes are read on your device. The image is never uploaded, and nothing is sent to a QR service. A picture can hold several QR codes: Octa Pass finds all of them, and if one isn't a one-time code, it says so.

To add codes that aren't for a login you already have, choose **New item → One-time codes from a QR code** (in the extension, the QR code button at the top of **This site**). Each code then goes to a login you pick, or becomes an item of its own.

### Moving codes from Google Authenticator

In Google Authenticator, choose **Transfer accounts → Export accounts**. It shows one or more QR codes. Scan each of them, or take a screenshot of each and add the screenshots: Octa Pass shows "2 of 3 QR codes scanned" until it has them all, and adds every account in them. You can also continue with the accounts you have so far.

## Linking a code to a login

Wherever several codes arrive at once (a Google Authenticator export, an [authenticator app import](/docs/import-export/from-authenticator-apps/)), Octa Pass shows where each one goes before saving anything:

- A code whose issuer matches a login (by name or website, and by username when there are several) joins that login.
- For every other code, **Change** opens a search over your logins by name, username or website. Pick one, or keep the code as an item of its own.
- A login that already has a one-time code can't take another, and each login takes one code from the import.

A code that is already an item of its own (from an earlier import, say) has **Link to a login** on its page. The code moves into the login you pick, with its issuer, period, digits and algorithm, and the old item goes to the trash, where you can still restore it for 30 days.

## Using codes

- After filling the password, the [browser extension](/docs/platforms/browser-extension/) fills the code field, or copies the code to your clipboard (auto-cleared).
- The iOS 18+ and macOS 15+ AutoFill providers offer codes in the system QuickType bar.
- The [CLI](/docs/platforms/cli/) prints a code with `octapass totp <item>`.

## Counter-based codes (HOTP)

A counter-based code doesn't change with time: each code is used once, and the login keeps a counter. There's nothing to show until you ask, so instead of a live code the login has **Next code**.

- **Next code** saves the moved counter first, then shows the code, so a code is never handed out twice. At worst one is skipped, which sites allow for.
- The login shows which number comes next. If a site stops accepting codes, **Change counter** sets the number it expects.
- The counter syncs, and the higher counter wins without a conflicting copy. Online, two devices using a code at once each get their own. A phone also works offline, where it can repeat a code another device just used; if the site refuses it, press **Next code** again.
- In the browser extension, filling a code field uses up the next code. Mac, iPhone and Android AutoFill don't offer counter-based codes, because they can't save the counter; use the app. Auto-type's `{TOTP}` and quick access can't produce them either.
- Moving a code to a new version never lowers its counter: [restoring an older version](/docs/features/offline-and-sync/#version-history) keeps the higher one.

Logins imported before Octa Pass had this keep the code in a hidden field, **One-time code (HOTP)**. Copy the `otpauth://hotp/…` link into the login's one-time code field to use it.

## All your codes in one list

**One-time codes** in the sidebar's Categories, next to Passkeys, lists every item that has a code: logins with a code, and codes saved on their own (for example ones imported from an authenticator app without a matching login). Its count is the number of those items.

Each row shows the item's current code with a ring that counts down to the next one. Click or tap the code to copy it; the clipboard is cleared after 30 seconds. Click the rest of the row to open the item. The list can be sorted and grouped like any other (see [sorting and grouping](/docs/features/sorting-and-grouping/)), but logins for the same website are never combined into one row here, so every code stays in view.

Whether an item has a code comes from the list information your device already has. Showing the code opens the item on your device, the same way opening it to look at the code does; nothing extra goes to the server.

## Should 2FA codes live with passwords?

Keeping both in one place trades a little defence-in-depth for convenience and phishing resistance: Octa Pass fills codes only on the matching domain. If you prefer to separate them, keep TOTP in a separate app. For the strongest protection, use [passkeys](/docs/features/passkeys/) where sites support them.

The [security dashboard](/docs/features/security-dashboard/) lists sites that support 2FA where you haven't set it up, based on the 2fa.directory dataset.
