---
title: Autofill
description: How Octa Pass fills logins, cards and identities in browsers and apps, how domain matching works, and the safety rules that stop phishing and clickjacking.
status: in-progress
sidebar:
  order: 2
---

:::note[In progress]
Autofill is built in the browser extension, the desktop app and the iPhone and Android apps, but it isn't released yet. See the [roadmap](/docs/reference/roadmap/).
:::

## Where autofill works

| Platform | How |
|---|---|
| Browsers (Chromium, Firefox) | The [browser extension](/docs/platforms/browser-extension/) fills in the page |
| Safari | A Safari Web Extension shipped inside the macOS and iOS apps |
| macOS 14+, iOS 17+ | The system AutoFill provider, in Safari and in native apps |
| Android 9+ | The Android Autofill Framework, with inline keyboard suggestions on Android 11+ |
| Windows | The extension in browsers. For other apps, **auto-type** from the [desktop app](/docs/platforms/desktop/) |
| Linux | The extension in browsers, plus auto-type (full on X11, limited on Wayland) |

Windows and Linux have no system autofill API for third-party password managers, so auto-type is the workaround there. See the [support matrix](/docs/platforms/support-matrix/).

## Device auth on fills

By default, Octa Pass asks for your device's lock each time it fills a login, one-time code, card or identity. The switch is **Settings → Security → Device auth → Ask on every fill**, per device and never synced. Turn it off and fills happen directly while the vault is unlocked, with a warning that anyone using the device can fill your logins; a locked vault still asks at least once. Revealing, copying and exporting have [their own rules](/docs/features/biometric-unlock/#revealing-and-copying). On a device with no lock Octa Pass can use, fills don't prompt while the vault is already unlocked (Chrome password-manager behaviour), and the master password opens the vault after a restart or lock. The web vault never offers a gateless mode.

## What it fills

- Login forms, including multi-step and identifier-first logins
- TOTP fields, and copying the code after the password is filled
- Card forms and identity/address forms
- [Passkeys](/docs/features/passkeys/) through WebAuthn
- New-account forms, with a [generated password](/docs/features/password-generator/) or a [masked email](/docs/features/masked-email/)

When you sign in or sign up, Octa Pass offers to **save or update** the login. When possible it waits until the page navigates successfully, so a failed login isn't saved.

## Save prompts

In the browser extension, save and update prompts are cards in the page's corner. When there's more than one, they stack.

- The title says what Octa Pass will do: **Save this login?** or **Update the saved password?** The site's host is on its own line under it.
- A panel shows the username and the password, masked. The dots are always the same length, so they don't give away how long the password is.
- **Save** or **Update** does it. **×** is **Not now**. **Never for this site** is a quiet link at the foot of the card.
- Short messages, such as *One-time code copied*, close by themselves. A thin bar shows how long is left, and pointing at the message or moving focus into it pauses it.
- *Saved in Octa Pass* after you use a suggested password stays until you close it. When you send the sign-up form, the login is confirmed and the message goes.

## The in-page list

In the browser extension, clicking a field Octa Pass can fill opens its list below the field. In a username field the list narrows as you type: it shows only the logins whose username or name contains what you've typed, and closes when none do. Clear the field to see them all again.

The list has:

- a header with the Octa Pass tile, **Octa Pass** and the site's host, so you can see which site it's offering for
- a row for each suggestion, with the site's icon (a letter tile until the icon loads), the title and the username
- dividers between kinds of suggestion, such as logins, a suggested password and a masked email
- the suggested password in a monospace box, so it's easy to read
- a footer with the keys to use: **↑↓ Move · ↵ Choose**

Clicking the Octa Pass icon in a field, or pressing **↓**, always opens the list. When your vault has nothing for that field, the list says **Nothing saved for this field**. Clicking into such a field opens nothing.

The extension tries to stay light on the page:

- It doesn't scan the whole page again when you click outside a field. It scans again when a frame loads, not for every image or script, and on busy pages it spaces the scans out.
- It keeps a field's suggestions for 15 seconds, so opening the list again is instant. It starts fetching them when you press the mouse button in a field, never when a field just gets focus.
- It asks for fewer site icons, and adds its styles to the page once.

## Filling when a page opens

The browser extension can fill a sign-in form as soon as the page opens, the way Chrome and Firefox do. It's off unless you turn it on: **Settings → Filling → Fill logins when a page opens**, on each device, never synced. With it on, Octa Pass fills the login you used last on that site, or its only login, and only when all of these are true:

- the page is a secure `https://` page, and the form isn't inside a frame
- the login is saved for that exact address: not another part of the site, not an equivalent domain
- the form's username and password fields are empty and visible
- Octa Pass is unlocked, and filling wouldn't ask you to confirm it's you first (with **Ask on every fill** on and **Stay unlocked** off, nothing is filled on load)

Start typing in a filled field to replace it: typing over the username clears the username and the password, typing over the password clears only the password. Clicking the field still opens the full list. Sign-up and change-password forms are never filled on load.

The website can read what's filled before you do anything, which is why this is off by default. Chrome partly avoids it by hiding a password from the page's scripts until you interact; an extension can't do that.

## Saving while Octa Pass is locked

Saving never asks you to unlock. If Octa Pass is locked when you sign in, check out or paste an API key, the browser extension still asks, and Android's **Save to Octa Pass?** sheet still works:

- **The prompt always says Save.** While it's locked, Octa Pass can't look in your vault, so it can't tell a new login from a changed password, or see that you saved it already. The extension adds a line saying it'll be added when you next unlock.
- **What you save waits on this device, sealed.** It's encrypted with your account's own public key, so even this device can't read it back until you unlock. It's never synced, and at most 50 saves wait at once. When that's full, nothing more is offered until you unlock.
- **The next unlock adds it to your vault:**
  - A new login, address, card or API key is tagged **Unconfirmed**, so you can check it.
  - If you already have a login for that site and username, it gets the new password, and the old one goes into its password history. Its tags stay as they were.
  - Anything your vault already has is dropped quietly, and so is a second save of the same thing.
- **Never for this site** still works while locked.
- **When it can't wait:** a device where Octa Pass hasn't been unlocked since this arrived has no key to seal to yet. There the extension doesn't offer, and Android asks you to unlock and save, as before. Signed out, there's nothing to save to.

On iPhone and iPad, iOS doesn't let password managers save what you type in other apps, so there's nothing to save while locked there.

## Saving addresses and cards

In the browser extension, Octa Pass also notices an address or card form you send, the same way it notices a sign-in, and asks **Save this address in Octa Pass?** or **Save this card in Octa Pass?**. Saved addresses become [Identity items](/docs/features/item-types/) and cards become Card items, in your personal vault, with or without an account.

- **What it reads:** only the fields it recognised. For an address: name, email, phone, address lines, city, region, postcode and country. For a card: the cardholder, number and expiry; the brand comes from the number. Other fields in the form are never read.
- **When it asks:** an address needs a street line and a city or postcode, so a newsletter or contact form never counts. A card number must pass the checksum every card number carries.
- **Update instead of save:** when a saved card has the same number, or a saved Identity has the same email or the same street line and postcode, the prompt offers **Update**. Only the fields the form had change. If nothing changed, there's no prompt.
- **The security code** (CVV) is never saved unless you tick **Also save the security code** on the prompt. Turn on **Settings → Device auth → Ask before filling a security code** and the extension asks you to confirm it's you (device unlock or master password) before the code goes into a page, even when filling doesn't otherwise ask. If you say no, the rest of the card is still filled. It's a setting of this browser, off by default, and it's never synced.
- **Never for this site** stops prompts for that kind of item on that site. **Settings → Never offered to save** lists those sites, so you can take it back.
- **Not on insecure pages:** there are no address or card prompts on plain `http://` pages (except `localhost`), and none in a form framed from another site until you [allow that frame](/docs/platforms/browser-extension/#forms-from-other-sites).
- The prompt names a card by its brand, last four digits and expiry. The full number stays in the extension's background and the vault; it's never written to logs or shown in the page.

A checkout page that asks for a billing address and a card in one form offers to save the card.

## HTTP sign-in prompts

Some sites, often routers, printers and admin pages, don't have a sign-in form: the browser itself pops up a box asking for a username and password (HTTP Basic or Digest authentication). In Chrome, Edge and Firefox the [browser extension](/docs/platforms/browser-extension/#http-sign-in-prompts) can answer that box for you:

- **Only the exact site.** A login is used only when one of its websites has the same scheme, host and port as the address asking. `https://nas.example` doesn't fill `http://nas.example` or `https://files.nas.example`.
- **The realm, when the login has one.** A site can ask for different sign-ins for different areas and names each one (its *realm*). A login with an **HTTP realm** is used only when the site asks for that realm; a login without one is used for any prompt on its site. You can set the realm in the login's editor; logins imported from another password manager keep theirs.
- **Your approval, the first time.** The first time a site asks, Octa Pass opens a small window naming the site and the logins it could use. Pick one to sign in; from then on Octa Pass answers that site's prompts by itself. **Not now** leaves the prompt to your browser. **Settings → HTTP sign-in prompts** lists the sites you allowed, so you can take one back.
- **Only while unlocked**, and never for a proxy, a frame or a request that another site's page started: the browser asks you instead. If the site turns the password down, the browser asks too, instead of Octa Pass trying again.

Safari doesn't let extensions answer these prompts, and the [desktop app](/docs/platforms/desktop/) doesn't show websites, so in both cases use the browser's own box (copy the password from Octa Pass).

## Domain matching

Octa Pass offers a login on the page's own part of a site, the parts above it and the parts below it, but not on the site's other parts. Say you're on `login.example.com`:

| Login saved for | Offered? |
|---|---|
| `login.example.com` (or `www.login.example.com`) | Yes, listed first |
| `example.com` | Yes, listed next. A login for `b.example.com` on `a.b.example.com` comes before one for `example.com`: the nearest first |
| `eu.login.example.com` | Yes, after those |
| `shop.example.com` | No. It's one tap away: see [other parts of a site](#other-parts-of-a-site) |
| `youtube.com` for `google.com` | Yes, last, if the two are [equivalent domains](#equivalent-domains) |

A leading `www.` counts as the bare address on both sides, and ports don't matter. So on `example.com` every login for any part of `example.com` is offered, and on `shop.example.com` the logins for `example.com` and for `shop.example.com` are.

The registrable domain (the part you'd buy, like `example.com` or `example.co.uk`) comes from the Public Suffix List, so `example.co.uk` and `evil.co.uk` never match each other, and neither do `alice.github.io` and `bob.github.io`. Addresses are compared after converting international domain names, so `bücher.de` and `xn--bcher-kva.de` are the same site and a look-alike with a Cyrillic letter is not.

Until 5 November 2026 Octa Pass offered every login for the whole registrable domain, so a login for `shop.example.com` was also suggested on `login.example.com`. Logins you saved before keep their websites; only what's suggested by default changed. If you want a login offered on every part of its domain again, choose **Every part of this domain** for that website.

### Other parts of a site

When the page has logins saved for other parts of its domain, the autofill list ends with a quiet entry, **Logins for other parts of example.com**. Open it to see those logins, each with the address it was saved for. They're never filled on their own: not when the page loads, not by the keyboard shortcut, only when you pick one.

After you fill one from there, Octa Pass asks **Add login.example.com to this login?** **Add** puts the page's address on the login, so next time it's suggested first; **Not now** leaves the login as it is. Octa Pass asks only where it can change the login (not for a login in a shared vault you can only read).

Where you find the entry:

- **Browser extension:** at the end of the in-page menu in username and password fields, and in **This site** in the Octa Pass tab, under the logins for the page.
- **iPhone and iPad:** in the Octa Pass list (from **Passwords** above the keyboard, or the key icon), the logins for this part of the site come first and a section for the other parts sits under them. The suggestions iOS shows above the keyboard come from the system's own matching of your saved websites, which Octa Pass doesn't control.
- **Android:** after you unlock, the Octa Pass list shows the logins for this part of the site and ends with the entry. In the sign-in sheet (Credential Manager) it's an action under the suggestions. If other parts have logins, Octa Pass shows the list even when only one login matches, instead of filling it straight away.
- **Desktop app:** AutoFill on the Mac and auto-type offer only the logins for this part of the site. Use search in the AutoFill list or in quick access to reach the others.

### Match rules for each website

Each website on a login can have its own rule, under the website in the login editor (**Fill on**):

| Rule | Matches |
|---|---|
| This site and its subdomains (default) | The page's own address, the domains above it and the addresses below it, as described above |
| Every part of this domain | Any address on the same registrable domain: `login.example.com` and `shop.example.com` for a login saved for either. The old default |
| This exact host | Only the same host and port, such as `accounts.example.com:8443` |
| Pages that start with this address | The same host and port, on pages whose path starts with the saved one. Hosts are compared properly, so `https://example.com` never matches `https://example.com.evil.io` |
| Regular expression | Advanced use: the saved text is a regular expression over the whole page address. A loose one can offer the login on other sites |
| Never fill here | Never suggested |

The rule applies when suggesting and again when filling, in the browser extension, the iPhone, Android and Mac AutoFill, and auto-type. A website without a rule of its own uses the default.

Imports keep the rules of the app you came from where they mean the same thing. Bitwarden's **Base domain** becomes **Every part of this domain**, because in Bitwarden it covers every subdomain; Bitwarden's and Proton Pass's **Default** uses Octa Pass's default. [Passkeys](/docs/features/passkeys/) don't use these rules: the site's own WebAuthn settings decide where a passkey works.

### Equivalent domains

Some sites share one sign-in, such as `google.com` and `youtube.com`. A login for one is offered on the others, ranked below an exact match. Octa Pass has a short built-in list. Under **Settings → Equivalent domains** you can add your own groups and turn built-in groups off.

- Typed addresses are reduced to their registrable domain, so `mail.example.com` becomes `example.com`.
- Public suffixes such as `co.uk` or `github.io`, IP addresses and anything else that isn't a single site are refused, and Octa Pass says which ones.
- The list is an encrypted item in your personal vault, so it follows your account and the server can't read it.

## Safety rules

These defaults defend against phishing and against the 2025 class of clickjacking attacks on password-manager extensions.

1. **Suggestions only on matching domains.** A look-alike domain never sees your logins.
2. **A user gesture is required.** Octa Pass fills only when you click its inline menu, use the keyboard shortcut or choose **Fill** in **This site**. The one exception is [filling when a page opens](#filling-when-a-page-opens), off unless you turn it on.
3. **No silent filling in cross-origin iframes.** A frame from another site needs your approval first: the menu names the frame's site and the page it's inside, and remembers your answer for that pair. Allowed frames get only the logins for their own site. See [forms from other sites](/docs/platforms/browser-extension/#forms-from-other-sites).
4. **Protected in-page UI.** The menu is rendered in an extension-owned frame or the browser's top layer. Octa Pass refuses to fill if the page hides, covers or makes its UI transparent.
5. **Warnings on `http://`.** Passwords and TOTP codes aren't filled on insecure pages without a warning.

The full reasoning is in the [threat model](/docs/security/threat-model/).

## Auto-type

On desktop, auto-type types `username ⇥ password ↵` (or the item's own sequence) into the focused window after checking that the window belongs to the item: in a browser by the page's address, never its title; in other apps by the window title or app name, or by the windows listed on the item. It uses the platform's input APIs: SendInput on Windows, CGEvent on macOS (needs Accessibility permission), XTest on X11, and the RemoteDesktop portal on Wayland where available. Where none of those work, it falls back to the clipboard with auto-clear. Details in the [desktop app docs](/docs/platforms/desktop/#auto-type).

## Quality

Autofill is tested against a [corpus](https://github.com/octap-app/octapass/tree/main/tools/autofill-corpus) of 76 synthetic pages covering login, sign-up, card and address forms, multi-step sign-ins, frames and shadow DOM. It scores 100% on the pages it was tuned on and 95% on pages written later as a held-out set. Snapshots of real top sites, and an opt-in report for "autofill didn't work here" that contains the form structure only, never values, are planned. Until then, [open an issue](https://github.com/octap-app/octapass/issues/new/choose).
