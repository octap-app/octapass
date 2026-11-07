---
title: Browser extension
description: The Octa Pass browser extension for Chrome, Edge, Firefox and other browsers, covering autofill, passkeys, TOTP, unlocking, building it from source and reproducible builds.
status: in-progress
sidebar:
  order: 2
---

:::note[In progress]
The extension is built in the repository (`apps/extension`) and works against an Octa Pass server, but it isn't in any extension store yet. It ships with Phase 2, the public alpha. Until then you can [build it and load it unpacked](#build-it-yourself).
:::

## Browsers

Chrome, Edge, Brave, Opera, Vivaldi, Arc and Firefox (desktop and Android), all using Manifest V3. Safari 18 and later, on the Mac, iPhone and iPad, gets the same extension inside a small Octa Pass app (see [Safari](#safari)).

Planned stores: Chrome Web Store, Microsoft Edge Add-ons, Firefox Add-ons (with source code uploaded for review) and Opera add-ons.

## What it does

- [Autofill](/docs/features/autofill/) logins, TOTP codes, cards, identities and addresses
- [Add one-time codes](/docs/features/totp/#adding-a-code) from the QR code a page shows (**Scan QR code on this page**), or from any QR code image on a page (right-click → **Add one-time code from QR**), with an account or on this device only. The extension reads a screenshot of the visible tab, only when you ask, and never downloads the image again
- Save and update logins when you sign in or sign up, and [addresses and cards](/docs/features/autofill/#saving-addresses-and-cards) when you check out, [even while Octa Pass is locked](/docs/features/autofill/#saving-while-octa-pass-is-locked): the save waits, sealed, and is added at the next unlock
- Create and use [passkeys](/docs/features/passkeys/)
- [Generate passwords](/docs/features/password-generator/) and [masked emails](/docs/features/masked-email/) in signup forms
- The full vault in a browser tab: the toolbar button opens it next to the page you're on (see [the Octa Pass tab](#the-octa-pass-tab))

## The Octa Pass tab

The toolbar button opens Octa Pass in a browser tab, next to the page you're on. If an Octa Pass tab is already open, it comes to the front instead: the one in this window, or else one in another window. There's no popup and no side panel.

The tab has the web vault's full layout. Its sidebar holds your vaults, categories, sharing, your organisation, emergency access, masked email, tools, trash, settings and your Health score.

- **This site** comes first in the sidebar. It lists the logins for the tab you came from, each with a **Fill** button, beside the item you open. If you switch to another tab in that window and then come back, it shows that tab's site. After **Fill**, the extension takes you back to the page.
- **Scan QR code on this page** (the QR code button on This site) brings the page's tab to the front for a moment to take a screenshot, then comes back.
- **Unlock** in the in-page menu opens the tab on the lock screen. Once you've unlocked, it takes you back to the page.
- Right-click → **Add one-time code from QR** opens the tab on the scan.
- The lock timers run in the extension's background, not in the tab, so leaving the tab open or closing it doesn't change when Octa Pass locks.
- Some questions still open in a small window of their own: [HTTP sign-in prompts](#http-sign-in-prompts), and **Ask on every fill**.
- **Settings** has the extension's own sections (autofill, frames, HTTP sign-in prompts, never-save sites) and your account's, as in the web vault: master password, Secret Key, vault keys, security log, two-step sign-in, devices, server and storage.
- The **Generator**'s masked email starts with the site of the tab you came from.

### Getting the other apps

A small card at the foot of the sidebar offers an Octa Pass app you don't have yet:

- **The desktop app**, when your account has no desktop device and the extension can't reach the desktop app on this computer. It never shows in Safari, because the Safari extension comes inside the Mac app.
- Otherwise **the phone app**, when no iPhone or Android device is signed in to your account. It doesn't show for a vault on this device only.

Close a card with × and that app isn't offered again. The link goes to the [desktop app](/docs/platforms/desktop/) or [mobile apps](/docs/platforms/mobile/) page, because the apps aren't in any store yet.

## API keys

Paste an API key into a form, and the extension offers to save it as an API credential. It works this out on your device: a value counts if it has a known shape (such as `ghp_…` or `sk_live_…`), or if the field is named as a key and the value looks random. It stays in the page's extension script until you choose **Save**, for at most two minutes, and nothing leaves your device.

It never offers on password, username, search, card or address fields, in frames, or on your web vault. Turn it off in **Settings → API keys**, or choose **Never for this site**.

In a field named as a token or API key, the in-page menu also offers API credentials saved for that site. They follow the same rules as logins: an exact site match, your click, and the autofill confirmation if it's on. An item with a live OAuth2 token fills that token while it's valid; the extension never asks a provider for a new one, so use the [CLI or Connect](/docs/features/connect/#live-api-tokens) for that.

## How it's built

| Part | Job |
|---|---|
| Background service worker | Runs the Octa Pass core (Rust compiled to WebAssembly) and sync. Browsers stop idle service workers, so while unlocked the account key is kept in memory-only session storage (`chrome.storage.session`), wrapped with a random per-session key, and never written to disk. Locking or closing the browser throws it away. |
| Content script | Detects forms and shows the in-page menu ([autofill engine](/docs/features/autofill/)), shows save prompts |
| Page script | A minimal script that intercepts WebAuthn calls for passkeys |
| Passkey prompt | An extension page the website frames but can't script: you choose Octa Pass or your browser's own passkey flow |
| App page | The web vault's screens in a browser tab, plus **This site** (the logins for the page you came from, with a Fill button) and a QR code scanner for that page |
| Native messaging host | Installed by the [desktop app](/docs/platforms/desktop/) for biometric unlock and a shared unlock session |

Form detection uses `autocomplete` attributes first, then field types, names, labels and placeholders in the 10 most common languages, plus the form's structure. There's no remote machine learning and no remotely loaded code. Site-specific fixes ship as a signed ruleset inside the extension.

The service worker only ever tells a page about logins for that page's own site, judged by the address the browser reports, never by what the page says. A login for `paypal.com` is never offered on `paypal.com.evil.io`, and a login saved for an `https` site is never offered on its plain-`http` twin. Passkey private keys stay in the service worker: the Octa Pass tab sees a passkey's name and site, never its key.

## Forms from other sites

Some sites show a form from another site inside their page: a sign-in box from an identity provider, or a payment form. Octa Pass does nothing in such a frame until you allow it. The first time you open its menu there, it names the frame's site and the page it's inside, for example *This form is from accounts.example-idp.com, inside shop.example*, and offers **Allow Octa Pass here**. Both names come from the browser, not from the page.

- Once allowed, the frame gets the logins saved for its own site, never the page's.
- The answer is remembered for that frame on that site only. The same frame inside another site asks again.
- Frames from the page's own site (`login.shop.example` inside `shop.example`) need no approval.
- **Settings → Frames from other sites** lists what you allowed. Remove one to be asked again.

Passkey requests from such frames are left to your browser.

## HTTP sign-in prompts

When a site asks for a username and password in the browser's own pop-up (HTTP Basic or Digest), Chrome, Edge and Firefox let the extension answer it (`webRequest.onAuthRequired`, with the `webRequestAuthProvider` permission). Octa Pass answers only with a login for the site's exact address, and for the realm the site names when the login has one. The first time, it opens a small window to ask which login to use; after that it answers that site by itself. Prompts from frames, from requests another site started, and from proxies are left to the browser. **Settings → HTTP sign-in prompts** lists the sites you allowed. More in [autofill](/docs/features/autofill/#http-sign-in-prompts).

## Unlocking

- Master password
- Through the [desktop app](/docs/platforms/desktop/) (Touch ID, Windows Hello), when it's running and signed in to the same account. Connect it once: on the Mac in **Settings → Browser extension → Connect browser extension**, on Windows and Linux from the app's **Browser → Connect browser extension**. The app wraps your account key for that one request, under a key only the extension and the app can derive. It only does this for [browsers it recognises](/docs/platforms/desktop/#supported-browsers); in others the lock screen says so.

With **Stay unlocked while you're logged in to this device** on (the default; Settings → Device auth), the extension stays unlocked until the browser closes: no lock timer and no lock when your computer locks or sleeps, and filling doesn't ask. When the desktop app is installed and stays unlocked too, the extension opens through it without a prompt when the browser starts and when its lock screen shows. Revealing or copying a secret doesn't ask while the vault is open; exporting always asks. See [Stay unlocked](/docs/features/biometric-unlock/#stay-unlocked-while-youre-logged-in).

With it off, the vault locks after the time you choose (15 minutes by default) and when your computer locks or sleeps.

### Device unlock in each browser

For Touch ID or Windows Hello in the extension, use the desktop app. The extension can't make a device passkey of its own yet. The [web vault](/docs/features/biometric-unlock/#web-vault) can, in these browsers:

| Browser | In the web vault | In the extension |
|---|---|---|
| Chrome, Edge | Yes: Touch ID, Windows Hello | Through the desktop app |
| Safari 18+ (macOS 15+, iOS 18+) | Yes: Touch ID, Face ID, the device passcode | Through the Octa Pass app |
| Firefox 139+ on macOS 15+ | Yes: Touch ID | Through the desktop app |
| Firefox 135+ on Windows and Linux | Where the device's authenticator supports PRF (not tested yet) | Through the desktop app |

Setting it up takes one Touch ID prompt in Safari and Firefox, which give the key while creating the passkey. Chrome and Edge may ask twice. If a browser turns the second prompt down, Settings shows **Finish with Touch ID** to finish with one more click. When a prompt fails, the message includes what the browser said.

With the extension installed, the web vault's device unlock (and any site's request for the PRF extension) goes straight to the browser. The extension's passkey prompt can't answer it.

In Firefox, **Settings → Security** in the extension links to the desktop app for this. Firefox lets an extension use passkeys only for websites, not for the extension itself.

## On this device only

You can use the extension without an account: choose **Use on this device only** on the first screen. Your vault is encrypted with your master password (Argon2id at 256 MiB) and stored in the browser. Nothing is sent anywhere.

- **Back it up** from Settings → This device. The `.octapass-backup` file is encrypted; it opens with your master password, or with the backup recovery code you wrote down when you created the vault. **Restore a backup** is on the first screen.
- **Turn on sync** when you want your vault on other devices. It creates an account and moves the vault into it as it is (the same keys and ciphertext), then gives you the account's Recovery Kit.
- Sign-in features (passkeys, sharing) need sync. The browser can't keep a local vault unlocked across its background restarts the way it keeps an account session, so the extension stays awake while a local vault is unlocked.

## Turning off the browser's own password manager

So you don't get two save prompts, Octa Pass can turn off the browser's own: **Settings → Browser's password manager → Use Octa Pass instead of Chrome's password manager** (or Edge's, or Firefox's). The extension also suggests it once, the first time you unlock.

- Turning it on asks for one extra permission, *Change your privacy-related settings* (`privacy`). Octa Pass asks for it only then, not when you install it.
- **Chrome and Edge:** choose what Octa Pass takes over: **Passwords**, **Addresses** and **Payment cards** (all three to start with). This turns off the browser's offers to save passwords, and its address and card autofill.
- **Firefox:** only password saving can be turned off by an extension. Turn off address and card autofill yourself in Firefox's settings, under Privacy & Security.
- **Safari:** extensions can't change this. On a Mac, open Safari → Settings → AutoFill; on iPhone or iPad, Settings → Apps → Safari → AutoFill. Turn off what you want Octa Pass to do instead.
- If another extension or your organization's policy controls a setting, Octa Pass says so and leaves it alone.
- Turning the option off gives the browser's own settings back, as they were, and drops the permission. If you remove the extension, Chrome and Edge put the browser's settings back by themselves.

To do it by hand instead:

- **Chrome/Edge:** Settings → Passwords → turn off *Offer to save passwords*; Settings → Autofill → turn off addresses and payment methods
- **Firefox:** Settings → Privacy & Security → uncheck *Ask to save passwords*
- **Safari on the Mac:** Settings → AutoFill → uncheck *User names and passwords*

## Build it yourself

You need Node 22+, pnpm, Rust with `wasm-pack` (for the core) and an Octa Pass server: the hosted one, or your own (see [self-hosting](/docs/self-hosting/overview/)).

```sh
pnpm install
pnpm build:extension   # the WebAssembly core when needed, then apps/extension/dist/chrome and dist/firefox
```

`pnpm build:extension` asks once which server the extension offers as "Octa Pass" on its sign-in screen, and can remember it; see [building the apps](/docs/contributing/development-setup/#build-the-apps).

- **Chrome, Edge, Brave:** open `chrome://extensions`, turn on *Developer mode*, choose *Load unpacked* and pick `apps/extension/dist/chrome`.
- **Firefox:** open `about:debugging#/runtime/this-firefox`, choose *Load Temporary Add-on* and pick `apps/extension/dist/firefox/manifest.json`. Firefox asks you to allow the extension on websites before it can fill.

Development builds carry a fixed key, so the unpacked Chrome extension's ID is always `oojckfebkmiogiahdggohbdnndbfcjnm`, the one the desktop app's native messaging manifest allows. `node apps/extension/scripts/build.ts --store` leaves the key out for store uploads. It needs Chrome or Edge 133+ or Firefox 130+.

`pnpm --filter @octapass/extension dev` rebuilds on every change and talks to a local server on `http://localhost:8080` (`pnpm --filter @octapass/web dev:stack` starts one). Reload the extension after a rebuild.

## Safari

:::note[In progress]
The Safari build exists in the repository (`apps/safari`) and builds for macOS and the iOS Simulator, but it hasn't been signed or run in Safari itself yet. It isn't in the App Store.
:::

Safari extensions ship inside an app. The Octa Pass app for Safari (`app.octap.safari`, macOS and iOS) carries the extension (`app.octap.safari.extension`) and has one screen: where to turn the extension on, and whether it's on already. The extension is the same code as in Chrome and Firefox, built for Safari, with these differences:

- **Turning it on:** Safari keeps extensions off until you turn them on, and asks before an extension may read a website.
  - **Mac:** Safari → Settings → Extensions, tick Octa Pass, then **Edit Websites** and allow it on other websites.
  - **iPhone and iPad:** Settings → Apps → Safari → Extensions → Octa Pass, turn on **Allow Extension** and allow it on all websites. On iOS 26.2 and later the app opens that page for you.
- **A tab, as in the other browsers.** The toolbar button opens Octa Pass in a tab. On iPhone and iPad the button is in the extensions menu in the address bar.
- **No unlock through the desktop app.** Safari's native messaging only reaches the app the extension ships in, not the [desktop app](/docs/platforms/desktop/). Unlock with your master password.
- **No lock when your computer locks.** Safari doesn't tell extensions when the computer locks. The vault still locks after the time you chose.
- Passkeys need Safari 18 or later, which runs Octa Pass's passkey script in the page's own JavaScript world.
- **No HTTP sign-in prompts.** Safari doesn't let extensions answer a site's username-and-password pop-up (it has no `webRequest.onAuthRequired`), so Safari shows its own.

### Build it for Safari

You need a Mac with Xcode 16 or later, plus what the [extension build](#build-it-yourself) needs.

```sh
apps/safari/scripts/build.sh   # the Safari extension, then the macOS app and the iOS Simulator app
```

It builds the extension with `node scripts/build.ts --target safari` (into `apps/extension/dist/safari`), copies it into the Xcode project and runs `xcodebuild`. Then it checks the extension in WebKit's own extension runtime (`WKWebExtension`, macOS 15.4 or later): the manifest loads, the background starts, the app page shows its first screen, and a vault on this device only can be created.

- **Mac:** builds are signed ad hoc, so Safari only loads them after Safari → Settings → Advanced → *Show features for web developers*, then Develop → Developer Settings → *Allow unsigned extensions* (Safari turns this off again when it quits). Open `apps/safari/build/DerivedData/Build/Products/Debug/Octa Pass.app` once, then turn the extension on.
- **iOS Simulator:** `xcrun simctl install booted "apps/safari/build/DerivedData/Build/Products/Debug-iphonesimulator/Octa Pass.app"`, or open `apps/safari/OctaPass.xcodeproj` in Xcode and run the *Octa Pass (iOS)* scheme.

## Reproducible builds

Anyone can rebuild the extension from source and compare it with the store version. Instructions will be published with the first release.
