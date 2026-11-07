---
title: The extension, built for Safari
date: 2026-10-24
summary: The Octa Pass extension now has a Safari build, packaged in small macOS and iOS apps that show you where to turn it on. It builds and passes checks in WebKit; it hasn't run in Safari itself yet.
tags: [extension, mobile]
---

Safari extensions ship inside an app, so the browser extension now has one: **Octa Pass for Safari**, for the Mac, iPhone and iPad (Safari 18 or later). The extension inside is the same code as in Chrome and Firefox. The app has a single screen with the steps to turn the extension on in Safari's settings, and shows whether it's on already.

## What's different in Safari

- The popup is the only view: Safari has no side panel.
- Unlock with your master password. Safari's native messaging can't reach the [desktop app](/docs/platforms/desktop/), so unlocking through it isn't available.
- Safari doesn't tell extensions when the computer locks. The vault still locks after the time you chose.
- Safari asks before the extension may read a website. Allow it on all websites so it can fill sign-in forms.

## How it's checked

The apps build for macOS and the iOS Simulator without an Apple developer account, and the iOS app runs in the Simulator. A check loads the extension into WebKit's own extension runtime, the engine Safari uses. It confirms the manifest loads, the background starts, the popup shows its first screen, and a vault on this device only can be created. That check found three ways WebKit delivers messages differently from Chrome: it drops messages that arrive before the background is listening, loses the first message when opening the popup has to start the background, and delivers some messages twice. The Safari build now handles all three for the popup.

Running in Safari itself needs a signed build or Safari's developer setting for unsigned extensions, so autofill and passkeys on real websites are still to be tested. See [Safari](/docs/platforms/browser-extension/#safari) to build it and try it.
