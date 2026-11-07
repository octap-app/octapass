---
title: Add one-time codes from any QR code, and link them to your logins
date: 2026-10-24
summary: Read a site's two-step QR code from the page, the screen, a photo or a screenshot, bring over every account from Google Authenticator's export QR codes, and choose which login each code joins.
tags: [core, extension, desktop, mobile, web, docs]
---

**Read QR codes everywhere.** Open a login and choose **Add one-time code**, or **New item → One-time codes from a QR code**. Then:

- In the browser extension, **Scan QR code on this page**, or right-click a QR code image and choose **Add one-time code from QR**. Works with an account and in a vault on this device only.
- In the Mac app, **Scan part of the screen**.
- On iPhone and Android, scan with the camera or choose a photo.
- Anywhere, choose an image, drop one, paste a screenshot, or paste the setup link or key.

Every image is read on your device by the same reader in the Octa Pass core (Rust), which finds all the QR codes in a picture, copes with tilted and grainy photos and light codes on dark pages, and says plainly when a QR code isn't a one-time code. Nothing is uploaded.

**Google Authenticator.** Its **Export accounts** QR codes bring over every account, even when the export is split over several QR codes: Octa Pass counts "2 of 3 scanned" until it has them all.

**Choose where each code goes.** Imports from Google Authenticator, Aegis, 2FAS, andOTP and `otpauth://` lists, and scans with several codes, now show each code before saving: matched codes keep their login, and for the others you search your logins by name, username or website, or keep the code as an item of its own. On the iPhone and Android, setup links and Google Authenticator exports that open Octa Pass (from a website, the Camera app, or **Set Up Codes In**) go through the same review. A code that's already an item of its own has **Link to a login**, which moves it into a login and puts the old item in the trash.

See [one-time codes](/docs/features/totp/#adding-a-code) and [importing from authenticator apps](/docs/import-export/from-authenticator-apps/).

**Fixed along the way:** importing a file in the Android app failed, because Android's web view sends the file differently; and an authenticator import into a vault that had a login without a website or username stopped with an error in the web vault and the extension.
