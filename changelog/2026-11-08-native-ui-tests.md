---
title: The phone apps' UI tests cover every flow, with screenshots in both languages and themes
date: 2026-11-08
summary: The native iPhone, iPad and Android apps have UI tests for the flows they lacked (files, share links, families, emergency access, export, import, deleting the account, filling other apps), a screenshot run in English and Arabic, light and dark, and an Android script to run them.
tags: [mobile, docs]
---

Plan 17's phase 3 asks for a UI test of every flow in the native phone apps, driving the real screens against a development server, and screenshots in both languages and themes. Plan 17a now lists each flow with the test that covers it on iPhone, iPad and Android, or why it can't be tested.

New tests:

- **iPhone and iPad:** an item's files (attached, opened in Quick Look, removed), identity, document and password items, a setup link through the code review and an `otpauth://` link opened from outside, share links, families, emergency access, devices, the security log, an encrypted export and deleting the account. `ScreenshotTests` finds everything by identifier, so it runs in Arabic as well as English, light and dark, on iPhone and iPad.
- **Android:** filling another app through Autofill and Credential Manager (`OtherAppsTest`, with the test app in `services/uitests` as the other app), an item's files, emergency access, importing a Chrome export, and deleting the account. `ScreenshotsTest` now takes the main screens in all four language and theme combinations.

Fixed along the way:

- `apps/android/scripts/ui-tests.sh` runs the Android UI tests: a fresh development server, `adb reverse`, the screen-lock PIN the device-unlock tests type (unlocking an emulator that started locked with it), the test app, and the screenshots. The tests named a script that went with the Tauri phone app.
- Android tests that still expected "Confirm it's you" before showing an SSH private key or an environment variable follow the rule from 2026-11-06: an open vault doesn't ask again.
- A failing Android test's screenshot is taken while the screen is still there, and kept where the script collects it.
- `apps/ios/scripts/ui-tests.sh` takes `OCTAPASS_DERIVED_DATA`, so two runs at once don't share a build folder.

The old Android smoke tests in `services/uitests/src/androidTest` drove the Tauri app's web view and no longer run. Credential transfer, which only they tested, needs Google Play services 25.38 or later, which the emulator images used here don't have. See [development setup](/docs/contributing/development-setup/#tests).
