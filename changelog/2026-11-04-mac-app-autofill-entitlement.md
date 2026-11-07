---
title: The Mac app carries the AutoFill entitlement itself
date: 2026-11-04
summary: Builds made with pnpm build:macos now give the Mac app its own provisioning profile and the AutoFill entitlement, as the iPhone app has, so that macOS can list Octa Pass under AutoFill from.
tags: [desktop]
---

On the iPhone, both the Octa Pass app and its AutoFill extension carry Apple's AutoFill entitlement, and Octa Pass shows up under **AutoFill From**. On the Mac, only the extension had it, and macOS found the extension but didn't list Octa Pass.

Builds signed with `pnpm build:macos` now give the Mac app its own provisioning profile, made by Xcode with your team, and the AutoFill entitlement with it. The same profile lets the app keep its Touch ID key in the protected keychain macOS meant for it; keys you saved before keep working.

After rebuilding, move the app to Applications, open it once, and look under System Settings → General → AutoFill & Passwords → **AutoFill from**. See [building the apps](/docs/contributing/development-setup/#build-the-apps).
