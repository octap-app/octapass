---
title: Release builds of the desktop app and extensions for your own server
date: 2026-10-24
summary: The desktop app, browser extensions and Safari app can be built for one server and installed outside the stores, the Windows installer can be cross-compiled on a Mac, and a release workflow builds everything on version tags.
tags: [release, desktop, extension]
---

For people who build Octa Pass for their own server and devices:

- **Your server by default.** Set `VITE_SERVER_URL` when building the desktop app, the extensions or the Safari app, and its "Octa Pass" server choice is your server. Other servers can still be picked at sign-in.
- **Extensions outside the stores.** A desktop build made with `OCTAPASS_EXTRA_EXTENSION_IDS` accepts your unpacked Chrome or Edge extension and your unlisted, self-signed Firefox add-on for unlocking with Touch ID or Windows Hello. Only do this for your own machines: any unpacked extension can claim a Chromium ID.
- **Signed with your certificate.** The macOS app's native host is now signed together with the app (`APPLE_SIGNING_IDENTITY`), and `DEVELOPMENT_TEAM` signs the Safari app, so Safari lists the extension without "Allow unsigned extensions".
- **Windows from a Mac.** `apps/desktop/scripts/build-windows.sh` cross-compiles the Windows installer with cargo-xwin and NSIS, with no Visual Studio or full LLVM needed.
- **Release workflow.** Pushing a `v*` tag builds the Windows installer, the macOS app and disk image, Linux packages and the extension packages on GitHub Actions, unsigned.

See [the desktop app](/docs/platforms/desktop/) and [the browser extension](/docs/platforms/browser-extension/).
