---
title: The browser extension is ready for the stores
date: 2026-11-08
summary: Version 0.1.0 of the extension for Chrome, Edge and Firefox, pointing at vault.octap.app, with Firefox's review warnings fixed.
tags: [extension, release]
---

The extension's first store version is **0.1.0**. Its "Octa Pass" server choice is the hosted service at [vault.octap.app](https://vault.octap.app).

For Firefox's review:

- The minimum Firefox is now **140** (142 on Android), the first versions that read `data_collection_permissions`, which addons.mozilla.org requires.
- The page icons and the fill menu insert their SVGs with `DOMParser` instead of `innerHTML`. They were always our own constant markup, never page data.
- The Firefox build leaves out Chrome's `chrome.dom` path: Firefox reaches closed shadow roots with its own `openOrClosedShadowRoot()`.

The store screenshots are regenerated, and the name reads **Octa Pass**, two words, in the sidebar, the emails and every logo.
