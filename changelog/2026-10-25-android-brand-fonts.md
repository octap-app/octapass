---
title: The Android app uses the brand fonts
date: 2026-10-25
summary: The native Android app now shows Mona Sans and Monaspace Neon, the same font files the web vault uses, instead of the phone's own font.
tags: [mobile]
---

The native Android app (not released yet) used the phone's system font, because the brand fonts existed only in the web format. It now bundles Mona Sans for text, with headlines at the brand's wider width, and Monaspace Neon for passwords, codes and keys.

The files are converted without changes from the ones the web vault ships, with their open font licenses, and a check fails if they ever drift from the web's versions. Characters Mona Sans doesn't cover, including Arabic, use the phone's font. See [`tools/native-fonts`](https://github.com/octapass/octapass/tree/main/tools/native-fonts).
