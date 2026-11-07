---
title: One-time codes on Apple Watch and Wear OS
date: 2026-11-02
summary: Watch apps show the one-time codes your phone sends, for 15 minutes at a time. The secrets never leave the phone.
tags: [mobile, security]
---

New Apple Watch and Wear OS apps show your [one-time codes](/docs/features/watch/), with a countdown ring, in English and Arabic.

It's off by default: turn on **Show codes on Apple Watch** or **Show codes on Wear OS** in Settings → Security on your phone, which asks for your device lock or master password first.

The phone makes the codes in the Rust core and sends the next 15 minutes for up to 50 items, favourites first. The watch gets item names and codes, never a secret, username or website. When the vault locks or you sign out the phone tells the watch to forget them, and they run out by themselves anyway. A watch with no passcode or screen lock won't show codes.

Not yet tried on a real paired watch, and the Apple Watch app isn't bundled with the iPhone app yet: that needs the watchOS platform on the build Mac. Design and reasons: [plan 05](https://github.com/octapass/octapass/blob/main/plans/05-clients-and-autofill.md).
