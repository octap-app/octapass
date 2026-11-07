---
title: An email when a new device signs in
date: 2026-10-24
summary: Octa Pass now emails you whenever a new device signs in to your account, with its name, platform and the time.
tags: [server, security]
---

When a device you aren't already signed in on signs in to your account, the server sends you a **New sign-in** email. It names the device and its platform and gives the time in UTC. There's no location in it: the server doesn't look up where IP addresses are.

If it wasn't you, sign that device out in **Settings → Devices** and change your master password: whoever it was knew your master password and Secret Key.

You won't get one when a device you're already signed in on signs in again, for the first sign-in right after you create your account, or when a recovery code was used (that sends its own email). See [authentication](/docs/security/authentication/#new-devices).
