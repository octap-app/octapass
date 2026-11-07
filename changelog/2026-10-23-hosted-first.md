---
title: The free Octa Pass service comes first
date: 2026-10-23
summary: Octa Pass is positioned as a free hosted password manager. Open source is how you can trust it, and self-hosting is an option that uses the same apps.
tags: [decision, website, docs]
---

## Decision

The product is the **free Octa Pass service**: create an account, install the apps, and your vault syncs everywhere with nothing to set up. Open source is a trust feature, because anyone can audit the code the service runs. Running your own server is an extra, mainly for organisations.

## What changed

- **Website:** the hero sells the free service, and a new **Free plan** section lists what's included and explains how it's funded without ads. Open source is now "so you don't have to trust us", near the end of the page.
- **Docs:** a new page, [connect the apps to your server](/docs/self-hosting/connect-apps/), explains that self-hosters use the same official apps through a server picker at sign-in.
- **Design:** an opt-in **push relay** lets self-hosted servers send instant sync pings to the iOS and Android apps. Only random device identifiers pass through it, never vault data.
- **Plans** `00`, `01`, `04`, `05` and `08` record the hosted-first positioning.
