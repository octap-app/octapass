---
title: Turn off or delete a masked email from Octa Pass
date: 2026-11-02
summary: Aliases in use now has Turn off, Turn on and Delete for each alias, for every provider with an API for them.
tags: [core, desktop, mobile, docs]
---

**Masked email → Aliases in use** can now turn an alias off and on, or delete it, without opening the provider's site. It works with SimpleLogin, addy.io, Fastmail, Forward Email and Firefox Relay. DuckDuckGo has no API for this, so those aliases are managed at duck.com. The request goes straight from your device to the provider with your token, as making an alias does.

Deleting asks first. The login keeps the address as plain text, because the site still has it, and only the link to the alias is removed. See [Masked email](/docs/features/masked-email/#turning-an-alias-off-or-deleting-it).
