---
title: Autofill keeps to your part of a site
date: 2026-11-05
summary: Octa Pass now suggests the logins for the page's own address, the domains above it and the addresses below it, not those for other parts of the same site. They're one tap away, and filling one offers to add the page to it.
tags: [decision, extension, desktop, mobile, core]
---

Until now, on `login.example.com` Octa Pass suggested every login saved anywhere on `example.com`, including the one for `shop.example.com`. On sites with many separate parts (a university, a company's tools, a hosting provider) that made the list long and the first suggestion often the wrong account.

Now, by default, a login is suggested on a page when it was saved for:

1. **the page's own address** (with or without `www.`), listed first;
2. **a domain above it**, such as `example.com` on `login.example.com`, listed next;
3. **an address below it**, such as `eu.login.example.com` on `login.example.com`, listed after those.

Logins for **other parts of the site**, such as `shop.example.com` on `login.example.com`, aren't suggested and are never filled on their own. They're one tap away: the autofill list ends with **Logins for other parts of example.com**. When you fill one from there, Octa Pass asks whether to add the page's address to that login, so next time it's suggested first.

Nothing about your saved logins changes. If you want a login offered on every part of its site, as before, open it, and under the website choose **Fill on → Every part of this domain**. Logins imported from Bitwarden with its **Base domain** rule already work that way. Equivalent domains (such as `google.com` and `youtube.com`) and passkeys work as before.

See [how domain matching works](/docs/features/autofill/#domain-matching).
