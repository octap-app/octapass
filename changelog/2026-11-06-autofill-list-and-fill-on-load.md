---
title: The autofill list narrows as you type, and can fill when a page opens
date: 2026-11-06
summary: In the browser extension, the in-page list now shows only the logins matching what you type in the username field, its text is readable on every site, and an opt-in setting fills the login you used last as soon as a sign-in page opens.
tags: [decision, security, extension, desktop, mobile]
---

**The list narrows as you type.** In a username field, the browser extension's in-page list now shows only the logins whose username or name contains what you've typed. It opens as you start typing and closes when nothing matches. Clear the field to see every login again.

**Fill when a page opens (opt-in).** A new setting, **Settings → Filling → Fill logins when a page opens**, fills a sign-in form as soon as the page shows it, the way Chrome and Firefox do, with the login you used last on that site. It's off by default, on each device, never synced. When it's on:

- it only fills secure `https://` pages, never a form inside a frame
- it only uses logins saved for that exact address
- it only fills a visible form whose fields are empty
- it only fills while Octa Pass is unlocked, and never when filling would ask you to confirm it's you first

Start typing in a filled field to replace what was filled. Typing over the username also clears the password. Clicking the field still opens the full list.

This is the one exception to "Octa Pass fills only after you pick something", and it's off by default because a website can read what's filled before you do anything. See [filling when a page opens](/docs/features/autofill/#filling-when-a-page-opens) and the [threat model](/docs/security/threat-model/).

**Fixed:**

- The in-page list's text was tiny on sites that shrink their base font size. It now has the same size everywhere.
- In Settings, a switch that doesn't apply right now (for example **Use device auth when Octa Pass opens** and **Ask on every fill** while **Stay unlocked** is on) now shows greyed out instead of looking active.
- AutoFill on iPhone and iPad now finds your logins in Chrome and other browsers, not just Safari. One address the browser sent that Octa Pass couldn't read used to fail the whole list.
- Logins saved without `https://` now show up in the QuickType bar.
- With **Stay unlocked** on, picking a password or code in the QuickType bar fills it straight away. A suggestion whose login was deleted shows the logins for that site instead of an error.
- The AutoFill list on iPhone is easier to read in dark mode: logins use the normal text colours instead of blue.
