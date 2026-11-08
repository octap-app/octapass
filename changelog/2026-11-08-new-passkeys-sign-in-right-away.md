---
title: A passkey saved on iPhone or Mac signs in right away
date: 2026-11-08
summary: New passkeys show up in the system's passkey sheet as soon as they're saved, and logins that only hold a passkey no longer appear as password fills.
tags: [ios, macos, passkeys, autofill]
---

**New passkeys sign in straight away.** When Octa Pass saved a passkey for a site or an app, it stored it in the vault but didn't tell iOS or macOS about it: the system's passkey sheet only learned of it when the Octa Pass app next synced. Until then, signing in with the new passkey showed nothing. The AutoFill extension now adds the passkey to the system's list as it saves it, before it answers the site.

**Passkey-only logins aren't offered as passwords.** A login made by saving a passkey has no password. It was listed among the password suggestions too, and picking it there filled an empty password. It's now offered only through its passkey.

Deleting a passkey in Octa Pass doesn't remove it from the site: to register a new one where the site says one already exists, remove the old passkey in the site's own security settings first.
