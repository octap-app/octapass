---
title: Bank accounts, licences and the other newer types fill, warn before they expire, and come from the CLI
date: 2026-11-08
summary: The browser extension fills bank accounts, database sign-ins, licence keys, ID numbers and wallet addresses; Health warns about expiring licences and API keys; and octapass create makes every type you type in.
tags: [extension, desktop, mobile, cli, docs]
---

The item types added on 2 November ([item types](/docs/features/item-types/)) now do what the older ones do.

**Autofill.** The [browser extension](/docs/features/autofill/#bank-accounts-licences-and-the-other-types) fills:

- **bank accounts** into payout, direct debit and transfer forms: account holder, IBAN, SWIFT/BIC, bank name, account number and routing number or sort code. Never the PIN.
- **databases** into a database console's sign-in, such as Adminer or phpMyAdmin: server, port, database, user name and password.
- **licence keys**, **ID document numbers** and **wallet addresses**, each only into the field you picked from. A wallet's seed phrase is never filled anywhere.

Like cards, they're offered only in the fields that take them and filled only when you pick one, with the same device auth and safety checks as a login. A bank's sign-in that asks for an account number and sort code stays a sign-in. On the desktop, auto-type types a database's user name and password into a database client. Phones fill logins and codes only, as before.

**Expiry warnings.** Health lists software licences and API credentials that have expired or will within 60 days, beside cards and ID documents, in every app.

**The CLI.** `octapass create` makes bank accounts, API credentials, licences, ID documents, crypto wallets, databases, custom items and templates, with each type's fields and the same checks the apps make (IBAN check digits, dates, ports). See [changing items](/docs/platforms/cli/#changing-items).

Also fixed: in the extension, a login form in a same-origin frame that you clicked into right after the page loaded sometimes showed no menu.
