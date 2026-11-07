---
title: Bank accounts, ID documents, crypto wallets and your own item types
date: 2026-11-02
summary: Seven new kinds of item in every app, payment QR codes for bank accounts and wallets, and imports that keep these items as what they are.
tags: [core, extension, desktop, mobile, cli]
---

Octa Pass can now keep more than logins and notes, each with fields that suit it. Everything is encrypted on your device like any other item.

- **Bank accounts:** bank, holder, IBAN, account number, routing or sort code, SWIFT code, branch and a hidden PIN. IBANs and SWIFT codes are checked when you save.
- **ID documents:** passports, driver's licences and national IDs, with issue and expiry dates. Scans are attachments.
- **Crypto wallets:** a hidden seed phrase, an optional passphrase, and addresses by network.
- **API credentials, software licences, and databases or servers**, whose connection string is hidden because it usually holds the password.
- **[Custom items and templates](/docs/features/item-types/):** define your own fields, save them as a template and reuse it. Templates hold field names, never values.

**QR codes.** A bank account in the SEPA area shows an EPC payment code, with an optional amount and reference. A wallet shows `bitcoin:` and `ethereum:` address links, or the plain address on other networks. The seed phrase, passphrase and PIN are never in a code, and the apps refuse a seed phrase pasted where an address goes.

**Imports and exports.** Importers that recognise these kinds of item now bring them in as the new types instead of notes, and both the Octa Pass export and CXF keep them. See [plan 07](https://github.com/octapass/octapass/blob/main/plans/07-import-export.md) for how CXF carries types it has no name for.

The CLI reads the new types: `octapass get "Savings" --field iban`, with hidden fields marked as secrets. It can't create them yet.
