---
title: Importing straight from Apple Passwords works on the iPhone
date: 2026-11-04
summary: Moving passwords from the Passwords app to Octa Pass with Export Data to Another App failed with "This file can't be imported with the source you chose". It now imports.
tags: [mobile, core]
---

On iOS 26, the Passwords app can hand your passwords, passkeys and codes straight to another app (**Export Data to Another App**). Choosing Octa Pass failed with "This file can't be imported with the source you chose".

Apple sends dates with fractions of a second, and Octa Pass only accepted whole seconds, as the Credential Exchange format specifies. It now reads both, so the export comes across with its dates. Nothing else about the import changed: you still see what's coming before anything is saved. See [importing from another app](/docs/import-export/from-cxf/).
