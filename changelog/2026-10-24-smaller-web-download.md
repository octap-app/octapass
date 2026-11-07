---
title: The web vault downloads half as much
date: 2026-10-24
summary: The encryption module the web vault loads on first visit went from 1.37 MB to 0.75 MB compressed, with the same unlock speed.
tags: [web]
---

The web vault does all of its encryption in a WebAssembly module that your browser downloads the first time you open it. That module had grown to 3.85 MB (1.37 MB compressed) as importers, website matching and passkeys were added. It's now **1.88 MB (0.75 MB compressed)**.

## What changed

- **The Public Suffix List is stored as data.** This is the list that says `github.io` and `co.uk` are shared suffixes, so `alice.github.io` and `bob.github.io` are different sites. It was compiled into code, nearly 900 KB of it. It's now the list itself, about 160 KB, indexed the first time it's needed. A test checks it against the library it replaces over almost 50,000 host names. The only differences are 22 hosts where that library got nested wildcard rules wrong: with the rule `*.run.app`, `mtls.run.app` is itself a shared suffix, so it never counts as one site with its neighbours.
- **Website rules with regular expressions use a smaller engine setup.** The speed-ups and the rarely used `\p{…}` character classes are left out. Rules run on a single address, so the speed-ups never mattered.
- **The web vault's build is optimized for size,** except the password hashing (Argon2id), which still runs at full speed. Unlocking takes as long as before. The extension and the apps keep the speed-optimized build, since they carry the module with them instead of downloading it.
