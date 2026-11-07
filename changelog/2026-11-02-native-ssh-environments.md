---
title: SSH keys and environments on iPhone, iPad and Android
date: 2026-11-02
summary: The native phone apps can now make, read, edit and save SSH keys, and keep environments with their projects, stages and variables.
tags: [mobile]
---

The native iPhone, iPad and Android apps now have the two item types only the web vault and CLI could open.

**SSH keys:** generate Ed25519, ECDSA or RSA keys on the phone, read a key from a file or by pasting it (with its passphrase when it has one), and save the private or public key through the share sheet. The private key stays hidden until you confirm it's you.

**Environments:** project, stage and ordered variables, each concealed or not, in the editor. Paste a `.env` file or choose one, reorder variables, and copy or save the whole file. The list groups environments by project, filters by project and stage, and shows each stage. The item says which names other stages have that this one doesn't, and warns on production.

See [SSH keys](/docs/features/ssh-keys/) and [environments](/docs/features/environments/).
