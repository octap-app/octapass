---
title: Files in the iPhone and Android apps
date: 2026-10-24
summary: The mobile apps can now add, open and remove attachments and Document files, offline too, with the system's own pickers and viewer.
tags: [mobile, security]
---

Attachments and Document items now work in the iPhone and Android apps. See [attachments on your phone](/docs/features/attachments/#on-your-phone).

## What's new

- **Add files** from the Files app or your documents, the system photo picker, or the camera. Octa Pass only gets the files and photos you pick.
- **Open files** in Quick Look on iPhone, or in the app you choose on Android, and share them from there. The decrypted copy lives in the app's private storage and is deleted when you close it and whenever the vault locks.
- **Offline:** files are encrypted and kept on the phone, marked **Waiting to upload**, and upload after their item the next time the app syncs. They open offline too.
- **Storage in Settings**, as in the web vault.
- An edit to the same item on another device no longer turns file changes into a conflicting copy: they're added to the other version, and only other edits become a copy. Conflicting copies never list files any more, because a file's key belongs to its original item.

## How files are protected

- Files are encrypted by the app's Rust core before upload, with the same format as the web vault and the desktop app. Their contents never pass through the app's web view.
- Files waiting to upload are stored on the phone as ciphertext only, exactly as the server will hold them.
