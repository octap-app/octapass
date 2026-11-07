---
title: Attachments and Document items
date: 2026-10-24
summary: Keep files with any item, or store them as Document items. Files are encrypted on your device before upload; the server stores ciphertext and its size only.
tags: [core, server, web, desktop, security]
---

You can now attach files to any item, and make **Document** items: a file plus notes. See [attachments and documents](/docs/features/attachments/).

## What's new

- **Attach files** from an item, or drop them onto it. Download and remove them from the same place. When you edit an item, files you add or remove are applied when you save.
- **Document items** in the editor, the item view and a new Documents category.
- **Storage in Settings**: how much of your 1 GB you use, and the size limit for one file (100 MB on the Octa Pass service).
- Works in the web vault and the desktop app. The mobile apps show Document items and keep their files, but can't open or add files yet.

## How files are protected

- Each file gets its own random key, wrapped by the item's key. The file is encrypted in 64 KiB chunks with XChaCha20-Poly1305, so neither your device nor the server needs it whole in memory, and a file that was changed, cut short or moved to another item fails to open instead of showing part of it.
- The file's name, type, size and key live in the item's encrypted details. The server sees only how big each encrypted file is and when it was added.
- In a shared vault everyone with access can open the files, and they count against the vault owner's storage. Removing someone from a vault doesn't require re-encrypting files.

## For self-hosters

- Files go to the data directory by default, or to S3-compatible storage with `OCTAPASS_S3_*` (AWS S3, MinIO, Garage and others). Limits are set with `OCTAPASS_MAX_ATTACHMENT_BYTES` and `OCTAPASS_MAX_FILE_BYTES`. See [configuration](/docs/self-hosting/configuration/#attachments).
- Files are deleted with their item when the trash is emptied, with their vault, and with the account. Deletions from object storage are queued and retried until they succeed.
- New endpoints: upload, download, list and delete under `/v1/vaults/{vaultId}/items/{itemId}/attachments`, and `GET /v1/account/usage`. See the [sync API](/docs/developers/sync-api/#attachments).
