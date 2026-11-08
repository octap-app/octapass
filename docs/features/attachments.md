---
title: Attachments and documents
description: Keep files with any Octa Pass item, or store them as Document items. Files are encrypted on your device; the server stores ciphertext and its size only.
status: beta
sidebar:
  order: 1.5
---

:::note[Where it works]
Attachments and Document items work in the web vault, the browser extension, the desktop apps and the iPhone, iPad and Android apps, with an account on an Octa Pass server. The CLI doesn't handle files, and a [vault without an account](/docs/features/local-vault/) can't hold them.
:::

You can keep files with any item: a scan of a card with the card, a recovery sheet with a login, a signed lease with your notes about it. A **Document** item is a file plus notes, for files that stand on their own.

## Adding files

- In an item, use **Attach files**, or drop files onto the Files section.
- When you edit an item, files you add or remove are applied when you save.
- To make a Document, choose **New item → Document**, pick its file and save.

Files you add are encrypted on your device before they're uploaded. Downloading decrypts them on your device again. A file that was changed or cut short on the way fails to open instead of showing you part of it.

## On your phone

- In an item, add files with **Choose files** (the Files app or your phone's documents), **Photos** (the system photo picker; Octa Pass only gets the photos you pick) or **Take a photo** where the phone has a camera.
- Tap the eye button to open a file. Octa Pass decrypts it into its own private storage and shows it in Quick Look on iPhone, or in the app you pick on Android; from there you can share it. The decrypted copy is deleted when you close it, and whenever the vault locks.
- Offline, files you add are encrypted and saved on the phone, marked **Waiting to upload**, and you can already open them. They upload, after their item, the next time the app syncs. Files you remove offline are deleted from the server then.
- If another device changed the same item meanwhile, your file changes are added to its version; only other edits you made become a conflicting copy.
- A file the server refuses when it finally uploads (too large, or over the storage limit) is taken off the item again.

The file's contents never pass through the app's web view: the phone's pickers hand them straight to the part of the app that encrypts them.

## Limits

| | Octa Pass service | Self-hosted default |
|---|---|---|
| Storage | 1 GB per account | 1 GiB, [configurable](/docs/self-hosting/configuration/#attachments) |
| One file | 100 MB | 100 MiB, configurable |

Storage counts the files in vaults you own, including items in the Trash. Files in a [shared vault](/docs/features/sharing/) count for the vault's owner, whoever added them. Settings shows how much you use.

## Sharing, moving and deleting

- Everyone with access to a shared vault can open its files. Members who can edit can add and remove them.
- Copying or moving an item to another vault encrypts its files again for the new item.
- [Share links](/docs/features/sharing/#one-time-share-links) don't include files.
- A file is deleted from the server when you remove it, when its item is emptied from the Trash after 30 days, and when you delete your account.
- The [encrypted export](/docs/import-export/export/) includes the files. The other export formats leave them out.

## How it's encrypted

Each file gets its own random key, wrapped by the item's key, and the file is encrypted in 64 KiB chunks with XChaCha20-Poly1305. The file's name, type, size and wrapped key are stored in the item's encrypted details. The details are in [encryption](/docs/security/encryption/#files).

The server sees that an item has files, how big they are once encrypted and when they were added. It never sees their names, types or contents. See [what the server sees](/docs/security/what-the-server-sees/).
