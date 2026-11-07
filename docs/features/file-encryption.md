---
title: Encrypting files
description: Encrypt files and folders in the age format for yourself, other Octa Pass users or a passphrase, from the CLI, the desktop app or your file manager, and what secure delete can and can't promise.
status: in-progress
sidebar:
  order: 19
---

:::note[In progress]
`octapass encrypt`, `decrypt` and `shred` work in the CLI today, and the desktop app has them under **Tools → Files**. The right-click menus are installed by the CLI and the app, and have not yet been tried in a real Finder, Explorer, Nautilus or Dolphin window.
:::

There's no safe way to lock a normal folder with permissions: an administrator, another operating system or a disk tool can still read it. Real protection means encrypting the contents, so that's what Octa Pass does.

Files are written in the [age](https://age-encryption.org) format, so they stay readable without Octa Pass. Anyone with the right key can open them with `age` or `rage`.

## Who can open a file

| Choice | How | Opens with |
|---|---|---|
| **Yourself** | `octapass encrypt plan.pdf` | Any device signed in to your account, or your exported file key |
| **Another Octa Pass user** | `--to grace@example.com` | Their account on any of their devices |
| **Any age user** | `--to age1…` | Their age key |
| **A passphrase** | `--passphrase` | The passphrase. It can't be recovered, and can't be combined with people |

You can name several people, and add `--self` to keep a way in for yourself.

A person's key comes from your Octa Pass server. Until you've compared it, it's only as trustworthy as that server, so Octa Pass says so and shows their fingerprint. Compare it the same way as for [sharing](/docs/features/sharing/).

## From the command line

```bash
octapass encrypt plan.pdf                    # plan.pdf.age, for you
octapass encrypt photos/                     # photos.tar.age: a folder becomes one file
octapass encrypt --to grace@example.com a.txt
octapass encrypt --passphrase --armor a.txt  # text, for pasting into an email
tar c src | octapass encrypt -o src.tar.age  # stdin to a file
octapass decrypt plan.pdf.age                # plan.pdf
octapass decrypt photos.tar.age              # photos/
```

Output appears only when it's whole, and nothing is replaced without `--force`. A damaged file leaves nothing behind. `octapass encrypt` for yourself doesn't need the vault unlocked once this device knows your public key.

Inside a folder only real files and folders are included: links and special files are left out, and you're told which. Unpacking refuses an archive holding links, devices or paths that climb out of the folder, so a file from someone else can't write anywhere else on your disk.

## Without Octa Pass

```bash
octapass file-key                          # your public key: age1…
octapass file-key --export -o my-key.txt   # your secret key, for this user's eyes only
age -d -i my-key.txt plan.pdf.age > plan.pdf
tar xf <(age -d -i my-key.txt photos.tar.age)
```

The **file key** only opens files encrypted for yourself. It's derived from your account's key, one way, so exporting it gives nothing else away. Exporting asks for your master password again. Keep the export somewhere safe: anyone holding it can open those files. Files other people encrypted for your account open only through Octa Pass, because the key behind them also opens your shared vaults and is never exported.

## In your file manager

**Tools → Files → Right-click menu** in the desktop app, or `octapass context-menu install`, adds **Encrypt with Octa Pass** and **Decrypt with Octa Pass**:

| System | Where |
|---|---|
| macOS | Finder Quick Actions |
| Windows | File Explorer's right-click menu |
| Linux | Scripts in Files (Nautilus), the Dolphin context menu |

With the desktop app, the chosen files open in **Tools → Files**, where you pick who they're for. With the CLI alone, encrypting is for yourself, decrypting needs an open session, and the result shows as a notification. Everything is per user, and `octapass context-menu remove` takes it all out.

## Secure delete

`octapass shred <paths>`, `octapass encrypt --shred`, and **Delete the originals** in the app overwrite a file once with random bytes, rename it, and remove it. What that achieves depends on the disk, and Octa Pass tells you which case you're in:

| Storage | What overwriting achieves |
|---|---|
| Spinning disk with ext4 or XFS | The original blocks are overwritten. This is the only case reported as overwritten. Backups and snapshots aren't touched |
| **APFS, Btrfs, ZFS, bcachefs** (copy-on-write) | The overwrite goes to new blocks. The old ones stay until they're reused, and snapshots keep them longer |
| **SSD or flash** | The drive moves writes around, so old copies can stay in cells nothing can reach |
| Network or cloud folder | Its server and backups keep their own copies |
| Anything Octa Pass can't identify, including all of Windows | Assume old copies can stay |

Every Mac with APFS and every SSD is in a best-effort row. There the protection that works is full-disk encryption (FileVault, BitLocker, LUKS), and keeping plaintext off the disk to begin with: put the file in an [Octa Pass Safe](/docs/features/octa-pass-safe/).

Hard links are named and left alone, because their data belongs to the other name too. Symbolic links are removed without touching what they point to.

Technical details are in [encryption](/docs/security/encryption/#files-you-encrypt).
