---
title: Octa Pass Safe
description: An encrypted folder that locks with your vault, with file contents and names encrypted per file, optional sync through your server, and what each system can show.
status: in-progress
sidebar:
  order: 20
---

:::note[In progress]
Safes work in the CLI and in the desktop app's **Tools → Files**, and sync between devices. Each system's file manager integration is built; see [where a Safe appears](#where-a-safe-appears) for what's been tested where.
:::

A Safe is a folder whose contents are encrypted on disk, one file at a time. While your vault is unlocked you use it like any other folder. When the vault locks, the keys are gone and what's left on disk is unreadable. "Locking a folder" in Octa Pass is always this encryption, never permissions.

## How it works

- **Each file is encrypted on its own**, under its own random key, and each change gets a new key. Names are encrypted too.
- **The folder on disk is a flat set of blobs with random names.** It doesn't show how many folders you have or which files belong together. It does show roughly how big each file is, how many there are, and when they change.
- **It locks with the vault.** The Safe's key is an item in your personal vault, so it's protected like your passwords, opens with the device unlock you already use, and isn't readable while the vault is locked. Open files are saved first.
- **Nothing readable is written while you work.** A file being written waits in a temporary file encrypted under a key that exists only in memory, so a crash leaves nothing to read.

## Using one

```bash
octapass safe create Taxes
octapass safe add Taxes return.pdf --to 2026
octapass safe ls Taxes 2026
octapass safe get Taxes 2026/return.pdf -o copy.pdf
octapass safe mv Taxes 2026/return.pdf 2026/final.pdf
octapass safe rm Taxes 2026 --recursive
```

In the desktop app, **Tools → Files → Safes** lists them. Open one to browse, drop files on the window to add them, and save decrypted copies. **Lock** closes it straight away.

## Sync

A Safe stays on one device unless you turn sync on, with `--sync`, `octapass safe set-sync <name> on`, or the switch in the app.

A Safe kept on one device is listed only on that device. Its key is in your vault like any other Safe's, so it's still protected and backed up with your vault, but your other devices leave it out: they have none of its files. Safes made in the Mac, iPhone or Android app before 2026-11-07 don't record their device, so they're listed wherever their folder is.

Its encrypted blobs then go through your Octa Pass server and count towards your storage. The server sees their sizes and when they change, never names or contents. Your other devices get the Safe's key from your vault and fetch the blobs when they open it.

- A rename only sends one small record, so reorganising costs almost nothing.
- If a file changes on two devices, both versions are kept: the other is saved beside it as `report (conflict 2026-11-02).pdf`.
- An edit beats a deletion. The file comes back.
- A file bigger than the server's per-file limit (100 MiB by default) stays on the device, and you're told which.

## Where a Safe appears

| System | How | State |
|---|---|---|
| CLI | `octapass safe` commands | Tested against a real server, two devices included |
| Desktop app | **Tools → Files**: browse, add by dropping files, save copies, sync, delete | Tested with a fake host in the UI tests; the Rust commands are unit tested |
| Linux | A folder, through FUSE: `octapass safe mount Taxes ~/Taxes`, or **Show as a folder** in the app | Tested on real mounts in a container. Needs a build with the `fuse` feature |
| macOS | Finder's sidebar, under Locations, through a File Provider extension | Built and tested against the app's socket; not yet loaded by macOS, which needs a signed build |
| Windows | File Explorer, through the Cloud Files API: **Show as a folder** | Written and type-checked; not yet run on Windows |
| Android | The Files app and any file picker, through a documents provider | Built and unit tested; not yet run on a phone |
| iPhone and iPad | The Files app, through a File Provider extension | Built for the simulator; not yet run on a phone |

The Mac, iPhone and Android apps sync synced Safes in the background: a few seconds after you change one, in the app or in Finder or Files, after each vault sync, and every two minutes while the vault is unlocked. The Windows and Linux app syncs open ones along with your vault. On a phone, **Safes** is a tab at the bottom of the app. **Sync now** syncs a Safe straight away and shows what it found.

If a Safe was deleted on another device, deleting it here still works. This device finds out it's already gone and removes its files.

To delete a Safe, open it and choose **Delete Safe**, or run `octapass safe delete <name>`. You type its name to confirm. Its key goes to the trash with it, and its files on your devices go straight away.

### What the system holds while unlocked

On Linux, decrypted data only passes through memory: the system's file cache, which goes when the mount does.

On Android, files open through a pipe from the app, so nothing decrypted is written either.

**File Provider on macOS and iPhone, and Cloud Files on Windows, work differently:** the operating system keeps a decrypted copy on disk of each file you open, in the folder it manages. Octa Pass removes those copies when the Safe or the vault locks, and at start-up in case the app crashed while unlocked, so between a crash and the next start they stay on disk. On a Mac, the names in an open Safe also go into Spotlight's index, and opened copies can reach Time Machine. If that matters, use the app's own Safe browser, keep full-disk encryption on, or exclude the Safe from Time Machine.

On iPhone and iPad, the Files extension can't unlock your vault, so while a Safe is open the app leaves just that Safe's key in the device's Keychain, readable only while the phone is unlocked and only until the app's auto-lock time. Locking removes it. If the app is closed by force while unlocked, the Safe stays readable in Files until that time passes or you open the app again.

## What it doesn't protect against

- Malware on an unlocked device can read what you can.
- Decrypted copies you save out of a Safe are ordinary files.
- **Rollback.** Blobs are authenticated, so they can't be changed or swapped. A server can still hold back the newest version of a file. Each device remembers the newest version it saw and warns if a file goes backwards or disappears, but a device that never saw the newer version can't tell.
- Losing your vault means losing your Safes: there's no other copy of the key. Recovery works as for the rest of your vault.

Technical details are in [encryption](/docs/security/encryption/#octa-pass-safe).
