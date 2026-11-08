---
title: A master password changed elsewhere unlocks your other devices
date: 2026-11-08
summary: After changing the master password on one device, the Mac, iPhone, iPad and Android apps unlock with the new one without signing out first, and the Mac's Master password screen takes typing again.
tags: [mobile, desktop, core]
---

**Unlocking after a change on another device.** Changing the master password signs your other devices out, but the copy of the vault each one keeps still opened with the old password, and the new one was refused until you signed out and back in. Now the lock screen asks the server first: a device that was signed out takes the new password and signs in again by itself, keeping everything it holds, including changes still waiting to upload. While it's online the old password is refused; offline, the copy on the device decides, as before. This also covers a device removed in Settings → Devices: unlocking with your password signs it back in. This is the native apps on the Mac, iPhone, iPad and Android; the Windows and Linux app doesn't do this yet.

**The Mac's Master password screen.** In Settings → Security → Master password the fields took only the right half of their boxes, with the dots at the far end, and a click in the empty half did nothing. The fields fill their boxes again, here and on the other Settings screens that ask for a password. A UI test changes the password in the Settings window, then locks and unlocks with the new one.

See [desktop apps](/docs/platforms/desktop/#master-password) and [mobile apps](/docs/platforms/mobile/).
