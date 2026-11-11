---
title: The Mac app's menu bar icon no longer disappears for good
date: 2026-11-11
summary: Once macOS hid the Octa Pass menu bar icon, the app turned its own "Show in the menu bar" setting off and the icon never came back. Now only that setting decides.
tags: [desktop]
---

On macOS 26 the system can hide a menu bar icon, for example when the app it's listed under isn't allowed in System Settings → Menu Bar. That app can be the terminal or IDE that started Octa Pass. When that happened, the Mac app saved it as your choice: **Settings → Running in the background → Show in the menu bar** went off, and the icon stayed away after every later start.

Now the icon follows that setting only, and it comes back the next time Octa Pass starts. If you ⌘-drag it out of the menu bar it returns at the next start too; turn the setting off to keep it hidden.

If your icon is missing now, turn **Show in the menu bar** back on in Settings once. See [running in the background](/docs/platforms/desktop/#running-in-the-background).
