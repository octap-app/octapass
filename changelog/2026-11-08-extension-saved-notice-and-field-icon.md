---
title: The extension's saved notice waits for you, and its field icon always answers
date: 2026-11-08
summary: In the browser extension, "Saved in Octa Pass" after a suggested password stays until you close it or the sign-up goes through; the Octa Pass icon in a field always opens its list; and ticking "Hide this value" in the editor no longer blanks the tab.
tags: [extension, web]
---

**Browser extension:**

- **"Saved in Octa Pass" stays.** After you use a suggested password, Octa Pass saves the login as **Unconfirmed** and says so. That message used to close by itself after four seconds. It now stays until you close it, and when you send the sign-up form with that password the login is confirmed and the message goes.
- **The icon in a field always answers.** Clicking the Octa Pass icon, or pressing **↓**, in a field your vault has nothing for (such as the Secret Key on the Octa Pass sign-in page) did nothing. The list now opens and says **Nothing saved for this field**. Clicking into such a field still opens nothing.
- **"Hide this value" in the item editor** no longer turns the Octa Pass tab blank (black in dark mode). The checkbox's hidden input sat outside the editor's scrolling pane, so ticking it scrolled the whole page away. The fix is in the shared checkbox, so the web vault has it too.

See [autofill](/docs/features/autofill/).
