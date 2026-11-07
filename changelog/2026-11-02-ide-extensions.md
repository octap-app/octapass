---
title: VS Code and JetBrains extensions, and API keys in the browser
date: 2026-11-02
summary: Browse references and run with secrets from your IDE, and save pasted API keys or fill bearer tokens from the browser extension.
tags: [extension, docs]
---

The VS Code and JetBrains extensions browse your vault's references through [Octa Pass Connect](/docs/features/connect/), insert `octapass://` links, and run commands with secrets injected. They only ever see names: values stay in `octapass run`.

The browser extension notices an API key pasted into a form and offers to save it, working it out on your device. It can also fill bearer tokens into developer portals, under the same matching and gesture rules as logins.
