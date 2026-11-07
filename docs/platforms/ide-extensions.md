---
title: IDE extensions
description: The Octa Pass extensions for VS Code and JetBrains IDEs browse your references, insert octapass:// links, and run commands with secrets injected, without ever reading a secret value.
status: in-progress
sidebar:
  order: 7
---

:::note[In progress]
Both extensions are built and tested on their own, but neither has been tried inside a real IDE yet, and there are no published builds. See each one's README to build it.
:::

The VS Code extension (`apps/vscode`) and the JetBrains plugin (`apps/jetbrains`, IntelliJ 2024.1 and later) do three things:

- **Browse references:** a tree of vault, item and field. Names only: no value is ever fetched for it.
- **Insert a reference:** puts `octapass://<vault>/<item>/<field>` at the cursor.
- **Run with secrets:** runs your command as `octapass run -- <command>` in the IDE's terminal, so the CLI resolves references. The value never enters the extension.

## Connect first

Browsing goes through [Octa Pass Connect](/docs/features/connect/), so start it (`octapass connect serve`, or the desktop app) and run **Octa Pass: Connect**. Approve the prompt; the prompt may name a helper program rather than the IDE itself.

The token is kept in the IDE's own secret store: VS Code's SecretStorage or the JetBrains PasswordSafe. **Octa Pass: Disconnect** gives it up. An IDE update can move the program that was approved, and then you approve it again.

**Run with secrets** doesn't use Connect. It needs the CLI's own session: run `octapass unlock` first.

## Good to know

- In `a && b`, only `a` gets the secrets, because the shell splits the line before `octapass run` sees it. Use a script, or `sh -c`.
- The path to the CLI is a machine-level setting (`octapass.cliPath` in VS Code), so a repository's settings can't swap the program. Run with secrets is off in untrusted workspaces.
- In a VS Code remote window, the terminal is on the remote machine, so it needs `octapass` there.
- Items with the same name in a vault are referenced by id.
