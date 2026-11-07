# Octa Pass for VS Code

A generic client of [Octa Pass Connect](../../docs/developers/connect-api.md). It does three things:

- **Browse references.** A view in its own activity bar container lists vault, item and field. Names only: it never asks for a value.
- **Insert references.** "Octa Pass: Insert Reference", or a click on a field, puts `octapass://<vault>/<item>/<field>` at the cursor.
- **Run with secrets.** "Octa Pass: Run with Secrets" asks for a command and runs `octapass run -- <command>` in a terminal. The CLI reads the secrets there; the extension never sees them. It remembers the last command per workspace.

"Octa Pass: Connect" asks for approval and keeps the token in VS Code's SecretStorage, nowhere else. "Octa Pass: Disconnect" gives it up.

It talks only to the Connect endpoint on your own computer, found in the order the docs give: `OCTAPASS_CONNECT`, the socket, then the port file. It activates when you open its view or run one of its commands.

## Settings

`octapass.cliPath` is the CLI that Run with Secrets uses, by default `octapass`. It can only be set in user settings, so a project's `.vscode/settings.json` can't point it at another program. Run with Secrets is off in untrusted workspaces.

## Good to know

- Connect has to be running: `octapass connect serve`, or turn it on in the desktop app.
- The command goes to the shell as you typed it, so in `a && b` only `a` gets the secrets. Use a script, or `sh -c`, for more than one command.
- Two items with the same name in a vault are written by id in the reference, because their name wouldn't say which one.
- In a remote window the extension still runs on your own computer, with your Connect, but the terminal is on the remote machine. `octapass run` has to be available there.

## Developing

```sh
pnpm install
pnpm --filter @octapass/vscode test
pnpm --filter @octapass/vscode typecheck
pnpm --filter @octapass/vscode run stage
code --extensionDevelopmentPath="$PWD/apps/vscode/dist/stage"
```

`stage` is there because VS Code doesn't allow a scoped extension name: `dist/stage` holds the same extension with the manifest named `octapass`. To package it, run `npx @vscode/vsce package` in that folder, or `pnpm build:vscode` from the repository root, which stages and packages `dist/octapass-<version>.vsix`.
