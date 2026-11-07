# Octa Pass for JetBrains IDEs

A generic client of [Octa Pass Connect](../../docs/developers/connect-api.md). It does three things:

- **Browse references.** The Octa Pass tool window lists vault, item and field. Names only: it never asks for a value.
- **Insert references.** "Insert Octa Pass Reference" (Tools > Octa Pass, or the editor's context menu) opens a chooser and puts `octapass://<vault>/<item>/<field>` at the caret. A double click or Enter on a field in the tool window does the same.
- **Run with secrets.** "Run with Secrets" asks for a command and runs `octapass run -- <command>` in a terminal tab. The CLI reads the secrets there; the plugin never sees them. It remembers the last command per project.

"Connect" asks for approval and keeps the token in the IDE's PasswordSafe, nowhere else. "Disconnect" gives it up.

It talks only to the Connect endpoint on your own computer, found in the order the docs give: `OCTAPASS_CONNECT`, the socket, then the port file.

## Settings

Settings > Tools > Octa Pass holds the CLI that Run with Secrets uses, by default `octapass`. It's an application setting, so no project can point it at another program.

## Good to know

- Connect has to be running: `octapass connect serve`, or turn it on in the desktop app.
- The command goes to the shell as you typed it, so in `a && b` only `a` gets the secrets. Use a script, or `sh -c`, for more than one command.
- Two items with the same name in a vault are written by id in the reference, because their name wouldn't say which one.

## Layout

| Path | What lives there |
|---|---|
| `client/` | The Connect client, references and the run line. No IntelliJ imports and no dependency beyond Kotlin, so it builds and tests without the SDK |
| `plugin/` | The tool window, actions, settings and token storage, on the IntelliJ Platform |

## Developing

JDK 17. The plugin builds against IntelliJ IDEA 2024.1, the newest platform that runs on JDK 17, and is marked for 2024.1 and later.

```sh
./gradlew :client:test     # No SDK needed
./gradlew test buildPlugin # Downloads the IntelliJ Platform once
./gradlew :plugin:runIde   # Tries it in a sandbox IDE
```

`pnpm build:jetbrains` from the repository root runs `buildPlugin`; the plugin's `.zip` lands in `plugin/build/distributions`.
