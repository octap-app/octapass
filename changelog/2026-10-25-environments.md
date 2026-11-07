---
title: Environments and .env files in the vault
date: 2026-10-25
summary: Keep a project's environment variables in the vault, edit them as a table in the web vault and extension, and load them into commands, files and your shell from the CLI.
tags: [core, cli, extension, docs]
---

**Environments** are now an item type: a project, a stage and an ordered list of variables, each hidden by default and with an optional note. A project's environment without a stage is its **shared** set; the stage's values load after it and override it. One variable is an environment with one entry.

- **Web vault and extension:** environments have their own category, group by project, show a stage chip, and filter by project and stage. The editor adds, removes, reorders and conceals variables, takes notes, and pastes or imports a `.env` file. View mode copies each value, or the whole set as `.env` (or downloads it). Production is marked. Search finds names, never values.
- **CLI:** `octapass env list|show|set|unset|create|import|export|diff`, `octapass run --env … -- command`, `--project`/`--stage`, `--env-file-out`, `octapass inject`, an `octapass.toml` project file and a shell hook for zsh, bash, fish and PowerShell. Exports are available as dotenv, JSON, shell, PowerShell and Docker formats. A production stage asks before it loads, and `env diff` compares stages without printing values.
- **Careful by default:** `env show` hides concealed values without `--reveal`, files are readable only by you (`0600`) and are not replaced without `--force`, temporary files are deleted when the command ends, and Octa Pass never writes secrets to your system's persistent environment.
- **Everywhere else:** Arabic covers every new string, the encrypted Octa Pass export keeps variables, their order, concealment, notes, project and stage, and the CSV export puts them in the notes column as it does for cards and Wi-Fi. The [environments page](/docs/features/environments/) has Docker, CI, Node, Python and plain-shell recipes.

See [Environments](/docs/features/environments/) and the [CLI reference](/docs/platforms/cli/#environments). The native phone apps come in a later wave; the desktop app reuses the web vault's screens.
