---
title: An agent skill for the octapass CLI
date: 2026-11-08
summary: skills/octapass-cli teaches AI agents to use the octapass command line without exposing secrets, and its tests check every command it names against the CLI's --help.
tags: [docs, cli, security]
---

Next to `octapass-docs`, the repository now has a second [agent skill](/docs/contributing/ai-agents/#the-octapass-cli-skill): `skills/octapass-cli/`. It teaches Claude Code, Codex, Cursor and other agents to use the [`octapass` CLI](/docs/platforms/cli/) for you. That covers finding and reading items, creating and editing them, generating passwords and one-time codes, handing secrets to commands with `octapass run` and `octapass://` references, environments, service accounts in GitHub Actions and GitLab CI, SSH keys and file encryption.

It starts with rules the agent follows before anything the task asks:

- It prints no secret unless you ask for that value. It looks at items with `octapass get`, which leaves secrets out, never with `get --json`, which includes them.
- It hands secrets to programs through `octapass run` and references instead of copying values.
- It never asks for, stores or passes your master password or Secret Key. When the vault is locked, you unlock it yourself, in your terminal or through the desktop app.
- It confirms before deleting, overwriting, exporting or changing your account, and never answers the CLI's own questions with `--yes`.

The skill is tested against the real CLI. The tests read the built binary's `--help` for all 135 commands and fail when the skill names a command, option or value that doesn't exist, an environment variable the CLI doesn't read, or exit codes that differ from the CLI's. They also fail when the CLI gains a command the skill doesn't cover. CI now runs them, and the `octapass-docs` tests, on every push.

The skill is on the website at `/skills/octapass-cli/SKILL.md`, and `llms.txt` links to it.
