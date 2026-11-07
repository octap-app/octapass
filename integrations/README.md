# Integrations

Files other systems consume. Each one is a thin wrapper over the `octapass` CLI; the logic stays in the CLI and the core.

| Path | What it is |
|---|---|
| [`github-action/`](github-action/) | A composite GitHub Action that loads secrets with a service account token |
| [`gitlab/`](gitlab/) | A GitLab CI template to `include` |

See [Service accounts](../docs/features/service-accounts.md).
