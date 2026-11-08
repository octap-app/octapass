---
title: Environments
description: Keep .env files and environment variables in the vault, give them to Docker, CI, Node, Python and plain shells, and load them in your shell as you move between projects.
status: beta
sidebar:
  order: 18
---

:::note[Where it works]
Environments work in the web vault, the browser extension, the CLI, the desktop apps and the iPhone, iPad and Android apps. The apps read, edit, filter, copy and save environments; running a command with them is the CLI's job.
:::

An **environment** is one variable (`API_KEY`) or a whole `.env` file kept as an item in your vault. Values are encrypted on your device like passwords, so the server never sees them, and the CLI hands them only to the command you run or the file you ask for. One environment can hold a project's shared settings and another its `production` values, so the same tools work on every stage.

## What an environment holds

| Field | Notes |
|---|---|
| **Title** | Such as `Shop API (production)`. |
| **Project** | A short identifier such as `shop-api` that groups one app's stages. Optional. |
| **Stage** | `development`, `staging`, `production`, `testing`, `preview`, `local`, or your own name. Optional. |
| **Variables** | An ordered list of `KEY`, value, a **concealed** flag (on by default) and an optional note. Order is kept when the environment is written to a file. |
| **Notes** | Like any item. |

A variable's name is letters, digits and `_`, and can't start with a digit. Each name is used once per environment; the editor and `env set` say which one is wrong. A lone variable is simply an environment with one entry.

A value can be an `octapass://<vault>/<item>/<field>` [reference](#references), for example a login's password. The reference is resolved only when the environment is used (`run`, `export` or the hook), and a resolved value is never written back to the vault.

## Projects and stages

An environment with a project and no stage is that project's **shared** set. When a project and stage are loaded together, the shared variables are applied first and the stage's override them:

| Order | What it is |
|---|---|
| 1 | The project's shared environment (no stage) |
| 2 | The stage's environment |
| 3 | Other environments named on the command line or in `octapass.toml`, in order |
| 4 | `--env-file` files, in order |
| 5 | References in the resulting environment |

Later values win, so a name set in `staging` overrides the shared value, and an environment named after it overrides both. `octapass env diff` shows which names are missing from one side or hold different values, without printing either value.

## In the web vault and the extension

Environments have their own category and their own section when a list is grouped by type. The list groups them by project, shows a **stage chip** on each, and filters by project and stage; a stage's item also says which keys the project's other stages have and this one doesn't. Search finds an environment by its title and variable names, never by values.

The editor is a table: add, remove, reorder and conceal variables, add a note, set the project and stage, and paste or import a `.env` file in bulk. In view mode each variable has its own reveal and copy button, and **Copy as .env** and **Download .env** work on the whole set, including concealed values. The browser extension's Octa Pass tab lists environments with the other item types and opens them in the same view.

Arabic is translated for every new string, like the rest of the web vault and the extension.

## On the computer

The CLI reads the same items. Files it writes are readable only by you (mode `0600`; on Windows the inherited permissions are replaced with one entry for your user) and are never replaced without `--force`.

| Command | What it does |
|---|---|
| `octapass env list [--vault V] [--project P]` | Lists environments, grouped by project, with their stages and the number of variables. Never prints values. |
| `octapass env show <env> [--reveal]` | Shows the variables. Concealed values stay hidden without `--reveal`. |
| `octapass env set <env> KEY=value… [--plain]` | Adds or changes variables. A bare `KEY` asks for the value without showing it; `--plain` leaves the values visible in lists. |
| `octapass env unset <env> KEY…` | Removes variables. |
| `octapass env create <title> [--vault V] [--project P] [--stage S]` | Creates an empty environment. |
| `octapass env import <file> --into <env>` | Reads a `.env` file into an existing environment, replacing names it already has. |
| `octapass env import <file> --new <title> [--project P] [--stage S]` | Creates an environment from a `.env` file. |
| `octapass env export <env> [--format dotenv\|json\|shell\|powershell\|docker] [-o FILE] [--force] [--keep-references]` | Writes the variables to stdout or a file. |
| `octapass env diff <project> <stage> <stage>` or `octapass env diff <env> <env>` | Lists missing and different names, without values. |
| `octapass run --env <env> [--env <env>] … -- <command>` | Runs a command with the environments, and any `octapass://` references, applied. |
| `octapass run --project P --stage S -- <command>` | Loads the project's shared set and that stage, then runs. |
| `octapass inject -i template -o out [--force]` | Replaces `octapass://` references in any text file. |
| `octapass env hook zsh\|bash\|fish\|powershell` | Prints a shell hook that loads a folder's environment as you `cd` into it. |
| `octapass env allow [path]` / `octapass env deny [path]` | Allows or stops the hook for a folder's `octapass.toml`. |

An environment can be named by its title (any case), its id, `vault/title`, or `project:stage` (`project:` alone is the shared set). `--json` works like the other commands. See the [CLI reference](/docs/platforms/cli/#environments) for the details and exit codes.

### References

A variable's whole value can point at another item's field:

```bash
octapass env set "Shop API (production)" DB_PASSWORD=octapass://Personal/Postgres/password
octapass run --env "Shop API (production)" -- ./migrate.sh
```

`octapass env export` writes the resolved value; `--keep-references` writes the reference as written. A reference is followed one step: if the value it points to is itself a reference, `run` stops with a clear error rather than looping. `octapass://<vault>/<item>/<KEY>` also reads a variable of an environment item directly, so a config file can point at a single variable instead of a whole item.

### A project file

Put an `octapass.toml` in a repository (the CLI looks in the current folder and its parents, up to the repository root) to say what `octapass run` and the shell hook load by default:

```toml
project = "shop-api"
stage = "development"
env = ["Personal/Shop API extras"]
vault = "Personal"
```

`--env`, `--project` and `--stage` on the command line override it. `OCTAPASS_STAGE` overrides the file's stage without editing it, which is handy in CI.

:::caution[Production asks first]
Loading a `production` stage that you didn't name explicitly asks for confirmation. Pass `--stage production` (or `--env shop-api:production`) to say you mean it, or `--yes` for a script. The shell hook asks the same way, and refuses when it has no terminal; it never asks for your master password.
:::

### The shell hook

`octapass env hook zsh` (or `bash`, `fish`, `powershell`) prints the code for your shell's startup file:

```bash
eval "$(octapass env hook zsh)"
```

At each prompt, in a folder with an `octapass.toml` that you allowed once with `octapass env allow`, the hook loads the project's environment and unloads it when you leave, when the file changes, or when Octa Pass locks. Nothing loads while the CLI is locked, and the hook never asks for the master password: run `octapass unlock` first. The allow list is kept in the CLI's data folder and is keyed by the file's path and contents, so editing `octapass.toml` asks again, as [direnv](https://direnv.net) does.

The hook sets variables in your shell only for the time you're in the project. Octa Pass never writes secrets to the system's persistent environment (`setx`, `/etc/environment`, `launchctl setenv` or your shell's startup files): they would sit there in plaintext for every program. Use `run`, the hook, or a file that is deleted afterwards.

## Docker

For Compose, either let the shell or `octapass run` provide the variables for `${KEY}` interpolation:

```bash
octapass run --env "Shop API (development)" -- docker compose up
```

```yaml
services:
  api:
    image: shop-api
    environment:
      - DATABASE_URL
      - LOG_LEVEL
```

or write a file for the `env_file:` setting. `--env-file-out` writes the environment to a file that is readable only by you for as long as the command runs, then deletes it, including when you press Ctrl-C:

```bash
octapass run --project shop-api --stage development \
  --env-file-out .env -- docker compose up
```

For a single container, `docker run --env-file` reads a plain `KEY=value` file:

```bash
docker run --env-file <(octapass env export "Shop API (development)" --format docker) shop-api
```

That process substitution is for bash and zsh on macOS and Linux; PowerShell and `cmd` need a temporary file (and `--format docker` refuses multi-line values, because Docker's format has no quoting).

Build-time secrets shouldn't become image layers. Pass them as BuildKit secrets, never as `ARG` or `ENV`:

```bash
octapass run --env "Shop API (development)" -- \
  docker build --secret id=npm_token,env=NPM_TOKEN .
```

```dockerfile
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci
```

An `ARG` or `ENV` value is kept in the image's history and readable by anyone who pulls it, even if a later layer removes it.

## CI

CI runners are non-interactive, so give the CLI the master password and Secret Key through the runner's secret store, then use `run` for the steps that need secrets:

```bash
printf '%s\n' "$OCTAPASS_PASSWORD" | octapass --password-stdin login --server "$OCTAPASS_SERVER"
octapass run --project shop-api --stage testing --yes -- npm test
```

`OCTAPASS_SECRET_KEY` covers the Secret Key on a first login without a terminal, and `OCTAPASS_TWO_STEP_CODE` a two-step code. The session stays in the runner's keyring (or in the data folder with `OCTAPASS_NO_KEYRING=1`, which does not keep the master password). Mark the variables as secret in the CI system, and don't echo them or pass them to `docker build` as build arguments. `--yes` skips the production confirmation for a named `production` stage; use it only where the job is meant to touch production.

## Node, Python and plain shells

Node reads `process.env`, Python `os.environ`, so `run` is enough:

```bash
octapass run --project shop-api -- npm start
octapass run --env "Shop API (testing)" -- python manage.py migrate
```

Tools that only read a `.env` file can get one for their lifetime:

```bash
octapass run --env "Shop API (development)" --env-file-out .env.local -- next dev
```

A plain shell can load an environment for one command or for the session, without writing it to disk:

```bash
eval "$(octapass env export "Shop API (development)" --format shell)"
```

The variables stay in that shell until you close it or unset them; `octapass run --env … --` keeps them to the command instead.

`--format shell` writes `export KEY='value'` lines for sh, bash and zsh, and `--format powershell` writes `$env:KEY = 'value'` lines:

```powershell
octapass env export "Shop API (development)" --format powershell | Out-String | Invoke-Expression
```

Windows differences: files written by the CLI use an owner-only ACL instead of Unix mode bits; PowerShell is the native shell format; the hook is installed in your PowerShell profile; and process substitution isn't available, so write `--env-file-out` or an export file for Docker. Docker Desktop, WSL and Git Bash otherwise behave like their Linux counterparts.

## Import, export and backups

- **Import:** a `.env` file in the editor (paste or choose a file) or with `octapass env import`. `#` comments and an optional `export ` are understood; multi-line double-quoted values (such as PEM keys) are kept; a name used twice is an error that names the line.
- **Export:** `.env` (dotenv), JSON, POSIX shell, PowerShell, or Docker's `--env-file` format. Exporting and importing again gives an equivalent file. `env export -o` writes a file readable only by you and won't replace one without `--force`.
- **Octa Pass backups:** environments are part of the encrypted Octa Pass export and import without losing their variables, order, concealed flags, notes, project or stage. The CSV export has no columns for them, so their variables go in the notes column, as cards and Wi-Fi networks do.

:::caution[Files are not encrypted]
`env export -o`, `--env-file-out` and `inject -o` write plaintext. They are private to your user, but anything that can read your files while the file exists can read the secrets. Delete exported files when you're done, and prefer `run` or the hook when a tool can take environment variables.
:::
