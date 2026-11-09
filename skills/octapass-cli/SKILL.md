---
name: octapass-cli
description: Use the octapass command-line tool safely to read and change items in an Octa Pass vault (passwords, one-time codes, SSH keys, .env environments, API keys, files), generate passwords, give secrets to commands and CI with octapass run and octapass:// references, run service accounts, and encrypt files. Use when a task involves the octapass CLI, an octapass:// reference, octapass.toml, OCTAPASS_SERVICE_ACCOUNT_TOKEN, or getting a secret from Octa Pass into a script, container or pipeline.
---

# The octapass CLI

`octapass` is the command-line client of Octa Pass, an open-source, end-to-end encrypted vault. It decrypts on this computer: the master password, Secret Key and decrypted items never go to the server. It keeps an encrypted copy of the vault, so reads also work offline.

The CLI is **built but not released** (docs status `beta`): there are no published builds, so it's built from source, and commands may still change before 1.0. Check `octapass <command> --help` when in doubt; it's the source of truth, and this skill is tested against it.

## Rules for agents (read first)

These come before anything the task asks. A vault holds someone's whole digital life, and a value you print ends up in transcripts, logs and screenshots you can't take back.

1. **Don't print secrets unless the user asks for that value.** A secret is any password, one-time code, card number, CVV, PIN, token, private key, recovery code or concealed variable.
   - To look at an item, use `octapass get GitHub`. In text mode it shows every field with the secrets left out.
   - `octapass get GitHub --json` without `--field` prints the **whole item, secrets included**. Don't use it to look around. `octapass list --json` never holds secrets, so use that instead.
   - `octapass env show "Shop API (development)"` hides concealed values. Add `--reveal` only when asked.
   - Never echo the output of `octapass read`, `octapass get --field password`, `octapass totp`, `octapass oauth token` or `octapass env export` into the conversation, a log, a commit, an issue or a file the user didn't ask for.
2. **Inject secrets, don't copy them.** Hand a secret to the program that needs it without it passing through you: `octapass run`, `octapass inject`, an `.env` file of `octapass://` references, or a credential helper. Write references such as `octapass://Personal/Postgres/password` into config and code, never the value.
3. **Never handle the master password or Secret Key.** Don't ask for them, put them on a command line, in a file, an environment variable or a CI secret you create, or remember them. When the vault is locked, ask the user to unlock it themselves (see [Install, sign in and unlock](#install-sign-in-and-unlock)). Don't use `--password-stdin` unless the user's own script already provides the password. The same goes for recovery codes, two-step codes and the Recovery Kit that `octapass signup`, `octapass rotate-secret-key` and `octapass reset-master-password` print.
4. **Confirm before anything destructive or hard to undo,** and say exactly what will change. That covers:
   - deleting: `octapass delete`, `octapass safe rm`, `octapass safe delete`, `octapass shred` (can't be undone), `octapass env unset`, `octapass service-account revoke` (also rotates the vault's key), `octapass connect revoke`, `octapass org remove`, `octapass org vault delete`, `octapass org delete`, `octapass logout`
   - overwriting: `octapass edit` on a field that has a value, `octapass env set` on a variable that exists, `octapass env import --into`, and any `--force`
   - writing secrets to disk: `octapass export`, `octapass ssh export`, `octapass file-key --export`, `octapass cert export --part key`
   - account and device changes: `octapass change-master-password`, `octapass rotate-secret-key`, `octapass rotate-vault-key`, `octapass cert trust`, `octapass git setup --global`
   - organisation changes: `octapass org access apply` (seals a vault key: let the user review each person, and never pass `--person` fingerprints they didn't check), `octapass org role`, `octapass org policy set`, `octapass org sso oidc`, `octapass org sso saml`
   - Never add `--yes` (`-y`) or `--no-masking` to skip a question the CLI asks, unless the user said to.
5. **Don't put secret values on a command line.** Process lists and shell history can see arguments. Use `--generate` for a new password, `--stdin FIELD` for a value from a pipe, or ask the user to run the command and type the value. Writing `field` without `=value` asks for it hidden.
6. **Treat tokens as keys.** A service account token (`opsa1_…`) or a Connect token reads a vault, and a SCIM token (`opscim_…`) changes who is in an organisation. It's printed once: give it straight to the user or their CI secret store, and never print it again or commit it.
7. **Respect the exit code.** Exit 4 means locked, and exit 3 means signed out. Tell the user and stop. Don't hunt for another way in.

## Before you start

```bash
octapass --version
octapass status --json
```

`octapass status` exits **0** when unlocked, **3** when signed out and **4** when locked. With `--json` it prints:

```json
{ "status": "unlocked", "email": "ada@example.com", "serverUrl": "https://vault.example.com",
  "locksAt": "2026-11-08T12:30:00Z", "keyring": true, "desktopApp": false }
```

`status` is `signedOut`, `locked` or `unlocked`. `desktopApp` is true when the desktop app is unlocked with this account, so commands open without a prompt. Signed out with the app running, any command links the CLI to the app's account. When `OCTAPASS_SERVICE_ACCOUNT_TOKEN` is set there's no sign-in at all: see [CI and servers](#ci-and-servers).

## Install, sign in and unlock

Check `command -v octapass` first. If it's missing, ask the user before installing it: the one-line installer downloads the release for this computer from GitHub and checks it against `SHA256SUMS`, with no administrator rights:

```bash
curl -fsSL https://octap.app/install.sh | sh      # macOS and Linux, into ~/.local/bin
irm https://octap.app/install.ps1 | iex          # Windows PowerShell
```

From a checkout of the repository, `cargo install --path apps/cli` works too. Both also install `docker-credential-octapass`, `git-credential-octapass` and `octapass-git-sign`.

**If the Octa Pass desktop app is on this computer, there's nothing to sign in to:** the CLI uses the app's account (see [The desktop app](#the-desktop-app)). Otherwise the user signs in once per computer. These commands ask for the email, master password, Secret Key (the first time) and a two-step code, so **the user runs them in their own terminal, not you**:

```bash
octapass login --server https://vault.example.com
octapass unlock --timeout 2h
octapass lock
```

- `octapass signup` creates an account and prints its Recovery Kit. Leave it to the user.
- `octapass unlock` keeps a session in the OS keyring until the user is idle for the timeout (default 30 minutes, 1 minute to 24 hours). Every 14 days the master password is needed again. The session belongs to the user account, not the terminal, so once they unlock in their terminal your commands work too.
- `OCTAPASS_SERVER` and `OCTAPASS_EMAIL` stand in for `--server` and `--email`.
- Without a keyring, or with `OCTAPASS_NO_KEYRING=1`, nothing is kept and every command needs the master password.

### The desktop app

While the Octa Pass desktop app is running, the CLI follows it:

- A CLI that isn't signed in uses the app's account on its first command, or with `octapass link`. It becomes a device of its own in the account ("Octa Pass CLI") and the user gets a new sign-in email, so tell them before the first command. A CLI signed in to its own account keeps it.
- While the app is unlocked, commands run with no prompt. While it's locked, a command makes a Touch ID, Windows Hello or system password prompt appear on the user's screen, which unlocks the app too. Tell them before you run it, so they approve only what they expect. If device unlock is off in the app, the command exits 4 and the user unlocks the app.
- `octapass lock` locks the app as well. Don't run it unless the user asks: it locks their app too.
- `OCTAPASS_NO_DESKTOP=1` never asks the app. `octapass export` and `octapass ssh export` always want the master password anyway.

The CLI tries these in order: a service account token, the keyring session, the desktop app, then the master password from a terminal or `--password-stdin`. With none of them it exits 4.

## Find and read items

```bash
octapass list --search github
octapass list --vault Work --json
octapass get GitHub
octapass get GitHub --field username
octapass get "AWS prod" --field "access key id" --vault Work
octapass totp GitHub
```

- An item is named by its title (any case) or its id. When two items share a title, the command exits **7** and lists their ids: use the id, or `--vault`. Items in the trash are left out.
- `--field` takes `password`, `username`, `totp` (the current code), `notes`, `url` (the first one), `title`, any field of the item's type (`number`, `cvv`, `iban`…) or a custom field's label.
- `-n` (`--no-newline`) leaves out the trailing newline. When stdout is a terminal, a warning goes to stderr before a secret.
- `octapass list --json` is an array of rows with `id`, `vaultId`, `vault`, `type`, `title`, `subtitle`, `urls`, `tags`, `favorite`, `pinned`, `hasTotp`, `hasPasskey`, `createdAt` and `updatedAt`. That's enough to pick an item without reading it.
- `octapass totp GitHub --json` prints `{"code": "123456", "period": 30, "remaining": 12}`.
- `octapass get GitHub --field password --json` prints `{"field": "password", "value": "…"}`.

## Create, edit, delete

```bash
octapass create login --title GitHub --url https://github.com username=ada --generate
octapass create login --title Mail --generate --words 5 --tag personal
octapass create card --title Visa cardholder="Ada Lovelace" expiry=04/29 number cvv
octapass create note --title Router --stdin notes < router.txt
octapass create database --title Warehouse host=db.internal port=5432 username=admin --generate
octapass create licence --title "Editor Pro" product="Editor Pro" license-key expiry-date=2027-06-01
octapass edit GitHub --add-tag work --remove-tag old
octapass edit GitHub --generate --length 32
octapass edit GitHub --unset "API key" --title "GitHub (work)"
octapass delete GitHub
octapass restore GitHub
```

- `octapass create` makes a `login`, `password`, `note`, `card`, `identity`, `wifi`, `bank-account`, `api-credential`, `licence`, `id-document`, `wallet`, `database`, `custom` or `template`. SSH keys, OpenPGP keys, environments, certificates, other keys and OAuth clients have their own commands below.
- Write `field=value`, or `field` alone for a hidden prompt (the user types it). `--stdin FIELD` reads one field from stdin. `--generate` makes a new password: 20 characters, or `--length` (4–128) or `--words` (3–20).
- Fields by type:
  - login and password: `username`, `password`, `totp`, `notes`
  - card: `cardholder`, `number`, `expiry`, `cvv`, `pin`, `brand`, `notes`
  - identity: `firstName`, `lastName`, `email`, `phone`, `birthDate`, `notes`, `address.line1`, `address.city`, `address.postalCode`, `address.country`…
  - wifi: `ssid`, `security`, `password`, `notes`
  - bank-account: `bankName`, `accountHolder`, `accountType`, `iban`, `accountNumber`, `routingNumber`, `swift`, `branch`, `pin`
  - api-credential: `credentialType`, `username`, `key`, `secret`, `host`, `expiryDate`
  - licence: `product`, `version`, `licenseKey`, `licensedTo`, `email`, `publisher`, `orderNumber`, `purchaseDate`, `expiryDate`
  - id-document: `documentType`, `number`, `fullName`, `birthDate`, `issuer`, `country`, `issueDate`, `expiryDate`
  - wallet: `walletName`, `seedPhrase`, `passphrase`, and `address.bitcoin`, `address.ethereum`… per address
  - database: `databaseType`, `host`, `port`, `database`, `username`, `password`, `connectionString`
  - custom: your own labels (hidden unless `--plain`); `--template NAME` starts from a template. template: labels with their kind as the value (`Locker`, `Combination=hidden`).
  - Every type takes `notes`. Names can be written `licenseKey` or `license-key`. Dates are `YYYY-MM-DD`; IBANs, SWIFT codes, ports and wallet addresses are checked.
  - Any other name becomes a custom field on a login or Wi-Fi item, hidden unless you add `--plain`.
- `--vault` picks the vault (default Personal). `--url` and `--tag` can repeat, and `--favorite` sets the favourite.
- `octapass edit` keeps fields it doesn't know about. A changed password goes into the item's history. `--add-url`, `--remove-url`, `--favorite` and `--no-favorite` change the rest.
- `octapass delete` moves an item to the trash, and `octapass restore` brings it back. Confirm with the user first anyway.
- With `--json`, `create` and `edit` print `{"id", "title", "type", "vaultId", "revision"}`. Without it, the new id goes to stdout.

## Generate passwords

`octapass generate` needs no account:

```bash
octapass generate
octapass generate --length 32 --no-symbols
octapass generate --avoid-ambiguous
octapass generate --words 5 --separator _ --capitalize --number
octapass generate --json
```

It prints `{"password": "…"}` with `--json`. A generated password is a secret too: when it's meant for an item, use `octapass create --generate` or `octapass edit --generate`, so it goes straight into the vault and never through your output.

## Give secrets to commands

A reference names one field: `octapass://<vault>/<item>/<field>`. Each part is a name (any case) or an id, spaces are fine, and `%2F` stands for a `/` in a name. A shared vault works by name, for example `octapass://Team Ops/Deploy/password`.

```bash
# .env.octapass: safe to commit, it holds references, not values
DATABASE_PASSWORD=octapass://Personal/Postgres/password
STRIPE_KEY=octapass://Personal/Stripe/api key
```

```bash
octapass run --env-file .env.octapass -- npm start
DATABASE_PASSWORD=octapass://Personal/Postgres/password octapass run -- ./migrate.sh
octapass inject -i config.tmpl.yaml -o config.yaml
octapass read octapass://Personal/Postgres/password
```

- **`octapass run` is the default choice.** It replaces every variable whose whole value is a reference, from the environment and `--env-file` files (later files win), then starts the command. The values go only to that command. If a reference doesn't resolve, the command doesn't start. `run` exits with the command's own code, or 127 when the command isn't found.
- `run` hides secrets in the command's output, replacing them with `<concealed by Octa Pass>`. It's a safety net, not a boundary: a program can still encode, split or send a value. `--no-masking` (or `OCTAPASS_NO_MASKING=1`) gives an interactive program the real terminal. Use it only when needed.
- `octapass inject` fills references in a template. `-o` writes a file only the user can read and won't replace one without `--force`. The output holds real secrets: keep it out of git and delete it when you're done.
- `octapass read` prints the value. Use it only inside a pipe or a `$(…)` whose result goes straight into a program, never to show the value.
- `--env-file-out .env` writes the variables to a file for as long as the command runs, then deletes it (also on Ctrl-C), for tools that only read a file.

### Environments

An environment is a whole `.env` file kept in the vault, optionally in a project with a stage:

```bash
octapass env list
octapass env create "Shop API (production)" --project shop-api --stage production
octapass env set "Shop API (production)" LOG_LEVEL=info --plain
octapass env set "Shop API (production)" DB_PASSWORD=octapass://Personal/Postgres/password
octapass env import .env.local --new "Shop API (development)" --project shop-api --stage development
octapass env show "Shop API (development)"
octapass env diff shop-api staging production
octapass run --project shop-api --stage development -- npm run dev
octapass env export "Shop API (development)" --format docker -o .env.docker
```

- An environment is named by its title, id, `vault/title` or `project:stage` (`project:` alone is the shared set).
- `run` loads, in this order: the project's shared set, the stage, each `--env` (it repeats, and later ones win), the `--env-file` files, then the references in the result.
- A `production` stage that wasn't named on the command line asks first. Don't answer for the user with `--yes`.
- `octapass env diff` prints the names that are missing or different, never the values.
- `octapass env export` writes `dotenv`, `json`, `shell`, `powershell` or `docker`, with real values. `--keep-references` writes the references instead, which is better when the file is going to be committed.
- `octapass.toml` in the folder or a parent sets the defaults (`project`, `stage`, `env`, `vault`), and `OCTAPASS_STAGE` overrides its stage.
- `eval "$(octapass env hook zsh)"` in the user's shell startup file loads an allowed folder's environment on `cd`. A folder is allowed once with `octapass env allow` and stopped with `octapass env deny`. That changes the user's shell, so suggest it rather than doing it yourself.

## CI and servers

CI should use a **service account**: a token for one shared vault, read-only unless made with `--write`. Never put a person's master password or Secret Key into CI.

```bash
octapass service-account create --vault CI --name "Deploy job" --expires 90d
octapass service-account list --vault CI
octapass service-account revoke 0f3c2a --vault CI
```

`create` prints the token once. The user puts it in the CI system's secret store as `OCTAPASS_SERVICE_ACCOUNT_TOKEN`. With that variable set, the reading commands work with no sign-in, keyring or password: `list`, `get`, `totp`, `read`, `run`, `inject`, `env list`, `env show`, `env export`, `env diff`, `oauth token`, `aws`, `kube` and `docker-credential get`. Anything else is refused.

```bash
octapass run --env shop-api:production -- ./deploy.sh
```

The GitHub Action and GitLab template in `integrations/` wrap this. See [references/ci.md](references/ci.md) for both, plus AWS, Kubernetes, Docker, Terraform, OAuth tokens and Octa Pass Connect.

## SSH keys and Git

```bash
octapass ssh list
octapass ssh generate --type ed25519 --comment ada@laptop --title "Laptop key"
octapass ssh public "Laptop key"
octapass ssh import ~/.ssh/id_ed25519
octapass ssh import --scan
octapass ssh export "Laptop key" --out ~/.ssh/id_ed25519
octapass git setup --signing-key "Laptop key" --dry-run
```

- `octapass ssh public` prints the `authorized_keys` line. It's public, so it's safe to show.
- Prefer the **SSH agent in the desktop app** to a key file on disk. The user turns it on in Settings → SSH agent, then points `SSH_AUTH_SOCK` or `IdentityAgent` at its socket. Each signature asks them with Touch ID or Windows Hello. The CLI has no agent of its own.
- `octapass ssh export` writes a private key (mode 0600) after the master password, so it's for the user to run. It won't replace a file without `--force`.
- `octapass git setup` configures `git-credential-octapass` and commit signing. `--agent` signs through the desktop app's agent, and `--dry-run` shows the settings without changing them. Without `--global` it changes only this repository.

## Files

```bash
octapass encrypt plan.pdf
octapass encrypt --to grace@example.com report.pdf
octapass encrypt photos/ --armor
octapass decrypt plan.pdf.age
octapass file-key
octapass safe list
octapass safe ls Taxes 2026
```

- `octapass encrypt` writes age files (`plan.pdf.age`, and a folder becomes `.tar.age`) that any age tool can open. It encrypts for yourself by default, or `--to` an Octa Pass email or `age1…` key, or `--passphrase`. Nothing is replaced without `--force`.
- `octapass decrypt` writes beside the file without `.age`, and `-o -` writes to stdout.
- `--shred` and `octapass shred` overwrite and delete the original. That can't be undone, and on SSDs and copy-on-write disks it isn't a guarantee: the CLI says which.
- `octapass file-key` shows the public key. `--export` prints the secret one, which is for the user to run.
- `octapass safe …` works with Safes, which are encrypted folders. See [references/commands.md](references/commands.md).

## Scripting

- `--json` is accepted everywhere. `status`, `list`, `get`, `totp`, `generate`, `create`, `edit`, `import`, the `env` and `ssh` commands and the toolkit print JSON with it. Data goes to stdout and messages to stderr, with no colours.
- `octapass` commands run one at a time, and a second one waits for the first.
- Commands sync with the server first. Offline, they use the local copy and say so on stderr.

| Exit | Meaning |
|:-:|---|
| 0 | Done. `status`: unlocked |
| 1 | Any other error |
| 2 | Bad arguments or input: an unknown option, a bad reference or env file, an import file in the wrong format |
| 3 | Not signed in, or the server session ended: the user runs `octapass login` |
| 4 | Locked, and no master password given: the user unlocks |
| 5 | Wrong master password or Secret Key, or a refused service account token |
| 6 | No such item, field or vault |
| 7 | More than one item or vault matches: use an id or `--vault` |
| 8 | The server can't be reached |
| 10 | `octapass cert expiring`: some certificates need renewing |

`octapass run` passes on its command's exit code.

## More

- [references/commands.md](references/commands.md): every command, including import and export, certificates, keys, JWTs, hashes, Safes, Connect and the cloud helpers.
- [references/ci.md](references/ci.md): GitHub Actions, GitLab CI, service accounts, AWS, Kubernetes, Docker, Terraform, OAuth tokens and Connect.
- The CLI docs page: `https://octap.app/docs/platforms/cli/` (in a checkout: `docs/platforms/cli.md`). The `octapass-docs` skill searches all the docs.
- The CLI's code is in `apps/cli/src` and its exit codes in `apps/cli/src/error.rs`. When this skill and `--help` disagree, `--help` wins.
