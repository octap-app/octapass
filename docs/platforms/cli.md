---
title: CLI
description: The octapass command-line tool for reading items, one-time codes and generated passwords, managing SSH keys, keeping .env files and environment variables, passing secrets to scripts with octapass:// references, and importing and exporting, with a session kept in the OS keyring.
status: beta
sidebar:
  order: 5
---

:::note[Preview]
The CLI works against an Octa Pass server today, but there are no released builds yet: build it from source. Commands and exit codes may still change before 1.0.
:::

`octapass` is a native Rust binary. It uses the same core as every other app, so your master password, Secret Key and decrypted items never leave your computer. It keeps an encrypted copy of your vault, so reading items also works offline.

## Install

You need [Rust](https://rustup.rs). From a checkout of the repository:

```bash
cargo install --path apps/cli
octapass --version
```

To stay unlocked between commands, the CLI uses the system keyring: the Keychain on macOS, Credential Manager on Windows, and the Secret Service (GNOME Keyring, KWallet) on Linux. Without one, it still works, but every command asks for your master password.

## Quick start

```bash
octapass login --server https://vault.example.com
octapass list --search github
octapass get GitHub --field password
octapass totp GitHub
octapass lock
```

`login` asks for your email, master password and, the first time on this computer, your Secret Key (it's on your [Recovery Kit](/docs/getting-started/recovery-kit/)). If the account uses [two-step sign-in](/docs/features/two-step-sign-in/), it then asks for a code from your authenticator app or a two-step recovery code. Security keys work only in the web vault. Without `--server` it uses `OCTAPASS_SERVER`, then the hosted service.

## Commands

| Command | What it does |
|---|---|
| `octapass signup [--server URL] [--email E] [--code C] [--timeout 30m]` | Creates an account, prints your Recovery Kit, and signs in. The master password must reach "strong", as in the web vault. |
| `octapass login [--server URL] [--email E] [--timeout 30m]` | Signs in and unlocks. |
| `octapass unlock [--timeout 30m]` | Unlocks with the master password and stays unlocked until you're idle for the timeout (1 minute to 24 hours, default 30 minutes). |
| `octapass lock` | Locks now. |
| `octapass logout` | Signs out on the server and removes the account from this computer: Secret Key, encrypted copy and keyring entry. |
| `octapass status` | Says whether you're signed in and unlocked. |
| `octapass change-master-password` | Changes it: asks for the current and the new master password. Your Secret Key, recovery code and items stay as they are; other devices are signed out. |
| `octapass rotate-secret-key [--new-recovery-code]` | Replaces your Secret Key and prints your new Recovery Kit. Your master password stays; other devices are signed out and need the new key. |
| `octapass rotate-vault-key <vault>` | Gives a vault you own or manage a new key. |
| `octapass reset-master-password [--server URL] [--email E] [--code C]` | Resets a forgotten master password with the emailed code and the recovery code from your Recovery Kit, then prints the new kit. |
| `octapass service-account create\|list\|revoke` | Makes and revokes [service accounts](/docs/features/service-accounts/). |
| `octapass connect serve\|status\|clients\|revoke\|approve\|pair\|read` | Runs and manages [Octa Pass Connect](/docs/features/connect/). |
| `octapass aws credential-process`, `octapass kube credential`, `octapass docker-credential` | [Credentials for other tools](#cloud-and-devops). |
| `octapass oauth create\|token\|show` | [Live OAuth2 tokens](/docs/features/connect/#live-api-tokens) from API credential items. |
| `octapass list [--vault V] [--search Q]` | Lists items: title, username, vault and id. The search looks at titles, usernames, URLs and tags. |
| `octapass get <item> [--field F] [--vault V] [-n]` | Shows an item without its secrets, or prints one field. |
| `octapass totp <item> [--vault V]` | Prints the current one-time code. |
| `octapass create <type> --title T [FIELD=VALUE…]` | Adds a login, password, note, card, identity or Wi-Fi item. See [changing items](#changing-items). |
| `octapass edit <item> [FIELD=VALUE…]` | Changes an item's fields, title, URLs, tags or favorite. |
| `octapass delete <item> [--vault V]` | Moves an item to the trash. |
| `octapass restore <item>` | Brings an item back from the trash. |
| `octapass generate [--length N \| --words N]` | Generates a password or passphrase. No account needed. |
| `octapass read octapass://<vault>/<item>/<field> [-n]` | Prints the value a reference points to. |
| `octapass run [--env E] [--project P] [--stage S] [--env-file F] [--env-file-out PATH] [--no-masking] -- <command>` | Runs a command with environments loaded and references in its environment replaced by their values, with secrets hidden in its output. |
| `octapass env …` | Lists, shows, creates, changes, imports and exports environments. See [environments](#environments). |
| `octapass inject -i template -o out [--force]` | Copies a text file, replacing octapass:// references with their values. |
| `octapass import <format> <file> [--vault V] [--key-file F] [--dry-run]` | Imports another app's export, or an Octa Pass export. |
| `octapass ssh list \| generate \| import \| export \| public` | Lists, makes, imports, exports and prints SSH keys. See [SSH keys](#ssh-keys). |
| `octapass gpg list \| import \| public` | Lists, imports and prints OpenPGP keys for signing commits. See [Git](#git). |
| `octapass git setup [--global] [--signing-key ITEM] [--agent]` | Points Git at the credential helper and commit signing. See [Git](#git). |
| `octapass encrypt [paths] [--self] [--to WHO] [--passphrase] [--output F] [--armor] [--shred] [--force]` | Encrypts files and folders in the age format. See [file encryption](/docs/features/file-encryption/). |
| `octapass decrypt [paths] [--identity F] [--output F] [--force]` | Decrypts age files; a `.tar.age` unpacks to a folder. |
| `octapass shred <paths> [--yes]` | Overwrites and deletes, and says what that achieved on this disk. |
| `octapass file-key [--export] [--output F] [--force]` | Prints your age public key, or exports the secret key for files encrypted for yourself. |
| `octapass safe list \| create \| ls \| add \| get \| mkdir \| mv \| rm \| sync \| set-sync \| delete \| mount` | Works with encrypted [Safes](/docs/features/octa-pass-safe/). `mount` needs a build with the `fuse` feature, on Linux. |
| `octapass context-menu install \| remove \| status` | Adds or removes "Encrypt with Octa Pass" in your file manager. |
| `octapass export [--format json\|csv\|cxf] [--encrypted] [--output F]` | Exports every item. |

Run `octapass <command> --help` for every option.

### Changing or resetting the master password

```bash
octapass change-master-password
octapass reset-master-password --server https://vault.example.com
```

`change-master-password` asks for your current master password (to prove it's you), then a new one twice. Your Secret Key, recovery code and items don't change; every other device is signed out and has to turn device unlock on again.

`reset-master-password` is for a forgotten master password. It emails you a code (a development server returns it instead), then asks for the code, the recovery code from your [Recovery Kit](/docs/getting-started/recovery-kit/) and a new master password twice. It prints your **new** Recovery Kit, with the new Secret Key and recovery code, to stdout: store it somewhere safe, because the old kit stops working. Then it signs in with the new password; if two-step sign-in is on, it asks for the second step as usual.

With `--password-stdin`, `change-master-password` reads the current password from the first line and the new one from the second. `reset-master-password` reads the recovery code from the first line and the new password from the second; pass the emailed code with `--code` unless the development server returned it.

### Items and fields

`<item>` is an item's title (any case) or its id. When two items have the same title, the command fails with exit code 7 and lists their ids; use an id, or `--vault` to look in one vault. Items in the trash are left out.

`--field` takes `password`, `username`, `totp` (the current code), `notes`, `url` (the first one), `title`, any other field of the item (such as `number` or `cvv` on a card, or `iban` on a bank account) or the label of a custom field. On a crypto wallet, `address` is the first address and a network or label picks another; the seed phrase counts as a secret, like every hidden field:

```bash
octapass get GitHub                       # every field, secrets left out
octapass get GitHub --field password      # just the password
octapass get "AWS prod" --field "access key id"
octapass get GitHub --json                # the whole item, secrets included
```

Secrets are printed only when you ask for them. When the output is a terminal, a warning goes to stderr first. `-n` leaves out the newline after the value. `reset-master-password` also prints secrets, because the new Recovery Kit is the only copy.

### Changing items

```sh
octapass create login --title GitHub --url https://github.com username=ada password
octapass create login --title Mail --generate --words 5
octapass create card --title Visa number cvv cardholder="Ada Lovelace" expiry=04/29
octapass create note --title "Router" --stdin notes < router.txt
octapass edit GitHub password --add-tag work
octapass edit GitHub --unset "API key" --title "GitHub (work)"
octapass delete GitHub
```

Write `field=value`, or just `field` to type the value without it showing. **Prefer that for secrets**: other programs can see command-line arguments, and your shell may keep them. `--stdin field` reads one field's value from stdin, after the `--password-stdin` line if there is one. `--generate` makes a new password.

Each type has its fields: `username`, `password`, `totp`, `notes` for a login; `cardholder`, `number`, `expiry`, `cvv`, `pin`, `brand`, `notes` for a card; `firstName`, `lastName`, `email`, `phone`, `birthDate`, `notes` and `address.line1`, `address.city` and so on for an identity; `ssid`, `security`, `password`, `notes` for Wi-Fi. On logins and Wi-Fi, any other name becomes a custom field, hidden unless you add `--plain`. SSH keys, OpenPGP keys and environments have their own commands; `edit` can change their title, URLs and tags.

Fields Octa Pass doesn't know about stay as they are. A changed password goes to the item's password history. If another device changed the item first, the vault keeps both, as in every other client.

### Generating passwords

```bash
octapass generate                          # 20 random characters
octapass generate --length 32 --no-symbols
octapass generate --avoid-ambiguous        # no I l 1 O 0 o |
octapass generate --words 5                # five words from the EFF list, joined by -
octapass generate --words 4 --separator _ --capitalize --number
```

Passwords are 4 to 128 characters long and passphrases 3 to 20 words, from the operating system's secure random number generator. See the [password generator](/docs/features/password-generator/).

## SSH keys

```bash
octapass ssh list
octapass ssh generate --type ed25519 --comment ada@laptop
octapass ssh generate --type rsa-3072 --title "Old server" --passphrase
octapass ssh import ~/.ssh/id_ed25519
octapass ssh import --scan
octapass ssh export "Laptop key" --out ~/.ssh/id_ed25519 --passphrase
octapass ssh public "Laptop key" >> ~/.ssh/authorized_keys
```

- `ssh list` shows the title, type, fingerprint and vault. `--json` adds the public key and id.
- `ssh generate` makes Ed25519, ECDSA P-256/P-384 or RSA 3072/4096 on this computer and saves it in Personal, or `--vault`. `--title` defaults to the comment or the key type. `--passphrase` asks for a passphrase to keep for exports; the stored key itself has none.
- `ssh import` reads OpenSSH, PEM and PKCS#8 private keys, asking for a passphrase when the file has one. `--scan` also reads `~/.ssh` and skips keys already in the vault by fingerprint.
- `ssh export` asks for your master password again, then writes an OpenSSH private key readable only by you (mode `0600`). It won't replace an existing file without `--force`. `--passphrase` asks for a new passphrase; without it the key's saved passphrase is used, and `--no-passphrase` leaves the file unprotected. Without `--out`, the key goes to stdout, never to a terminal.
- `ssh public` prints the `authorized_keys` line (the public key and its comment).

DSA and FIDO (`sk-`) keys are listed and can be imported, but can't be generated, used or exported to other formats yet. PuTTY and 3DES keys need converting with `ssh-keygen` first. See [SSH keys](/docs/features/ssh-keys/).

## Git

```sh
octapass git setup --global                               # Git asks Octa Pass for passwords
octapass git setup --global --signing-key "Laptop key"    # and signs commits with this key
```

`setup` changes Git's own settings, this repository's without `--global`; `--dry-run` shows them first.

### Passwords

`git-credential-octapass` gives Git the username and password of the login saved for that host. It's stricter than autofill, because Git names exactly where the password goes: the scheme, host and port must match the login's URL (a leading `www.` aside), and a password is sent over `http://` only if the login's URL says `http://`. With `credential.useHttpPath` on, a login saved for a repository's path answers for that repository, ahead of one for the whole host.

- Most forges want a token instead of your password. Add a custom field called **Git token** to the login and Octa Pass gives that instead.
- If several logins fit, nothing is given and you're told why: put the username in the remote's URL, or set `credential.username`.
- When Git reports a password was rejected, nothing is deleted from your vault. Octa Pass saves nothing from Git either, unless you set the helper up as `octapass --store`.
- A locked vault unlocks through the [desktop app](#sessions), or asks for the master password on your terminal, unless `GIT_TERMINAL_PROMPT=0`.

### Signing commits

`--signing-key` takes an SSH key or an OpenPGP key from your vault and turns on `commit.gpgsign`.

- **SSH keys:** Git runs `octapass-git-sign` in place of `ssh-keygen`, and the CLI signs with the key from your unlocked vault. Add `--agent` to sign through the [SSH agent](/docs/features/ssh-keys/#ssh-agent) in the desktop app instead, which asks you each time. Any key of type Ed25519, ECDSA or RSA can sign.
- **OpenPGP keys:** bring one in with `octapass gpg import key.asc` (from `gpg --armor --export-secret-keys`). Git runs `octapass-git-sign` in place of `gpg`. Ed25519 and ECDSA keys can sign. **RSA OpenPGP keys can't**: the OpenPGP library signs with a crate that has an open timing advisory, so Octa Pass keeps the key but refuses to sign with it. `octapass gpg public <item>` prints the public key for your forge's settings.

Verifying signatures, and any key that isn't in your vault, goes to the real `ssh-keygen` or `gpg`.

## Developer toolkit

`octapass cert`, `acme`, `key`, `jwt`, `hash`, `hmac`, `encode`, `decode`, `detect`, `random`, `pwhash` and `totp-secret` make and read certificates, keys, tokens, hashes and encodings. None of them need an account unless they save to the vault, and all of them take `--json`. They read files or stdin and write stdout, so they fit in pipelines. See [Developer toolkit](/docs/features/developer-toolkit/).

A generator's private key is never printed on a terminal. Pass `--save` for the vault or `--out-key <file>`, or pipe the output.

## Secrets in scripts and apps

Reference secrets with `octapass://<vault>/<item>/<field>` instead of writing them into files. Each part is a name (any case) or an id. Spaces are fine; write `%2F` for a `/` in a name.

```bash
# .env.octapass
DATABASE_PASSWORD=octapass://Personal/Postgres/password
STRIPE_KEY=octapass://Personal/Stripe/api key
```

```bash
octapass run --env-file .env.octapass -- npm start
DATABASE_PASSWORD=octapass://Personal/Postgres/password octapass run -- ./migrate.sh
octapass read octapass://Personal/Postgres/password
```

`octapass run` resolves every variable whose whole value is a reference, from the environment and the env files (later files win over earlier ones and over the environment), then starts the command with them. The values go to that command only: `octapass` never prints them or writes them to disk. If a reference can't be resolved, the command doesn't start. `run` exits with the command's own exit code (127 if it can't be found).

**Secrets are hidden in the command's output.** While a secret is loaded, `run` starts the command as a child and filters its stdout and stderr, replacing each secret with `<concealed by Octa Pass>`, also when it arrives in pieces. Secrets are references to secret fields and concealed variables; a username or a variable you marked as plain stays visible, and so do values under 4 characters, which would turn the output into noise. Each line of a multi-line secret is hidden too.

The command's output is then a pipe, not your terminal, so colours may go and full-screen programs won't work: use `--no-masking` (or `OCTAPASS_NO_MASKING=1`) for those, and `run` hands the terminal over as before. With no secrets loaded nothing changes. Masking helps with logs and shared screens, but it's not a boundary: a program can still encode, split or send a value.

Env files are `KEY=value` lines, with `#` comments, an optional `export `, single-quoted values (taken as written) and double-quoted values (with `\n`, `\t`, `\r`, `\"` and `\\`, and real line breaks for multi-line values such as PEM keys). A ` #` after an unquoted value starts a comment. The CLI's `env import` and the web vault and extension read the same format; each has its own implementation, kept in step by tests.

### Environments

Keep a whole `.env` file, or one variable, in the vault and give it to a command. Values are encrypted in the vault and decrypted here on the device; they are never sent anywhere else.

```bash
octapass env create "Shop API (production)" --project shop-api --stage production
octapass env set "Shop API (production)" DB_PASSWORD=octapass://Personal/Postgres/password LOG_LEVEL=info
octapass env import .env.local --new "Shop API (development)" --project shop-api --stage development
octapass env list
octapass env show "Shop API (development)" --reveal
octapass env export "Shop API (development)" --format docker -o .env
octapass env diff shop-api staging production
```

An environment is named by its title (any case), its id, `vault/title`, or `project:stage` (`project:` alone is the project's shared set). A project's environment without a stage is shared: `run` loads it first and the stage's variables override it. `octapass env list` groups environments by project and shows each stage; `env diff` prints which names are missing or hold different values, never the values themselves.

`octapass run` takes `--env` more than once (later ones win), or `--project P --stage S`, and loads the same set the shell hook does. Variables are applied in this order: the project's shared set, the stage, the named environments, the `--env-file` files, then references in the result. A `production` stage loaded without naming it on the command line asks for confirmation; `--yes` skips the question for a script. With `--env-file-out PATH`, the variables are written to a file readable only by you for as long as the command runs (deleted afterwards, including on Ctrl-C), for tools that only read a file such as Docker Compose's `env_file:`.

`octapass.toml` in the current folder or a parent (up to the repository root) sets the defaults:

```toml
project = "shop-api"
stage = "development"
env = ["Personal/Shop API extras"]
vault = "Personal"
```

`--env`, `--project` and `--stage` replace those defaults, and `OCTAPASS_STAGE` overrides the file's stage. `octapass env hook zsh|bash|fish|powershell` prints a hook for your shell's startup file that loads an allowed folder's environment as you enter it and unloads it when you leave, when the file changes, or when Octa Pass locks. Allow a folder once with `octapass env allow`; the allow list is keyed by the file's path and contents. The hook never asks for your master password, and nothing loads while the CLI is locked. Octa Pass never writes secrets to the system's persistent environment; use `run`, the hook or a file that is deleted afterwards. See [environments](/docs/features/environments/) for Docker, CI, Node and Python examples.

`octapass inject` replaces `octapass://` references in any text file (or stdin) and writes the result to stdout or `--output`, which is readable only by you and not replaced without `--force`.

A reference names a vault by its name, so `octapass://Team Ops/Deploy/password` works for a shared vault. (`octapass://` references in config files are planned for 1.0.)

## Cloud and DevOps

Each of these prints what one tool expects, from a vault item, so the secret stays out of its config file. They work with a keyring session or a [service account](/docs/features/service-accounts/).

### AWS

`~/.aws/config`:

```ini
[profile prod]
credential_process = octapass aws credential-process "AWS prod" --vault CI
```

The item needs the fields `accessKeyId` and `secretAccessKey` (a login's username and password also work), and optionally `sessionToken` and `expiration`.

### Kubernetes

In your kubeconfig:

```yaml
users:
  - name: prod
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: octapass
        args: ["kube", "credential", "Cluster prod", "--vault", "CI"]
        interactiveMode: Never
```

The item needs a `token` field (an OAuth2 item's live `accessToken` works too), or `clientCertificateData` with `clientKeyData`.

### Docker

`cargo install --path apps/cli` also installs `docker-credential-octapass`. In `~/.docker/config.json`:

```json
{ "credsStore": "octapass" }
```

`docker login` then saves to your vault as a login tagged `docker-credential`, and `docker logout` moves it to the trash. Service accounts can read these, not save them.

### Terraform and Pulumi

Use `octapass run`: see [Service accounts](/docs/features/service-accounts/#terraform-and-pulumi).

## Sessions

`octapass unlock` (and `login`) creates a random session key and keeps it in the OS keyring. Your account key, encrypted with that session key, stays in the CLI's data folder. Neither one opens your vault alone, and the master password is never stored.

- Every command moves the end of the session forward, so it ends after the timeout without a command. `octapass lock` ends it at once.
- Every 14 days the master password is needed again, as with Touch ID in the other apps.
- `octapass export` and `octapass ssh export` always ask for the master password again.
- Without a keyring, or with `OCTAPASS_NO_KEYRING=1`, nothing is kept: each command that needs the vault asks for the master password, or reads it with `--password-stdin`.

The keyring entry is named "Octa Pass CLI" and a hash, so it doesn't reveal your email or server. The data folder is `~/Library/Application Support/com.octapass.cli` on macOS, `%APPDATA%\com.octapass.cli` on Windows and `~/.local/share/com.octapass.cli` on Linux, readable only by you. It holds your Secret Key, the encrypted vault and a refresh token, like the [desktop app](/docs/platforms/desktop/).

Commands sync with the server first. When it can't be reached, they use the copy on this computer and say so on stderr.

### Unlocking through the desktop app

While the [desktop app](/docs/platforms/desktop/) is running and signed in to the same account, a locked `octapass` asks it instead of asking for your master password. The app asks for Touch ID, Windows Hello or your system password, naming the program, and then hands over your account key encrypted for this one command. Nothing is kept on disk or in the keyring.

- The approval covers this program in this terminal for 30 idle minutes, in the app's memory. Locking the app ends it, and so does `octapass lock`.
- A locked app is unlocked by the same prompt, if device unlock is on there. Otherwise, unlock the app first or use your master password.
- A session in the keyring is used first, when you have one. `OCTAPASS_NO_DESKTOP=1` never asks the app.
- On the Mac the app is sandboxed, so it listens in its own folder, `~/Library/Group Containers/<team>.app.octap/cli.sock`, and `octapass` looks for it there. `OCTAPASS_DESKTOP_DATA_DIR` names another folder (for development).
- `octapass export` and `octapass ssh export` still ask for the master password.

## Scripting

- `--json` prints JSON for `status`, `list`, `get`, `totp`, `generate`, `import`, the `env` commands and the `ssh` commands.
- `--password-stdin` reads the master password from the first line of stdin, for `login`, `unlock`, `export` and any command run while locked. A file's password (an encrypted export, or a password-protected import) is read from the next line.
- Messages go to stderr and data to stdout. There are no colours.
- `octapass` commands run one at a time: a second one waits for the first.

```bash
octapass status --json
octapass list --json --search aws | jq -r '.[].id'
printf '%s\n' "$OCTAPASS_PASSWORD" | octapass --password-stdin get GitHub --field password
```

### Exit codes

| Code | Meaning |
|:-:|---|
| 0 | Done. `status`: unlocked. |
| 1 | Another error. |
| 2 | Bad arguments or input (an unknown option, an invalid reference or env file, an import file that isn't in that format). |
| 3 | Not signed in, or the server session ended (run `octapass login` again). |
| 4 | Locked, and no master password was given. |
| 5 | Wrong master password or Secret Key (or export file password). |
| 6 | No such item, field or vault. |
| 7 | More than one item (or vault) matches. |
| 8 | The server can't be reached. |

### Environment variables

| Variable | Use |
|---|---|
| `OCTAPASS_SERVER` | The server for `login` when there's no `--server`. |
| `OCTAPASS_EMAIL` | The email for `login` when there's no `--email`. |
| `OCTAPASS_SECRET_KEY` | The Secret Key for a first `login` without a terminal. |
| `OCTAPASS_SSO_CODE` | The code from the sign-in page, when an organisation requires [single sign-on](/docs/features/single-sign-on/). `login` prints the address to open. |
| `OCTAPASS_TWO_STEP_CODE` | A code from your authenticator app, or a two-step recovery code, for a `login` without a terminal when the account uses [two-step sign-in](/docs/features/two-step-sign-in/). |
| `OCTAPASS_STAGE` | The stage `run` and the shell hook load when no `--stage` is given, overriding `octapass.toml`. |
| `OCTAPASS_NO_KEYRING` | `1` to never use the keyring. |
| `OCTAPASS_SERVICE_ACCOUNT_TOKEN` | Read as a [service account](/docs/features/service-accounts/): no sign-in or keyring. Only commands that read work. |
| `OCTAPASS_CONNECT` | Where [Connect](/docs/developers/connect-api/#finding-it) is, for `octapass connect` as a client. |
| `OCTAPASS_CONNECT_TOKEN` | This client's token, for `octapass connect read`. |
| `OCTAPASS_OAUTH_CLIENT_SECRET`, `OCTAPASS_OAUTH_REFRESH_TOKEN` | Secrets for `octapass oauth create` without a terminal. |
| `OCTAPASS_NO_DESKTOP` | `1` to never ask the desktop app. |
| `OCTAPASS_NO_MASKING` | `1` for `run` to leave the command's output alone, like `--no-masking`. |
| `OCTAPASS_CLI_DATA_DIR` | Another data folder (for example, one per test run). |

## Import and export

```bash
octapass import chrome ~/Downloads/Chrome\ Passwords.csv
octapass import bitwarden ./bitwarden_export.json --vault Personal
octapass import otpauth ./codes.txt --dry-run
```

Formats: `octapass` (an Octa Pass export: the encrypted `.octapass` file with its attached files, or plaintext JSON), `cxf` (the FIDO Credential Exchange Format), `chrome` (also Edge, Brave, Opera, Vivaldi, Arc), `firefox`, `safari` (also Apple Passwords), `bitwarden` (JSON, also password-protected), `1password` (`.1pux`), `1password-csv`, `lastpass`, `keepass` (`.kdbx` with `--key-file` if it has one, XML or CSV), `protonpass`, `dashlane`, `enpass`, `keeper`, `nordpass`, `roboform`, `zoho-vault`, `avira`, `norton`, `mcafee`, `kaspersky`, `aegis`, `2fas`, `andotp`, `csv` (any CSV with a header row) and `otpauth` (`otpauth://` and Google Authenticator `otpauth-migration://` links, one per line). One-time codes for logins you already have are added to those logins. A password-protected file asks for its password at a terminal. See [import](/docs/import-export/overview/).

```bash
octapass export --encrypted --output backup.octapass
octapass export --format json --output backup.json
octapass export --format cxf --output export.cxf.json
octapass export --format csv > logins.csv
```

`--encrypted` writes everything, attached files included, encrypted with a password you choose (asked twice); `octapass import octapass` brings it back into any account. `json` has everything but the files, in the same format as the web vault's export; `cxf` is for other managers that support the Credential Exchange Format; `csv` has one row per item for other password managers. Files written with `--output` are readable only by you. Plaintext exports aren't encrypted, so delete them when you're done. See [export](/docs/import-export/export/).

## Security notes

- Never put your master password on the command line, where shell history and other users' process lists can see it. Let `octapass` ask, or use `--password-stdin`.
- A command started by `octapass run` can read, print or log its secrets, and other programs running as you can read its environment. Masking hides plain copies in its output, nothing more. Only run commands you trust.
- Anyone who can use your account while the session is unlocked can read your vault, as with any unlocked app. Lock when you step away, or use a short `--timeout`.
- On macOS, the Keychain may ask once whether `octapass` may use its entry, and again after you install a new build.
