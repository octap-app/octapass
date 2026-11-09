# octapass command reference

Every command the CLI has, grouped. Each one takes `--json` and `--password-stdin`, and `octapass <command> --help` lists the rest. The [rules for agents](../SKILL.md#rules-for-agents-read-first) apply to all of them: a ⚠ marks commands that print or write secrets, delete, or change the account, so confirm with the user before running them.

The tests in `../tests/` check every command and flag written here against the real `--help`. When you add a command to the CLI, add it here too.

## Account and session

| Command | What it does |
|---|---|
| `octapass signup` | ⚠ Creates an account and prints its Recovery Kit. The user runs it. `--server`, `--email`, `--code`, `--timeout` |
| `octapass login` | The user signs in: email, master password, Secret Key the first time, then a two-step code. `--server`, `--email`, `--timeout` |
| `octapass unlock` | The user unlocks and stays unlocked until idle. `--timeout 2h` |
| `octapass link` | Uses the account of the Octa Pass app on this computer, without signing in here. Refuses when already signed in |
| `octapass lock` | Locks now. While the desktop app is running, it locks the app too |
| `octapass logout` | ⚠ Signs out and removes the account's data from this computer |
| `octapass status` | Exits 0 when unlocked, 3 when signed out and 4 when locked |
| `octapass change-master-password` | ⚠ The user changes it, and other devices are signed out |
| `octapass rotate-secret-key` | ⚠ A new Secret Key and Recovery Kit. `--new-recovery-code` also replaces the recovery code |
| `octapass rotate-vault-key` | ⚠ Gives a vault a new key: `octapass rotate-vault-key Team` |
| `octapass reset-master-password` | ⚠ For a forgotten master password, with the recovery code. Prints a new Recovery Kit |

Variables for a login without a terminal: `OCTAPASS_SERVER`, `OCTAPASS_EMAIL`, `OCTAPASS_SECRET_KEY`, `OCTAPASS_TWO_STEP_CODE` and `OCTAPASS_SSO_CODE`. They belong to the user's own automation; an agent never sets them.

## Items

| Command | What it does |
|---|---|
| `octapass list` | `--vault`, `--search` (title, username, URLs, tags). No secrets, even with `--json` |
| `octapass get` | `octapass get GitHub` shows an item without secrets. `--field`, `--vault`, `-n`. ⚠ `--json` without `--field` includes the secrets |
| `octapass totp` | The current one-time code: `octapass totp GitHub --vault Work` |
| `octapass create` | `login`, `password`, `note`, `card`, `identity`, `wifi`, `bank-account`, `api-credential`, `licence`, `id-document`, `wallet`, `database`, `custom` or `template`. `--title`, `--vault`, `--url`, `--tag`, `--favorite`, `--template`, `--generate`, `--length`, `--words`, `--stdin`, `--plain` |
| `octapass edit` | ⚠ Overwrites fields. `--title`, `--unset`, `--add-url`, `--remove-url`, `--add-tag`, `--remove-tag`, `--favorite`, `--no-favorite`, `--generate`, `--stdin`, `--plain` |
| `octapass delete` | ⚠ Moves an item to the trash |
| `octapass restore` | Brings it back from the trash |
| `octapass generate` | A password or passphrase, no account needed. `--length`, `--words`, `--no-uppercase`, `--no-lowercase`, `--no-digits`, `--no-symbols`, `--avoid-ambiguous`, `--separator`, `--capitalize`, `--number` |

## Secrets for programs

| Command | What it does |
|---|---|
| `octapass run` | `octapass run --env-file .env.octapass -- npm start`. `--env`, `--project`, `--stage`, `--env-file`, `--env-file-out`, `--yes`, `--no-masking` |
| `octapass inject` | `octapass inject -i app.tmpl -o app.conf`. Fills references in a template, and `--force` replaces the output |
| `octapass read` | ⚠ Prints one reference's value: `octapass read octapass://Personal/Postgres/password -n` |
| `octapass env list` | Environments grouped by project. `--vault`, `--project` |
| `octapass env show` | Concealed values stay hidden. ⚠ `--reveal` shows them |
| `octapass env set` | ⚠ `octapass env set Dev KEY=value`, or `KEY` alone for a hidden prompt. `--plain` for non-secrets |
| `octapass env unset` | ⚠ `octapass env unset Dev OLD_KEY` |
| `octapass env create` | `octapass env create Dev --project shop-api --stage development --vault Personal` |
| `octapass env import` | `octapass env import .env --new Dev`, or ⚠ `--into Dev`, which replaces variables with the same name. `--vault`, `--project`, `--stage` |
| `octapass env export` | ⚠ Real values. `--format` is `dotenv`, `json`, `shell`, `powershell` or `docker`. `-o`, `--force`, and `--keep-references` to keep the references |
| `octapass env diff` | Names only, never values: `octapass env diff shop-api staging production` |
| `octapass env hook` | Prints a shell hook: `octapass env hook zsh` (also `bash`, `fish`, `powershell`) |
| `octapass env allow` | Lets the hook load this folder's `octapass.toml` until the file changes |
| `octapass env deny` | Stops it |

## SSH, OpenPGP and Git

| Command | What it does |
|---|---|
| `octapass ssh list` | Title, type, fingerprint and vault. `--vault` |
| `octapass ssh generate` | `--type` is `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `rsa-3072` or `rsa-4096`. `--title`, `--comment`, `--vault`, `--passphrase` |
| `octapass ssh import` | Private key files, or `--scan` for `~/.ssh`. `--vault` |
| `octapass ssh export` | ⚠ Writes a private key after the master password. `--out`, `--passphrase`, `--no-passphrase`, `--force`, `--vault` |
| `octapass ssh public` | The `authorized_keys` line. Public, so safe to show |
| `octapass gpg list` | OpenPGP keys. `--vault` |
| `octapass gpg import` | `octapass gpg import key.asc --title "Signing key"`. `--vault` |
| `octapass gpg public` | The public key block, for a forge's settings |
| `octapass git setup` | ⚠ Configures Git. `--global`, `--signing-key`, `--agent`, `--no-credentials`, `--dry-run` |

The SSH agent belongs to the desktop app (Settings → SSH agent), not the CLI.

## Files and Safes

| Command | What it does |
|---|---|
| `octapass encrypt` | age files. `--self`, `--to`, `--passphrase`, `-o`, `--armor`, ⚠ `--shred`, `--force`, `--notify` |
| `octapass decrypt` | `-i` for an age identity file, `-o`, `--force`, `--notify` |
| `octapass shred` | ⚠ Overwrites and deletes, and can't be undone. Without `--yes` it asks |
| `octapass file-key` | Your `age1…` public key. ⚠ `--export` prints the secret key, and `-o` writes it to a file |
| `octapass safe list` | Your Safes |
| `octapass safe create` | `octapass safe create Taxes --sync` |
| `octapass safe ls` | `octapass safe ls Taxes 2026` |
| `octapass safe add` | `octapass safe add Taxes return.pdf --to 2026` |
| `octapass safe get` | `octapass safe get Taxes 2026/return.pdf -o return.pdf`. `--force` |
| `octapass safe mkdir` | `octapass safe mkdir Taxes 2026/receipts` |
| `octapass safe mv` | `octapass safe mv Taxes old.pdf archive/old.pdf` |
| `octapass safe rm` | ⚠ `-r` for a folder |
| `octapass safe sync` | Sends and fetches changes now |
| `octapass safe set-sync` | `octapass safe set-sync Taxes on` (or `off`) |
| `octapass safe delete` | ⚠ Deletes a Safe and everything in it. Without `--yes` it asks |
| `octapass safe mount` | Linux with the `fuse` build feature: `octapass safe mount Taxes ~/Taxes` |
| `octapass context-menu install` | ⚠ Adds "Encrypt with Octa Pass" to the file manager |
| `octapass context-menu remove` | Removes it |
| `octapass context-menu status` | Shows whether it's there |

## Import and export

| Command | What it does |
|---|---|
| `octapass import` | `octapass import bitwarden-json export.json --dry-run`. `--vault`, `--key-file` (KeePass), `--dry-run` |
| `octapass export` | ⚠ Every item, after the master password. `--format` is `json`, `csv` or `cxf`. `--encrypted` (JSON only) and `-o` |

Run `octapass import --dry-run` first and show the user the counts. Import formats: `chrome`, `firefox`, `safari`, `bitwarden-json`, `bitwarden-csv`, `onepassword-1pux`, `onepassword-csv`, `lastpass-csv`, `generic-csv`, `otpauth`, `octapass`, `cxf`, `protonpass`, `dashlane`, `keeper`, `nordpass`, `keepass`, `enpass`, `roboform`, `aegis`, `2fas`, `andotp`, `ente-auth`, `raivo`, `zoho-vault`, `avira`, `norton`, `mcafee` and `kaspersky`.

A plaintext export holds every secret in the clear. Prefer `octapass export --encrypted -o backup.octapass`, and remind the user to delete a plaintext file once they're done with it.

## Organisations

For owners and admins. Roles, groups, policies, SSO and SCIM are server settings and open nothing; the one command that seals a vault key is `octapass org access apply`, and it's the user's review, not yours.

| Command | What it does |
|---|---|
| `octapass org show` | The organisation, your role, its policies and invitations to you |
| `octapass org create` | ⚠ Starts an organisation with you as owner: `octapass org create "Acme"` |
| `octapass org rename` | ⚠ Renames it (owners) |
| `octapass org delete` | ⚠ Deletes it and all its vaults, after the master password. `--confirm-name` |
| `octapass org join` | ⚠ Accepts an invitation by its id. Its policies apply from then on |
| `octapass org decline` | Declines an invitation |
| `octapass org leave` | ⚠ Leaves; its vaults go at once. `--orphan-vaults` |
| `octapass org members` | Members and pending invites (admins) |
| `octapass org invite` | ⚠ Emails an invitation. `--admin` |
| `octapass org uninvite` | Cancels an invite, by id or email |
| `octapass org role` | ⚠ Sets a member's role: `member`, `admin` or `owner` (owners) |
| `octapass org remove` | ⚠ Removes a member; they lose its vaults at once. `--orphan-vaults` |
| `octapass org group list` | Groups and who's in them |
| `octapass org group create` | Makes a group |
| `octapass org group rename` | Renames a group |
| `octapass org group delete` | ⚠ Deletes a group; its members lose the vaults only it gave them |
| `octapass org group add` | Adds a member to a group. They get its vaults only after `org access apply` |
| `octapass org group remove` | ⚠ Takes a member out of a group, with its vaults |
| `octapass org vault list` | Organisation vaults, their groups, and which need a new key |
| `octapass org vault create` | Makes an organisation vault, owned by you |
| `octapass org vault delete` | ⚠ Deletes a vault and everything in it, after the master password |
| `octapass org vault link` | Links a group to a vault. `--role` is `read`, `write` or `manage` |
| `octapass org vault unlink` | ⚠ Unlinks a group; people who had the vault only through it lose it |
| `octapass org access list` | What vaults wait for, with each person's fingerprint worked out on this device |
| `octapass org access apply` | ⚠ Seals a vault to the people waiting. In a terminal it asks the user person by person; in a script each one needs `--person EMAIL=FINGERPRINT` |
| `octapass org rotate` | ⚠ Gives an organisation vault a new key after someone lost access |
| `octapass org policy show` | The policies |
| `octapass org policy set` | ⚠ Sets one: `octapass org policy set disable-export on` |
| `octapass org sso show` | SSO settings and what to register at the identity provider |
| `octapass org sso oidc` | ⚠ OpenID Connect settings. `--issuer`, `--client-id`, `--client-secret` (asks for it) |
| `octapass org sso saml` | ⚠ SAML settings. `--metadata FILE`, or `--entity-id`, `--sso-url` and `--certificate FILE` |
| `octapass org sso test` | Prints a test sign-in URL for the user to open |
| `octapass org sso remove` | ⚠ Removes SSO settings and every member's link |
| `octapass org scim show` | The SCIM base URL and tokens |
| `octapass org scim token create` | ⚠ Prints a SCIM token (`opscim_…`) once |
| `octapass org scim token revoke` | ⚠ Ends a SCIM token |
| `octapass org events` | The admin activity log |

Never pass `--person` fingerprints you didn't get from the user: they come from comparing with each person out of band, and sealing on a fingerprint the server showed you defeats the review.

## Service accounts, Connect and cloud helpers

These are in [ci.md](ci.md).

| Command | What it does |
|---|---|
| `octapass service-account create` | ⚠ Prints a token once. `--vault`, `--name`, `--write`, `--expires` |
| `octapass service-account list` | `--vault` |
| `octapass service-account revoke` | ⚠ Ends it and rotates the vault's key. `--vault` |
| `octapass connect serve` | Runs Connect in the foreground. `--port` |
| `octapass connect status` | Whether Connect is running and unlocked |
| `octapass connect clients` | Approved clients |
| `octapass connect revoke` | ⚠ Takes a client's approval back |
| `octapass connect approve` | ⚠ Approves a client after the master password and prints its token. `--name` |
| `octapass connect pair` | Asks a running Connect for approval. `--name` |
| `octapass connect read` | References through Connect, with `OCTAPASS_CONNECT_TOKEN` |
| `octapass aws credential-process` | For `credential_process` in `~/.aws/config`. `--vault` |
| `octapass kube credential` | An ExecCredential for a kubeconfig `exec` plugin. `--vault` |
| `octapass docker-credential` | The Docker helper protocol (`get`, `store`, `erase`, `list`), run through `docker-credential-octapass` |
| `octapass oauth create` | Saves an OAuth2 client. `--flow` is `client-credentials` or `refresh-token`. `--token-url`, `--client-id`, `--scope`, `--audience`, `--vault` |
| `octapass oauth token` | ⚠ The current access token. `-n`, `--vault` |
| `octapass oauth show` | The token's claims and expiry, not the token |

## Developer toolkit

None of these need an account unless they save to the vault (`--save`, `--title`, `--vault`). They read files or stdin and write stdout. A generated private key is never printed to a terminal: use `--save`, `--out-key FILE` or a pipe, and don't paste keys into the conversation.

| Command | What it does |
|---|---|
| `octapass cert self-signed` | `octapass cert self-signed localhost 127.0.0.1 --out cert.pem --out-key key.pem` |
| `octapass cert ca-create` | A private CA, limited to private names unless `--permit`, or ⚠ `--unconstrained` |
| `octapass cert issue` | `octapass cert issue --ca "Local CA" app.test --out app.pem --out-key app-key.pem` |
| `octapass cert csr` | A signing request. `--key` to use an existing key |
| `octapass cert sign-csr` | `octapass cert sign-csr --ca "Local CA" request.csr` |
| `octapass cert read` | Subject, names, chain, expiry and problems. `--host` checks a name |
| `octapass cert fetch` | The certificate a server presents. This one uses the network |
| `octapass cert convert` | `--to` is `pem`, `der` or `p12` |
| `octapass cert p12-read` | Reads a PKCS#12 file, and ⚠ `--out-key` writes its key |
| `octapass cert trust` | ⚠ Makes this device trust a CA. `--dry-run` first |
| `octapass cert untrust` | ⚠ Stops trusting it |
| `octapass cert list` | Certificates in the vault, with their expiry |
| `octapass cert expiring` | Exits 10 when some need renewing. `--within 30` |
| `octapass cert export` | `--part` is `certificate`, `chain`, `fullchain`, ⚠ `key` or ⚠ `p12` |
| `octapass acme issue` | Let's Encrypt and other ACME CAs: `octapass acme issue example.com --staging --agree-tos --email ops@example.com` |
| `octapass acme renew` | Renews with the same CA, names and account key |
| `octapass key generate` | `--type` is `ed25519`, `p256`, `p384`, `rsa2048`, `rsa3072` or `rsa4096` |
| `octapass key inspect` | Fingerprints and public forms |
| `octapass key convert` | Between PEM, DER, JWK, OpenSSH, PKCS#8 and PKCS#1: `octapass key convert key.pem --to jwk` |
| `octapass key age` | A new age key |
| `octapass key gpg` | A new OpenPGP key: `--user-id "Ada <ada@example.com>"`. `--save` |
| `octapass key export` | ⚠ Writes a Key item's private key after the master password |
| `octapass jwt decode` | Reads a token without checking it |
| `octapass jwt verify` | Checks the signature and time limits with `--key` or `--jwks-url`. Exits 1 when it isn't valid |
| `octapass jwt sign` | Signs claims: `--alg`, `--key` or `--secret-file` |
| `octapass jwt decrypt` | Decrypts a JWE with a key you hold |
| `octapass jwt keygen` | A new signing key with its JWK and JWKS. `--alg`, `--save` |
| `octapass jwt jwks` | A JWKS from public keys, to publish |
| `octapass hash` | Hashes files, `--text` or stdin. `-a` picks the algorithm, and `--check` exits 1 on a mismatch |
| `octapass hmac` | An HMAC, with the key from `--secret-file` |
| `octapass encode` | `octapass encode base64 hello`: `base64`, `base64url`, `base32`, `hex`, `url`, `html` or `unicode` |
| `octapass decode` | The same formats, back |
| `octapass detect` | Guesses what a pasted string is |
| `octapass random bytes` | `octapass random bytes 32 --format base64` |
| `octapass random uuid` | `-v 7`, `-c 5` |
| `octapass random ulid` | `-c 5` |
| `octapass random token` | An API token: `octapass random token --prefix sk_live_ --save --title "Stripe test"`. `--shape`, `--length` |
| `octapass pwhash hash` | Argon2id, bcrypt, scrypt or PBKDF2 hashes for your own app. `--scheme` |
| `octapass pwhash verify` | Exits 1 when the password doesn't match |
| `octapass totp-secret` | A new TOTP secret for your own app's 2FA. `--issuer`, `--account`, `--save` |
