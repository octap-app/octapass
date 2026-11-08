# CI, servers and other tools

Everything here keeps secrets out of config files and logs: the tool asks `octapass` at the moment it needs a value. The [rules for agents](../SKILL.md#rules-for-agents-read-first) still apply. Never print a token, and never write a value where a reference would do.

## Service accounts

A service account is a token for **one shared vault**, read-only unless made with `--write`. Personal vaults can't have one. Making one needs the manage role on that vault.

```bash
octapass service-account create --vault CI --name "Deploy job"
octapass service-account create --vault CI --name "Nightly backup" --write --expires 90d
octapass service-account list --vault CI
octapass service-account revoke 0f3c2a --vault CI
```

- `create` prints the token (`opsa1_…`) **once**. Hand it straight to the user's CI secret store, never into a file in the repository, a log or the conversation. If an agent ran `create`, tell the user the token is in that command's output and stop there.
- With `OCTAPASS_SERVICE_ACCOUNT_TOKEN` set, these work with no sign-in: `list`, `get`, `totp`, `read`, `run`, `inject`, `env list`, `env show`, `env export`, `env diff`, `oauth token`, `aws`, `kube` and `docker-credential get`. Everything else is refused.
- A malformed token exits 2. A revoked, expired or refused one exits 5.
- `revoke` ends it at once and rotates the vault's key, so confirm first. If a token leaked, the secrets it could read must be changed too: revoking doesn't make them secret again.
- Make one service account per job, in a vault that holds only what that job needs.

## GitHub Actions

`integrations/github-action` is a composite action. It reads each reference with `octapass read`, masks the value in the log and exports it to later steps. It needs an `octapass` binary on the runner (there are no released builds yet), passed as `cli` if it isn't on `PATH`.

```yaml
- uses: ./integrations/github-action
  with:
    token: ${{ secrets.OCTAPASS_SERVICE_ACCOUNT_TOKEN }}
    secrets: |
      DATABASE_URL=octapass://CI/Shop database/url
      STRIPE_KEY=octapass://CI/Stripe/password
- run: ./deploy.sh
```

To give secrets to one step only, without exporting them to every later step, set the token in that step's `env` and run the command through `octapass run`:

```yaml
- run: octapass run --env-file .env.octapass -- ./deploy.sh
  env:
    OCTAPASS_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OCTAPASS_SERVICE_ACCOUNT_TOKEN }}
```

## GitLab CI

`integrations/gitlab/octapass.gitlab-ci.yml` gives you a `.octapass` job to extend. It checks that `OCTAPASS_SERVICE_ACCOUNT_TOKEN` is set and that `octapass` is on the image. Add the token as a masked, protected CI/CD variable.

```yaml
include:
  - local: integrations/gitlab/octapass.gitlab-ci.yml

deploy:
  extends: .octapass
  variables:
    DATABASE_URL: octapass://CI/Shop database/url
  script:
    - octapass run -- ./deploy.sh
```

## Other CI and servers

The same pattern works anywhere: put the token in the platform's secret store, write references into the job's variables or an `.env.octapass` file, and start the program with `octapass run`.

```bash
octapass run --env shop-api:production -- ./deploy.sh
octapass run --project shop-api --stage testing -- npm test
octapass inject -i k8s/secret.tmpl.yaml -o k8s/secret.yaml
```

A `production` stage that comes from `octapass.toml` rather than the command line asks first, and `--yes` skips that. Add `--yes` only to a job the user says is meant to touch production.

## Terraform and Pulumi

There's no plugin: both read environment variables.

```bash
TF_VAR_database_password="octapass://CI/Shop database/password" octapass run -- terraform apply
PULUMI_CONFIG_PASSPHRASE=octapass://CI/Pulumi/password octapass run -- pulumi up
```

## AWS

In `~/.aws/config`:

```ini
[profile prod]
credential_process = octapass aws credential-process "AWS prod" --vault CI
```

The item needs `accessKeyId` and `secretAccessKey` fields (a login's username and password work too), and optionally `sessionToken` and `expiration`.

## Kubernetes

In a kubeconfig:

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

The item needs a `token` field (an OAuth2 item's live `accessToken` works too), or `clientCertificateData` with `clientKeyData`. The command it runs is `octapass kube credential "Cluster prod" --vault CI`.

## Docker

`cargo install --path apps/cli` also installs `docker-credential-octapass`. In `~/.docker/config.json`:

```json
{ "credsStore": "octapass" }
```

`docker login` then saves a login tagged `docker-credential`, and `docker logout` moves it to the trash. Under the hood Docker runs `octapass docker-credential get`. A service account can read these logins but can't save them.

## Git

```bash
octapass git setup --dry-run
octapass git setup --global --signing-key "Laptop key" --agent
```

`git-credential-octapass` gives Git the login saved for that exact scheme, host and port. A custom field named **Git token** is given instead of the password. Commit signing uses `octapass-git-sign`, with an SSH or OpenPGP key from the vault. `--global` changes the user's global Git settings, so confirm first.

## OAuth2 tokens

An API credential item can hold an OAuth2 client, and Octa Pass then hands out a current access token at its `accessToken` field:

```bash
octapass oauth create "Billing API" --flow client-credentials --token-url https://auth.example.com/oauth/token --client-id abc --scope "read write"
octapass oauth show "Billing API"
API_TOKEN="octapass://Work/Billing API/accessToken" octapass run -- ./call-api.sh
```

`oauth create` asks for the client secret or refresh token, or reads `OCTAPASS_OAUTH_CLIENT_SECRET` and `OCTAPASS_OAUTH_REFRESH_TOKEN` when there's no terminal. `oauth show` prints claims and the expiry, not the token, and `octapass oauth token "Billing API"` prints the token itself.

## Octa Pass Connect

Connect is a local helper that gives approved programs a secret by reference. It only works while the vault is unlocked, and it records every secret it hands out in the user's security log.

```bash
octapass connect serve
octapass connect status
octapass connect clients
octapass connect revoke 7d1e
octapass connect approve --name "Nightly report"
octapass connect pair --name "My script"
OCTAPASS_CONNECT_TOKEN=… octapass connect read "octapass://Work/Billing API/accessToken"
```

- `serve` runs in the foreground and asks for each approval in its own terminal. The desktop app can run Connect instead, from Settings → Octa Pass Connect.
- `approve` and `pair` print a client token, valid for 30 days. Treat it like a password.
- `OCTAPASS_CONNECT` says where Connect is listening when it isn't in the usual place.
- The protocol is in the docs: `docs/developers/connect-api.md`.
