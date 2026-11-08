---
title: Service accounts
description: Give CI jobs and servers read-only access to one shared vault with a token that never reaches the server, is revocable at any time, and shows every use in your security log.
status: in-progress
sidebar:
  order: 30
---

:::note[In progress]
Service accounts work through the CLI and the server. Managers can make and revoke them in the web vault, the browser extension's Octa Pass tab and the Windows and Linux app, but not yet in the Mac, iPhone, iPad or Android apps. They can't read files attached to items yet. There are no released CLI builds, so CI needs one you built.
:::

A **service account** lets software read a vault with no person there: a GitHub Actions job, a GitLab pipeline, a server at startup. It has its own token, bound to **one shared vault**, and it's **read-only** unless you say otherwise.

## Make one

You need the manage role on a shared vault. Personal vaults can't have service accounts: their key can't be rotated, so access could never really be taken back. Make a shared vault that holds only what the job needs.

```bash
octapass service-account create --vault CI --name "Deploy job"
```

Or open the vault under **Sharing** and use **Service accounts**. The token (`opsa1_…`) is shown once, and Octa Pass can't show it again.

| Option | Meaning |
|---|---|
| `--write` | It can save items too. Without it, it can only read. |
| `--expires 90d` | It stops working after that long (`12h`, `90d`). Without it, it lasts until revoked. |

Keep the token in your CI system's secret store. **The token is a key**: whoever has it can read the vault, so treat it as you would a password to that vault.

## Use it

Set `OCTAPASS_SERVICE_ACCOUNT_TOKEN`, and the commands that read work with no sign-in, keyring or master password:

```bash
export OCTAPASS_SERVICE_ACCOUNT_TOKEN=opsa1_…
octapass read "octapass://CI/Deploy key/password"
octapass run --env shop-api:production -- ./deploy.sh
```

`list`, `get`, `totp`, `read`, `run`, `inject`, `env list`, `env show`, `env export`, `env diff`, `oauth token`, `aws`, `kube` and `docker-credential get` work this way. Anything else is refused while the variable is set.

### GitHub Actions

```yaml
- uses: octap-app/octapass-action@v0
  with:
    token: ${{ secrets.OCTAPASS_SERVICE_ACCOUNT_TOKEN }}
    secrets: |
      DATABASE_URL=octapass://CI/Shop database/url
      STRIPE_KEY=octapass://CI/Stripe/password
- run: ./deploy.sh
```

Values are masked in the logs and exported to later steps. The action calls an `octapass` binary already on the runner.

### GitLab CI

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

Add `OCTAPASS_SERVICE_ACCOUNT_TOKEN` as a masked, protected CI/CD variable.

### Terraform and Pulumi

No plugin needed. Both read environment variables, so `octapass run` is all it takes:

```bash
export TF_VAR_database_password=octapass://CI/Shop database/password
octapass run -- terraform apply

export PULUMI_CONFIG_PASSPHRASE=octapass://CI/Pulumi/password
octapass run -- pulumi up
```

## See what it did

Each fetch and each save appears in the security log of whoever made the service account, with its id. A revoked or expired token that's still being tried appears too.

The log records **that the vault was read, not which secret**. The server sends ciphertext and can't know which item a runner decrypted.

## Revoke it

```bash
octapass service-account list --vault CI
octapass service-account revoke <id> --vault CI
```

Revoking ends it at once: live sessions go, and it can't sign in. Then your device rotates the vault's key, as it does when a member is removed.

Anything it already read stays known to whoever held the token, so **if a token leaked, change the secrets in that vault too**.

If another manager rotates the vault's key, tokens made by someone else stop working and show **needs a new token**. A token only trusts its creator's signature, so that a server can't hand it a key of its own. Revoke it and make a new one.

## Limits

- One vault per token. Make one per job.
- Files attached to items can't be read yet.
- A service account can never manage members or rotate keys, whatever its role.

See [what the server sees](/docs/security/what-the-server-sees/) and the [design in the threat model](/docs/security/threat-model/).
