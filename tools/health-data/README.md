# Health datasets

`packages/vault-client/src/data/passkey-domains.ts` is generated from the passkeys directory's public list. The list ships with each release; no client looks sites up one by one.

```sh
curl -sS -o /tmp/passkeys-supported.json https://passkeys-api.2fa.directory/v1/supported.json
node tools/health-data/update-passkey-domains.mjs /tmp/passkeys-supported.json
```

The script keeps well-formed domain names only and reduces them to registrable domains with the same `registrableDomain` the health report uses, so a login at `accounts.example.com` matches a directory entry for `example.com` or `login.example.com`. The Rust apps read the same file with `include_str!`, so run their tests after an update.

The list comes from [2factorauth/passkeys](https://github.com/2factorauth/passkeys), licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Keep the attribution in the generated file and in `docs/features/security-dashboard.md`.

## Signed updates

Clients also take newer lists between releases, as a file signed with the project's Ed25519 key (plan 06 History). After changing either list, sign them:

```sh
node tools/health-data/sign.mjs --key /path/to/health-data-signing-key.pem   # the next version
node tools/health-data/sign.mjs --check                                     # what CI can run
```

This writes `packages/vault-client/src/data/health-data.json`, which every client and the server compile in, and `apps/website/public/data/health-data.json`, which the site publishes for servers with `OCTAPASS_HEALTH_DATA_URL` set. The version goes up by one each time (`--version <n>` to choose; it can't go down, because clients refuse older files). The private key never goes in the repository. `--keygen <file>` makes a new key pair and prints the public key, which then replaces `HEALTH_DATA_PUBLIC_KEY` in `packages/vault-client/src/tools/healthData.ts` and `PUBLIC_KEY` in `crates/octapass-core/src/health_data.rs`, in the same release.
