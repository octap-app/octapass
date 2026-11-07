# Health datasets

`packages/vault-client/src/data/passkey-domains.ts` is generated from the passkeys directory's public list. The list ships with each release; no client looks sites up one by one.

```sh
curl -sS -o /tmp/passkeys-supported.json https://passkeys-api.2fa.directory/v1/supported.json
node tools/health-data/update-passkey-domains.mjs /tmp/passkeys-supported.json
```

The script keeps well-formed domain names only and reduces them to registrable domains with the same `registrableDomain` the health report uses, so a login at `accounts.example.com` matches a directory entry for `example.com` or `login.example.com`. The Rust apps read the same file with `include_str!`, so run their tests after an update.

The list comes from [2factorauth/passkeys](https://github.com/2factorauth/passkeys), licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Keep the attribution in the generated file and in `docs/features/security-dashboard.md`.
