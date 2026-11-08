---
title: Developer toolkit
description: Generate and inspect TLS certificates, keys, JWTs, hashes and encodings on your own device, from the CLI and the Tools section of the apps.
status: in-progress
sidebar:
  order: 19
---

:::note[In progress]
The toolkit works in the CLI, the web vault, the browser extension's Octa Pass tab and the Windows and Linux desktop app. The iPhone, iPad, Android and Mac apps have a smaller set so far: see [Where each tool works](#where-each-tool-works).
:::

The developer toolkit makes and reads the things developers handle every day: certificates, keys, tokens, hashes and encodings. Every tool runs on your device, in the same Rust core everywhere. Nothing you paste is sent to Octa Pass.

## Certificates

```sh
# A self-signed certificate
octapass cert self-signed localhost 127.0.0.1 --out cert.pem --out-key key.pem

# A private CA, saved to the vault, trusted on this machine, issuing for local names
octapass cert ca-create --name "My dev CA" --save
octapass cert trust "My dev CA"
octapass cert issue app.test "*.app.test" --ca "My dev CA" --save --title "app.test"

# Requests, reading and converting
octapass cert csr example.com www.example.com --out req.csr --out-key key.pem
octapass cert read cert.pem --host example.com
octapass cert fetch example.com:443
octapass cert convert cert.pem --to p12 --key key.pem --out bundle.p12
```

Key types are RSA 2048, 3072 and 4096, ECDSA P-256 and P-384, and Ed25519. New certificates use SHA-256 or stronger.

**A private CA is limited to private names** unless you pass `--unconstrained`. It can issue for `localhost`, `*.test`, `*.local`, `*.internal`, `*.home.arpa` and private IP ranges, and for anything you add with `--permit`. These limits are part of the CA's certificate, so a stolen CA key can't impersonate your bank to a machine that trusts it.

`cert trust` adds a CA to this machine's trust store: the login keychain on macOS, the current user's Root store on Windows, and the system store plus your NSS database on Linux, which needs `sudo`. It uses only the public certificate, shows what it will run, and asks first. `cert untrust` removes it.

The reader shows the subject, names, issuer chain, expiry, key type and fingerprints, and flags expired certificates, weak keys and signatures, missing names, name mismatches and broken chains. Reading a file or pasted text is offline. `cert fetch` is the one command that connects: it completes a TLS handshake with that host, sends nothing else, and reports whether the Mozilla root program trusts the chain.

## Certificates from real CAs

```sh
# Try the staging CA first: it has generous limits
octapass acme issue example.com --email you@example.com --agree-tos --staging

# DNS-01, needed for wildcards
CLOUDFLARE_API_TOKEN=… octapass acme issue "*.example.com" --challenge dns --dns cloudflare --email you@example.com --agree-tos

# Renew with the same CA, names and account key
octapass acme renew example.com
```

| Challenge | How |
|---|---|
| HTTP-01 | `octapass` listens on port 80 (`--http-port` behind a redirect), or writes the answer to `--webroot`. Doesn't work for wildcards. |
| DNS-01 | `--dns manual` prints the record and waits. `--dns hook --dns-hook ./script` runs your script with `OCTAPASS_ACME_ACTION`, `OCTAPASS_ACME_NAME` and `OCTAPASS_ACME_VALUE`, which covers any DNS host. `--dns cloudflare` and `--dns digitalocean` use a token from `CLOUDFLARE_API_TOKEN` or `DIGITALOCEAN_TOKEN`. |

Use `--zerossl` with `--eab-kid` and `--eab-key` for ZeroSSL, or `--directory` for any other CA. Keys are made on your device: the CA sees public keys, a CSR and signatures. The certificate, its key and the ACME account key are saved to the vault as a Certificate item.

**Renewal reminders:** `octapass cert expiring` lists certificates inside their renewal window, the last third of their life or the last 30 days, whichever is shorter, and exits 10 when there are any, so a cron job can act on it. The Tools section shows the same list.

## Keys

```sh
octapass key generate --type ed25519 --save --title "Signing key"
octapass key gpg --user-id "Ada Lovelace <ada@example.com>" --save
octapass key age --save
octapass key inspect key.pem
octapass key convert key.pem --to jwk
octapass key convert id_ed25519 --to pkcs8-pem --encrypt --out key.pem
```

The converter reads PEM (PKCS#8, encrypted PKCS#8, PKCS#1, SEC1 and SPKI), OpenSSH, JWK, base64 DER and the public key of a certificate. It writes all of them except where a format can't hold the key. Fingerprints are the SSH `SHA256:` form, the SHA-256 of the public key (with its `pin-sha256` form) and the RFC 7638 JWK thumbprint.

## JWT, JWS and JWE

```sh
octapass jwt decode "$TOKEN"
octapass jwt verify "$TOKEN" --key public.pem
octapass jwt verify "$TOKEN" --jwks-url https://issuer.example/.well-known/jwks.json
octapass jwt sign '{"sub":"ada"}' --alg ES256 --key key.pem --iat --expires-in 3600
octapass jwt decrypt "$JWE" --key key.pem
octapass jwt keygen --alg ES256 --save
```

The reader explains claims in plain language ("Expires in 12 minutes") and flags `alg: none`, expired and not-yet-valid tokens. Decoding doesn't prove a token is genuine: only verifying does.

Signing and verifying cover HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512 and EdDSA with Ed25519. `verify` exits 1 when a token isn't valid.

Decryption covers `dir`, AES key wrap, AES-GCM key wrap, RSA-OAEP, RSA-OAEP-256, ECDH-ES on the NIST curves and PBES2, with AES-GCM and AES-CBC-HMAC content encryption. **RSA1_5 is refused:** it's the padding-oracle construction RFC 8725 warns about. X25519 ECDH isn't supported yet.

Tokens are checked the way RFC 8725 asks: the header never decides how a key is read, so a public key can't be replayed as an HMAC secret, `alg: none` never verifies, and a critical header this tool doesn't understand fails.

## Hashes, encodings and random data

```sh
octapass hash file.tar.gz --algo sha256,blake3
octapass hash file.tar.gz --check "sha256sum-line-or-hash"
octapass hmac file --secret-file key.txt
octapass encode base64 "hello"
octapass decode hex 68656c6c6f
octapass detect "SGVsbG8="
octapass random bytes 32 --format base64
octapass random uuid --version 7
octapass random ulid
octapass random token --shape base62 --prefix sk_live_ --save --title "Stripe test key"
```

Hashes are SHA-1, SHA-2, SHA-3, BLAKE2, BLAKE3, MD5 and CRC32. MD5, SHA-1 and CRC32 are labelled wherever they appear: they're for checking old checksums only. Files are read in chunks, so size isn't a limit. Encodings are Base64, base64url, base32, hex, URL encoding, HTML entities and Unicode escapes.

## Password hashes and 2FA secrets

```sh
printf %s "$PASSWORD" | octapass pwhash hash --scheme argon2id
printf %s "$PASSWORD" | octapass pwhash verify '$argon2id$…'
octapass totp-secret --issuer "My app" --account ada@example.com
```

Argon2id, bcrypt, scrypt and PBKDF2 write the formats libraries store: PHC strings, and `$2b$` for bcrypt. New hashes must meet OWASP's minimum costs. Hashes to verify may be weaker, so old ones can still be checked, but absurdly expensive ones are refused so a pasted hash can't freeze your device. bcrypt refuses passwords over 72 bytes rather than silently ignoring the rest.

## Saving and exporting

Results save as encrypted items: **Certificate** items hold the certificate, chain and private key, and **Key** items hold JWT, OpenPGP and age keys. API keys save as API credentials and TOTP secrets as one-time codes.

Private keys follow the same rules as [SSH keys](/docs/features/ssh-keys/):

- They're made on your device and stored only encrypted in the vault.
- They're shown, copied or exported only after you confirm with your master password or device unlock.
- The CLI never prints one on a terminal. Pass `--save` or `--out-key`, or pipe the output. Files are written readable only by you, and existing files aren't replaced without `--force`.

## Where each tool works

| | CLI | Web vault | Windows and Linux app | Browser extension | iPhone, Android and Mac apps |
|---|---|---|---|---|---|
| Generators, inspectors, converters | Yes | Yes | Yes | Yes, the web vault's tools in the Octa Pass tab | JWT and certificate reader, hashes, encodings, random values, key generation saved to the vault |
| Read a live `host:443` | Yes | No: a web page can't open a TLS connection | Yes | No | No |
| Fetch a JWKS URL | Yes | When the site allows it (CORS) | Yes | As in the web vault | No |
| Trust a local CA | Yes | No | Yes | No | No |
| ACME | Yes | No | No | No | No |

The web vault loads the tools as a separate download the first time you use them, so signing in stays quick.
