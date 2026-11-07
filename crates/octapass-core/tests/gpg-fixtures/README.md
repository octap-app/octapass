# OpenPGP fixtures

`rsa.asc`: an RSA key without a passphrase, exported by GnuPG, for testing that RSA keys are read
but refused for signing (plan 16). It protects nothing.

```sh
gpg --batch --gen-key <<'E'
%no-protection
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign,cert
Name-Real: Octa Pass RSA
Name-Email: rsa@octap.app
Expire-Date: 0
%commit
E
gpg --batch --pinentry-mode loopback --passphrase '' --armor --export-secret-keys rsa@octap.app > rsa.asc
```

`ed25519-subkey.asc` and `.pub.asc`: an Ed25519 key with a signing subkey, no passphrase, exported by
GnuPG 2.5 (`--export-options backup`, which GnuPG 2.5 needed here so the export didn't hang). It
protects nothing.
