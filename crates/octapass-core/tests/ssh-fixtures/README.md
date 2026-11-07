# SSH key fixtures

Throwaway keys made only for `tests/ssh.rs`. They protect nothing. The passphrase, where there is
one, is `correct horse`.

Made with OpenSSH 10.3p1 and LibreSSL 3.3.6 (macOS):

```sh
ssh-keygen -q -t ed25519 -N '' -C 'ed25519@fixture' -f ed25519
ssh-keygen -q -t ed25519 -N 'correct horse' -C 'ed25519-pass@fixture' -f ed25519-pass
ssh-keygen -q -t ecdsa -b 256 -N '' -C 'p256@fixture' -f ecdsa-p256
ssh-keygen -q -t ecdsa -b 384 -m PEM -N '' -C 'p384@fixture' -f ecdsa-p384-sec1
ssh-keygen -q -t ecdsa -b 521 -m PKCS8 -N '' -C 'p521@fixture' -f ecdsa-p521-pkcs8
ssh-keygen -q -t rsa -b 3072 -m PEM -N '' -C 'rsa@fixture' -f rsa-3072-pkcs1
ssh-keygen -q -t rsa -b 3072 -m PEM -N 'correct horse' -C 'rsa-pass@fixture' -f rsa-3072-pkcs1-pass
ssh-keygen -q -t rsa -b 3072 -m PKCS8 -N 'correct horse' -C 'rsa-pkcs8-pass@fixture' -f rsa-3072-pkcs8-pass
ssh-keygen -q -t rsa -b 4096 -N 'correct horse' -C 'rsa4096-pass@fixture' -f rsa-4096-pass

# Named-curve EC keys (LibreSSL's ssh-keygen writes explicit curve parameters instead).
openssl ecparam -name prime256v1 -genkey -noout -out ecdsa-p256-named-sec1
openssl pkcs8 -topk8 -nocrypt -in ecdsa-p256-named-sec1 -out ecdsa-p256-named-pkcs8
openssl ec -in ecdsa-p256-named-sec1 -aes256 -passout 'pass:correct horse' -out ecdsa-p256-named-sec1-pass
for f in ecdsa-p256-named-sec1 ecdsa-p256-named-pkcs8; do ssh-keygen -y -f $f > $f.pub; done
ssh-keygen -y -P 'correct horse' -f ecdsa-p256-named-sec1-pass > ecdsa-p256-named-sec1-pass.pub

# DSA (OpenSSH 10 no longer makes or reads DSA keys).
openssl dsaparam -noout -genkey -out dsa 1024 && openssl dsa -in dsa -out dsa
```

The expected fingerprints in the tests are what `ssh-keygen -l -E sha256 -f <key>.pub` prints. There's
no `.pub` (or ssh-keygen fingerprint) for `dsa`. LibreSSL can't write Ed25519 PKCS#8, and nothing
here makes FIDO (`sk-`) keys without a security key, so the tests build those two cases in code.

## Signature vectors

`message.txt` is the signed message. `ed25519.sshsig` and `rsa-3072-pkcs1.sshsig` are what the real
tool wrote; both schemes are deterministic, so `tests/ssh_sign.rs` compares them byte for byte:

```sh
ssh-keygen -Y sign -n git -f ed25519 < message.txt > ed25519.sshsig
ssh-keygen -Y sign -n git -f rsa-3072-pkcs1 < message.txt > rsa-3072-pkcs1.sshsig
```
