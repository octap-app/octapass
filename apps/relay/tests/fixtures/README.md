Test-only keys, generated with `openssl` for this crate's tests. They protect nothing.

- `dkim.pem`, `dkim.pub`: the relay's DKIM key. `sender-dkim.pem`, `sender-dkim.pub`: a mailbox provider's.
- `tls-ca.pem`, `tls-cert.pem`, `tls-key.pem`: a throwaway CA and the certificate for `mx.relay.example`.
