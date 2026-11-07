//! The developer toolkit's command line (plan 16): generators, inspectors and converters. None of
//! these need an account unless they read from or save to the vault.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

#[derive(Debug, Subcommand)]
pub enum ToolCommand {
    /// TLS certificates: self-signed, a private CA, requests, and reading them.
    #[command(subcommand)]
    Cert(CertCommand),
    /// Certificates from Let's Encrypt, ZeroSSL or another ACME CA.
    #[command(subcommand)]
    Acme(AcmeCommand),
    /// Keys: generate, convert, and fingerprints. RSA, ECDSA, Ed25519, OpenPGP and age.
    #[command(subcommand)]
    Key(KeyCommand),
    /// JWT, JWS and JWE: read, sign, verify and decrypt tokens, and make signing keys.
    #[command(subcommand)]
    Jwt(JwtCommand),
    /// Hash files, text or stdin, or check a file against a published checksum.
    Hash(HashArgs),
    /// HMAC of a file, text or stdin.
    Hmac(HmacArgs),
    /// Encode text or stdin.
    Encode(CodecArgs),
    /// Decode text or stdin.
    Decode(CodecArgs),
    /// Guess what a pasted string is.
    Detect {
        /// Default: stdin.
        text: Option<String>,
    },
    /// Random bytes, UUIDs, ULIDs, NanoIDs and API tokens.
    #[command(subcommand)]
    Random(RandomCommand),
    /// Password hashes for your own apps: Argon2id, bcrypt, scrypt and PBKDF2.
    #[command(subcommand)]
    Pwhash(PwhashCommand),
    /// A new TOTP secret, for adding 2FA to your own app.
    TotpSecret(TotpSecretArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ToolKeyType {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    P256,
    P384,
    Ed25519,
}

impl ToolKeyType {
    pub fn name(self) -> &'static str {
        match self {
            Self::Rsa2048 => "rsa2048",
            Self::Rsa3072 => "rsa3072",
            Self::Rsa4096 => "rsa4096",
            Self::P256 => "p256",
            Self::P384 => "p384",
            Self::Ed25519 => "ed25519",
        }
    }
}

/// Where a generator's result goes.
#[derive(Debug, Args)]
pub struct KeepArgs {
    /// Save it to the vault as an encrypted item.
    #[arg(long)]
    pub save: bool,
    /// The saved item's title.
    #[arg(long, requires = "save")]
    pub title: Option<String>,
    /// The vault to save to (name or id). Default: Personal.
    #[arg(long, requires = "save")]
    pub vault: Option<String>,
    /// Write the private key to this file, readable only by you.
    #[arg(long, value_name = "FILE")]
    pub out_key: Option<PathBuf>,
    /// Write the certificate, CSR or public part to this file instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// Replace files that exist.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct SubjectArgs {
    /// Common name. Default: the first name.
    #[arg(long)]
    pub cn: Option<String>,
    #[arg(long)]
    pub org: Option<String>,
    #[arg(long)]
    pub org_unit: Option<String>,
    /// Two letters.
    #[arg(long)]
    pub country: Option<String>,
    #[arg(long)]
    pub state: Option<String>,
    #[arg(long)]
    pub locality: Option<String>,
}

#[derive(Debug, Args)]
pub struct CaArgs {
    /// The CA: a Certificate item (title or id), or a PEM file holding its certificate.
    #[arg(long, value_name = "ITEM|FILE")]
    pub ca: String,
    /// The CA's private key file, when --ca is a file without one.
    #[arg(long, value_name = "FILE")]
    pub ca_key: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum CertCommand {
    /// A self-signed certificate.
    SelfSigned {
        /// DNS names, IP addresses, emails or URIs. The first is the common name by default.
        #[arg(required = true)]
        names: Vec<String>,
        #[command(flatten)]
        subject: SubjectArgs,
        /// Default 365.
        #[arg(long)]
        days: Option<u32>,
        #[arg(long = "type", value_enum, default_value = "p256")]
        key_type: ToolKeyType,
        /// Also allow client authentication.
        #[arg(long)]
        client_auth: bool,
        #[command(flatten)]
        keep: KeepArgs,
    },
    /// A private CA. It can only issue for private names (localhost, *.test, private IPs) unless
    /// told otherwise, so a stolen key can't impersonate public sites.
    CaCreate {
        /// The CA's name. Default: Octa Pass Local CA.
        #[arg(long)]
        name: Option<String>,
        /// Default 3650.
        #[arg(long)]
        days: Option<u32>,
        #[arg(long = "type", value_enum, default_value = "p256")]
        key_type: ToolKeyType,
        /// Another name or CIDR range it may issue for. Can be given more than once.
        #[arg(long, value_name = "NAME|CIDR")]
        permit: Vec<String>,
        /// Let it issue for any name. Anyone with its key can then impersonate any site to the
        /// machines that trust it.
        #[arg(long)]
        unconstrained: bool,
        #[command(flatten)]
        keep: KeepArgs,
    },
    /// Issue a certificate from a private CA.
    Issue {
        #[arg(required = true)]
        names: Vec<String>,
        #[command(flatten)]
        ca: CaArgs,
        #[command(flatten)]
        subject: SubjectArgs,
        /// Default 365.
        #[arg(long)]
        days: Option<u32>,
        #[arg(long = "type", value_enum, default_value = "p256")]
        key_type: ToolKeyType,
        #[arg(long)]
        client_auth: bool,
        #[command(flatten)]
        keep: KeepArgs,
    },
    /// A certificate signing request (CSR).
    Csr {
        names: Vec<String>,
        #[command(flatten)]
        subject: SubjectArgs,
        #[arg(long = "type", value_enum, default_value = "p256")]
        key_type: ToolKeyType,
        /// Use this private key file instead of making one.
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        out_key: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Sign a CSR with a private CA.
    SignCsr {
        /// The CSR. Default: stdin.
        file: Option<PathBuf>,
        #[command(flatten)]
        ca: CaArgs,
        #[arg(long)]
        days: Option<u32>,
    },
    /// Read certificates or a CSR: subject, names, chain, expiry, key, fingerprints, problems.
    Read {
        /// PEM or DER. Default: stdin.
        file: Option<PathBuf>,
        /// Check the certificate covers this name.
        #[arg(long)]
        host: Option<String>,
    },
    /// Connect to a server and read the certificate it presents. This is the one command here
    /// that goes to the network: it completes a TLS handshake with that host and sends nothing else.
    Fetch {
        /// host, host:port or a URL. Port 443 by default.
        target: String,
    },
    /// Convert between PEM, DER and PKCS#12.
    Convert {
        /// Default: stdin.
        file: Option<PathBuf>,
        #[arg(long, value_enum)]
        to: CertFormat,
        /// PKCS#12: the private key file.
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        /// PKCS#12: certificates to include after the first.
        #[arg(long, value_name = "FILE")]
        chain: Option<PathBuf>,
        /// PKCS#12: the name shown when importing.
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Read a PKCS#12 file: its certificates, and its key when --out-key is given.
    P12Read {
        file: PathBuf,
        #[arg(long, value_name = "FILE")]
        out_key: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Make this device trust a CA. Only its public certificate is used.
    Trust(TrustArgs),
    /// Stop this device trusting a CA.
    Untrust(TrustArgs),
    /// Certificates in the vault, with their expiry.
    List {
        #[arg(long)]
        vault: Option<String>,
    },
    /// Certificates that need renewing. Exits 10 when there are any, for scripts and cron.
    Expiring {
        /// Also list those expiring within this many days. Default: each one's renewal window.
        #[arg(long)]
        within: Option<i64>,
        #[arg(long)]
        vault: Option<String>,
    },
    /// Write a certificate, its chain, or (after your master password) its private key or a
    /// PKCS#12 file.
    Export {
        item: String,
        #[arg(long, value_enum, default_value = "certificate")]
        part: CertPart,
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        vault: Option<String>,
    },
}

#[derive(Debug, Args)]
pub struct TrustArgs {
    /// A Certificate item (title or id), or a PEM file.
    pub ca: String,
    /// Don't ask first.
    #[arg(long, short)]
    pub yes: bool,
    /// Show what would run, and run nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CertFormat {
    Pem,
    Der,
    P12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CertPart {
    Certificate,
    Chain,
    Fullchain,
    Key,
    P12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AcmeChallenge {
    /// Answer on HTTP. Doesn't work for wildcards.
    Http,
    /// Answer with a DNS TXT record. Required for wildcards.
    Dns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DnsProviderArg {
    /// Prints the record for you to add, and waits.
    Manual,
    /// Runs --dns-hook with the record in its environment.
    Hook,
    /// Token in CLOUDFLARE_API_TOKEN.
    Cloudflare,
    /// Token in DIGITALOCEAN_TOKEN.
    Digitalocean,
}

#[derive(Debug, Args)]
pub struct AcmeOptions {
    #[arg(long, value_enum, default_value = "http")]
    pub challenge: AcmeChallenge,
    /// HTTP: put the answers in this web root instead of listening.
    #[arg(long, value_name = "DIR")]
    pub webroot: Option<PathBuf>,
    /// HTTP: the port to listen on. The CA connects to port 80, so anything else needs a redirect.
    #[arg(long, default_value_t = 80)]
    pub http_port: u16,
    #[arg(long, value_enum, default_value = "manual")]
    pub dns: DnsProviderArg,
    /// The script for --dns hook. It gets OCTAPASS_ACME_ACTION (publish or remove),
    /// OCTAPASS_ACME_NAME and OCTAPASS_ACME_VALUE.
    #[arg(long, value_name = "PROGRAM")]
    pub dns_hook: Option<String>,
    /// Seconds to wait for a record to reach the CA.
    #[arg(long, default_value_t = 30)]
    pub dns_wait: u64,
}

#[derive(Debug, Subcommand)]
pub enum AcmeCommand {
    /// Get a certificate and save it to the vault.
    Issue {
        #[arg(required = true)]
        domains: Vec<String>,
        /// For the CA's expiry notices.
        #[arg(long)]
        email: Option<String>,
        /// Accept the CA's terms of service.
        #[arg(long)]
        agree_tos: bool,
        /// Let's Encrypt's staging CA: untrusted certificates, generous limits. Try this first.
        #[arg(long)]
        staging: bool,
        /// ZeroSSL. Needs --eab-kid and --eab-key from your ZeroSSL account.
        #[arg(long)]
        zerossl: bool,
        /// Any other CA's directory URL.
        #[arg(long, value_name = "URL")]
        directory: Option<String>,
        #[arg(long)]
        eab_kid: Option<String>,
        /// Default: OCTAPASS_ACME_EAB_KEY.
        #[arg(long)]
        eab_key: Option<String>,
        #[arg(long = "type", value_enum, default_value = "p256")]
        key_type: ToolKeyType,
        #[command(flatten)]
        options: AcmeOptions,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        vault: Option<String>,
    },
    /// Renew a certificate that came from ACME, with the same CA, names and account key.
    Renew {
        item: String,
        #[command(flatten)]
        options: AcmeOptions,
        #[arg(long)]
        vault: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KeyFormat {
    Pkcs8Pem,
    Pkcs8Der,
    /// PKCS#1 for RSA, SEC1 for EC.
    TraditionalPem,
    OpensshPrivate,
    Jwk,
    SpkiPem,
    SpkiDer,
    Pkcs1PublicPem,
    OpensshPublic,
    JwkPublic,
}

impl KeyFormat {
    pub fn name(self) -> &'static str {
        match self {
            Self::Pkcs8Pem => "pkcs8-pem",
            Self::Pkcs8Der => "pkcs8-der",
            Self::TraditionalPem => "traditional-pem",
            Self::OpensshPrivate => "openssh-private",
            Self::Jwk => "jwk",
            Self::SpkiPem => "spki-pem",
            Self::SpkiDer => "spki-der",
            Self::Pkcs1PublicPem => "pkcs1-public-pem",
            Self::OpensshPublic => "openssh-public",
            Self::JwkPublic => "jwk-public",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// A new RSA, ECDSA or Ed25519 key.
    Generate {
        #[arg(long = "type", value_enum, default_value = "ed25519")]
        key_type: ToolKeyType,
        #[command(flatten)]
        keep: KeepArgs,
    },
    /// Fingerprints and public forms of any key.
    Inspect {
        /// PEM, DER, OpenSSH or JWK. Default: stdin.
        file: Option<PathBuf>,
    },
    /// Convert a key between PEM, DER, JWK, OpenSSH, PKCS#8 and PKCS#1.
    Convert {
        /// Default: stdin.
        file: Option<PathBuf>,
        #[arg(long, value_enum)]
        to: KeyFormat,
        /// Protect the result with a passphrase (asks).
        #[arg(long)]
        encrypt: bool,
        /// OpenSSH: the key's comment.
        #[arg(long)]
        comment: Option<String>,
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// A new age key, for file encryption.
    Age {
        #[command(flatten)]
        keep: KeepArgs,
    },
    /// A new OpenPGP key, for signing commits and email.
    Gpg {
        /// Name <email>
        #[arg(long)]
        user_id: String,
        #[arg(long = "type", value_enum, default_value = "ed25519")]
        key_type: GpgKeyType,
        #[command(flatten)]
        keep: KeepArgs,
    },
    /// Write a Key item's private key, after your master password.
    Export {
        item: String,
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        vault: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum GpgKeyType {
    Ed25519,
    Rsa4096,
}

#[derive(Debug, Args)]
pub struct SecretArgs {
    /// Read the secret from this file (or `-` for stdin) as raw text.
    #[arg(long, value_name = "FILE")]
    pub secret_file: Option<PathBuf>,
    /// How the secret is written: utf8, base64, base64url or hex.
    #[arg(long)]
    pub secret_encoding: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum JwtCommand {
    /// Read a token without checking it.
    Decode {
        /// Default: stdin.
        token: Option<String>,
    },
    /// Check a token's signature and time limits. Exits 1 when it isn't valid.
    Verify {
        /// Default: stdin.
        token: Option<String>,
        /// A key, certificate, JWK or JWKS file.
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        /// Fetch the JWKS from this https:// address. This goes to the network.
        #[arg(long, value_name = "URL")]
        jwks_url: Option<String>,
        #[command(flatten)]
        secret: SecretArgs,
        /// Allowed clock difference, in seconds.
        #[arg(long)]
        leeway: Option<u64>,
    },
    /// Sign claims into a token.
    Sign {
        /// The claims as JSON. Default: stdin.
        claims: Option<String>,
        /// HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512 or EdDSA.
        #[arg(long)]
        alg: String,
        /// A private key file.
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        #[command(flatten)]
        secret: SecretArgs,
        #[arg(long)]
        kid: Option<String>,
        /// Add `iat`.
        #[arg(long)]
        iat: bool,
        /// Add `exp`, this many seconds from now.
        #[arg(long, value_name = "SECONDS")]
        expires_in: Option<u64>,
    },
    /// Decrypt a JWE with a key you hold.
    Decrypt {
        /// Default: stdin.
        token: Option<String>,
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        #[command(flatten)]
        secret: SecretArgs,
    },
    /// A new signing key, with its JWK and JWKS.
    Keygen {
        #[arg(long)]
        alg: String,
        /// RSA size: 2048, 3072 or 4096.
        #[arg(long)]
        bits: Option<u32>,
        #[command(flatten)]
        keep: KeepArgs,
    },
    /// A JWKS from public keys, to publish.
    Jwks {
        /// Key files.
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub struct HashArgs {
    /// Files. Default: stdin.
    pub files: Vec<PathBuf>,
    /// Algorithms, repeated or comma-separated. Default: sha256. `all` for every one.
    #[arg(long = "algo", short, value_delimiter = ',')]
    pub algorithms: Vec<String>,
    /// Hash this text instead of a file.
    #[arg(long)]
    pub text: Option<String>,
    /// Compare with a published checksum: a hash, a sha256sum line, or `sha256-…`. Exits 1 on a
    /// mismatch.
    #[arg(long, value_name = "CHECKSUM")]
    pub check: Option<String>,
}

#[derive(Debug, Args)]
pub struct HmacArgs {
    /// A file. Default: stdin.
    pub file: Option<PathBuf>,
    #[arg(long = "algo", short, default_value = "sha256")]
    pub algorithm: String,
    #[arg(long)]
    pub text: Option<String>,
    #[command(flatten)]
    pub secret: SecretArgs,
}

#[derive(Debug, Args)]
pub struct CodecArgs {
    /// base64, base64url, base32, hex, url, html or unicode.
    pub format: String,
    /// Default: stdin.
    pub text: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum RandomCommand {
    /// Random bytes.
    Bytes {
        length: usize,
        /// hex, base64, base64url or base32.
        #[arg(long, default_value = "hex")]
        format: String,
    },
    /// UUIDs.
    Uuid {
        /// 4 or 7.
        #[arg(long, short, default_value_t = 4)]
        version: u8,
        #[arg(long, short, default_value_t = 1)]
        count: usize,
    },
    /// ULIDs.
    Ulid {
        #[arg(long, short, default_value_t = 1)]
        count: usize,
    },
    /// An API key or token.
    Token {
        /// hex, base64url, base62, uuid4, uuid7, ulid or nanoid.
        #[arg(long, default_value = "base62")]
        shape: String,
        /// Bytes for hex and base64url, characters for base62 and nanoid.
        #[arg(long)]
        length: Option<usize>,
        /// Put in front, as in sk_live_.
        #[arg(long)]
        prefix: Option<String>,
        /// A custom alphabet.
        #[arg(long)]
        alphabet: Option<String>,
        /// Save it to the vault as an API credential.
        #[arg(long)]
        save: bool,
        #[arg(long, requires = "save")]
        title: Option<String>,
        #[arg(long, requires = "save")]
        vault: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PwhashCommand {
    /// Hash a password (from stdin, or asks).
    Hash {
        /// argon2id, bcrypt, scrypt or pbkdf2.
        #[arg(long, default_value = "argon2id")]
        scheme: String,
        /// argon2id: memory in KiB.
        #[arg(long)]
        memory: Option<u32>,
        /// argon2id passes, or pbkdf2 rounds.
        #[arg(long)]
        iterations: Option<u32>,
        /// argon2id or scrypt lanes.
        #[arg(long)]
        parallelism: Option<u32>,
        /// bcrypt cost.
        #[arg(long)]
        cost: Option<u32>,
        /// scrypt: log2 of N.
        #[arg(long)]
        log_n: Option<u8>,
        /// pbkdf2: sha256 or sha512.
        #[arg(long)]
        digest: Option<String>,
    },
    /// Check a password (from stdin, or asks) against a hash. Exits 1 when it doesn't match.
    Verify { hash: String },
}

#[derive(Debug, Args)]
pub struct TotpSecretArgs {
    #[arg(long)]
    pub issuer: Option<String>,
    #[arg(long)]
    pub account: Option<String>,
    /// sha1 (what most authenticator apps read), sha256 or sha512.
    #[arg(long)]
    pub algorithm: Option<String>,
    #[arg(long)]
    pub digits: Option<u32>,
    #[arg(long)]
    pub period: Option<u64>,
    /// Save it to the vault as a one-time code.
    #[arg(long)]
    pub save: bool,
    #[arg(long, requires = "save")]
    pub title: Option<String>,
    #[arg(long, requires = "save")]
    pub vault: Option<String>,
}
