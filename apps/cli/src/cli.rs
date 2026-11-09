//! The command line, as `clap` parses it.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use octapass_core::import::ImportSource;

#[derive(Debug, Parser)]
#[command(
    name = "octapass",
    version,
    about = "Octa Pass from the command line: items, one-time codes, passwords and secrets for scripts."
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args)]
pub struct Global {
    /// Read the master password from the first line of stdin instead of asking.
    #[arg(long, global = true)]
    pub password_stdin: bool,
    /// Print JSON instead of text.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create an account. Prints your Recovery Kit: keep it safe.
    Signup {
        /// Your Octa Pass server. Defaults to OCTAPASS_SERVER, then the hosted service.
        #[arg(long)]
        server: Option<String>,
        /// Defaults to OCTAPASS_EMAIL, or asks.
        #[arg(long)]
        email: Option<String>,
        /// The 6-digit code we emailed you, instead of asking.
        #[arg(long)]
        code: Option<String>,
        /// Lock after this long without a command (for example 15m or 2h).
        #[arg(long, value_name = "DURATION")]
        timeout: Option<String>,
    },
    /// Sign in with your email, master password and Secret Key.
    Login {
        /// Your Octa Pass server. Defaults to OCTAPASS_SERVER, then the hosted service.
        #[arg(long)]
        server: Option<String>,
        /// Defaults to OCTAPASS_EMAIL, or asks.
        #[arg(long)]
        email: Option<String>,
        /// Lock after this long without a command (for example 15m or 2h).
        #[arg(long, value_name = "DURATION")]
        timeout: Option<String>,
    },
    /// Unlock with the master password and stay unlocked until you're idle.
    Unlock {
        /// Lock after this long without a command (for example 15m or 2h). Default 30m.
        #[arg(long, value_name = "DURATION")]
        timeout: Option<String>,
    },
    /// Lock now.
    Lock,
    /// Sign out and remove this account's data from this device.
    Logout,
    /// Show whether you're signed in and unlocked. Exits 0 when unlocked, 3 when signed out, 4
    /// when locked.
    Status,
    /// Change your master password. Your Secret Key and recovery code stay the same.
    ChangeMasterPassword,
    /// Replace your Secret Key. Your master password stays the same; other devices are signed out
    /// and need the new key. Prints your new Recovery Kit.
    RotateSecretKey {
        /// Replace your recovery code too, if a Recovery Kit may have been seen.
        #[arg(long)]
        new_recovery_code: bool,
    },
    /// Give a vault a new key. Every item moves to it; your items and members stay the same.
    RotateVaultKey {
        /// The vault's name or id.
        vault: String,
    },
    /// Reset a forgotten master password with the recovery code from your Recovery Kit.
    ResetMasterPassword {
        /// Your Octa Pass server. Defaults to OCTAPASS_SERVER, then the hosted service.
        #[arg(long)]
        server: Option<String>,
        /// Defaults to OCTAPASS_EMAIL, or asks.
        #[arg(long)]
        email: Option<String>,
        /// The 6-digit code we emailed you, instead of asking.
        #[arg(long)]
        code: Option<String>,
    },
    /// List items.
    List {
        /// Only this vault (name or id).
        #[arg(long)]
        vault: Option<String>,
        /// Only items whose title, username, URLs or tags contain this.
        #[arg(long)]
        search: Option<String>,
    },
    /// Show an item, or one of its fields.
    Get {
        /// The item's title or id.
        item: String,
        /// password, username, totp (the current code), notes, url, or a custom field's label.
        #[arg(long)]
        field: Option<String>,
        /// Look in this vault only (name or id).
        #[arg(long)]
        vault: Option<String>,
        /// Don't print a newline after the value.
        #[arg(short = 'n', long)]
        no_newline: bool,
    },
    // ---------- Developer toolkit (plan 16) ----------
    #[command(flatten)]
    Tool(crate::tools_cli::ToolCommand),
    /// Print an item's current one-time code.
    Totp {
        /// The item's title or id.
        item: String,
        /// Look in this vault only (name or id).
        #[arg(long)]
        vault: Option<String>,
    },
    /// Add an item: `octapass create login --title GitHub username=ada password`.
    Create(CreateArgs),
    /// Change an item: `octapass edit GitHub password --add-tag work`.
    Edit(EditArgs),
    /// Move an item to the trash.
    Delete {
        /// The item's title or id.
        item: String,
        /// Look in this vault only (name or id).
        #[arg(long)]
        vault: Option<String>,
    },
    /// Bring an item back from the trash.
    Restore {
        /// The item's title or id.
        item: String,
    },
    /// Generate a password or passphrase. Doesn't need an account.
    Generate(GenerateArgs),
    /// Print the value of an octapass://<vault>/<item>/<field> reference.
    Read {
        reference: String,
        /// Don't print a newline after the value.
        #[arg(short = 'n', long)]
        no_newline: bool,
    },
    /// Run a command with environments loaded and octapass:// references in its environment
    /// replaced by their values.
    Run {
        /// Load this environment (a title, an id, vault/title, or project:stage). Can be given
        /// more than once; later ones win. Default: the octapass.toml of this folder or a parent.
        #[arg(long, value_name = "ENV")]
        env: Vec<String>,
        /// Load this project's shared variables and, with --stage, that stage's.
        #[arg(long)]
        project: Option<String>,
        /// The stage to load (development, staging, production, …). Default: OCTAPASS_STAGE, then
        /// octapass.toml.
        #[arg(long)]
        stage: Option<String>,
        /// Also read variables from this file (KEY=value lines). Can be given more than once.
        #[arg(long, value_name = "FILE")]
        env_file: Vec<PathBuf>,
        /// Also write the variables to this .env file (readable only by you) while the command
        /// runs, and delete it when it ends. For tools that only read a file.
        #[arg(long, value_name = "PATH")]
        env_file_out: Option<PathBuf>,
        /// Don't ask before running with production variables.
        #[arg(long, short)]
        yes: bool,
        /// Don't hide secrets in the command's output, and give it the real terminal. For
        /// interactive programs. Also OCTAPASS_NO_MASKING=1.
        #[arg(long)]
        no_masking: bool,
        /// The command and its arguments, after `--`.
        #[arg(required = true, last = true, num_args = 1..)]
        command: Vec<String>,
    },
    /// Import another app's export into a vault.
    Import {
        format: ImportFormat,
        file: PathBuf,
        /// The vault to import into (name or id). Default: Personal.
        #[arg(long)]
        vault: Option<String>,
        /// KeePass: the database's key file.
        #[arg(long, value_name = "FILE")]
        key_file: Option<PathBuf>,
        /// Read the file and report what would be imported, without saving anything.
        #[arg(long)]
        dry_run: bool,
    },
    // ---------- Environments (plan 16) ----------
    /// Environments: .env files and environment variables kept in the vault.
    #[command(subcommand)]
    Env(EnvCommand),
    /// Copy a text file, replacing octapass://<vault>/<item>/<field> references with their values.
    Inject {
        /// The template. Default: stdin.
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,
        /// Write here (readable only by you) instead of stdout.
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Replace the output file if it exists.
        #[arg(long)]
        force: bool,
    },
    /// SSH keys: list, generate, import, export and print public keys.
    Ssh {
        #[command(subcommand)]
        command: SshCommand,
    },
    /// Service accounts: non-human access to one shared vault, for CI and servers.
    #[command(subcommand, name = "service-account", alias = "sa")]
    ServiceAccount(ServiceAccountCommand),
    /// Your organisation: members, groups, vaults, access, policies, SSO and SCIM.
    #[command(subcommand, alias = "organisation")]
    Org(OrgCommand),
    /// Octa Pass Connect: a local helper that gives approved tools a secret by reference.
    #[command(subcommand)]
    Connect(ConnectCommand),
    /// AWS: credentials for `credential_process` in ~/.aws/config.
    #[command(subcommand)]
    Aws(AwsCommand),
    /// Kubernetes: credentials for a kubeconfig `exec` plugin.
    #[command(subcommand)]
    Kube(KubeCommand),
    /// The Docker credential helper protocol. Run through `docker-credential-octapass`.
    DockerCredential {
        /// get, store, erase or list. The rest comes on stdin, as Docker sends it.
        operation: DockerOperation,
    },
    /// Live OAuth2 tokens from API credential items.
    #[command(subcommand)]
    Oauth(OauthCommand),
    /// OpenPGP keys for signing Git commits.
    Gpg {
        #[command(subcommand)]
        command: GpgCommand,
    },
    /// Git: the credential helper and commit signing with keys from the vault.
    Git {
        #[command(subcommand)]
        command: GitCommand,
    },
    /// Encrypt files or folders in the age format. They open with any age tool.
    Encrypt(EncryptArgs),
    /// Decrypt age files. Files encrypted for you or with a passphrase.
    Decrypt(DecryptArgs),
    /// Overwrite and delete files or folders, and say honestly what that achieved on this disk.
    Shred {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
    },
    /// Show your age public key, or export the secret key that opens files encrypted for you.
    FileKey {
        /// Print the secret key (`AGE-SECRET-KEY-1…`). Asks for the master password again.
        #[arg(long)]
        export: bool,
        /// Write it to this file, readable only by you, instead of printing it.
        #[arg(long, short, value_name = "PATH", requires = "export")]
        output: Option<PathBuf>,
        /// Replace the file if it exists.
        #[arg(long, requires = "output")]
        force: bool,
    },
    /// Octa Pass Safe: an encrypted drive that locks with your vault.
    Safe {
        #[command(subcommand)]
        command: SafeCommand,
    },
    /// Add or remove "Encrypt with Octa Pass" in your file manager's right-click menu.
    ContextMenu {
        #[command(subcommand)]
        command: ContextMenuCommand,
    },
    /// Export every item. Asks for the master password again.
    Export {
        #[arg(long, default_value = "json")]
        format: ExportFormat,
        /// Everything, attached files included, encrypted with a password you choose (JSON only).
        /// With --password-stdin, that password is the line after the master password.
        #[arg(long)]
        encrypted: bool,
        /// Write to this file (readable only by you) instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum OrgCommand {
    /// Your organisation, your role in it, its policies, and invitations to your email.
    Show,
    /// Start an organisation, with you as its owner.
    Create { name: String },
    /// Rename it (owners).
    Rename { name: String },
    /// Delete it and all its vaults (owners). Asks for the master password.
    Delete {
        /// The organisation's name, to confirm.
        #[arg(long, value_name = "NAME")]
        confirm_name: String,
    },
    /// Accept an invitation (see `org show`). Its policies apply from then on.
    Join {
        /// The invitation's id.
        invite: String,
    },
    /// Decline an invitation.
    Decline { invite: String },
    /// Leave your organisation. Its vaults go at once.
    Leave {
        /// Go ahead even if a vault is left with nobody able to manage it.
        #[arg(long)]
        orphan_vaults: bool,
    },
    /// Members and pending invites (admins).
    Members,
    /// Invite someone by email (admins). The same answer whether or not they have an account.
    Invite {
        email: String,
        /// Invite as an admin rather than a member.
        #[arg(long)]
        admin: bool,
    },
    /// Cancel a pending invite (admins), by its id or email.
    Uninvite { invite: String },
    /// Change a member's role (owners).
    Role {
        /// The member's email or account id.
        member: String,
        role: OrgRoleArg,
    },
    /// Remove a member (admins; owners for an owner). They lose its vaults at once.
    Remove {
        /// The member's email or account id.
        member: String,
        /// Go ahead even if a vault is left with nobody able to manage it.
        #[arg(long)]
        orphan_vaults: bool,
    },
    /// Groups: lists of people that vaults are linked to (admins).
    #[command(subcommand)]
    Group(OrgGroupCommand),
    /// Organisation vaults and the groups they're linked to (admins).
    #[command(subcommand)]
    Vault(OrgVaultCommand),
    /// Vaults waiting for a key holder: review who gets them, and seal.
    #[command(subcommand)]
    Access(OrgAccessCommand),
    /// Give an organisation vault a new key after someone lost access.
    Rotate {
        /// The vault (name or id).
        vault: String,
    },
    /// The organisation's policies (owners change them).
    #[command(subcommand)]
    Policy(OrgPolicyCommand),
    /// Single sign-on: OpenID Connect or SAML, a step after the master password (owners).
    #[command(subcommand)]
    Sso(OrgSsoCommand),
    /// SCIM provisioning tokens for your identity provider (owners).
    #[command(subcommand)]
    Scim(OrgScimCommand),
    /// The admin activity log, newest first (admins).
    Events,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OrgRoleArg {
    Member,
    Admin,
    Owner,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum GroupRoleArg {
    Read,
    Write,
    Manage,
}

#[derive(Debug, Subcommand)]
pub enum OrgGroupCommand {
    List,
    Create {
        name: String,
    },
    Rename {
        group: String,
        name: String,
    },
    Delete {
        group: String,
    },
    /// Add a member to a group. They get its vaults when a key holder applies access.
    Add {
        group: String,
        /// The member's email or account id.
        member: String,
    },
    /// Take a member out of a group. They lose the vaults only it gave them, at once.
    Remove {
        group: String,
        member: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum OrgVaultCommand {
    List,
    /// A new organisation vault, owned by you.
    Create {
        name: String,
    },
    /// Delete a vault and everything in it (owners). Needs no key. Asks for the master password.
    Delete {
        vault: String,
    },
    /// Link a group to a vault. Its members get it when a key holder applies access.
    Link {
        vault: String,
        group: String,
        #[arg(long, default_value = "write")]
        role: GroupRoleArg,
    },
    Unlink {
        vault: String,
        group: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum OrgAccessCommand {
    /// What each vault waits for, with fingerprints computed here.
    List,
    /// Seal a vault to the people waiting for it, after you review each one. In a terminal you're
    /// asked person by person; otherwise name each one with --person.
    Apply {
        /// The vault (name or id).
        vault: String,
        /// `EMAIL=FINGERPRINT`: seal to this person if their keys still give this fingerprint
        /// (the 24 digits, as `access list` shows them). Repeat for each person.
        #[arg(long = "person", value_name = "EMAIL=FINGERPRINT")]
        people: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum OrgPolicyCommand {
    Show,
    /// Set one policy: require-two-step, require-sso, disable-share-links,
    /// disable-emergency-access, disable-export (on/off), sso-max-age-hours (0 to 8760),
    /// max-auto-lock-minutes, min-password-length (a number, or none).
    Set {
        name: String,
        value: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum OrgSsoCommand {
    /// The saved settings, and what to register at the identity provider.
    Show,
    /// Use OpenID Connect. The server fetches the issuer's discovery document first.
    Oidc {
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        client_id: String,
        /// Ask for a client secret (the next stdin line with --password-stdin). Without it, a
        /// saved secret for the same issuer is kept.
        #[arg(long)]
        client_secret: bool,
    },
    /// Use SAML 2.0: the identity provider's metadata file, or its three fields.
    Saml {
        /// The IdP's metadata XML file.
        #[arg(long, value_name = "FILE", conflicts_with_all = ["entity_id", "sso_url", "certificate"])]
        metadata: Option<PathBuf>,
        #[arg(long, requires_all = ["sso_url", "certificate"])]
        entity_id: Option<String>,
        /// Its HTTP-Redirect single sign-on URL.
        #[arg(long)]
        sso_url: Option<String>,
        /// A signing certificate (PEM file). Repeat during a key rollover.
        #[arg(long, value_name = "FILE")]
        certificate: Vec<PathBuf>,
    },
    /// Start a test sign-in: open the URL in a browser. Requiring SSO needs one.
    Test,
    /// Remove the settings and every member's link to the provider.
    Remove,
}

#[derive(Debug, Subcommand)]
pub enum OrgScimCommand {
    /// The SCIM base URL and the tokens.
    Show,
    /// Make a token and print it, once.
    Token {
        #[command(subcommand)]
        command: OrgScimTokenCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum OrgScimTokenCommand {
    Create { name: String },
    Revoke { id: String },
}

#[derive(Debug, Subcommand)]
pub enum ServiceAccountCommand {
    /// Make a service account for a shared vault you manage, and print its token, once.
    Create {
        /// The shared vault it reads (name or id).
        #[arg(long)]
        vault: String,
        /// What it's for. Sealed, so only you can read it.
        #[arg(long)]
        name: String,
        /// Let it save items too. Read-only without this.
        #[arg(long)]
        write: bool,
        /// Stop working after this long (for example 90d or 12h). Default: until it's revoked.
        #[arg(long, value_name = "DURATION")]
        expires: Option<String>,
    },
    /// List a vault's service accounts.
    List {
        /// The shared vault (name or id).
        #[arg(long)]
        vault: String,
    },
    /// End a service account now and rotate the vault's key.
    Revoke {
        /// The service account's id.
        id: String,
        /// The shared vault (name or id).
        #[arg(long)]
        vault: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConnectCommand {
    /// Listen for local tools until Ctrl-C. Approvals are asked here, in this terminal.
    Serve {
        /// Listen on 127.0.0.1 instead of a socket. Port 0 lets the system choose.
        #[arg(long, value_name = "PORT")]
        port: Option<u16>,
    },
    /// Show whether Connect is running and the vault unlocked.
    Status,
    /// List approved clients.
    Clients,
    /// Take a client's approval back.
    Revoke {
        /// The client's id, from `octapass connect clients`.
        id: String,
    },
    /// Approve a client from here, without it asking, and print its token. Asks for the master
    /// password. For tools that can't wait for a prompt.
    Approve {
        /// What to call it.
        #[arg(long)]
        name: String,
    },
    /// Ask a running Connect for approval as a new client, and print the token.
    Pair {
        /// What to call this client.
        #[arg(long)]
        name: String,
    },
    /// Read references through a running Connect, with the token in OCTAPASS_CONNECT_TOKEN.
    Read {
        #[arg(required = true)]
        references: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum AwsCommand {
    /// Print an item's keys in the format credential_process expects.
    #[command(name = "credential-process")]
    CredentialProcess {
        /// The item's title or id.
        item: String,
        /// Look in this vault only (name or id).
        #[arg(long)]
        vault: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum KubeCommand {
    /// Print an ExecCredential with the item's token or client certificate.
    Credential {
        /// The item's title or id.
        item: String,
        /// Look in this vault only (name or id).
        #[arg(long)]
        vault: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DockerOperation {
    Get,
    Store,
    Erase,
    List,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OauthFlow {
    /// A client id and secret
    ClientCredentials,
    /// A long-lived refresh token
    RefreshToken,
}

#[derive(Debug, Subcommand)]
pub enum OauthCommand {
    /// Save an OAuth2 client as an API credential item. Secrets are asked for, or read from
    /// OCTAPASS_OAUTH_CLIENT_SECRET and OCTAPASS_OAUTH_REFRESH_TOKEN.
    Create {
        title: String,
        #[arg(long, value_enum)]
        flow: OauthFlow,
        #[arg(long)]
        token_url: String,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        audience: Option<String>,
        /// The vault to save it in (name or id). Default: Personal.
        #[arg(long)]
        vault: Option<String>,
    },
    /// Print the item's current token, fetching a new one when it's near its end.
    Token {
        /// The item's title or id.
        item: String,
        /// Look in this vault only (name or id).
        #[arg(long)]
        vault: Option<String>,
        /// Don't print a newline after the value.
        #[arg(short = 'n', long)]
        no_newline: bool,
    },
    /// Show the current token's claims and expiry, not the token.
    Show {
        /// The item's title or id.
        item: String,
        /// Look in this vault only (name or id).
        #[arg(long)]
        vault: Option<String>,
    },
}

impl Command {
    /// Whether it only reads, so a service account can run it.
    pub fn works_with_service_account(&self) -> bool {
        match self {
            Self::List { .. }
            | Self::Get { .. }
            | Self::Totp { .. }
            | Self::Generate(_)
            | Self::Read { .. }
            | Self::Run { .. }
            | Self::Inject { .. }
            | Self::Aws(_)
            | Self::Kube(_) => true,
            Self::Oauth(command) => !matches!(command, OauthCommand::Create { .. }),
            Self::DockerCredential { operation } => {
                matches!(operation, DockerOperation::Get | DockerOperation::List)
            }
            Self::Env(command) => matches!(
                command,
                EnvCommand::List { .. }
                    | EnvCommand::Show { .. }
                    | EnvCommand::Export { .. }
                    | EnvCommand::Diff { .. }
            ),
            _ => false,
        }
    }
}

/// Field values, as `create` and `edit` take them.
#[derive(Debug, Args)]
pub struct FieldArgs {
    /// field=value, or just the field's name to type the value without it showing. Names that
    /// aren't fields of the type become custom fields on logins.
    #[arg(value_name = "FIELD[=VALUE]")]
    pub fields: Vec<String>,
    /// Generate a new password for the item.
    #[arg(long)]
    pub generate: bool,
    /// With --generate: this many characters (4-128). Default 20.
    #[arg(long, requires = "generate", conflicts_with = "words")]
    pub length: Option<usize>,
    /// With --generate: a passphrase of this many words (3-20).
    #[arg(long, requires = "generate")]
    pub words: Option<usize>,
    /// Read this field's value from stdin, after any --password-stdin line.
    #[arg(long, value_name = "FIELD")]
    pub stdin: Option<String>,
    /// New custom fields are shown without asking, instead of hidden.
    #[arg(long)]
    pub plain: bool,
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// login, password, note, card, identity, wifi, bank-account, api-credential, licence,
    /// id-document, wallet, database, custom or template.
    #[arg(value_name = "TYPE")]
    pub item_type: String,
    #[arg(long)]
    pub title: Option<String>,
    /// The vault to save it in (name or id). Default: Personal.
    #[arg(long)]
    pub vault: Option<String>,
    /// A website. Can be given more than once.
    #[arg(long = "url", value_name = "URL")]
    pub urls: Vec<String>,
    /// A tag. Can be given more than once.
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
    #[arg(long)]
    pub favorite: bool,
    /// For a custom item: start with this template's fields (its name or id).
    #[arg(long, value_name = "TEMPLATE")]
    pub template: Option<String>,
    #[command(flatten)]
    pub values: FieldArgs,
}

#[derive(Debug, Args)]
pub struct EditArgs {
    /// The item's title or id.
    pub item: String,
    /// Look in this vault only (name or id).
    #[arg(long)]
    pub vault: Option<String>,
    /// A new title.
    #[arg(long)]
    pub title: Option<String>,
    /// Remove this field. Can be given more than once.
    #[arg(long, value_name = "FIELD")]
    pub unset: Vec<String>,
    #[arg(long = "add-url", value_name = "URL")]
    pub add_urls: Vec<String>,
    #[arg(long = "remove-url", value_name = "URL")]
    pub remove_urls: Vec<String>,
    #[arg(long = "add-tag", value_name = "TAG")]
    pub add_tags: Vec<String>,
    #[arg(long = "remove-tag", value_name = "TAG")]
    pub remove_tags: Vec<String>,
    #[arg(long, conflicts_with = "no_favorite")]
    pub favorite: bool,
    #[arg(long)]
    pub no_favorite: bool,
    #[command(flatten)]
    pub values: FieldArgs,
}

/// `octapass env …`. An environment is named by its title, its id, `vault/title`, or
/// `project:stage`.
#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// List environments, grouped by project.
    List {
        /// Only this vault (name or id).
        #[arg(long)]
        vault: Option<String>,
        /// Only this project.
        #[arg(long)]
        project: Option<String>,
    },
    /// Show an environment's variables. Concealed values stay hidden without --reveal.
    Show {
        env: String,
        #[arg(long)]
        reveal: bool,
    },
    /// Add or change variables: KEY=value, or KEY alone to type the value without it showing.
    Set {
        env: String,
        #[arg(required = true, value_name = "KEY=value")]
        variables: Vec<String>,
        /// Show these values without --reveal (for names, ports and other non-secrets).
        #[arg(long)]
        plain: bool,
    },
    /// Remove variables.
    Unset {
        env: String,
        #[arg(required = true, value_name = "KEY")]
        keys: Vec<String>,
    },
    /// Create an empty environment.
    Create {
        title: String,
        /// The vault to create it in (name or id). Default: Personal.
        #[arg(long)]
        vault: Option<String>,
        /// The project it belongs to, such as shop-api.
        #[arg(long)]
        project: Option<String>,
        /// Its stage: development, staging, production, testing, preview, local or your own.
        #[arg(long)]
        stage: Option<String>,
    },
    /// Read a .env file into an environment.
    Import {
        file: PathBuf,
        /// Add to this environment, replacing variables with the same name.
        #[arg(
            long,
            value_name = "ENV",
            conflicts_with = "new",
            required_unless_present = "new"
        )]
        into: Option<String>,
        /// Create a new environment with this title.
        #[arg(long, value_name = "TITLE")]
        new: Option<String>,
        /// With --new: the vault (name or id). Default: Personal.
        #[arg(long, requires = "new", conflicts_with = "into")]
        vault: Option<String>,
        #[arg(long, requires = "new", conflicts_with = "into")]
        project: Option<String>,
        #[arg(long, requires = "new", conflicts_with = "into")]
        stage: Option<String>,
    },
    /// Write an environment's variables as a .env file, JSON, shell or PowerShell commands, or for
    /// docker run --env-file.
    Export {
        env: String,
        #[arg(long, default_value = "dotenv")]
        format: EnvFormatArg,
        /// Write to this file (readable only by you) instead of stdout.
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Replace the output file if it exists.
        #[arg(long)]
        force: bool,
        /// Write octapass:// references as they are instead of their values.
        #[arg(long)]
        keep_references: bool,
    },
    /// List the variables missing from one side or different, without their values:
    /// `diff <project> <stage> <stage>` or `diff <env> <env>`.
    #[command(arg_required_else_help = true)]
    Diff {
        #[arg(num_args = 2..=3, required = true, value_name = "ENV")]
        names: Vec<String>,
    },
    /// Print a shell hook that loads this folder's octapass.toml environments when you cd into it.
    /// Add `eval "$(octapass env hook zsh)"` to your shell's startup file.
    Hook { shell: Shell },
    /// Let the shell hook load this folder's octapass.toml (until the file changes).
    Allow {
        /// A folder or octapass.toml. Default: the current folder.
        path: Option<PathBuf>,
    },
    /// Stop the shell hook loading this folder's octapass.toml.
    Deny { path: Option<PathBuf> },
    /// What the shell hook runs at each prompt: prints the commands that load or unload variables.
    #[command(hide = true)]
    HookEnv { shell: Shell },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EnvFormatArg {
    Dotenv,
    Json,
    /// export KEY='value' (sh, bash, zsh)
    Shell,
    /// $env:KEY = 'value'
    Powershell,
    /// KEY=value for docker run --env-file (no line breaks)
    Docker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Shell {
    Zsh,
    Bash,
    Fish,
    #[value(alias = "pwsh")]
    Powershell,
}

#[derive(Debug, Subcommand)]
pub enum SshCommand {
    /// List SSH keys: title, type and fingerprint.
    List {
        /// Only this vault (name or id).
        #[arg(long)]
        vault: Option<String>,
    },
    /// Make a new key on this device and save it. Prints its public key.
    Generate {
        #[arg(long = "type", value_name = "TYPE", default_value = "ed25519")]
        key_type: KeyType,
        /// Default: the comment, or the key type.
        #[arg(long)]
        title: Option<String>,
        /// Ends the public key, usually you@computer.
        #[arg(long)]
        comment: Option<String>,
        /// The vault to save it in (name or id). Default: Personal.
        #[arg(long)]
        vault: Option<String>,
        /// Ask for a passphrase to keep with the key, used when exporting it.
        #[arg(long)]
        passphrase: bool,
    },
    /// Import private key files (OpenSSH, PEM or PKCS#8). Asks for passphrases.
    Import {
        files: Vec<PathBuf>,
        /// Also import the private keys in ~/.ssh. Keys already in the vault are skipped.
        #[arg(long)]
        scan: bool,
        /// The vault to import into (name or id). Default: Personal.
        #[arg(long)]
        vault: Option<String>,
    },
    /// Write a key's private key file, readable only by you. Asks for the master password again.
    Export {
        /// The key's title or id.
        item: String,
        /// The file to write. Without it, the key goes to stdout (not to a terminal).
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// Protect the file with a new passphrase (asked for). Default: the key's saved passphrase, if any.
        #[arg(long, conflicts_with = "no_passphrase")]
        passphrase: bool,
        /// Write the file without a passphrase, even when the key has one saved.
        #[arg(long)]
        no_passphrase: bool,
        /// Replace the file if it exists.
        #[arg(long)]
        force: bool,
        /// Look in this vault only (name or id).
        #[arg(long)]
        vault: Option<String>,
    },
    /// Print a key's public key line, for authorized_keys or a server's settings.
    Public {
        /// The key's title or id.
        item: String,
        /// Look in this vault only (name or id).
        #[arg(long)]
        vault: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum GpgCommand {
    /// List OpenPGP keys: title, key id and User ID.
    List {
        /// Only this vault (name or id).
        #[arg(long)]
        vault: Option<String>,
    },
    /// Import a private key (`gpg --armor --export-secret-keys`). Asks for its passphrase.
    Import {
        file: PathBuf,
        /// Default: the key's User ID.
        #[arg(long)]
        title: Option<String>,
        /// The vault to import into (name or id). Default: Personal.
        #[arg(long)]
        vault: Option<String>,
    },
    /// Print a key's public key block, for GitHub's or GitLab's settings.
    Public {
        /// The key's title or id.
        item: String,
        /// Look in this vault only (name or id).
        #[arg(long)]
        vault: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum GitCommand {
    /// Use Octa Pass for Git: the credential helper, and commit signing with --signing-key.
    Setup {
        /// Change your global Git settings instead of this repository's.
        #[arg(long)]
        global: bool,
        /// Sign commits with this SSH or OpenPGP key from the vault (title or id).
        #[arg(long, value_name = "ITEM")]
        signing_key: Option<String>,
        /// Sign through the SSH agent in the desktop app, so each signature is approved there,
        /// instead of through this CLI.
        #[arg(long, requires = "signing_key")]
        agent: bool,
        /// Leave the credential helper as it is.
        #[arg(long)]
        no_credentials: bool,
        /// Show the settings without changing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// The credential helper's protocol: what `git-credential-octapass` runs.
    #[command(hide = true)]
    Credential {
        /// Save credentials Git reports as working. Off by default.
        #[arg(long)]
        store: bool,
        /// get, store or erase.
        operation: String,
    },
    /// Signing and verifying for Git: what `octapass-git-sign` runs.
    #[command(hide = true)]
    Sign {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KeyType {
    /// Works with almost every server (recommended)
    Ed25519,
    #[value(name = "ecdsa-p256")]
    EcdsaP256,
    #[value(name = "ecdsa-p384")]
    EcdsaP384,
    /// For old servers only
    #[value(name = "rsa-3072")]
    Rsa3072,
    #[value(name = "rsa-4096")]
    Rsa4096,
}

#[derive(Debug, Args)]
pub struct EncryptArgs {
    /// Files and folders. A folder becomes one `.tar.age` file. None, or `-`: read stdin.
    pub paths: Vec<PathBuf>,
    /// Encrypt for yourself. The default when no one else is named; with --to, adds you.
    #[arg(long = "self")]
    pub for_self: bool,
    /// Encrypt for this person: an Octa Pass account's email, or an `age1…` public key. Can be
    /// given more than once.
    #[arg(long, value_name = "WHO")]
    pub to: Vec<String>,
    /// Encrypt with a passphrase instead. Can't be combined with --to or --self.
    #[arg(long, conflicts_with_all = ["to", "for_self"])]
    pub passphrase: bool,
    /// Where to write. Default: beside the original, with `.age` added; `-` is stdout.
    #[arg(long, short, value_name = "PATH", allow_hyphen_values = true)]
    pub output: Option<PathBuf>,
    /// Write text (PEM style) instead of binary.
    #[arg(long, short)]
    pub armor: bool,
    /// Overwrite and delete the original after encrypting. See `octapass shred`.
    #[arg(long)]
    pub shred: bool,
    /// Replace the output if it exists.
    #[arg(long)]
    pub force: bool,
    /// Tell the result in a system notification (for right-click menus, with no terminal).
    #[arg(long)]
    pub notify: bool,
}

#[derive(Debug, Args)]
pub struct DecryptArgs {
    /// `.age` files. A `.tar.age` unpacks to a folder. None, or `-`: read stdin.
    pub paths: Vec<PathBuf>,
    /// Open with the keys in this age identity file instead of your account. Can be given more
    /// than once.
    #[arg(long, short, value_name = "PATH")]
    pub identity: Vec<PathBuf>,
    /// Where to write. Default: beside the file, without `.age`; `-` is stdout.
    #[arg(long, short, value_name = "PATH", allow_hyphen_values = true)]
    pub output: Option<PathBuf>,
    /// Replace the output if it exists.
    #[arg(long)]
    pub force: bool,
    /// Tell the result in a system notification (for right-click menus, with no terminal).
    #[arg(long)]
    pub notify: bool,
}

#[derive(Debug, Subcommand)]
pub enum SafeCommand {
    /// List your Safes.
    List,
    /// Make a new Safe.
    Create {
        name: String,
        /// Keep it in step across your devices, through the server.
        #[arg(long)]
        sync: bool,
    },
    /// Show what's in a folder of a Safe.
    Ls {
        safe: String,
        /// A folder in the Safe, like `Taxes/2026`. Default: the top.
        #[arg(default_value = "")]
        path: String,
    },
    /// Copy files into a Safe.
    Add {
        safe: String,
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// The folder in the Safe to put them in. Default: the top.
        #[arg(long, default_value = "")]
        to: String,
    },
    /// Copy a file out of a Safe. Default output: its name, in this folder; `-` is stdout.
    Get {
        safe: String,
        path: String,
        #[arg(long, short, value_name = "PATH", allow_hyphen_values = true)]
        output: Option<PathBuf>,
        /// Replace the output if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Make a folder in a Safe, with any folders above it.
    Mkdir { safe: String, path: String },
    /// Rename or move something in a Safe.
    Mv {
        safe: String,
        from: String,
        to: String,
    },
    /// Delete a file or folder from a Safe.
    Rm {
        safe: String,
        path: String,
        /// Delete a folder with everything in it.
        #[arg(long, short)]
        recursive: bool,
    },
    /// Send and fetch changes through the server now.
    Sync { safe: String },
    /// Delete a Safe and everything in it. Its key goes to the trash with its item; the files
    /// on this device go now.
    Delete {
        safe: String,
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
    },
    /// Turn sync through the server on or off for a Safe.
    SetSync {
        safe: String,
        #[arg(value_enum)]
        state: OnOff,
    },
    /// Show a Safe as a folder until it's unmounted or the vault locks (Linux, with FUSE).
    Mount {
        safe: String,
        /// The empty folder to show it in.
        mountpoint: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OnOff {
    On,
    Off,
}

#[derive(Debug, Subcommand)]
pub enum ContextMenuCommand {
    /// Add the menu for this user. Encrypts for yourself, and decrypts while a session is open;
    /// the desktop app adds a richer one from its Tools section.
    Install,
    /// Remove it.
    Remove,
    /// Show whether it's there.
    Status,
}

#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// A passphrase of this many words (3-20).
    #[arg(long, conflicts_with = "length")]
    pub words: Option<usize>,
    /// A random password of this many characters (4-128). Default 20.
    #[arg(long)]
    pub length: Option<usize>,
    #[arg(long, conflicts_with = "words")]
    pub no_uppercase: bool,
    #[arg(long, conflicts_with = "words")]
    pub no_lowercase: bool,
    #[arg(long, conflicts_with = "words")]
    pub no_digits: bool,
    #[arg(long, conflicts_with = "words")]
    pub no_symbols: bool,
    /// Leave out characters that are easy to misread (I l 1 O 0 o |).
    #[arg(long, conflicts_with = "words")]
    pub avoid_ambiguous: bool,
    /// Between passphrase words. Default "-".
    #[arg(long, requires = "words")]
    pub separator: Option<String>,
    /// Capitalise passphrase words.
    #[arg(long, requires = "words")]
    pub capitalize: bool,
    /// Add a digit to one passphrase word.
    #[arg(long, requires = "words")]
    pub number: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ImportFormat {
    /// Chrome, Edge, Brave, Opera, Vivaldi, Arc (CSV)
    Chrome,
    Firefox,
    /// Safari and Apple Passwords (CSV)
    Safari,
    /// Bitwarden or Vaultwarden JSON, also password-protected
    #[value(name = "bitwarden-json", alias = "bitwarden")]
    BitwardenJson,
    /// Bitwarden or Vaultwarden CSV
    #[value(name = "bitwarden-csv")]
    BitwardenCsv,
    /// 1Password .1pux
    #[value(name = "onepassword-1pux", alias = "1password", alias = "1pux")]
    OnePassword1Pux,
    /// 1Password CSV
    #[value(name = "onepassword-csv", alias = "1password-csv")]
    OnePasswordCsv,
    #[value(name = "lastpass-csv", alias = "lastpass")]
    LastPassCsv,
    /// Any CSV with a header row
    #[value(name = "generic-csv", alias = "csv")]
    GenericCsv,
    /// otpauth:// and otpauth-migration:// links, one per line
    #[value(name = "otpauth")]
    OtpAuth,
    /// An Octa Pass export: encrypted (.octapass) or plaintext JSON
    #[value(name = "octapass")]
    OctaPass,
    /// The FIDO Credential Exchange Format (JSON)
    #[value(name = "cxf")]
    Cxf,
    /// Proton Pass ZIP (PGP-encrypted with a passphrase too), JSON or CSV
    #[value(name = "protonpass", alias = "proton")]
    ProtonPass,
    /// Dashlane ZIP of CSVs, or JSON
    #[value(name = "dashlane")]
    Dashlane,
    /// Keeper CSV or JSON
    #[value(name = "keeper")]
    Keeper,
    #[value(name = "nordpass")]
    NordPass,
    /// KeePass or KeePassXC: .kdbx (with --key-file if it has one), XML or CSV
    #[value(name = "keepass", alias = "keepassxc", alias = "kdbx")]
    KeePass,
    #[value(name = "enpass")]
    Enpass,
    #[value(name = "roboform")]
    RoboForm,
    /// Aegis Authenticator JSON, plain or encrypted
    #[value(name = "aegis")]
    Aegis,
    /// 2FAS backups, plain or encrypted
    #[value(name = "2fas")]
    TwoFas,
    /// andOTP backups, plain or encrypted
    #[value(name = "andotp")]
    AndOtp,
    /// Ente Auth plaintext or password-encrypted export
    #[value(name = "ente-auth", alias = "ente")]
    EnteAuth,
    /// Raivo OTP ZIP (encrypted with the Raivo master password) or its JSON
    #[value(name = "raivo")]
    Raivo,
    /// Zoho Vault: General CSV or Zoho Vault CSV
    #[value(name = "zoho-vault", alias = "zoho")]
    ZohoVault,
    /// Avira Password Manager CSV
    #[value(name = "avira")]
    Avira,
    /// Norton Password Manager CSV
    #[value(name = "norton")]
    Norton,
    /// McAfee True Key CSV
    #[value(name = "mcafee", alias = "true-key", alias = "truekey")]
    McAfee,
    /// Kaspersky Password Manager: the text export, in English, or CSV
    #[value(name = "kaspersky")]
    Kaspersky,
}

impl From<ImportFormat> for ImportSource {
    fn from(format: ImportFormat) -> Self {
        match format {
            ImportFormat::Chrome => ImportSource::Chrome,
            ImportFormat::Firefox => ImportSource::Firefox,
            ImportFormat::Safari => ImportSource::Safari,
            ImportFormat::BitwardenJson => ImportSource::BitwardenJson,
            ImportFormat::BitwardenCsv => ImportSource::BitwardenCsv,
            ImportFormat::OnePassword1Pux => ImportSource::OnePassword1Pux,
            ImportFormat::OnePasswordCsv => ImportSource::OnePasswordCsv,
            ImportFormat::LastPassCsv => ImportSource::LastPassCsv,
            ImportFormat::GenericCsv => ImportSource::GenericCsv,
            ImportFormat::OtpAuth => ImportSource::OtpAuth,
            ImportFormat::OctaPass => ImportSource::OctaPass,
            ImportFormat::Cxf => ImportSource::Cxf,
            ImportFormat::ProtonPass => ImportSource::ProtonPass,
            ImportFormat::Dashlane => ImportSource::Dashlane,
            ImportFormat::Keeper => ImportSource::Keeper,
            ImportFormat::NordPass => ImportSource::NordPass,
            ImportFormat::KeePass => ImportSource::KeePass,
            ImportFormat::Enpass => ImportSource::Enpass,
            ImportFormat::RoboForm => ImportSource::RoboForm,
            ImportFormat::Aegis => ImportSource::Aegis,
            ImportFormat::TwoFas => ImportSource::TwoFas,
            ImportFormat::AndOtp => ImportSource::AndOtp,
            ImportFormat::EnteAuth => ImportSource::EnteAuth,
            ImportFormat::Raivo => ImportSource::Raivo,
            ImportFormat::ZohoVault => ImportSource::ZohoVault,
            ImportFormat::Avira => ImportSource::Avira,
            ImportFormat::Norton => ImportSource::Norton,
            ImportFormat::McAfee => ImportSource::McAfee,
            ImportFormat::Kaspersky => ImportSource::Kaspersky,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// Everything, as Octa Pass JSON
    Json,
    /// One row per item, for other password managers
    Csv,
    /// The FIDO Credential Exchange Format, for other apps that support it
    Cxf,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn the_command_line_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_takes_everything_after_the_separator() {
        let cli = Cli::try_parse_from([
            "octapass",
            "run",
            "--env-file",
            "a.env",
            "--",
            "npm",
            "start",
            "--json",
        ])
        .unwrap();
        let Command::Run {
            env_file, command, ..
        } = cli.command
        else {
            panic!("not run");
        };
        assert_eq!(env_file, [PathBuf::from("a.env")]);
        assert_eq!(command, ["npm", "start", "--json"]);
        assert!(!cli.global.json);
    }

    #[test]
    fn run_takes_environments_in_order() {
        let cli = Cli::try_parse_from([
            "octapass",
            "run",
            "--env",
            "shop-api:production",
            "--env",
            "Extra",
            "--env-file-out",
            ".env",
            "--",
            "docker",
            "compose",
            "up",
        ])
        .unwrap();
        let Command::Run {
            env, env_file_out, ..
        } = cli.command
        else {
            panic!("not run");
        };
        assert_eq!(env, ["shop-api:production", "Extra"]);
        assert_eq!(env_file_out, Some(PathBuf::from(".env")));
    }

    #[test]
    fn env_commands_parse() {
        let parse = |args: &[&str]| {
            let mut all = vec!["octapass", "env"];
            all.extend_from_slice(args);
            Cli::try_parse_from(all)
        };
        assert!(parse(&["set", "Shop", "A=1", "B"]).is_ok());
        assert!(
            parse(&["import", "x.env"]).is_err(),
            "needs --into or --new"
        );
        assert!(parse(&["import", "x.env", "--into", "A", "--new", "B"]).is_err());
        assert!(parse(&["import", "x.env", "--into", "A", "--stage", "dev"]).is_err());
        assert!(parse(&["export", "Shop", "--format", "docker"]).is_ok());
        assert!(parse(&["diff", "shop-api", "staging", "production"]).is_ok());
        assert!(parse(&["diff", "one"]).is_err());
        assert!(parse(&["hook", "pwsh"]).is_ok());
        assert!(parse(&["hook", "tcsh"]).is_err());
    }

    #[test]
    fn service_accounts_can_only_read() {
        let works = |args: &[&str]| {
            let mut all = vec!["octapass"];
            all.extend_from_slice(args);
            Cli::try_parse_from(all)
                .unwrap()
                .command
                .works_with_service_account()
        };
        assert!(works(&["read", "octapass://a/b/c"]));
        assert!(works(&["run", "--", "x"]));
        assert!(works(&["env", "export", "Shop"]));
        assert!(works(&["docker-credential", "get"]));
        assert!(works(&["oauth", "token", "x"]));
        assert!(!works(&["docker-credential", "store"]));
        assert!(!works(&["env", "set", "Shop", "A=1"]));
        assert!(!works(&["logout"]));
        assert!(!works(&["export"]));
        assert!(!works(&["connect", "serve"]));
        assert!(!works(&["service-account", "list", "--vault", "x"]));
        assert!(!works(&[
            "oauth",
            "create",
            "x",
            "--flow",
            "client-credentials",
            "--token-url",
            "u",
            "--client-id",
            "i"
        ]));
    }

    #[test]
    fn import_formats_have_short_aliases() {
        let cli = Cli::try_parse_from(["octapass", "import", "bitwarden", "x.json"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Import {
                format: ImportFormat::BitwardenJson,
                ..
            }
        ));
    }

    #[test]
    fn words_and_length_are_exclusive() {
        assert!(
            Cli::try_parse_from(["octapass", "generate", "--words", "5", "--length", "9"]).is_err()
        );
        assert!(Cli::try_parse_from(["octapass", "generate", "--separator", "_"]).is_err());
        assert!(
            Cli::try_parse_from(["octapass", "generate", "--words", "4", "--capitalize"]).is_ok()
        );
    }
}
