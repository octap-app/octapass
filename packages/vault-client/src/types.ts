// The Octa Pass item model and the UI ↔ data contract (plans/11-milestone-1-web-vault.md).

import type { HealthSettingsDetails } from './tools/healthSettings';
import type { UsageStatsDetails } from './usage';
// Every change here must be recorded in that plan's History section.

import type { IconAnswer } from './siteIcons';

/**
 * `maskedEmailProvider` holds the token for a masked email service (`MaskedEmailService`). It syncs
 * like any item but is kept out of item lists: lists show it only when filtered by that type.
 * `equivalentDomains` is a setting held the same way (`EquivalentDomainsDetails`), and so is
 * `usageStats`, how often and when each item was used (`UsageStatsDetails`). A `place` is a place
 * saved for Nearby (`PlaceData` in its overview, `PlaceDetails`): kept out of item lists too, and
 * listed in Nearby and the Places manager.
 */
export type ItemType =
  | 'login'
  | 'secureNote'
  | 'card'
  | 'identity'
  | 'password'
  | 'document'
  | 'wifi'
  | 'sshKey'
  | 'maskedEmailProvider'
  | 'environment'
  | 'healthSettings'
  | 'equivalentDomains'
  | 'usageStats'
  | 'place'
  | 'certificate'
  | 'key'
  | TableItemType
  | 'custom'
  | 'customTemplate';

/** The types built from the field table in `itemFields.ts`. */
export type TableItemType = 'bankAccount' | 'apiCredential' | 'softwareLicense' | 'idDocument' | 'cryptoWallet' | 'database';

export const SCHEMA_VERSION = 1;

/**
 * How a saved website matches a page. `subdomains` is the default: the same host, a domain above it
 * or a host below it, on one registrable domain (`login.example.com` matches `example.com` and
 * `eu.login.example.com`, not `shop.example.com`; plan 05, History 2026-11-05). `baseDomain`: any
 * host on the same registrable domain (the default before 2026-11-05, now only when chosen).
 * `host`: the same host and port. `startsWith`: the same host and port and a path that starts the
 * same. `regex`: the saved text is a regular expression over the page's address. `never`: not offered.
 */
export type UrlMatchMode = 'subdomains' | 'baseDomain' | 'host' | 'startsWith' | 'regex' | 'never';

export const URL_MATCH_MODES: readonly UrlMatchMode[] = ['subdomains', 'baseDomain', 'host', 'startsWith', 'regex', 'never'];

/** The mode of a website stored without one. Editors don't store it. */
export const DEFAULT_URL_MATCH_MODE: UrlMatchMode = 'subdomains';

/** Plaintext needed for lists and autofill matching. Encrypted separately from the details. */
export interface ItemOverview {
  schemaVersion: typeof SCHEMA_VERSION;
  title: string;
  type: ItemType;
  urls?: string[];
  /** Per-website match modes, keyed by the URL exactly as written in `urls`. Missing means `subdomains`. */
  urlMatch?: Record<string, UrlMatchMode>;
  subtitle?: string;
  tags?: string[];
  favorite?: boolean;
  /** Pinned: listed under Pinned in the sidebar. A list of its own, apart from the favourites. */
  pinned?: boolean;
  /** When the item was first saved in the app it was imported from. Shown instead of `Item.createdAt`. */
  createdAt?: string;
  /** When it last changed in that app. Shown instead of `Item.updatedAt`; an edit here drops it. */
  updatedAt?: string;
  /** When it was last used to sign in, from that app. */
  lastUsedAt?: string;
  /** The app and the item's id there, so importing the same file again updates the item. */
  importedFrom?: ImportedFrom;
  /** The ids of the places (`place` items) the item belongs to, listed under them in Nearby. */
  places?: string[];
  /** A `place` item's point, radius and Wi-Fi networks. */
  place?: PlaceData;
}

/**
 * Where a place is: an optional point (degrees, WGS 84), a radius in metres around it (default
 * `PLACE_DEFAULT_RADIUS`) and the Wi-Fi network names (SSIDs) that mean being there. All inside the
 * encrypted overview; matching it against where the device is happens on the device (plan 03, *Nearby*).
 */
export interface PlaceData {
  latitude?: number;
  longitude?: number;
  radius?: number;
  networks?: string[];
}

export const PLACE_DEFAULT_RADIUS = 150;
export const PLACE_MIN_RADIUS = 25;
export const PLACE_MAX_RADIUS = 10_000;

/** Where the device is, as far as it can tell: connected Wi-Fi networks and one location reading. */
export interface Here {
  networks?: string[];
  position?: { latitude: number; longitude: number; accuracy?: number };
}

/** A place in the Nearby list: `here` when the device is at it (and how it knows), `distance` in metres. */
export interface NearbyPlace {
  id: string;
  here?: 'wifi' | 'location';
  distance?: number;
  /** The place's items, a section per type in the list's type order, each by name. */
  sections: { type: ItemType | (string & {}); items: string[] }[];
}

/** `source` is the `ImportSource` the item came through; `id` is the item's id in that app. */
export interface ImportedFrom {
  source: string;
  id: string;
}

export type TwoFactorMethod = 'totp' | 'sms' | 'email' | 'key' | 'passkey' | 'none';

export interface Passkey {
  rpId: string;
  userName: string;
  createdAt: string;
}

export interface BackupCode {
  code: string;
  used: boolean;
}

/** A site's security question. The answer is hidden like a password; a random one is safest. */
export interface SecurityQuestion {
  question: string;
  answer: string;
}

/** The masked email services Octa Pass can make aliases with. */
export type MaskedEmailProviderId = 'simplelogin' | 'addy' | 'firefoxRelay' | 'fastmail' | 'duckduckgo' | 'forwardEmail';

/**
 * Where a recovery email or phone came from, so it follows the source: an email or phone in an
 * Identity item, or a masked email alias (`aliasId` is the provider's id for it, or the address
 * when the provider has none).
 */
export type RecoverySource = { kind: 'identity'; itemId: string } | { kind: 'alias'; provider: MaskedEmailProviderId; aliasId: string };

export interface RecoveryInfo {
  email?: string;
  emailSource?: RecoverySource;
  phone?: string;
  /** Only `identity`: there are no masked phone numbers. */
  phoneSource?: Extract<RecoverySource, { kind: 'identity' }>;
  backupCodes?: BackupCode[];
  securityQuestions?: SecurityQuestion[];
  twoFactorMethod?: TwoFactorMethod;
}

export interface CustomField {
  label: string;
  value: string;
  hidden: boolean;
}

export interface PasswordHistoryEntry {
  password: string;
  changedAt: string;
}

/**
 * A file kept with an item. The file is encrypted on the device with its own key and stored on the
 * server; this entry, inside the item's encrypted details, is the only place its name, type and key
 * live. Added and removed through `AttachmentService`, never by editing the list.
 */
export interface Attachment {
  id: string;
  name: string;
  /** Media type, e.g. `application/pdf`; empty when unknown. */
  type: string;
  /** Bytes before encryption. */
  size: number;
  /** The file key, wrapped by the item key. Useless without the item key, which stays in the core. */
  key: string;
  /** The phone apps: saved on this phone and waiting to upload. Never stored. */
  pending?: boolean;
}

/**
 * Where and how the desktop app may auto-type a login. `sequence` uses `{USERNAME}`, `{PASSWORD}`,
 * `{TOTP}`, `{TAB}`, `{ENTER}` and `{DELAY n}` (see `autoType.ts`); missing means the default.
 * `windowTitles` are window titles (or app names) the login may be typed into, with `*` and `?`.
 */
export interface AutoTypeSettings {
  sequence?: string;
  windowTitles?: string[];
}

export interface LoginDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  username?: string;
  password?: string;
  /** otpauth:// URI or a bare base32 secret. */
  totp?: string;
  notes?: string;
  /** Display only in milestone 1. */
  passkeys?: Passkey[];
  recovery?: RecoveryInfo;
  customFields?: CustomField[];
  passwordHistory?: PasswordHistoryEntry[];
  /** When the password was set, from the app it was imported from. Shown with the newest history entry, whichever is later. */
  passwordChangedAt?: string;
  /** The realm of a site's HTTP sign-in prompt (`WWW-Authenticate`), for logins saved from one. */
  httpRealm?: string;
  attachments?: Attachment[];
  /** Desktop auto-type. Other clients keep it untouched. */
  autoType?: AutoTypeSettings;
}

export interface SecureNoteDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  notes: string;
  attachments?: Attachment[];
}

export interface CardDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  cardholder?: string;
  number?: string;
  /** MM/YY */
  expiry?: string;
  cvv?: string;
  pin?: string;
  brand?: string;
  notes?: string;
  attachments?: Attachment[];
}

export interface Address {
  line1?: string;
  line2?: string;
  city?: string;
  region?: string;
  postalCode?: string;
  country?: string;
}

export interface IdentityDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  firstName?: string;
  lastName?: string;
  email?: string;
  phone?: string;
  address?: Address;
  birthDate?: string;
  notes?: string;
  attachments?: Attachment[];
}

/** A file plus notes. The file is the first attachment. */
export interface DocumentDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  notes?: string;
  attachments?: Attachment[];
}

/**
 * How a Wi-Fi network is secured. Personal networks share one password; `wpaWpa2` and `wpa2Wpa3`
 * are the transition modes routers offer for older devices. Enterprise networks sign each person in
 * (802.1X). Open networks have no password.
 */
export type WifiSecurity = 'open' | 'wep' | 'wpa' | 'wpaWpa2' | 'wpa2' | 'wpa2Wpa3' | 'wpa3' | 'wpa2Enterprise' | 'wpa3Enterprise';

/** The EAP methods an Enterprise network can use. */
export type WifiEapMethod = 'peap' | 'ttls' | 'tls' | 'pwd' | 'leap' | 'fast';

/** The inner sign-in of PEAP and TTLS. */
export type WifiPhase2 = 'mschapv2' | 'gtc' | 'pap' | 'chap' | 'mschap';

/** A Wi-Fi network. The overview's subtitle is always the network name (see `summarizeItem`). */
export interface WifiDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  /** The network name, exactly as broadcast. */
  ssid: string;
  security: WifiSecurity;
  /** The shared password (Personal, WEP), or the user's own on an Enterprise network. */
  password?: string;
  /** The network doesn't broadcast its name. */
  hidden?: boolean;
  /** Enterprise only, like the next five. */
  eapMethod?: WifiEapMethod;
  phase2?: WifiPhase2;
  username?: string;
  /** The outer (anonymous) identity, when it differs from the username. */
  identity?: string;
  /** The domain the server's certificate must match. */
  serverDomain?: string;
  /** The CA certificate (PEM) that signed the server's certificate. */
  caCertificate?: string;
  /** Shows a sign-in page (captive portal) after joining, as in hotels and airports. */
  captivePortal?: boolean;
  /**
   * Set up by an organisation: a work or school network. On iPhone, iPad and Mac, "Managed" means a
   * configuration profile (MDM) installed it; this flag is the user's own note, not that state.
   */
  managed?: boolean;
  /** A phone's or tablet's Personal Hotspot. */
  hotspot?: boolean;
  notes?: string;
  customFields?: CustomField[];
  passwordHistory?: PasswordHistoryEntry[];
  attachments?: Attachment[];
}

/**
 * An SSH key (plan 16). The overview's subtitle is the fingerprint. Keys made or imported here have
 * the first four fields; keys from other apps may have only some.
 */
export interface SshKeyDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  /** OpenSSH format, without a passphrase: the vault encrypts it. Shown only after confirming again. */
  privateKey?: string;
  /** The public key without its comment: `ssh-ed25519 AAAA…`. */
  publicKey?: string;
  /** The SSH algorithm name: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, … (`sshKeyTypeLabel` for people). */
  keyType?: string;
  /** `SHA256:…`, as `ssh-keygen -l` shows it. */
  fingerprint?: string;
  /** Usually `user@host`; ends the `authorized_keys` line. */
  comment?: string;
  /** Protects copies written out of the vault (offered on export). The stored key has none. */
  passphrase?: string;
  /** `false` keeps the key out of the desktop app's SSH agent. Missing means offered. */
  sshAgent?: boolean;
  notes?: string;
  customFields?: CustomField[];
  attachments?: Attachment[];
}

/** The keys Octa Pass makes. */
export type SshKeyKind = 'ed25519' | 'ecdsaP256' | 'ecdsaP384' | 'rsa3072' | 'rsa4096';

/** A key made or read on this device. `usable` is false for DSA and FIDO (`sk-`) keys. */
export interface SshKeyMaterial {
  privateKey: string;
  publicKey: string;
  keyType: string;
  bits: number;
  fingerprint: string;
  comment: string;
  usable: boolean;
}

/** How the user confirms it's them before a private key is shown, copied or saved. */
export type SshKeyConfirmation = { password: string } | { device: true };

/** How the user confirms it's them before a secret is revealed, copied or exported. */
export type IdentityConfirmation = { password: string } | { device: true };

/**
 * SSH key operations, run by the core on this device (plan 16). Missing on hosts that don't offer
 * them yet: their SSH key items show the public key and fingerprint only.
 */
/** A TLS certificate with its key and chain (plan 16). Made by the developer toolkit. */
export interface CertificateDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  /** PEM. The other fields are read out of it. */
  certificate?: string;
  chain?: string;
  /** PKCS#8 PEM without a passphrase: the vault encrypts it. Shown only after confirming. */
  privateKey?: string;
  commonName?: string;
  sans?: string[];
  issuer?: string;
  /** RFC 3339. */
  notBefore?: string;
  /** RFC 3339. Drives renewal reminders. */
  notAfter?: string;
  keyType?: string;
  /** SHA-256 of the certificate, colon-separated. */
  fingerprint?: string;
  isCa?: boolean;
  /** `selfSigned`, `localCa`, `acme` or `imported`. */
  source?: string;
  /** ACME: the CA, names and account key, to renew without asking again. */
  acme?: Record<string, unknown>;
  notes?: string;
  customFields?: CustomField[];
  attachments?: Attachment[];
}

/** A key that isn't an SSH key (plan 16): JWT signing keys, OpenPGP and age keys. */
export interface KeyItemDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  /** `jwt`, `openpgp`, `age` or `asymmetric`. */
  kind?: string;
  algorithm?: string;
  privateKey?: string;
  publicKey?: string;
  /** HMAC secrets, which have no public half. */
  secret?: string;
  /** The key as a JWK. Secret: it holds the private parts. */
  jwk?: string;
  /** Public parts only: what gets published. */
  jwks?: string;
  keyId?: string;
  fingerprint?: string;
  /** OpenPGP: `Name <email>`. */
  userId?: string;
  passphrase?: string;
  notes?: string;
  customFields?: CustomField[];
  attachments?: Attachment[];
}

/** One digest from the toolkit. */
export interface ToolHash {
  algorithm: string;
  hex: string;
  base64: string;
  /** MD5, SHA-1 and CRC32: for checking old checksums only. */
  legacy: boolean;
}

/** What a TLS handshake with a live server gave. */
export interface HostCertificates {
  host: string;
  port: number;
  /** PEM of the chain the server sent. */
  pem: string;
  protocol: string;
  cipherSuite: string;
  trusted: boolean;
  trustError?: string;
}

/**
 * The developer toolkit (plan 16). `run` is the Rust core's `toolkit::run`, in this device's worker
 * or native code; nothing it does leaves the device. The optional methods are the only network or
 * system access, and each host has what it can do.
 */
export interface ToolkitService {
  run<T = Record<string, unknown>>(op: string, input: object): Promise<T>;
  /** Hashes a file in chunks. Missing where files can't reach the core (the extension popup). */
  hashFile?(file: Blob, algorithms: string[]): Promise<ToolHash[]>;
  /** Fetches a JWKS. The UI says it's going to the network first. */
  fetchJwks?(url: string): Promise<string>;
  /** Reads a live server's certificate. Native apps only: a web page can't open a TLS connection. */
  fetchHostCertificates?(target: string): Promise<HostCertificates>;
  /** Installs or removes a private CA in this device's trust store. Desktop only. */
  setCaTrust?(certificate: string, trusted: boolean): Promise<void>;
}

export interface SshKeyService {
  generate(kind: SshKeyKind, comment: string): Promise<SshKeyMaterial>;
  /**
   * Reads a private key file or pasted text (OpenSSH, PEM, PKCS#8). Throws `sshPassphraseRequired`
   * (ask, then call again), `wrongPassphrase`, `sshPublicKeyOnly`, `unsupportedSshKey` or `invalidSshKey`.
   */
  read(text: string, passphrase?: string): Promise<SshKeyMaterial>;
  /** A stored key as an OpenSSH private key file with `comment`, protected by `passphrase` when given. */
  write(privateKey: string, comment: string, passphrase?: string): Promise<string>;
  /** Checks the master password or device unlock again (plan 16 §6). Throws `invalidCredentials` or a device unlock error. */
  confirm(proof: SshKeyConfirmation): Promise<void>;
  /** Device unlock is on here, so `confirm` can use it. */
  canConfirmWithDevice(): Promise<boolean>;
}

/** A private key file found in `~/.ssh`. */
export interface SshHomeKey {
  name: string;
  /** Asks for a passphrase. A protected key's details come from its `.pub`, if there is one. */
  protected: boolean;
  keyType?: string | null;
  fingerprint?: string | null;
  comment?: string | null;
}

/** `~/.ssh` on this computer. Only the desktop app has it. */
export interface SshHomeService {
  scan(): Promise<SshHomeKey[]>;
  /** Reads a key `scan` found. Throws as `SshKeyService.read` does. */
  read(name: string, passphrase?: string): Promise<SshKeyMaterial>;
  /** Writes an item's key and its `.pub`. Throws `alreadyExists` unless `replace`. Returns the path. */
  write(itemId: string, name: string, passphrase?: string, replace?: boolean): Promise<string>;
}

export interface SshAgentStatus {
  enabled: boolean;
  running: boolean;
  /** Where `SSH_AUTH_SOCK` should point. */
  endpoint?: string | null;
  /** `~/.ssh/config` points at the agent. */
  configConnected: boolean;
  /** Why the agent isn't running. */
  error?: string | null;
  /** The keys offered now: none while locked. */
  keys: { title: string; fingerprint: string; keyType: string }[];
  windows: boolean;
}

/** The SSH agent in the desktop app (plan 16). */
export interface SshAgentService {
  status(): Promise<SshAgentStatus>;
  setEnabled(enabled: boolean): Promise<SshAgentStatus>;
  connectConfig(): Promise<SshAgentStatus>;
  disconnectConfig(): Promise<SshAgentStatus>;
}

/** The desktop app running in the background: its tray icon and opening at login. Per device. */
export interface BackgroundStatus {
  /** The tray icon (the menu bar on macOS). */
  tray: boolean;
  /** The system opens the app at login, in the background. */
  openAtLogin: boolean;
  /** `false` while the app runs from a disk image or from Downloads, where opening at login can't be turned on. */
  installed: boolean;
  /** The words differ: the menu bar on macOS, the system tray elsewhere. */
  platform: 'macos' | 'windows' | 'linux';
  /** Why the tray icon or opening at login doesn't work, or why the last change failed. */
  error?: string | null;
}

/** Settings → Running in the background, in the desktop app. */
export interface BackgroundService {
  status(): Promise<BackgroundStatus>;
  setTray(visible: boolean): Promise<BackgroundStatus>;
  setOpenAtLogin(enabled: boolean): Promise<BackgroundStatus>;
}

/** Where a browser gets the Octa Pass extension. Chrome, Chromium and Brave use the Chrome Web Store. */
export type ExtensionStore = 'chrome' | 'edge' | 'firefox';

/** The browser extension on this computer, as the desktop app sees it. Per device, never synced. */
export interface BrowserExtensionStatus {
  /** The supported browsers on this computer: "Chrome", "Edge", "Brave", "Chromium", "Firefox". */
  browsers: { name: string; store: ExtensionStore }[];
  /** Those connected: the extension can reach the app from them (the native messaging manifest is there). */
  connected: string[];
  /** The browsers the extension has reached the app from, as the app names them ("Google Chrome"). None: most likely not installed. */
  seen: string[];
}

/** Settings → Browser extension and the offer of the extension, in the desktop app. */
export interface BrowserExtensionService {
  status(): Promise<BrowserExtensionStatus>;
  connect(): Promise<BrowserExtensionStatus>;
  disconnect(): Promise<BrowserExtensionStatus>;
  /** Opens where `browser` (a name from `browsers`) gets the extension. */
  get(browser: string): Promise<void>;
}

/** A masked email service connected with the user's own API token. */
export interface MaskedEmailProviderDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  provider: MaskedEmailProviderId;
  token: string;
  /** A self-hosted server (SimpleLogin, addy.io). */
  baseUrl?: string;
  /** The domain new aliases are made on (addy.io, Forward Email). */
  domain?: string;
  attachments?: Attachment[];
}

/** One variable of an environment. Concealed variables are hidden until revealed, like passwords. */
export interface EnvironmentVariable {
  /** Letters, digits and `_`, not starting with a digit. Used once per environment. */
  key: string;
  /** The value, or an `octapass://<vault>/<item>/<field>` reference to another item's field. */
  value: string;
  /** Hidden until revealed. New variables are concealed. */
  concealed: boolean;
  note?: string;
}

/**
 * A set of environment variables: one app's `.env` file for one stage, or a single variable.
 * A project without a stage is its shared set, loaded before the stage's variables.
 */
export interface EnvironmentDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  /** A short identifier such as `shop-api`: letters, digits, `-` and `_`. */
  project?: string;
  /** How the project is shown, when it isn't the identifier itself. */
  projectName?: string;
  /** development, staging, production, testing, preview, local, or a custom name. */
  stage?: string;
  /** In the order shown and written to files. */
  variables: EnvironmentVariable[];
  notes?: string;
  attachments?: Attachment[];
}

/** A `place` item's details: a note. The rest is in the overview's `place`. */
export interface PlaceDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  notes?: string;
  attachments?: never;
}

/** The user's own equivalent domains. One hidden item; never edited as an item (`EquivalentDomains`). */
export interface EquivalentDomainsDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  /** Groups of registrable domains treated as one site. */
  groups: string[][];
  /** Built-in groups turned off, each named by its first domain. */
  excludedDefaults?: string[];
  /** Files never go here; this keeps `ItemDetails.attachments` readable on every type. */
  attachments?: never;
}

interface TableDetails {
  schemaVersion: number;
  notes?: string;
  customFields?: CustomField[];
  attachments?: Attachment[];
}

export interface BankAccountDetails extends TableDetails {
  bankName?: string;
  accountHolder?: string;
  /** `checking | savings | business | other`, or the words another app used. */
  accountType?: string;
  iban?: string;
  accountNumber?: string;
  /** A routing, sort or branch code. */
  routingNumber?: string;
  /** The SWIFT code (BIC). */
  swift?: string;
  branch?: string;
  pin?: string;
}

/**
 * An API key or token. The extension saves pasted keys with both `credential`/`hostname` and the item
 * editor's `key`/`host`. `oauth2` holds a live token (plan 16); the extension only reads it.
 */
export interface ApiCredentialDetails extends TableDetails {
  /** `apiKey | bearerToken | oauth | jwt | basicAuth | other`, or the words another app used. */
  credentialType?: string;
  credential?: string;
  hostname?: string;
  username?: string;
  key?: string;
  secret?: string;
  host?: string;
  /** `YYYY-MM-DD` */
  expiryDate?: string;
  /** `expiresAt` is Unix seconds. */
  oauth2?: { accessToken?: string; expiresAt?: number };
}

export interface SoftwareLicenseDetails extends TableDetails {
  product?: string;
  version?: string;
  licenseKey?: string;
  licensedTo?: string;
  email?: string;
  publisher?: string;
  orderNumber?: string;
  /** `YYYY-MM-DD` */
  purchaseDate?: string;
  /** `YYYY-MM-DD` */
  expiryDate?: string;
}

/** A passport, driver's licence or national ID. Scans are its `attachments`. */
export interface IdDocumentDetails extends TableDetails {
  /** `passport | driverLicense | nationalId | other`, or the words another app used. */
  documentType?: string;
  number?: string;
  fullName?: string;
  /** `YYYY-MM-DD` */
  birthDate?: string;
  issuer?: string;
  country?: string;
  /** `YYYY-MM-DD` */
  issueDate?: string;
  /** `YYYY-MM-DD` */
  expiryDate?: string;
}

export interface WalletAddress {
  /** `bitcoin | ethereum`, or the name of another chain. */
  network: string;
  address: string;
  label?: string;
}

/** The seed phrase and passphrase are never shown as a QR code: only addresses are. */
export interface CryptoWalletDetails extends TableDetails {
  walletName?: string;
  seedPhrase?: string;
  /** The optional BIP-39 passphrase (the "25th word"). */
  passphrase?: string;
  addresses?: WalletAddress[];
}

export interface DatabaseDetails extends TableDetails {
  /** `postgresql | mysql | sqlServer | oracle | mongodb | redis | sqlite | server | other`, or the words another app used. */
  databaseType?: string;
  host?: string;
  /** Text: other apps export ports that aren't numbers, and those are kept. */
  port?: string;
  database?: string;
  username?: string;
  password?: string;
  /** Usually holds the password, so it's a secret too. */
  connectionString?: string;
  passwordHistory?: { password: string; changedAt: string }[];
}

export type CustomItemFieldKind = 'text' | 'hidden' | 'multiline' | 'url' | 'date' | 'email' | 'phone' | 'totp';

export interface TemplateField {
  label: string;
  /** A kind this version doesn't know counts as hidden. */
  kind: CustomItemFieldKind;
}

export interface TypedField extends TemplateField {
  value: string;
}

/** An item of the user's own type. Its template's fields are copied in, so it outlives the template. */
export interface CustomDetails {
  schemaVersion: number;
  /** The `customTemplate` item this was made from, and its name then. */
  templateId?: string;
  templateName?: string;
  fields: TypedField[];
  notes?: string;
  attachments?: Attachment[];
}

/** A user's own item type: its fields, without values. The item's title is the type's name. */
export interface CustomTemplateDetails {
  schemaVersion: number;
  fields: TemplateField[];
  attachments?: Attachment[];
}

/** The `password` type is a login without a username or URL; it shares the login details shape. */
export interface ItemDetailsByType {
  healthSettings: HealthSettingsDetails;
  login: LoginDetails;
  password: LoginDetails;
  secureNote: SecureNoteDetails;
  card: CardDetails;
  identity: IdentityDetails;
  document: DocumentDetails;
  wifi: WifiDetails;
  sshKey: SshKeyDetails;
  maskedEmailProvider: MaskedEmailProviderDetails;
  environment: EnvironmentDetails;
  equivalentDomains: EquivalentDomainsDetails;
  usageStats: UsageStatsDetails;
  place: PlaceDetails;
  certificate: CertificateDetails;
  key: KeyItemDetails;
  bankAccount: BankAccountDetails;
  apiCredential: ApiCredentialDetails;
  softwareLicense: SoftwareLicenseDetails;
  idDocument: IdDocumentDetails;
  cryptoWallet: CryptoWalletDetails;
  database: DatabaseDetails;
  custom: CustomDetails;
  customTemplate: CustomTemplateDetails;
}

export type ItemDetails = ItemDetailsByType[ItemType];

/** A decrypted item. Unknown fields inside `overview` and `details` must be kept when saving. */
export interface Item {
  id: string;
  vaultId: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  deletedAt?: string;
  overview: ItemOverview;
  details: ItemDetails;
}

/** What `saveItem` accepts: no id for a new item; the revision it was based on for an edit. */
export interface ItemDraft {
  id?: string;
  vaultId: string;
  revision?: number;
  overview: ItemOverview;
  details: ItemDetails;
}

/** A list row: the overview plus a few flags computed from the details, never secrets. */
export interface ItemSummary {
  id: string;
  vaultId: string;
  type: ItemType;
  title: string;
  /** For Wi-Fi networks, the network name; for SSH keys, the fingerprint. */
  subtitle?: string;
  urls?: string[];
  /** Per-website match modes (see `ItemOverview.urlMatch`), for autofill. */
  urlMatch?: Record<string, UrlMatchMode>;
  tags?: string[];
  favorite: boolean;
  /** Missing from an older native host, which means not pinned. */
  pinned?: boolean;
  /** The places it belongs to (`ItemOverview.places`). */
  places?: string[];
  /** A place's point, radius and networks (`ItemOverview.place`). */
  place?: PlaceData;
  hasTotp: boolean;
  hasPasskey: boolean;
  /** Environments: the project and stage, and the variable names (never values) for search. */
  project?: string;
  stage?: string;
  variableKeys?: string[];
  createdAt: string;
  updatedAt: string;
  deletedAt?: string;
}

/** A past version of an item, from its encrypted history. */
export interface ItemVersion {
  revision: number;
  /** When this version was saved. */
  updatedAt: string;
  overview: ItemOverview;
  details: ItemDetails;
}

/** What Settings → Equivalent domains shows. */
export interface EquivalentDomains {
  /** The user's own groups, each sorted. */
  groups: string[][];
  /** The built-in groups, for turning them off. */
  defaults: string[][];
  /** Built-in groups turned off, each named by its first domain. */
  excludedDefaults: string[];
}

export interface ItemFilter {
  vaultId?: string;
  type?: ItemType;
  query?: string;
  trash?: boolean;
  favorites?: boolean;
  pinned?: boolean;
  /** Only logins that hold at least one passkey. */
  passkeys?: boolean;
  /** Only items that hold a one-time code (`hasTotp`): logins with a code, and codes saved on their own. */
  totp?: boolean;
}

/** Each role includes the ones below it: `read` views, `write` edits items, `manage` adds and removes members, `owner` also manages owners. */
export type VaultRole = 'owner' | 'manage' | 'write' | 'read';

export type VaultType = 'personal' | 'shared' | 'family';

/**
 * What the key log says about keys the server offered: `verified` (in the log and matching),
 * `notLogged` (nothing to check, which isn't a pass), `failed` (don't seal to them) or
 * `unavailable` (the check couldn't run: offline, rate limited, or an older server).
 */
export type KeyLogCheck = 'verified' | 'notLogged' | 'failed' | 'unavailable';

/** An account's signed statement of its public keys. The UI passes it along and never reads it. */
export interface KeyRecord {
  logId: string;
  accountId: string;
  label: string;
  publicEncKey: string;
  publicSignKey: string;
  publicPqKey: string;
  createdAt: number;
  signature: string;
}

/** Why the key log wants the user's attention. */
export type KeyLogAlertKind = 'logChanged' | 'logInconsistent' | 'foreignRecord' | 'ownRecordMissing';

/** This device's view of the key log, for the settings. */
export interface KeyLogState {
  /** The account's keys, ML-KEM key included, are in the log. */
  published: boolean;
  /** When this device last read the log to the end. */
  checkedAt?: string;
  alert?: { kind: KeyLogAlertKind; at: string };
}

/** An account's public keys in a form people can compare out of band: in person, or on a call. */
export interface Fingerprint {
  /** Six groups of four digits. */
  digits: string;
  emoji: { emoji: string; name: string }[];
}

export interface VaultMember {
  name: string;
  email: string;
  role: VaultRole;
  accountId?: string;
  /** Computed on this device from the member's public keys, never taken from the server. */
  fingerprint?: Fingerprint;
  /** The user confirmed this fingerprint with the member, and the keys haven't changed since. */
  verified?: boolean;
  /** What the key log says about this member's keys, checked on this device. */
  keyLog?: KeyLogCheck;
  /** The signed-in user. */
  isYou?: boolean;
  addedAt?: string;
}

export interface Vault {
  id: string;
  name: string;
  type: VaultType;
  role: VaultRole;
  members?: VaultMember[];
  /**
   * Shared and family vaults whose grant signature didn't verify. The vault key isn't used, so the
   * vault has no items here; the UI warns instead.
   */
  untrusted?: boolean;
}

export interface ServerInfo {
  name: string;
  version: string;
  apiVersion: 1;
  signups: 'open' | 'invite' | 'closed';
  pushRelay: boolean;
  /** The server has an HIBP key, so email breach alerts can be turned on. Missing on older servers. */
  emailBreachChecks?: boolean;
}

export type SessionStatus = 'signedOut' | 'locked' | 'unlocked';

export interface SessionState {
  status: SessionStatus;
  email?: string;
  serverUrl?: string;
  /**
   * Unlocked only: the user opened this session themselves, with the master password or device
   * unlock, and it hasn't locked since. Reveal and copy don't ask again then; exports and the
   * account's settings still do (plan 03 History, 2026-11-05). Never a key, only a fact about this
   * session; a lock or another account ends it.
   */
  confirmed?: boolean;
}

/** The same session with `confirmed` set as given, and only while it's unlocked. */
export function withConfirmed(session: SessionState, confirmed: boolean): SessionState {
  const rest: SessionState = { ...session };
  delete rest.confirmed;
  return session.status === 'unlocked' && confirmed ? { ...rest, confirmed: true } : rest;
}

/** An account whose Secret Key is stored on this device, so signing in needs only the password. */
export interface RememberedAccount {
  email: string;
  serverUrl: string;
}

/** Shown once at sign-up and printed by the user. Generated on the device, never on the server. */
/** A kit from a change that may keep the recovery code: without one, the old kit's code still works. */
export type NewRecoveryKit = Omit<RecoveryKit, 'recoveryCode'> & { recoveryCode?: string };

export interface RecoveryKit {
  email: string;
  serverUrl: string;
  secretKey: string;
  recoveryCode: string;
  createdAt: string;
}

export type GeneratorOptions =
  | {
      kind: 'password';
      length: number;
      uppercase: boolean;
      lowercase: boolean;
      digits: boolean;
      symbols: boolean;
      /** Leave out look-alike characters such as 0/O and 1/l/I. */
      avoidAmbiguous: boolean;
    }
  | {
      kind: 'passphrase';
      words: number;
      separator: string;
      capitalize: boolean;
      includeNumber: boolean;
    };

/** A code the UI turns into a translated hint, so the estimator stays language-neutral. */
export type StrengthFeedback =
  | 'tooShort'
  | 'commonPassword'
  | 'dictionaryWord'
  | 'sequence'
  | 'repeat'
  | 'keyboardPattern'
  | 'date'
  | 'addMoreWords'
  | 'addVariety';

export interface StrengthEstimate {
  score: 0 | 1 | 2 | 3 | 4;
  guessesLog10: number;
  feedback?: StrengthFeedback;
}

/** A counter-based code. Each one is made once, when the user asks. */
export interface HotpCode {
  code: string;
  /** The counter it was made from. The item's counter has already moved past it. */
  counter: number;
}

export interface TotpCode {
  code: string;
  period: number;
  remaining: number;
}

export interface HealthEntry {
  itemId: string;
  vaultId: string;
  title: string;
  subtitle?: string;
  /** Identifies this warning for `HealthSettings.dismiss`. Lists that aren't warnings leave it out. */
  warning?: string;
  /** The site's `/.well-known/change-password`, on warnings a new password fixes. */
  changePasswordUrl?: string;
}

/** What the dashboard checks. A dismissed warning keeps its check, so the list of them can name it. */
export type HealthCheck =
  | 'weak'
  | 'reused'
  | 'breached'
  | 'old'
  | 'missing2fa'
  | 'passkeyAvailable'
  | 'insecureUrl'
  | 'expiring'
  | 'backupCodes'
  | 'recoveryNo2fa'
  | 'recoveryBreached'
  | 'emailBreach';

/** One breach, as Have I Been Pwned lists it. Never the breach's HTML description. */
export interface EmailBreach {
  /** HIBP's stable name for the breach. */
  name: string;
  title: string;
  domain?: string;
  /** `YYYY-MM-DD`. */
  breachDate?: string;
  /** What leaked, in HIBP's English: `Email addresses`, `Passwords`. */
  dataClasses: string[];
}

export interface EmailBreachResult {
  address: string;
  breaches: EmailBreach[];
}

/** An account email or alias found in a breach. */
export interface EmailBreachFinding extends EmailBreach {
  address: string;
  warning: string;
  /** Appeared since the check before the last one. */
  isNew: boolean;
}

export interface HealthReport {
  /** 0–100. */
  score: number;
  /** Logins that have a password. */
  checked: number;
  weak: (HealthEntry & { score: StrengthEstimate['score'] })[];
  /** Each group shares one password. */
  reused: HealthEntry[][];
  breached: (HealthEntry & { count: number })[];
  /** False when the breach check could not reach the range API; `breached` is then empty. */
  breachCheckCompleted: boolean;
  /** Logins for sites known to support two-factor sign-in that have no one-time code or passkey saved. */
  missing2fa: HealthEntry[];
  /** The recovery map: each email and phone that can reset logins, the most used first. */
  recovery: RecoveryContact[];
  /**
   * Recovery emails whose own login is in the vault without two-step sign-in. Whoever gets into
   * that inbox can reset every login in `accounts`.
   */
  recoveryNo2fa: (HealthEntry & { email: string; accounts: number })[];
  /**
   * Recovery emails found in a breach by email breach alerts. Whoever gets into that inbox can reset
   * every login in `accounts`. The entry is the inbox's own login when the vault has it, else it has
   * no item and the address as its title. Not part of the score.
   */
  recoveryBreached: (HealthEntry & { email: string; accounts: number; breaches: string[] })[];
  /** Passwords not changed for a year, the oldest first. Not part of the score. */
  old: (HealthEntry & { changedAt: string; ageDays: number })[];
  /** Logins for sites that accept passkeys, without one saved. Not part of the score. */
  passkeyAvailable: HealthEntry[];
  /** Logins with an `http://` website, other than this device or the local network. */
  insecureUrls: (HealthEntry & { url: string })[];
  /** Cards, IDs, passports, software licences and API credentials that expired or expire within 60 days, the soonest first. Not part of the score. */
  expiring: (HealthEntry & { expiresOn: string; daysLeft: number })[];
  /** Logins with saved backup codes and two or fewer unused. Not part of the score. */
  lowBackupCodes: (HealthEntry & { unused: number })[];
  /** Opt-in. Empty when off, and not part of the score. */
  /** `recoveryEmails`: the second opt-in, which also sends recovery emails that are neither the account email nor an alias. */
  emailBreaches: { enabled: boolean; recoveryEmails: boolean; checkedAt?: string; found: EmailBreachFinding[] };
  /** Warnings the user dismissed: left out of the lists above and of the score. */
  dismissed: (HealthEntry & { warning: string; check: HealthCheck })[];
  generatedAt: string;
}

/**
 * An email or phone that can reset other logins: their recovery email or phone, or (for an email)
 * the email they sign in with, since sites send password resets there.
 */
export interface RecoveryContact {
  kind: 'email' | 'phone';
  /** As the first login that uses it wrote it. */
  value: string;
  /** Logins that can be reset through it. Never empty. */
  logins: HealthEntry[];
  /** An email's own login (its mail provider's account), when the vault has it. */
  account?: HealthEntry & { twoStep: boolean };
  /** A login links it to a masked email alias from this provider. */
  aliasProvider?: MaskedEmailProviderId;
  /** The provider's id for that alias. */
  aliasId?: string;
  /** A login links it to this Identity item. */
  identityId?: string;
}

export interface AccountSummary {
  email: string;
  itemCount: number;
  vaultCount: number;
  deviceCount: number;
  /** Names of shared vaults this user alone owns: deleting the account deletes them for every member. */
  sharedVaultsOwned: string[];
}

export type DevicePlatform = 'mac' | 'windows' | 'ios' | 'android' | 'other';

export interface UnlockMethods {
  /** This browser has a platform authenticator that can do PRF (as far as it can tell before trying). */
  deviceUnlockSupported: boolean;
  deviceUnlockEnabled: boolean;
  /** English name of the device's lock, e.g. "Touch ID". The UI translates by `platform`. */
  label: string;
  platform: DevicePlatform;
  /** Device unlock is set up but the 14-day master password check is due. */
  passwordRequired: boolean;
}

/** Plan 18's switch on this device, as Settings shows it. */
export interface StayUnlockedStatus {
  /** `null` until this device has decided: the app's migration decides from its lock settings. */
  on: boolean | null;
  /** This device can stay unlocked: it has a system key store (desktop) or a passcode (phones). */
  available: boolean;
  /** Why not, when not. */
  unavailable?: 'noKeyring' | 'noPasscode' | 'noScreenLock';
  /** The current account's key is on this device: opening needs no prompt. */
  enrolled: boolean;
  /** The 14-day master password check is due: the master password opens the vault once first. */
  passwordRequired: boolean;
  /** The browser extension: it opens through the desktop app when that stays unlocked, otherwise it keeps the vault in memory until the browser closes. */
  browser?: boolean;
}

/** Stay unlocked is in force: on, and this device holds the key (or, in the extension, the switch alone). */
export function staysUnlocked(status: StayUnlockedStatus | undefined): boolean {
  return status?.on === true && status.available && (status.enrolled || status.browser === true);
}

/** Every source the core can import (crates/octapass-core `import`). */
export type ImportSource =
  | 'chrome'
  | 'firefox'
  | 'safari'
  | 'bitwarden-json'
  | 'bitwarden-csv'
  | 'onepassword-1pux'
  | 'onepassword-csv'
  | 'lastpass-csv'
  | 'generic-csv'
  | 'otpauth'
  | 'octapass'
  | 'cxf'
  | 'protonpass'
  | 'dashlane'
  | 'keeper'
  | 'nordpass'
  | 'keepass'
  | 'enpass'
  | 'roboform'
  | 'aegis'
  | '2fas'
  | 'andotp'
  | 'ente-auth'
  | 'raivo'
  | 'zoho-vault'
  | 'avira'
  | 'norton'
  | 'mcafee'
  | 'kaspersky';

export interface ImportOptions {
  /** The file's password: Octa Pass encrypted exports, Bitwarden, KeePass, Proton Pass, authenticator backups. */
  password?: string;
  /** KeePass: the key file, if the database uses one. */
  keyFile?: Blob;
}

export interface ImportResult {
  /** New items, and one-time codes added to logins. */
  imported: number;
  /** Items already in the vault that the file changed (matched by the other app's id, or as duplicates). */
  updated?: number;
  /** Items already in the vault exactly as the file has them. */
  unchanged?: number;
  skipped: number;
  warnings: string[];
  /** Attached files restored (Octa Pass encrypted exports). */
  files?: number;
}

/** Authenticator imports, whose one-time codes the user can link to other logins before saving. */
export const REVIEWED_IMPORTS: readonly ImportSource[] = ['otpauth', 'aegis', '2fas', 'andotp', 'ente-auth', 'raivo'];

/** An authenticator import parsed and waiting for the review. Nothing is saved yet. */
export interface ImportReview {
  /** For `finishImport` and `cancelImport`. */
  id: string;
  codes: ReviewCode[];
  /** New items that aren't one-time codes (counter-based codes kept as fields, notes). */
  otherItems: number;
  skipped: number;
  warnings: string[];
}

/** A one-time code in the import review. Never holds the secret. */
export interface ReviewCode {
  /** For `CodeLink.code`. */
  index: number;
  title: string;
  issuer?: string;
  account?: string;
  /** The login the import matched it to; without one it becomes a login of its own. */
  loginId?: string;
}

/** The review's choice for a code: add it to `loginId`, or keep it as a login of its own. */
export interface CodeLink {
  code: number;
  loginId?: string;
}

/** What scanned QR codes hold (crates/octapass-core `tools::qr`). */
export interface QrScan {
  /** Each one-time code once, Google Authenticator exports expanded. `uri` holds the secret. */
  codes: { uri: string; issuer?: string; account?: string; counterBased: boolean }[];
  /** Google Authenticator exports split over several QR codes that still miss some; `scanned` counts from 1. */
  incomplete: { id: number; size: number; scanned: number[] }[];
  /** QR codes that aren't one-time codes. */
  other: number;
  /** QR codes that look like one-time codes but can't be read. */
  broken: number;
}

/**
 * `json` and `csv` are plaintext; `cxf` is the FIDO Credential Exchange Format (plaintext JSON);
 * `encrypted` is everything, attachments included, under a password chosen for the export.
 */
export type ExportFormat = 'json' | 'csv' | 'cxf' | 'encrypted';

export interface ExportOptions {
  /** The password for an `encrypted` export. */
  password?: string;
  /** Checked before exporting when given: exports ask for the master password again (plan 07). */
  masterPassword?: string;
}

/** A signed-in device, from the server's list. */
export interface Device {
  id: string;
  name: string;
  /** What the client said it is: `web`, `extension`, `ios`, `android`, `mac`, … */
  platform: string;
  createdAt: string;
  lastSeenAt: string;
  /** The device this service runs on. */
  current: boolean;
}

/** Someone found by email, to share with. The fingerprint is computed here from the public keys. */
export interface AccountLookup {
  accountId: string;
  email: string;
  publicEncKey: string;
  publicSignKey: string;
  fingerprint: Fingerprint;
  /** The account's signed key record, which carries its ML-KEM key. Opaque to the UI. */
  keyRecord?: KeyRecord;
  /** What the key log says about these keys. `failed` keeps them from being shared with. */
  keyLog?: KeyLogCheck;
}

export interface FamilyMember {
  accountId: string;
  email: string;
  role: 'organiser' | 'member';
  joinedAt: string;
  isYou: boolean;
}

export interface FamilyInvite {
  familyId: string;
  accountId: string;
  email: string;
  organiserEmail: string;
  invitedAt: string;
}

export interface Family {
  id: string;
  vaultId: string;
  organiserId: string;
  /** The signed-in user organises it. */
  isOrganiser: boolean;
  /** Members plus pending invites can't go over this. */
  maxMembers: number;
  members: FamilyMember[];
  /** Pending invites; only the organiser sees them. */
  invites: FamilyInvite[];
  createdAt: string;
}

export interface FamilyState {
  family?: Family;
  /** Invitations this account received. */
  invitations: FamilyInvite[];
}

export interface ShareLinkOptions {
  /** 1 to 720 (30 days). */
  expiresInHours: number;
  /** 1 to 100. */
  maxViews: number;
  /** Also needed to open the link; send it separately. */
  passphrase?: string;
}

/** A new share link. `key` belongs only in the link's `#` fragment, which browsers never send. */
export interface CreatedShareLink {
  id: string;
  key: string;
  expiresAt: string;
  /** The address to send, from hosts whose pages aren't on the web vault's origin (the apps). */
  url?: string;
}

export interface ShareLinkInfo {
  id: string;
  /** The item it was made from, while it still exists in this vault. */
  itemId?: string;
  itemTitle?: string;
  expiresAt: string;
  maxViews: number;
  views: number;
  passphraseRequired: boolean;
  createdAt: string;
}

/** What `GET /v1/share-links/{id}` returned. Fetching it used up one view. */
export interface ShareLinkEnvelope {
  ciphertext: string;
  passphraseRequired: boolean;
  expiresAt: string;
  viewsLeft: number;
}

/** A shared item, decrypted on the viewer's device. */
export interface SharedItem {
  overview: ItemOverview;
  details: ItemDetails;
}

export type EmergencyScope = { type: 'account' } | { type: 'vault'; vaultId: string };
export type EmergencyAccessLevel = 'view' | 'takeover';
export type EmergencyStatus = 'idle' | 'requested' | 'released';

export interface EmergencyContact {
  id: string;
  grantorId: string;
  grantorEmail: string;
  contactId: string;
  contactEmail: string;
  scope: EmergencyScope;
  accessLevel: EmergencyAccessLevel;
  /** 1 to 30. */
  waitDays: number;
  status: EmergencyStatus;
  requestedAt?: string;
  /** When a pending request releases the key unless the grantor denies it. */
  releasesAt?: string;
  releasedAt?: string;
  createdAt: string;
  /** A vault scope: the vault's key was rotated, and the contact's copy opens nothing new until the grantor renews it. */
  keyStale?: boolean;
  /** The family's organiser holds this: they can reset the account, and can't read it. */
  organiserRecovery?: boolean;
}

export interface EmergencyContacts {
  /** Contacts the user chose. */
  granted: EmergencyContact[];
  /** People who chose the user as their contact. */
  received: EmergencyContact[];
}

/** A grantor's vaults, opened read-only by their emergency contact after release. */
export interface EmergencyVaultView {
  contact: EmergencyContact;
  vaults: Vault[];
  items: Item[];
}

export type SecurityEventType =
  | 'emergency-contact-added'
  | 'emergency-contact-removed'
  | 'emergency-access-requested'
  | 'emergency-access-denied'
  | 'emergency-access-approved'
  | 'emergency-access-released'
  | 'two-step-enabled'
  | 'two-step-disabled'
  | 'authenticator-changed'
  | 'security-key-added'
  | 'security-key-removed'
  | 'recovery-codes-renewed'
  | 'recovery-code-used'
  | 'two-step-locked'
  | 'trusted-devices-forgotten'
  | 'password-changed'
  | 'password-reset'
  | 'vault-exported'
  | 'secret-key-rotated'
  | 'vault-key-rotated'
  | 'emergency-takeover'
  | 'organiser-recovery-enabled'
  | 'organiser-recovery-disabled'
  | 'service-account-created'
  | 'service-account-revoked'
  | 'service-account-read'
  | 'service-account-wrote'
  | 'service-account-denied'
  | 'connect-secret-read';

/** A program a person approved to ask Octa Pass Connect for secrets. */
export interface ConnectClient {
  id: string;
  /** What it calls itself: only a claim. */
  name: string;
  /** The program that was approved, when the system could tell. */
  program?: string;
  /** Unix seconds. */
  approvedAt: number;
  expiresAt: number;
  lastUsedAt?: number;
}

/** Turns the local helper on and off on this device, and manages who it talks to. */
export interface ConnectService {
  getState(): Promise<{ enabled: boolean; clients: ConnectClient[] }>;
  setEnabled(enabled: boolean): Promise<void>;
  revokeClient(id: string): Promise<void>;
}

/** A `connect-secret-read` entry, opened on this device: the server only holds a sealed blob. */
export interface ConnectEventDetail {
  /** Unix seconds, on the device that handed it out. */
  at: number;
  clientId: string;
  clientName: string;
  reference: string;
}

/**
 * Non-human access to one shared vault (plan 03). The token is shown once, when it's made, and
 * reaches neither the server nor this record.
 */
export interface ServiceAccount {
  id: string;
  vaultId: string;
  /** Only its creator can open the name. */
  name?: string;
  role: 'read' | 'write';
  createdAt: string;
  expiresAt?: string;
  lastUsedAt?: string;
  revokedAt?: string;
  /** Someone other than its creator rotated the vault's key: the token needs replacing. */
  needsNewToken: boolean;
}

export interface SecurityEvent {
  type: SecurityEventType;
  createdAt: string;
  otherAccountEmail?: string;
  emergencyContactId?: string;
  /** `vault-exported`: the device as it was named when it exported, even after it signed out. */
  deviceName?: string;
  devicePlatform?: string;
  exportFormat?: ExportFormat;
  /** Whether the file held the attachments (only the encrypted export does). */
  exportAttachments?: boolean;
  /** The `service-account-*` entries: which one. */
  serviceAccountId?: string;
  /** `connect-secret-read`, when this device could open it. */
  connect?: ConnectEventDetail;
}

/**
 * Everything that needs an account on a sync server: devices, shared vaults, families, share links,
 * emergency access and the security log (plan 15). Unlocked only, except the share-link viewer.
 */
export interface SharingService {
  // Devices
  listDevices(): Promise<Device[]>;
  /** Renames the device this service runs on. */
  renameDevice(name: string): Promise<void>;
  /** Signs another device out remotely. Signing out this one is `signOut`. */
  signOutDevice(deviceId: string): Promise<void>;

  // Identity
  /** The signed-in account's own fingerprint, to read out to people sharing with it. */
  getMyFingerprint(): Promise<Fingerprint>;
  /** Throws `notFound` when the email has no account. */
  lookupAccount(email: string): Promise<AccountLookup>;
  /** Remembers that the user compared this account's fingerprint with its owner. */
  markVerified(account: Pick<AccountLookup, 'accountId' | 'fingerprint'>): Promise<void>;
  /** This device's view of the key log. */
  getKeyLogState(): Promise<KeyLogState>;
  /** Clears the alert and the pins behind it, trusting the log as it is now. */
  dismissKeyLogAlert(): Promise<void>;

  // Shared vaults
  createVault(name: string): Promise<Vault>;
  renameVault(vaultId: string, name: string): Promise<void>;
  /** The vault's members, with fingerprints computed on this device. */
  listMembers(vaultId: string): Promise<VaultMember[]>;
  /** Invites `account` (from `lookupAccount`, after the user compared its fingerprint). */
  addMember(vaultId: string, account: AccountLookup, role: VaultRole): Promise<void>;
  changeRole(vaultId: string, accountId: string, role: VaultRole): Promise<void>;
  /** Removes the member, then gives the vault a new key so what they kept stops working. */
  removeMember(vaultId: string, accountId: string): Promise<void>;
  leaveVault(vaultId: string): Promise<void>;
  /** Managers of shared vaults: every service account, revoked ones too. */
  listServiceAccounts(vaultId: string): Promise<ServiceAccount[]>;
  /** Makes one on this device. `token` is shown once and is kept nowhere. */
  createServiceAccount(vaultId: string, input: { name: string; role: 'read' | 'write'; expiresAt?: string }): Promise<{ account: ServiceAccount; token: string }>;
  /** Ends it now, then gives the vault a new key. */
  revokeServiceAccount(vaultId: string, id: string): Promise<void>;
  /** Moves an item to another vault: a copy there, the original to the trash. */
  moveItem(itemId: string, toVaultId: string): Promise<Item>;
  copyItem(itemId: string, toVaultId: string): Promise<Item>;

  // Families
  getFamily(): Promise<FamilyState>;
  /** Creates a family and its shared Family vault, organised by the user. */
  createFamily(): Promise<void>;
  inviteToFamily(account: AccountLookup): Promise<void>;
  acceptFamilyInvite(familyId: string): Promise<void>;
  declineFamilyInvite(familyId: string): Promise<void>;
  /** Organiser: cancels a pending invite. */
  cancelFamilyInvite(accountId: string): Promise<void>;
  /** Organiser: removes a member, then rotates the Family vault key. */
  removeFamilyMember(accountId: string): Promise<void>;
  leaveFamily(): Promise<void>;
  /** Organiser: deletes the family and its Family vault for everyone. */
  deleteFamily(): Promise<void>;
  /**
   * A new key for a vault this account owns or manages, on demand: every item key is re-wrapped
   * under it. Vault-scoped emergency contacts then need `renewEmergencyKey`.
   */
  rotateVaultKey(vaultId: string): Promise<void>;

  // Share links
  createShareLink(itemId: string, options: ShareLinkOptions): Promise<CreatedShareLink>;
  listShareLinks(): Promise<ShareLinkInfo[]>;
  revokeShareLink(id: string): Promise<void>;
  /** Works signed out. Counts a view; throws `notFound` once a link is used up, expired or revoked. */
  fetchShareLink(serverUrl: string, id: string): Promise<ShareLinkEnvelope>;
  /** Decrypts on this device. Throws `wrongPassphrase` or `invalidShareLink`. */
  openShareLink(ciphertext: string, key: string, passphrase?: string): Promise<SharedItem>;

  // Emergency access
  listEmergencyContacts(): Promise<EmergencyContacts>;
  addEmergencyContact(input: { account: AccountLookup; waitDays: number; accessLevel: EmergencyAccessLevel; scope: EmergencyScope }): Promise<EmergencyContact>;
  /** Either side: removes a contact, or steps down as one. */
  removeEmergencyContact(id: string): Promise<void>;
  requestEmergencyAccess(id: string): Promise<void>;
  denyEmergencyAccess(id: string): Promise<void>;
  approveEmergencyAccess(id: string): Promise<void>;
  /** As the contact, once released: the grantor's vaults in scope, read-only. */
  openEmergencyAccess(id: string): Promise<EmergencyVaultView>;
  /** As the contact, once released: downloads and decrypts a file of an item `openEmergencyAccess` showed. */
  getEmergencyAttachment(id: string, itemId: string, attachmentId: string): Promise<Blob>;
  /**
   * As the grantor, after a rotation: seals the vault's current key to the contact again. Pass the
   * looked-up account, whose fingerprint the user saw: it's never renewed by itself (plan 03 History).
   */
  renewEmergencyKey(id: string, account: AccountLookup): Promise<void>;
  /**
   * As the contact of a released takeover record (plan 06): sets a new master password, Secret Key
   * and recovery code for the grantor, who is signed out everywhere. `contactPassword` is the
   * user's own master password. The kit returned is the only copy: show it before anything else.
   */
  takeOverAccount(id: string, input: { contactPassword: string; newPassword: string }): Promise<NewRecoveryKit>;
  /** As a family member: lets the organiser help recover this account (opt-in, plan 06). */
  enableOrganiserRecovery(input: { account: AccountLookup; waitDays: number }): Promise<EmergencyContact>;

  // Security log
  getSecurityLog(): Promise<SecurityEvent[]>;

  /** Called when members, families, invitations, links or emergency contacts change, here or elsewhere. */
  onSharingChange(cb: () => void): () => void;
}

/** What the vaults the account owns hold on its server, and the server's limits. */
export interface StorageUsage {
  /** Stored (encrypted) bytes of attachments, trash included. */
  attachmentBytes: number;
  maxAttachmentBytes: number;
  /** The largest file the server takes, as stored: encryption adds 52 bytes plus 16 per 64 KiB. */
  maxFileBytes: number;
}

/**
 * Encrypted files on items (any type; a `document` item is one file plus notes). Files are
 * encrypted and decrypted on this device; the server stores ciphertext only. Needs a sync server
 * account, so hosts without one leave it out.
 */
export interface AttachmentService {
  /**
   * Encrypts the file, uploads it and lists it in the item's details. Returns the updated item.
   * Throws `fileTooLarge` or `quotaExceeded` before uploading when it can tell.
   */
  addAttachment(itemId: string, file: Blob, name: string): Promise<Item>;
  /** Downloads and decrypts the file. Its `type` is the attachment's media type. */
  getAttachment(itemId: string, attachmentId: string): Promise<Blob>;
  /** Takes the file off the item and deletes it from the server. Returns the updated item. */
  removeAttachment(itemId: string, attachmentId: string): Promise<Item>;
  getStorageUsage(): Promise<StorageUsage>;
  /** Hosts whose files never pass through the web page (the phone apps): their own pickers and viewer. */
  readonly native?: NativeFiles;
}

/** Where a phone app's pickers take a file from. */
export type FileSource = 'files' | 'photos' | 'camera';

/** A file the phone's picker copied into the app's private storage. The page only gets this description. */
export interface PickedFile {
  id: string;
  name: string;
  /** Media type; empty when unknown. */
  type: string;
  size: number;
}

/**
 * The phone apps' file handling: the system pickers, and the system viewer (Quick Look, or the app
 * the user picks on Android), which can also share the file. Files are encrypted and decrypted by
 * the app itself, so their contents never reach the page.
 */
export interface NativeFiles {
  /** Where files can be picked from on this phone; the camera only where there is one. */
  readonly sources: FileSource[];
  /** Opens the system picker. Empty when the user cancels. Throws `cameraUnavailable` without camera access. */
  pick(source: FileSource): Promise<PickedFile[]>;
  /** Encrypts and attaches a picked file, then deletes the picked copy. Offline, it waits to upload. */
  attachPicked(itemId: string, file: PickedFile): Promise<Item>;
  /** Deletes picked files that won't be attached. */
  discardPicked(files: PickedFile[]): Promise<void>;
  /**
   * Decrypts the file into the app's private storage and shows it in the system viewer; resolves once
   * the viewer is closed and the decrypted copy is deleted. Throws `noFileViewer` when nothing opens it.
   */
  open(itemId: string, attachmentId: string): Promise<void>;
}

export type OrgRole = 'owner' | 'admin' | 'member';

/** An organisation's rules. A policy restricts; it never moves a key (plan 03). */
export interface OrgPolicies {
  /** Server: organisation vaults are withheld until two-step sign-in is on. */
  requireTwoStep: boolean;
  /** Server: members sign in through the identity provider after their master password. */
  requireSso: boolean;
  /** 0 checks only at sign-in. */
  ssoMaxAgeHours: number;
  /** Server: no share links. */
  disableShareLinks: boolean;
  /** Server: no new emergency contacts; existing ones don't reach organisation vaults. */
  disableEmergencyAccess: boolean;
  /** Apps: exports leave out organisation vaults. A modified client can ignore it. */
  disableExport: boolean;
  /** Apps: the longest auto-lock a member may choose. */
  maxAutoLockMinutes?: number;
  /** Apps: the shortest new master password. The server never sees the password. */
  minPasswordLength?: number;
}

export interface Organisation {
  id: string;
  name: string;
  role: OrgRole;
  policies: OrgPolicies;
  memberCount: number;
  /** This member breaks a policy, so organisation vaults are withheld. */
  accessWithheld: boolean;
  createdAt: string;
}

export interface OrgInvitation {
  id: string;
  orgId: string;
  orgName: string;
  role: OrgRole;
  invitedBy?: string;
  /** What joining agrees to. */
  policies: OrgPolicies;
  invitedAt: string;
  expiresAt: string;
}

export interface OrganisationState {
  organisation?: Organisation;
  invitations: OrgInvitation[];
}

export interface OrgMember {
  accountId: string;
  email: string;
  role: OrgRole;
  twoStep: boolean;
  ssoLinked: boolean;
  joinedAt: string;
  isYou: boolean;
}

export interface OrgInvite {
  id: string;
  email: string;
  role: OrgRole;
  invitedAt: string;
  expiresAt: string;
}

export interface OrgMembers {
  members: OrgMember[];
  invites: OrgInvite[];
}

export interface OrgGroup {
  id: string;
  name: string;
  /** Account ids. */
  members: string[];
  createdAt: string;
}

export interface OrgVault {
  id: string;
  /** Only if this account can open the vault: names are encrypted inside it. */
  name?: string;
  shortId: string;
  groups: { groupId: string; role: VaultRole }[];
  memberCount: number;
  /** At 0 nobody can grant access or rotate the key, and it can only be deleted. */
  managerCount: number;
  role?: VaultRole;
  rotationPending: boolean;
  createdAt: string;
}

/** Someone a vault's key would be sealed to, with a fingerprint computed on this device. */
export interface OrgAccessGrant {
  accountId: string;
  email: string;
  role: VaultRole;
  /** Replaces a grant with a lower role. */
  upgrade: boolean;
  fingerprint: Fingerprint;
  /** The fingerprint matches one verified on this device. */
  verified: boolean;
  /** The fingerprint differs from one verified on this device: applying refuses it. */
  keyChanged: boolean;
}

/** What a vault waits for from a key holder. */
export interface OrgAccessReview {
  vaultId: string;
  /** Only if this account can open the vault. */
  vaultName?: string;
  shortId: string;
  /** This account holds the key and may manage the vault. */
  canApply: boolean;
  /** Someone lost access: the key should be rotated. */
  rotate: boolean;
  grants: OrgAccessGrant[];
}

export interface OrgSsoSettings {
  /** Which protocol the saved settings use; absent when there are none. */
  protocol?: 'oidc' | 'saml';
  /** OpenID Connect. */
  issuer?: string;
  clientId?: string;
  hasClientSecret: boolean;
  /** SAML 2.0: the identity provider as saved. */
  saml?: OrgSamlIdp;
  /** When a test sign-in last finished with these settings. Requiring SSO needs one. */
  testedAt?: string;
  /** The OpenID Connect redirect URI to register at the identity provider. */
  callbackUrl: string;
  /** What to register at a SAML identity provider, whatever is saved now. */
  samlServiceProvider: { entityId: string; acsUrl: string; metadataUrl: string };
}

export interface OrgSamlIdp {
  entityId: string;
  ssoUrl: string;
  /** Signing certificates: SHA-256 fingerprints as identity providers show them. */
  certificates: { sha256: string; notAfter?: string }[];
}

/** SAML settings: the provider's metadata XML, or its entity id, SSO URL and certificates (PEM). */
export interface OrgSamlInput {
  metadataXml?: string;
  entityId?: string;
  ssoUrl?: string;
  certificates?: string[];
}

/** A SCIM bearer token, without its secret. */
export interface OrgScimToken {
  id: string;
  name: string;
  createdBy?: string;
  createdAt: string;
  lastUsedAt?: string;
}

export interface OrgScim {
  /** The SCIM 2.0 base URL to give the identity provider. */
  baseUrl: string;
  tokens: OrgScimToken[];
}

export interface OrgEvent {
  id: string;
  /** A stable kebab-case name, for example `member-removed`. */
  type: string;
  actor?: string;
  subject?: string;
  createdAt: string;
}

/**
 * Organisations, groups, policies and SSO settings (plan 03). Admin calls throw `notAllowed` for
 * members. Nothing here reaches a key without a person confirming it on a key holder's device.
 */
export interface OrganisationService {
  getOrganisation(): Promise<OrganisationState>;
  createOrganisation(name: string): Promise<void>;
  renameOrganisation(name: string): Promise<void>;
  /** Deletes its vaults too. Asks for the master password. */
  deleteOrganisation(input: { password: string; confirmName: string }): Promise<void>;
  acceptOrgInvite(orgId: string, inviteId: string): Promise<void>;
  declineOrgInvite(orgId: string, inviteId: string): Promise<void>;

  listOrgMembers(): Promise<OrgMembers>;
  inviteOrgMember(email: string, role: OrgRole): Promise<void>;
  cancelOrgInvite(inviteId: string): Promise<void>;
  setOrgMemberRole(accountId: string, role: OrgRole): Promise<void>;
  /** Throws `orgVaultOrphaned` unless `orphanVaults` says to go ahead. */
  removeOrgMember(accountId: string, options?: { orphanVaults?: boolean }): Promise<void>;
  leaveOrganisation(options?: { orphanVaults?: boolean }): Promise<void>;

  listOrgGroups(): Promise<OrgGroup[]>;
  createOrgGroup(name: string): Promise<OrgGroup>;
  renameOrgGroup(groupId: string, name: string): Promise<void>;
  deleteOrgGroup(groupId: string): Promise<void>;
  addOrgGroupMember(groupId: string, accountId: string): Promise<void>;
  removeOrgGroupMember(groupId: string, accountId: string): Promise<void>;

  listOrgVaults(): Promise<OrgVault[]>;
  createOrgVault(name: string): Promise<void>;
  /** Needs no key: it's how an organisation clears a vault nobody can open. Asks for the master password. */
  deleteOrgVault(input: { password: string; vaultId: string }): Promise<void>;
  linkOrgVaultGroup(vaultId: string, groupId: string, role: VaultRole): Promise<void>;
  unlinkOrgVaultGroup(vaultId: string, groupId: string): Promise<void>;

  /** What vaults wait for from a key holder, for a person to review. */
  getOrgAccess(): Promise<OrgAccessReview[]>;
  /** Seals the vault to exactly these reviewed people. Keys that changed since throw `untrustedVault`. */
  applyOrgAccess(vaultId: string, confirmed: Pick<OrgAccessGrant, 'accountId' | 'fingerprint'>[]): Promise<void>;
  rotateOrgVault(vaultId: string): Promise<void>;

  setOrgPolicies(policies: OrgPolicies): Promise<void>;
  getOrgSso(): Promise<OrgSsoSettings>;
  saveOrgSso(input: { issuer: string; clientId: string; clientSecret?: string }): Promise<OrgSsoSettings>;
  /** SAML 2.0 instead of OpenID Connect. The server never fetches anything for it. */
  saveOrgSaml(input: OrgSamlInput): Promise<OrgSsoSettings>;
  removeOrgSso(): Promise<void>;
  /** The URL of a test sign-in, to open in a browser. */
  testOrgSso(): Promise<string>;
  listOrgEvents(): Promise<OrgEvent[]>;
  /** SCIM provisioning (owners): the base URL and the tokens, never their secrets. */
  getOrgScim(): Promise<OrgScim>;
  /** A new token. Its secret is in this answer only. */
  createOrgScimToken(name: string): Promise<{ token: OrgScimToken; secret: string }>;
  revokeOrgScimToken(tokenId: string): Promise<void>;
}

/** A way to finish two-step sign-in on a new device. */
export type TwoStepMethod = 'totp' | 'securityKey' | 'recoveryCode';

/**
 * What `signIn` ended with. `twoStepRequired`: the password and Secret Key were right, and the account
 * asks new devices for a second step. `methods` lists only what this app can do (security keys only
 * where WebAuthn works for the server's relying party). Finish with `finishTwoStep`.
 */
export type SignInResult =
  | { status: 'signedIn' }
  | { status: 'twoStepRequired'; methods: TwoStepMethod[] }
  /**
   * The password and Secret Key were right, and the account's organisation requires single sign-on.
   * Open `url` in a browser; the last page there shows a code, which `finishSso` takes. SSO only
   * decides whether this sign-in may go on: the master password still unlocks the vault.
   */
  | SsoRequired;

export interface SsoRequired {
  status: 'ssoRequired';
  url: string;
  orgName: string;
}

/**
 * A sign-in waiting for its second step, as `pendingTwoStep` finds it. `twoStepExpired`: it was lost
 * (too slow, or the app restarted), so sign in again.
 */
export type PendingTwoStep = { status: 'twoStepRequired'; methods: TwoStepMethod[] } | SsoRequired | { status: 'twoStepExpired' };

export type TwoStepProof = { method: 'totp'; code: string } | { method: 'recoveryCode'; code: string } | { method: 'securityKey' };

export interface SecurityKeyInfo {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt?: string;
}

export interface TwoStepStatus {
  enabled: boolean;
  securityKeys: SecurityKeyInfo[];
  recoveryCodesLeft: number;
  /** Whether this app can register and use security keys for this server. */
  securityKeysSupported: boolean;
}

export interface TotpSetup {
  /** Base32, to type into an authenticator app. */
  secret: string;
  /** `otpauth://totp/…`, for the QR code. */
  otpauthUri: string;
}

/**
 * Two-step sign-in settings (plan 03, "Account 2FA"). Unlocked only. Every change asks for the master
 * password, which re-authenticates with the server first.
 */
export interface TwoStepService {
  getTwoStepStatus(): Promise<TwoStepStatus>;
  /** Starts adding an authenticator app (or replacing it). Nothing changes until `confirmTotpSetup`. */
  startTotpSetup(password: string): Promise<TotpSetup>;
  /**
   * Checks a code from the new authenticator and turns two-step sign-in on (or swaps the authenticator).
   * `recoveryCodes` comes back only when it was off before: show them once. Wrong code: `invalidTwoStepCode`.
   */
  confirmTotpSetup(code: string): Promise<{ recoveryCodes?: string[] }>;
  /** Registers a security key or passkey. Two-step sign-in must already be on. */
  addSecurityKey(input: { password: string; name: string }): Promise<SecurityKeyInfo>;
  removeSecurityKey(input: { id: string; password: string }): Promise<void>;
  /** Replaces every recovery code. Show the new ones once. */
  renewRecoveryCodes(password: string): Promise<string[]>;
  /** Turns two-step sign-in off: the authenticator, security keys and recovery codes are removed. */
  disableTwoStep(password: string): Promise<void>;
  /**
   * Every other device asks for the second step at its next sign-in. Their sessions stay: sign
   * devices out from the device list. Missing where the host can't do it yet.
   */
  forgetTrustedDevices?(): Promise<void>;
}

/** What `finishPasswordReset` ended with. */
export interface PasswordResetResult {
  recoveryKit: RecoveryKit;
  signIn?: SignInResult;
}

/** One vault on this device only (plan 01, Local mode). */
export interface LocalVaultInfo {
  id: string;
  name: string;
  createdAt: string;
  lastBackupAt?: string;
  /** 30 days since the last backup, or since creating it with none, and no folder keeping up: remind the user. */
  backupDue: boolean;
  /** Where automatic backups go. Missing: they're off. */
  backupFolder?: string;
  /** Bound to this device's chip: a copied file is useless elsewhere. */
  chipBound: boolean;
  /** The vault the app has open, or would open. */
  current: boolean;
}

export interface LocalCapabilities {
  /** New vaults are bound to this device's chip. */
  chip: boolean;
  /** The lowest strength score a new master password may have here. */
  minScore: number;
}

/** What opens a `.octapass-backup` file. */
export type LocalBackupKey = { password: string } | { recoveryCode: string; newPassword: string };

/** How a `local:` session's vaults are managed. Only hosts with their own storage have this; a web page never does (plan 05). */
export interface LocalVaultService {
  capabilities(): Promise<LocalCapabilities>;
  list(): Promise<LocalVaultInfo[]>;
  /** "Use on this device only": a new vault, unlocked and current. Returns the backup recovery code. */
  create(input: { name: string; password: string }): Promise<string>;
  /** Restores a backup as a new vault, unlocked and current. Throws `invalidBackup`. */
  restore(file: Uint8Array, key: LocalBackupKey): Promise<void>;
  /** Makes another local vault current. It opens locked. */
  switchTo(id: string): Promise<void>;
  /** Back to the first screen, to add a vault or sign in. Nothing is deleted. */
  leave(): Promise<void>;
  rename(name: string): Promise<void>;
  /** Deletes the open vault here for good, after its master password. Backups stay where they are. */
  remove(password: string): Promise<void>;
  /** Asks where to save a backup of the open vault, and saves it. The path, or `undefined` when cancelled. */
  saveBackup(): Promise<string | undefined>;
  recoveryCode(): Promise<string>;
  /** Asks for a folder and turns automatic backups on there, writing the first one. `undefined` when cancelled. */
  chooseBackupFolder(): Promise<string | undefined>;
  clearBackupFolder(): Promise<void>;
  /** Turn on sync: the sign-up steps, keeping this vault's keys. */
  startTurnOnSync(input: { serverUrl: string; email: string; password: string }): Promise<{ signupId: string; devVerificationCode?: string }>;
  /** Registers, moves the items as they are and removes the local vault. Show the Recovery Kit next. */
  finishTurnOnSync(input: { signupId: string; verificationCode: string }): Promise<RecoveryKit>;
}

/** A session on a vault with no server: its `serverUrl` is `local:…`. */
export function isLocalServer(serverUrl: string | undefined): boolean {
  return serverUrl?.startsWith('local:') ?? false;
}

export interface VaultService {
  // Server + account
  getServerInfo(serverUrl: string): Promise<ServerInfo>;
  startSignup(input: { serverUrl: string; email: string; password: string }): Promise<{ signupId: string; devVerificationCode?: string }>;
  /** Signs the user in. */
  finishSignup(input: { signupId: string; verificationCode: string }): Promise<{ recoveryKit: RecoveryKit }>;
  /** `secretKey` is needed on a device that has no remembered account for this email. */
  signIn(input: { serverUrl: string; email: string; password: string; secretKey?: string }): Promise<SignInResult>;
  /**
   * After `twoStepRequired`: finishes signing in. A wrong code throws `invalidTwoStepCode` (try again);
   * `twoStepExpired` means start over with `signIn`.
   */
  finishTwoStep(proof: TwoStepProof): Promise<void>;
  /**
   * After `ssoRequired`: gives the code the browser showed. It can end in `twoStepRequired`, when the
   * account has two-step sign-in too. `ssoPending`: the browser hasn't finished yet. A wrong code
   * throws `invalidTwoStepCode`; `twoStepExpired` means start over with `signIn`.
   */
  finishSso?(code: string): Promise<SignInResult>;
  /** The sign-in still waiting for its second step, for a screen opened again meanwhile (the extension popup). */
  pendingTwoStep?(): Promise<PendingTwoStep | undefined>;
  /** Drops a sign-in waiting for its second step: "Start over". */
  cancelTwoStep?(): Promise<void>;
  rememberedAccounts(): RememberedAccount[];
  lock(): void;
  unlock(password: string): Promise<void>;
  signOut(): Promise<void>;
  getSession(): SessionState;
  onSessionChange(cb: (s: SessionState) => void): () => void;
  /** The Secret Key stored on this device, so a signed-in user can find it again. Unlocked only. */
  getSecretKey(): Promise<string>;
  getAccountSummary(): Promise<AccountSummary>;

  // Device unlock (Touch ID, Windows Hello, device passcode) through a platform passkey with PRF
  getUnlockMethods(): Promise<UnlockMethods>;
  /** Unlocked only. Creates the passkey and wraps the account key with its PRF output, on this browser only. */
  enableDeviceUnlock(): Promise<void>;
  disableDeviceUnlock(): Promise<void>;
  /** Locked only. Throws `passwordRequired` when the master password hasn't been used for 14 days. */
  unlockWithDevice(): Promise<void>;
  /**
   * Confirms it's really the user before revealing, copying or exporting a secret: device auth where
   * this device has it, else the master password (plan 03, the two-gate model). Unlocked only.
   */
  confirmIdentity?(proof: IdentityConfirmation): Promise<void>;
  /** Device unlock is on here, so `confirmIdentity({ device: true })` works. */
  canConfirmIdentityWithDevice?(): Promise<boolean>;
  /** Re-authenticates with the master password, deletes everything server-side, wipes local data and signs out. */
  deleteAccount(input: { confirmEmail: string; password: string }): Promise<void>;
  /**
   * Sets a new master password after checking the current one (`invalidCredentials` when it's
   * wrong). The Secret Key and recovery code stay. Every other device is signed out, and device
   * unlock is turned off. Missing where the host can't do it yet.
   */
  changeMasterPassword?(input: { currentPassword: string; newPassword: string }): Promise<void>;
  /**
   * A new Secret Key, after checking the master password (`invalidCredentials` when it's wrong).
   * The master password stays, and the recovery code too unless `newRecoveryCode` is set. Every
   * other device is signed out, and device unlock is turned off. The kit returned is the only
   * copy of the new key off this device: show it. Missing where the host can't do it yet.
   */
  rotateSecretKey?(input: { password: string; newRecoveryCode: boolean }): Promise<NewRecoveryKit>;
  /**
   * The master password reset with the recovery code (plan 03, Recovery): emails a code. Missing
   * where the host can't do it yet; `verifyPasswordReset` and `finishPasswordReset` go with it.
   */
  startPasswordReset?(input: { serverUrl: string; email: string }): Promise<{ resetId: string; devVerificationCode?: string }>;
  /** Checks the emailed code: `invalidVerificationCode` to try again, `resetExpired` to start over. */
  verifyPasswordReset?(input: { resetId: string; verificationCode: string }): Promise<void>;
  /**
   * Sets the new master password with the recovery code (`invalidRecoveryCode` when it doesn't open
   * the account) and signs in. Show the new Recovery Kit: the recovery code is always new, and so is
   * the Secret Key unless this device remembers the account. Every device was signed out. No `signIn`
   * when signing in failed afterwards: the password is set, so sign in by hand.
   */
  finishPasswordReset?(input: { resetId: string; recoveryCode: string; password: string }): Promise<PasswordResetResult>;
  /** Drops a reset in progress: "Start over". */
  cancelPasswordReset?(resetId: string): Promise<void>;

  // Vault
  listVaults(): Promise<Vault[]>;
  listItems(filter?: ItemFilter): Promise<ItemSummary[]>;
  getItem(id: string): Promise<Item>;
  /** Create or update. A stale `revision` saves a conflict copy instead of overwriting. */
  saveItem(item: ItemDraft): Promise<Item>;
  /** Moves the item to the trash. */
  deleteItem(id: string): Promise<void>;
  restoreItem(id: string): Promise<void>;
  onItemsChange(cb: () => void): () => void;
  /** The item's past versions, newest first (at most 10). Empty where none are kept (a vault on this device only). */
  itemVersions?(id: string): Promise<ItemVersion[]>;
  /** Makes a past version the current one, as a new edit: the version it replaces stays in the history. */
  restoreItemVersion?(id: string, revision: number): Promise<Item>;
  /** Saves the moved counter of the item's HOTP code, then gives the code. `notFound` when it has none. */
  nextHotpCode?(id: string): Promise<HotpCode>;
  /** Brings the item's HOTP code back in step with the site. Not an edit: no history entry. */
  setHotpCounter?(id: string, counter: number): Promise<Item>;
  /**
   * Nearby: every place with its items, the places the device is at first, then the others nearest
   * first when its location is known. Worked out on the device by the core; `here` never leaves it.
   * Missing where the host has no core to ask.
   */
  nearby?(here: Here): Promise<NearbyPlace[]>;
  /**
   * The place to offer a new item to ("You're at Office. Add this item to it?"), when the device is
   * at one that everyone who sees the item can see and the item isn't at it yet.
   */
  suggestPlace?(itemId: string, here: Here): Promise<string | undefined>;
  /** The user's equivalent domains and the built-in ones. Missing where the host doesn't offer them yet. */
  equivalentDomains?(): Promise<EquivalentDomains>;
  /** Saves the list; the result says what was refused (public suffixes, addresses, anything that isn't a domain). */
  saveEquivalentDomains?(input: { groups: string[][]; excludedDefaults: string[] }): Promise<EquivalentDomains & { rejected: string[] }>;
  /** A password in the user's `options`, adjusted to what the password rules dataset knows about `url`. */
  generatePasswordForSite?(url: string, options: Extract<GeneratorOptions, { kind: 'password' }>): Promise<string>;

  // Tools (run locally, never send secrets)
  generatePassword(opts: GeneratorOptions): string;
  estimateStrength(password: string): StrengthEstimate;
  /** Async because HMAC runs through WebCrypto. */
  totpCode(totp: string, at?: number): Promise<TotpCode>;
  /** How many times the password appears in the Pwned Passwords range API; 0 = not found. */
  checkBreached(password: string): Promise<number>;
  getHealthReport(): Promise<HealthReport>;
  /**
   * Asks the signed-in server to look one address up in Have I Been Pwned. **This sends the address
   * to the server, which sends it to HIBP**, so only `HealthSettings` calls it, after the user opted
   * in. Throws `notFound` when the server has no HIBP key, and for local vaults, which have no server.
   */
  lookupEmailBreaches(address: string): Promise<EmailBreach[]>;
  exportVault(format: ExportFormat, options?: ExportOptions): Promise<Blob>;
  importFile(source: ImportSource, file: File, options?: ImportOptions): Promise<ImportResult>;
  /**
   * Authenticator imports (`REVIEWED_IMPORTS`) and scanned QR codes: parses the file and keeps it
   * until `finishImport` saves it with the review's choices, or `cancelImport` drops it. Locking
   * drops it too.
   */
  reviewImport(source: ImportSource, file: Blob, options?: ImportOptions): Promise<ImportReview>;
  /** Codes without a link stay as the review showed them. Throws `importReviewExpired`. */
  finishImport(reviewId: string, links: CodeLink[]): Promise<ImportResult>;
  cancelImport(reviewId: string): Promise<void>;
  /** The text of every QR code in a PNG, JPEG, WebP or GIF image, read on this device. Throws `invalidImage`. */
  readQrCodes(image: Blob): Promise<string[]>;
  /** What scanned QR texts hold. Pass every text scanned so far: split exports are joined. */
  summarizeQrScans(texts: string[]): Promise<QrScan>;

  /**
   * Plan 03's autofill gate where the fills happen in native code (the desktop app). The switch
   * lives in `settings.requireDeviceAuthOnAutofill`; this tells the native side.
   */
  setFillGate?(on: boolean): Promise<void>;
  /**
   * Plan 18: "Stay unlocked while you're logged in to this device". Missing where it isn't offered
   * (the web vault: a page can't tell who's at the keyboard).
   */
  getStayUnlocked?(): Promise<StayUnlockedStatus>;
  setStayUnlocked?(on: boolean): Promise<StayUnlockedStatus>;
  /**
   * Opens the vault without a prompt when stay unlocked can (on, a key on this device, the 14-day
   * check not due, "Lock now" not holding). False: ask as before.
   */
  unlockStayUnlocked?(): Promise<boolean>;
  /** Vaults on this device only. Missing where local mode isn't offered, as in the web vault (plan 05). */
  readonly local?: LocalVaultService;
  /**
   * The open local vault's backups, where the host keeps its one local vault outside `local` (the
   * browser extension), for Health's backup reminder. Read on the device; nothing is sent.
   */
  localBackupInfo?(): Promise<{ createdAt?: string; lastBackupAt?: string }>;
  /** Sharing and the other account features. Missing on hosts without a sync server account. */
  readonly sharing?: SharingService;
  /** Organisations; missing where the host has no sync server account. */
  readonly organisations?: OrganisationService;
  /** Two-step sign-in settings. Missing on hosts without a sync server account. */
  readonly twoStep?: TwoStepService;
  /** Attachments and Document files. Missing on hosts without a sync server account. */
  readonly attachments?: AttachmentService;
  /** Masked email aliases through the user's own provider account. Missing where it isn't wired up. */
  readonly maskedEmail?: MaskedEmailService;
  /** Auto-type settings in the item editor. Only the desktop app types. */
  readonly autoType?: AutoTypeService;
  /** The device's Wi-Fi: connected and in-range marks, importing saved networks. Apps only. */
  readonly wifi?: WifiService;
  /**
   * The device's location for Nearby, where the host reads it its own way (the desktop app). Without
   * it, the web vault asks the browser (`navigator.geolocation`).
   */
  readonly location?: LocationService;
  /** Octa Pass Connect, in the desktop app. */
  readonly connect?: ConnectService;
  /** Generating, importing and exporting SSH keys. Missing where the host doesn't offer it yet. */
  readonly sshKeys?: SshKeyService;
  /** `~/.ssh` on this computer. Only the desktop app has it. */
  readonly sshHome?: SshHomeService;
  /** The SSH agent. Only the desktop app has it. */
  readonly sshAgent?: SshAgentService;
  /** The tray icon and opening at login. Only the desktop app has them. */
  readonly background?: BackgroundService;
  /** Connecting the browser extension, and offering it until it has reached the app. Only the desktop app has it. */
  readonly browserExtension?: BrowserExtensionService;
  /** The developer toolkit. Missing where the host doesn't offer it. */
  readonly toolkit?: ToolkitService;
  /**
   * Asks `serverUrl` for a website icon from the native side, where the web view can't call the
   * server (the apps). Missing elsewhere: pages call the server with `fetch` (`siteIcons.ts`).
   */
  fetchSiteIcon?(serverUrl: string, domain: string): Promise<IconAnswer>;
  /**
   * Offer device unlock right after sign-in or sign-up (the desktop and phone apps, where it's the
   * system's own lock and AutoFill uses it too). The web vault leaves it in Settings.
   */
  readonly offerDeviceUnlock?: boolean;
  /** Ways to read QR codes besides choosing, dropping or pasting an image, which every app has. */
  readonly qrCapture?: QrCaptureService;
  /** Encrypting files, secure delete and Octa Pass Safes. Only the desktop app reaches local files. */
  readonly files?: FilesService;
}

/** How a drive stores data, which decides what a secure delete can promise (plan 16 §4). */
export type FileStorage = 'inPlaceDisk' | 'copyOnWrite' | 'solidState' | 'network' | 'unknown';
export type DeleteGuarantee = 'overwritten' | 'bestEffort';

/** A file or folder on this computer that the user handed to the app. */
export interface LocalFile {
  path: string;
  name: string;
  size: number;
  folder: boolean;
  /** An age file, by its contents. */
  encrypted: boolean;
  storage: FileStorage;
  guarantee: DeleteGuarantee;
}

export type FileTarget = { kind: 'yourself' } | { kind: 'people'; to: string[]; yourself: boolean } | { kind: 'passphrase'; passphrase: string };

export interface FileResult {
  source: string;
  output: string;
  bytes: number;
  /** Links and special files inside a folder, which aren't included. */
  skipped: string[];
  /** Set when the original was deleted, with what that could promise. */
  shredded?: DeleteGuarantee;
  storage?: FileStorage;
}

/** An Octa Pass account found to encrypt a file for. */
export interface FileRecipient {
  email: string;
  recipient: string;
  fingerprint: string;
  /** Whether the user compared the fingerprint with its owner. */
  verified: boolean;
}

export type FileMenuSurface = 'finder' | 'explorer' | 'nautilus' | 'dolphin';

export interface FileMenuStatus {
  surface: FileMenuSurface;
  installed: boolean;
}

/** Something about a Safe that the user should hear. */
export type SafeWarning = { kind: 'damagedBlob'; blob: string } | { kind: 'rolledBack'; object: string } | { kind: 'missing'; object: string } | { kind: 'orphaned'; name: string };

export interface SafeSummary {
  itemId: string;
  vaultId: string;
  safeId: string;
  name: string;
  /** Whether its encrypted blobs go through the server to the account's other devices. */
  sync: boolean;
  /** Unlocked on this device right now. */
  open: boolean;
  /** Showing as a folder or drive. */
  mounted: boolean;
  /** Whether this device can show it as a folder. */
  canMount: boolean;
  /** Finder shows it while it's open (macOS). */
  inFinder?: boolean;
  warnings: SafeWarning[];
}

export interface SafeEntry {
  id: string;
  parent: string;
  name: string;
  folder: boolean;
  size: number;
  /** Milliseconds since 1970. */
  modified: number;
}

export interface SafeSyncReport {
  downloaded: number;
  uploaded: number;
  deleted: number;
  /** Copies kept because a file changed on two devices. */
  conflicts: string[];
  /** Files too big for this server, which stay on this device. */
  tooBig: string[];
}

/** The top folder of a Safe. */
export const SAFE_ROOT = '00000000-0000-0000-0000-000000000000';

/**
 * Local files, on the app's native side. The page only ever names paths the user handed over by
 * dropping them, choosing them in a dialog or from a right-click menu.
 */
export interface FilesService {
  describe(paths: string[]): Promise<LocalFile[]>;
  /** The system's chooser. Empty when the user cancels. */
  choose(folder: boolean): Promise<string[]>;
  /** Paths dropped on the window. Returns the function that stops listening. */
  onDrop(handler: (paths: string[]) => void): Promise<() => void>;
  /** Paths sent from a right-click menu. */
  onRequest(handler: (request: { action: 'encrypt' | 'decrypt'; paths: string[] }) => void): Promise<() => void>;
  encrypt(input: { paths: string[]; target: FileTarget; armor: boolean; shredOriginals: boolean }): Promise<FileResult[]>;
  /** `passwordRequired` when a file needs a passphrase and none was given. */
  decrypt(input: { paths: string[]; passphrase?: string }): Promise<FileResult[]>;
  findRecipient(email: string): Promise<FileRecipient>;
  ownRecipient(): Promise<string>;
  menuStatus(): Promise<FileMenuStatus[]>;
  installMenu(language: string): Promise<void>;
  removeMenu(): Promise<void>;
  listSafes(): Promise<SafeSummary[]>;
  createSafe(input: { name: string; sync: boolean }): Promise<SafeSummary>;
  setSafeSync(input: { itemId: string; sync: boolean }): Promise<SafeSummary>;
  syncSafe(itemId: string): Promise<SafeSyncReport>;
  safeEntries(input: { itemId: string; folder: string }): Promise<SafeEntry[]>;
  safeAddFiles(input: { itemId: string; folder: string; paths: string[] }): Promise<void>;
  safeCreateFolder(input: { itemId: string; folder: string; name: string }): Promise<SafeEntry>;
  safeRename(input: { itemId: string; id: string; folder: string; name: string }): Promise<void>;
  safeDelete(input: { itemId: string; id: string }): Promise<void>;
  /** Saves a decrypted copy where the user picks. `false` when they cancel. */
  safeSaveFile(input: { itemId: string; id: string }): Promise<boolean>;
  safeLock(itemId: string): Promise<void>;
  /** Shows a Safe as a folder (Linux, Windows) and returns where. */
  safeMount(itemId: string): Promise<string>;
  /** Deletes a Safe: its key goes to the trash with its item, its files on this device now. */
  deleteSafe(itemId: string): Promise<void>;
  /** What went wrong when Safes last locked, once (files kept open by another app, unsaved edits). */
  lockProblems(): Promise<string[]>;
}

/**
 * `page`: the extension's screenshot of the current tab. `screen`: a part of the screen the user
 * selects (the desktop app on macOS). `camera`, `photo`: the phone's camera and photo library.
 */
export type QrCaptureSource = 'page' | 'screen' | 'camera' | 'photo';

/** Reading QR codes from what only this app can reach. Everything is read on the device. */
export interface QrCaptureService {
  /** In the order to offer them. */
  readonly sources: QrCaptureSource[];
  /** `false` where a file chooser would close the window (the extension's popup). */
  readonly chooseFiles?: boolean;
  /** The text of each QR code found (possibly none), or `undefined` when the user cancelled. */
  capture(source: QrCaptureSource): Promise<string[] | undefined>;
}

/**
 * Where provider calls run. `browser`: a web page, where the browser only allows providers that
 * answer CORS requests. `extension` and `app`: no such limit.
 */
export type MaskedEmailContext = 'browser' | 'extension' | 'app';

/** A connected provider, without its token. */
export interface MaskedEmailConnection {
  /** The vault item that holds the token. */
  itemId: string;
  provider: MaskedEmailProviderId;
  baseUrl?: string;
  domain?: string;
  /** False when this browser won't let a web page call the provider: use the extension or the apps. */
  usableHere: boolean;
}

export interface MaskedAlias {
  email: string;
  provider: MaskedEmailProviderId;
  /** The provider's id for the alias, or the address when it has none. */
  aliasId: string;
}

/** An alias already made, as a login links to it. */
export interface AliasRef {
  provider: MaskedEmailProviderId;
  aliasId: string;
  email: string;
}

/**
 * Masked email aliases (plan 06, Phase A). Calls go from this device straight to the provider with
 * the user's token, which is kept in the vault as a `maskedEmailProvider` item and never sent to the
 * Octa Pass server unencrypted.
 */
export interface MaskedEmailService {
  readonly context: MaskedEmailContext;
  listConnections(): Promise<MaskedEmailConnection[]>;
  /** Stores the token in the personal vault. Doesn't call the provider. */
  connect(input: { provider: MaskedEmailProviderId; token: string; baseUrl?: string; domain?: string }): Promise<MaskedEmailConnection>;
  /** Moves the token's item to the trash. Aliases made with it keep working. */
  disconnect(itemId: string): Promise<void>;
  /**
   * Makes a new alias for `site` (a URL or host), described with the site's domain. Uses the given
   * connection, or the first one usable here. Throws `maskedEmailNotSetUp`, `maskedEmailBlocked`,
   * `maskedEmailToken`, `maskedEmailRateLimited`, `maskedEmailUnreachable` or `maskedEmailFailed`.
   */
  createAlias(input: { site: string; connectionId?: string }): Promise<MaskedAlias>;
  /**
   * Turns an alias on or off at its provider. Throws what `createAlias` throws, and
   * `maskedEmailFailed` where the provider has no call for it (see `canManageAlias`).
   */
  setAliasEnabled(alias: AliasRef, enabled: boolean): Promise<void>;
  /** Deletes an alias at its provider, then unlinks it from these logins, which keep the address as text. */
  deleteAlias(alias: AliasRef, loginIds: readonly string[]): Promise<void>;
}

/** A network the device sees in range. */
export interface WifiSighting {
  ssid: string;
  /** 0–100: how strong the signal is. */
  signal: number;
}

/** A network saved in this device's own Wi-Fi settings. */
export interface DeviceWifiNetwork {
  ssid: string;
  security?: WifiSecurity;
  hidden?: boolean;
  /** Only from `readSavedPasswords`, and only where the system gave it. */
  password?: string;
}

/**
 * The system's location permission: iOS, Android and macOS tell apps network names only with it.
 * `unsupported`: the system has no way to tell apps (or this build can't ask).
 */
export type WifiPermission = 'granted' | 'denied' | 'prompt' | 'unsupported';

/** What this device's Wi-Fi lets Octa Pass do. Each platform allows a different part (docs/features/wifi.md). */
export interface WifiFeatures {
  /** Read the name of the network the device is on. */
  current: boolean;
  /** List the networks in range, with their signal. Not on iPhone. */
  nearby: boolean;
  /** Read the networks saved on the device, and their passwords where the system allows. Computers only. */
  savedNetworks: boolean;
  /** Notice when the device joins a network, to offer saving it. */
  joins: boolean;
}

/** Whether Nearby may read the device's location: asked once, by the system's own prompt. */
export type LocationPermission = 'granted' | 'prompt' | 'denied' | 'unavailable';

/**
 * One reading of the device's location for Nearby, foreground only: never watched, never kept, and
 * matched against places on the device (plan 03, *Nearby*).
 */
export interface LocationService {
  permission(): Promise<LocationPermission>;
  /** Asks for permission first if it hasn't been given. Rejects when refused or unavailable. */
  current(): Promise<{ latitude: number; longitude: number; accuracy?: number }>;
}

/**
 * The device's own Wi-Fi: the desktop and phone apps (plan 01, Wi-Fi). Network names leave the
 * device only inside encrypted items. Missing in the web vault and the extension: browsers can't see
 * Wi-Fi.
 */
export interface WifiService {
  /** Where the app runs: what it may do, and how to say what it can't, differ. */
  readonly platform: 'mac' | 'windows' | 'linux' | 'ios' | 'android';
  readonly features: WifiFeatures;
  permission(): Promise<WifiPermission>;
  /** Shows the system's permission dialog when it hasn't been answered. Only when the user opens Wi-Fi. */
  requestPermission(): Promise<WifiPermission>;
  /** The network the device is on now; `undefined` when none, or the system won't say. */
  currentNetwork(): Promise<string | undefined>;
  /**
   * Networks in range, strongest first, one entry per name. `rescan` asks for a new scan; Android
   * allows only a few a minute, so it may answer with the last results.
   */
  nearbyNetworks(rescan?: boolean): Promise<WifiSighting[]>;
  /** The networks saved on this device, without passwords. */
  savedNetworks?(): Promise<DeviceWifiNetwork[]>;
  /**
   * The chosen saved networks with their passwords. The system may ask first (macOS asks for an
   * administrator's name and password for each). A password it won't give is left out.
   */
  readSavedPasswords?(ssids: string[]): Promise<DeviceWifiNetwork[]>;
  /** Calls `cb` with the name of each network the device joins while the app runs. */
  onJoin?(cb: (ssid: string) => void): () => void;
}

/** What the item editor needs to offer auto-type settings. The typing itself is the desktop app's. */
export interface AutoTypeService {
  /** The global auto-type shortcut as the keyboard shows it, like `⌘⇧\`. */
  readonly shortcut: string;
}
