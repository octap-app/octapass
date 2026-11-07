import { VaultError } from '../errors';
import { uuidv7 } from '../ids';
import {
  attachmentsOf,
  compareSummaries,
  isValidEmail,
  keepAttachments,
  loginDetails,
  matchesFilter,
  normalizeEmail,
  normalizePassword,
  restoredVersion,
  summarizeItem,
  withAttachments,
  withPasswordHistory,
} from '../items';
import { generateRecoveryCode, generateSecretKey, normalizeSecretKey } from '../secretKey';
import { HOSTED_SERVER_URL, serverOrigin } from '../serverUrl';
import { createBreachChecker } from '../tools/breach';
import { exportCsv, exportJson } from '../tools/export';
import { generatePassword } from '../tools/generator';
import { buildHealthReport } from '../tools/health';
import { createMaskedEmailService, fetchHttp } from '../maskedEmail';
import { createSshKeyService, type SshCore } from '../sshKeys';
import { parseImport } from '../tools/import';
import { parseOtpLinks, readMockQrCodes, summarizeLinks, type MockCode } from './otpImport';
import { base32Encode, base64UrlEncode, crockfordEncode } from '../tools/encoding';
import { randomInt } from '../tools/random';
import { estimateStrength } from '../tools/strength';
import { isHotp, nextHotp, totpCode, withHotpCounter } from '../tools/totp';
import { storeEquivalentDomains } from '../equivalentDomains';
import type {
  AccountSummary,
  Attachment,
  AttachmentService,
  GeneratorOptions,
  EmailBreach,
  HealthReport,
  MaskedEmailService,
  ExportFormat,
  ExportOptions,
  CodeLink,
  ImportOptions,
  ImportReview,
  QrScan,
  ImportResult,
  ImportSource,
  Item,
  ItemDraft,
  LoginDetails,
  ItemFilter,
  ItemSummary,
  PasswordResetResult,
  PendingTwoStep,
  NewRecoveryKit,
  RecoveryKit,
  RememberedAccount,
  SecurityEvent,
  SecurityEventType,
  SecurityKeyInfo,
  ServerInfo,
  SessionState,
  SshKeyConfirmation,
  SshKeyService,
  StorageUsage,
  SignInResult,
  StrengthEstimate,
  TotpCode,
  TotpSetup,
  TwoStepMethod,
  TwoStepProof,
  TwoStepService,
  TwoStepStatus,
  UnlockMethods,
  Vault,
  VaultService,
  EquivalentDomains,
  EquivalentDomainsDetails,
  HotpCode,
  ItemVersion,
} from '../types';
import { withConfirmed } from '../types';
import { openKeyValueStore, type KeyValueStore } from '../idb';
import { MockOrganisations } from './MockOrganisations';
import { emptySharing, MockSharing } from './MockSharing';
import { derivePasswordKey, deriveDeviceKey, fromBase64, importAsk, openBytes, openJson, randomBytes, sealBytes, sealJson, toBase64, type Sealed } from './sealing';
import { seedVault, type VaultData } from './seed';
import {
  createSecurityKey,
  DEVICE_LABELS,
  detectPlatform,
  evaluatePrf,
  getSecurityKeyAssertion,
  isPlatformAuthenticatorAvailable,
  securityKeysSupported,
  setUpDeviceCredential,
} from '../webauthn';

export const DEFAULT_SERVER_URL = HOSTED_SERVER_URL;

const TRASH_DAYS = 30;
/** The hosted service's limits (plan 10), applied to plaintext sizes here. */
const MOCK_ATTACHMENT_QUOTA = 1024 ** 3;
const MOCK_MAX_FILE = 100 * 1024 ** 2;
const attachmentKey = (id: string) => `attachment:${id}`;
const SIGNUP_TTL_MS = 15 * 60_000;
/** As the real server: a sign-in waits 5 minutes for its second step, with 5 tries. */
const TWO_STEP_TTL_MS = 5 * 60_000;
const TWO_STEP_TRIES = 5;
const TOTP_SETUP_TTL_MS = 10 * 60_000;
const RECOVERY_CODES = 10;
/** Device unlock asks for the master password again after this long (plan 11). */
export const PASSWORD_RECHECK_MS = 14 * 86_400_000;

/** What the pretend server keeps: ciphertext only. */
interface ServerAccount {
  email: string;
  serverUrl: string;
  salt: string;
  /** The ASK, sealed by the password key. */
  wrappedAsk: Sealed;
  /** The ASK, sealed by the recovery code's key. Missing on accounts made before resets existed. */
  recoveryWrappedAsk?: Sealed;
  /** The vault, sealed by the ASK. */
  vault: Sealed;
  /** Two-step sign-in, when it's on. */
  twoStep?: ServerTwoStep;
}

interface ServerTwoStep {
  /** Base32, as the authenticator app has it. */
  totpSecret: string;
  /** Unused recovery codes, in canonical form (no dash). */
  recoveryCodes: string[];
  securityKeys: (SecurityKeyInfo & { credentialId: string })[];
}

/** A sign-in waiting for its second step: the vault is open, but not handed over yet. */
interface WaitingTwoStep {
  serverUrl: string;
  email: string;
  secretKey: string;
  unlocked: Unlocked;
  methods: TwoStepMethod[];
  expiresAt: number;
  tries: number;
}

/** What this device keeps per signed-in account. */
interface DeviceAccount extends RememberedAccount {
  secretKey: string;
  /** Signed in here before, so two-step sign-in doesn't ask again. Gone with a sign-out. */
  trusted?: boolean;
}

/** A master password reset, from the emailed code to the new password. */
interface PendingReset {
  serverUrl: string;
  email: string;
  code: string;
  expiresAt: number;
  verified: boolean;
  tries: number;
}

interface PendingSignup {
  serverUrl: string;
  email: string;
  password: string;
  code: string;
  expiresAt: number;
}

/** Kept in this browser only, never synced or sent (plan 11, "Device unlock"). */
interface DeviceUnlockRecord {
  accountId: string;
  credentialId: string;
  deviceSalt: string;
  /** The ASK, sealed by the key derived from the passkey's PRF output. */
  wrappedAsk: Sealed;
  enabledAt: string;
  lastPasswordUnlockAt: string;
}

interface Unlocked {
  ask: Uint8Array<ArrayBuffer>;
  vaultKey: CryptoKey;
  data: VaultData;
  /** When the master password was last proven, carried through device unlocks for the 14-day rule. */
  passwordCheckedAt: string;
}

export interface MockOptions {
  /** IndexedDB database name. */
  dbName?: string;
  /** Simulated network latency range in milliseconds. */
  latency?: [number, number];
  /** Used by the breach check; defaults to the global fetch. */
  fetch?: typeof fetch;
  /** Start new accounts with the demo vault. */
  seed?: boolean;
  /** Loads the core's SSH key functions (the WASM core). Without it there's no `sshKeys`. */
  sshCore?: () => Promise<SshCore>;
}

const KEYS = { server: 'server-accounts', device: 'device-accounts', session: 'session', deviceUnlock: 'device-unlock' } as const;

function accountKey(serverUrl: string, email: string): string {
  return `${serverUrl}|${email}`;
}

/** Recovery codes compare without dashes, spaces or case, and with the letters people mistake for digits. */
/** What seals the ASK for the recovery code. The code is random, so a fixed salt does. */
function recoveryKey(code: string): Promise<CryptoKey> {
  return derivePasswordKey(canonicalRecoveryCode(code), 'recovery', toBase64(new Uint8Array(16)));
}

function canonicalRecoveryCode(code: string): string {
  return code
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
}

function newRecoveryCodes(): string[] {
  return Array.from({ length: RECOVERY_CODES }, () => crockfordEncode(randomBytes(7)).slice(0, 10));
}

const showRecoveryCode = (code: string) => `${code.slice(0, 5)}-${code.slice(5)}`;

function otpauthUri(email: string, secret: string): string {
  return `otpauth://totp/${encodeURIComponent(`Octa Pass:${email}`)}?secret=${secret}&issuer=${encodeURIComponent('Octa Pass')}`;
}

/** The current code, or the one either side of it for a clock that's a little off. */
async function totpMatches(email: string, secret: string, code: string): Promise<boolean> {
  const typed = code.replace(/\s/g, '');
  if (!/^\d{6}$/.test(typed)) return false;
  const uri = otpauthUri(email, secret);
  for (const offset of [0, -30_000, 30_000]) if ((await totpCode(uri, Date.now() + offset)).code === typed) return true;
  return false;
}

function thisDevice() {
  const now = new Date().toISOString();
  return { id: uuidv7(), name: 'This browser', platform: 'web', createdAt: now, lastSeenAt: now, current: true };
}

export class MockVaultService implements VaultService, AttachmentService, TwoStepService {
  private session: SessionState = { status: 'signedOut' };
  private unlocked: Unlocked | undefined;
  private waitingTwoStep: WaitingTwoStep | undefined;
  private totpSetup: { secret: string; expiresAt: number } | undefined;
  private server: Record<string, ServerAccount> = {};
  private device: DeviceAccount[] = [];
  private deviceUnlock: Record<string, DeviceUnlockRecord> = {};
  private readonly signups = new Map<string, PendingSignup>();
  private readonly resets = new Map<string, PendingReset>();
  private readonly sessionListeners = new Set<(s: SessionState) => void>();
  private readonly itemListeners = new Set<() => void>();
  private readonly checkBreachedImpl: (password: string) => Promise<number>;
  readonly sharing: MockSharing;
  readonly organisations = new MockOrganisations(() => this.sharing.emit());
  /** Calls the real providers from this page, like the web vault. */
  readonly maskedEmail: MaskedEmailService;
  readonly sshKeys: SshKeyService | undefined;

  get attachments(): AttachmentService {
    return this;
  }

  get twoStep(): TwoStepService {
    return this;
  }

  /** Imports waiting for the review. */
  private readonly reviews = new Map<string, MockCode[]>();
  /** Past versions, newest first. Kept for this visit only: the mock has no server. */
  private readonly versions = new Map<string, ItemVersion[]>();

  private constructor(
    private readonly store: KeyValueStore,
    private readonly options: Required<Pick<MockOptions, 'latency' | 'seed'>>,
    fetchImpl: typeof fetch | undefined,
    sshCore: (() => Promise<SshCore>) | undefined,
  ) {
    this.sshKeys = sshCore && createSshKeyService(sshCore, (proof) => this.confirmIdentity(proof), async () => this.currentDeviceUnlock() !== undefined);
    this.checkBreachedImpl = createBreachChecker(fetchImpl ? { fetch: fetchImpl } : undefined);
    this.maskedEmail = createMaskedEmailService(this, { context: 'browser', http: fetchHttp(fetchImpl) });
    this.sharing = new MockSharing({
      store,
      vault: () => this.vault(),
      write: (change) => this.write(change),
      network: (scale) => this.network(scale),
      account: () => ({ email: this.session.email!, key: accountKey(this.session.serverUrl!, this.session.email!) }),
    });
  }

  static async create(options: MockOptions = {}): Promise<MockVaultService> {
    const store = await openKeyValueStore(options.dbName ?? 'octapass-mock');
    const service = new MockVaultService(store, { latency: options.latency ?? [150, 450], seed: options.seed ?? true }, options.fetch, options.sshCore);
    service.server = (await store.get<Record<string, ServerAccount>>(KEYS.server)) ?? {};
    service.device = (await store.get<DeviceAccount[]>(KEYS.device)) ?? [];
    service.deviceUnlock = (await store.get<Record<string, DeviceUnlockRecord>>(KEYS.deviceUnlock)) ?? {};
    const session = await store.get<RememberedAccount>(KEYS.session);
    if (session && service.deviceAccount(session.serverUrl, session.email)) {
      // Keys live only in memory, so a reload always comes back locked.
      service.session = { status: 'locked', email: session.email, serverUrl: session.serverUrl };
    }
    return service;
  }

  // ---------- Server + account ----------

  async getServerInfo(serverUrl: string): Promise<ServerInfo> {
    const url = new URL(serverOrigin(serverUrl));
    await this.network();
    if (url.hostname.endsWith('.invalid')) throw new VaultError('serverUnreachable');
    const hosted = url.origin === DEFAULT_SERVER_URL;
    return { name: hosted ? 'Octa Pass' : url.hostname, version: '0.1.0-mock', apiVersion: 1, signups: 'open', pushRelay: hosted, emailBreachChecks: hosted };
  }

  async startSignup(input: { serverUrl: string; email: string; password: string }) {
    const serverUrl = serverOrigin(input.serverUrl);
    const email = normalizeEmail(input.email);
    if (!isValidEmail(email)) throw new VaultError('invalidEmail');
    await this.network();
    if (this.server[accountKey(serverUrl, email)]) throw new VaultError('emailTaken');
    const signupId = uuidv7();
    const code = String(randomInt(1_000_000)).padStart(6, '0');
    this.signups.set(signupId, { serverUrl, email, password: normalizePassword(input.password), code, expiresAt: Date.now() + SIGNUP_TTL_MS });
    return { signupId, devVerificationCode: code };
  }

  async finishSignup(input: { signupId: string; verificationCode: string }): Promise<{ recoveryKit: RecoveryKit }> {
    const pending = this.signups.get(input.signupId);
    await this.network();
    if (!pending || pending.expiresAt < Date.now()) throw new VaultError('signupExpired');
    if (input.verificationCode.replace(/\s/g, '') !== pending.code) throw new VaultError('invalidVerificationCode');
    this.signups.delete(input.signupId);

    const secretKey = generateSecretKey();
    const recoveryCode = generateRecoveryCode();
    const salt = toBase64(randomBytes(16));
    const ask = randomBytes(32);
    const vaultKey = await importAsk(ask);
    const data: VaultData = this.options.seed ? seedVault(pending.email) : { vaults: [{ id: uuidv7(), name: 'Personal', type: 'personal', role: 'owner' }], items: [], sharing: { ...emptySharing(), devices: [thisDevice()] } };
    this.server[accountKey(pending.serverUrl, pending.email)] = {
      email: pending.email,
      serverUrl: pending.serverUrl,
      salt,
      wrappedAsk: await sealBytes(await derivePasswordKey(pending.password, secretKey, salt), ask, 'ask'),
      recoveryWrappedAsk: await sealBytes(await recoveryKey(recoveryCode), ask, 'recovery'),
      vault: await sealJson(vaultKey, data, 'vault'),
    };
    await this.store.set(KEYS.server, this.server);
    await this.rememberDevice({ email: pending.email, serverUrl: pending.serverUrl, secretKey, trusted: true });
    await this.startSession(pending.serverUrl, pending.email, { ask, vaultKey, data, passwordCheckedAt: new Date().toISOString() });

    return {
      recoveryKit: { email: pending.email, serverUrl: pending.serverUrl, secretKey, recoveryCode, createdAt: new Date().toISOString() },
    };
  }

  async signIn(input: { serverUrl: string; email: string; password: string; secretKey?: string }): Promise<SignInResult> {
    const serverUrl = serverOrigin(input.serverUrl);
    const email = normalizeEmail(input.email);
    const remembered = this.deviceAccount(serverUrl, email);
    // One the user typed wins: this device's copy is out of date after a rotation elsewhere.
    const typed = input.secretKey?.trim();
    const secretKey = typed ? normalizeSecretKey(typed) : remembered?.secretKey;
    if (!typed && !secretKey) throw new VaultError('secretKeyRequired');
    if (!secretKey) throw new VaultError('invalidSecretKey');
    await this.network();
    const account = this.server[accountKey(serverUrl, email)];
    // One error for every failure, as with OPAQUE: the server can't tell which part was wrong.
    if (!account) throw new VaultError('invalidCredentials');
    const unlocked = await this.openVault(account, normalizePassword(input.password), secretKey);
    this.dropWaitingTwoStep();
    if (account.twoStep && !remembered?.trusted) {
      const methods: TwoStepMethod[] = ['totp'];
      if (account.twoStep.securityKeys.length > 0 && this.securityKeysWork()) methods.push('securityKey');
      methods.push('recoveryCode');
      this.waitingTwoStep = { serverUrl, email, secretKey, unlocked, methods, expiresAt: Date.now() + TWO_STEP_TTL_MS, tries: 0 };
      return { status: 'twoStepRequired', methods };
    }
    if (!remembered?.trusted || remembered.secretKey !== secretKey) await this.rememberDevice({ email, serverUrl, secretKey, trusted: true });
    await this.notePasswordUnlock(accountKey(serverUrl, email));
    await this.startSession(serverUrl, email, unlocked);
    return { status: 'signedIn' };
  }

  async pendingTwoStep(): Promise<PendingTwoStep | undefined> {
    const pending = this.waitingTwoStep;
    if (!pending) return undefined;
    if (pending.expiresAt >= Date.now()) return { status: 'twoStepRequired', methods: [...pending.methods] };
    this.dropWaitingTwoStep();
    return { status: 'twoStepExpired' };
  }

  async cancelTwoStep(): Promise<void> {
    this.dropWaitingTwoStep();
  }

  async finishTwoStep(proof: TwoStepProof): Promise<void> {
    const pending = this.waitingTwoStep;
    if (!pending || pending.expiresAt < Date.now()) {
      this.dropWaitingTwoStep();
      throw new VaultError('twoStepExpired');
    }
    const twoStep = this.server[accountKey(pending.serverUrl, pending.email)]?.twoStep;
    let passed = !twoStep;
    let usedRecoveryCode = false;
    if (twoStep && proof.method === 'securityKey') {
      const { credentialId } = await getSecurityKeyAssertion({
        challenge: base64UrlEncode(randomBytes(32)),
        rpId: location.hostname,
        allowCredentials: twoStep.securityKeys.map((k) => k.credentialId),
        timeout: 120_000,
        userVerification: 'discouraged',
      });
      const key = twoStep.securityKeys.find((k) => k.credentialId === credentialId);
      if (key) key.lastUsedAt = new Date().toISOString();
      passed = Boolean(key);
    }
    await this.network();
    if (this.waitingTwoStep !== pending) throw new VaultError('twoStepExpired');
    if (twoStep && proof.method === 'totp') passed = await totpMatches(pending.email, twoStep.totpSecret, proof.code);
    if (twoStep && proof.method === 'recoveryCode') {
      const index = twoStep.recoveryCodes.indexOf(canonicalRecoveryCode(proof.code));
      if (index >= 0) twoStep.recoveryCodes.splice(index, 1);
      passed = usedRecoveryCode = index >= 0;
    }
    if (!passed) {
      if (++pending.tries >= TWO_STEP_TRIES) this.dropWaitingTwoStep();
      throw new VaultError('invalidTwoStepCode');
    }
    this.waitingTwoStep = undefined;
    await this.store.set(KEYS.server, this.server);
    await this.rememberDevice({ email: pending.email, serverUrl: pending.serverUrl, secretKey: pending.secretKey, trusted: true });
    await this.notePasswordUnlock(accountKey(pending.serverUrl, pending.email));
    await this.startSession(pending.serverUrl, pending.email, pending.unlocked);
    if (usedRecoveryCode) await this.logEvent('recovery-code-used');
  }

  rememberedAccounts(): RememberedAccount[] {
    return this.device.map(({ email, serverUrl }) => ({ email, serverUrl }));
  }

  lock(): void {
    if (this.session.status !== 'unlocked') return;
    this.reviews.clear();
    this.forgetKeys();
    this.setSession({ ...this.session, status: 'locked' });
  }

  async unlock(password: string): Promise<void> {
    const { email, serverUrl } = this.session;
    if (this.session.status !== 'locked' || !email || !serverUrl) throw new VaultError('locked');
    const device = this.deviceAccount(serverUrl, email);
    const account = this.server[accountKey(serverUrl, email)];
    if (!device || !account) throw new VaultError('invalidCredentials');
    this.unlocked = await this.openVault(account, normalizePassword(password), device.secretKey);
    await this.notePasswordUnlock(accountKey(serverUrl, email));
    this.purgeExpiredTrash();
    this.setSession({ ...this.session, status: 'unlocked' });
    this.emitItems();
  }

  /** Signing out forgets this device's Secret Key, so the next sign-in here needs the Recovery Kit. */
  async signOut(): Promise<void> {
    const { email, serverUrl } = this.session;
    this.forgetKeys();
    this.dropWaitingTwoStep();
    if (email && serverUrl) {
      this.device = this.device.filter((d) => accountKey(d.serverUrl, d.email) !== accountKey(serverUrl, email));
      await this.store.set(KEYS.device, this.device);
      await this.removeDeviceUnlock(accountKey(serverUrl, email));
    }
    await this.store.delete(KEYS.session);
    this.setSession({ status: 'signedOut' });
  }

  getSession(): SessionState {
    return this.session;
  }

  onSessionChange(cb: (s: SessionState) => void): () => void {
    this.sessionListeners.add(cb);
    return () => this.sessionListeners.delete(cb);
  }

  async getSecretKey(): Promise<string> {
    this.vault();
    const { email, serverUrl } = this.session;
    return this.deviceAccount(serverUrl!, email!)!.secretKey;
  }

  async getAccountSummary(): Promise<AccountSummary> {
    const { vaults, items, sharing } = this.vault();
    await this.network(0.5);
    return {
      email: this.session.email!,
      itemCount: items.filter((i) => !i.deletedAt).length,
      vaultCount: vaults.length,
      deviceCount: Math.max(1, sharing?.devices.length ?? 0),
      sharedVaultsOwned: vaults.filter((v) => v.type !== 'personal' && v.role === 'owner' && !v.members?.some((m) => m.role === 'owner' && m.email !== this.session.email)).map((v) => v.name),
    };
  }

  async deleteAccount(input: { confirmEmail: string; password: string }): Promise<void> {
    const { email, serverUrl } = this.session;
    this.vault();
    if (normalizeEmail(input.confirmEmail) !== email) throw new VaultError('emailMismatch');
    const device = this.deviceAccount(serverUrl!, email!)!;
    await this.reauth(input.password);
    delete this.server[accountKey(serverUrl!, email!)];
    delete this.deviceUnlock[accountKey(serverUrl!, email!)];
    this.device = this.device.filter((d) => d !== device);
    this.forgetKeys();
    // This device's copy goes too. The mock database doubles as the pretend server, so it is only
    // emptied entirely when no other account lives in it.
    if (Object.keys(this.server).length === 0 && this.device.length === 0) {
      await this.store.clear();
    } else {
      await this.store.set(KEYS.server, this.server);
      await this.store.set(KEYS.device, this.device);
      await this.store.set(KEYS.deviceUnlock, this.deviceUnlock);
      await this.store.delete(KEYS.session);
    }
    if (typeof caches !== 'undefined') {
      for (const name of await caches.keys()) await caches.delete(name);
    }
    this.setSession({ status: 'signedOut' });
  }

  async changeMasterPassword(input: { currentPassword: string; newPassword: string }): Promise<void> {
    const unlocked = this.unlockedState();
    const { email, serverUrl } = this.session;
    await this.reauth(input.currentPassword);
    const account = this.serverAccount();
    const salt = toBase64(randomBytes(16));
    const { secretKey } = this.deviceAccount(serverUrl!, email!)!;
    account.wrappedAsk = await sealBytes(await derivePasswordKey(normalizePassword(input.newPassword), secretKey, salt), unlocked.ask, 'ask');
    account.salt = salt;
    delete this.deviceUnlock[accountKey(serverUrl!, email!)];
    await this.store.set(KEYS.deviceUnlock, this.deviceUnlock);
    unlocked.passwordCheckedAt = new Date().toISOString();
    await this.saveServer('password-changed');
  }

  async rotateSecretKey(input: { password: string; newRecoveryCode: boolean }): Promise<NewRecoveryKit> {
    const unlocked = this.unlockedState();
    const { email, serverUrl } = this.session;
    await this.reauth(input.password);
    const account = this.serverAccount();
    const salt = toBase64(randomBytes(16));
    const secretKey = generateSecretKey();
    account.wrappedAsk = await sealBytes(await derivePasswordKey(normalizePassword(input.password), secretKey, salt), unlocked.ask, 'ask');
    account.salt = salt;
    const kit: NewRecoveryKit = { email: email!, serverUrl: serverUrl!, secretKey, createdAt: new Date().toISOString() };
    if (input.newRecoveryCode) kit.recoveryCode = generateRecoveryCode();
    await this.rememberDevice({ ...this.deviceAccount(serverUrl!, email!)!, secretKey });
    delete this.deviceUnlock[accountKey(serverUrl!, email!)];
    await this.store.set(KEYS.deviceUnlock, this.deviceUnlock);
    unlocked.passwordCheckedAt = new Date().toISOString();
    await this.saveServer('secret-key-rotated');
    return kit;
  }

  async startPasswordReset(input: { serverUrl: string; email: string }): Promise<{ resetId: string; devVerificationCode?: string }> {
    const serverUrl = serverOrigin(input.serverUrl);
    const email = normalizeEmail(input.email);
    if (!isValidEmail(email)) throw new VaultError('invalidEmail');
    await this.network();
    const resetId = uuidv7();
    const code = String(randomInt(1_000_000)).padStart(6, '0');
    this.resets.set(resetId, { serverUrl, email, code, expiresAt: Date.now() + SIGNUP_TTL_MS, verified: false, tries: 0 });
    return { resetId, devVerificationCode: code };
  }

  async verifyPasswordReset(input: { resetId: string; verificationCode: string }): Promise<void> {
    const reset = this.pendingReset(input.resetId);
    await this.network();
    if (input.verificationCode.replace(/\s/g, '') !== reset.code || !this.server[accountKey(reset.serverUrl, reset.email)]) {
      if (++reset.tries >= 5) this.resets.delete(input.resetId);
      throw new VaultError('invalidVerificationCode');
    }
    reset.verified = true;
  }

  async finishPasswordReset(input: { resetId: string; recoveryCode: string; password: string }): Promise<PasswordResetResult> {
    const reset = this.pendingReset(input.resetId);
    if (!reset.verified) throw new VaultError('resetExpired');
    const { serverUrl, email } = reset;
    const account = this.server[accountKey(serverUrl, email)]!;
    let ask: Uint8Array<ArrayBuffer>;
    try {
      if (!account.recoveryWrappedAsk) throw new VaultError('invalidRecoveryCode');
      ask = await openBytes(await recoveryKey(input.recoveryCode), account.recoveryWrappedAsk, 'recovery');
    } catch {
      throw new VaultError('invalidRecoveryCode');
    }
    await this.network();
    const remembered = this.deviceAccount(serverUrl, email);
    const secretKey = remembered?.secretKey ?? generateSecretKey();
    const recoveryCode = generateRecoveryCode();
    const salt = toBase64(randomBytes(16));
    account.salt = salt;
    account.wrappedAsk = await sealBytes(await derivePasswordKey(normalizePassword(input.password), secretKey, salt), ask, 'ask');
    account.recoveryWrappedAsk = await sealBytes(await recoveryKey(recoveryCode), ask, 'recovery');
    // The security log lives in the vault, which the recovered ASK opens.
    const vaultKey = await importAsk(ask);
    const data = await openJson<VaultData>(vaultKey, account.vault, 'vault');
    (data.sharing ??= emptySharing()).log.push({ type: 'password-reset', createdAt: new Date().toISOString() });
    account.vault = await sealJson(vaultKey, data, 'vault');
    ask.fill(0);
    this.resets.delete(input.resetId);
    // Every device is signed out, and none skips two-step sign-in any more.
    if (this.session.email === email && this.session.serverUrl === serverUrl) {
      this.forgetKeys();
      await this.store.delete(KEYS.session);
      this.setSession({ status: 'signedOut' });
    }
    delete this.deviceUnlock[accountKey(serverUrl, email)];
    if (remembered) await this.rememberDevice({ ...remembered, trusted: false });
    await this.store.set(KEYS.server, this.server);
    await this.store.set(KEYS.deviceUnlock, this.deviceUnlock);
    const recoveryKit: RecoveryKit = { email, serverUrl, secretKey, recoveryCode, createdAt: new Date().toISOString() };
    const signIn = await this.signIn({ serverUrl, email, password: input.password, secretKey });
    return { recoveryKit, signIn };
  }

  async cancelPasswordReset(resetId: string): Promise<void> {
    this.resets.delete(resetId);
  }

  private pendingReset(resetId: string): PendingReset {
    const reset = this.resets.get(resetId);
    if (!reset || reset.expiresAt < Date.now()) {
      this.resets.delete(resetId);
      throw new VaultError('resetExpired');
    }
    return reset;
  }

  // ---------- Two-step sign-in settings ----------
  // The pretend server checks real authenticator codes, so set it up with any authenticator app, or
  // paste the setup key into a login's one-time code field in this vault.

  async getTwoStepStatus(): Promise<TwoStepStatus> {
    this.vault();
    await this.network(0.5);
    const twoStep = this.serverAccount().twoStep;
    return {
      enabled: Boolean(twoStep),
      securityKeys: (twoStep?.securityKeys ?? []).map(({ credentialId: _credentialId, ...key }) => ({ ...key })),
      recoveryCodesLeft: twoStep?.recoveryCodes.length ?? 0,
      securityKeysSupported: this.securityKeysWork(),
    };
  }

  async startTotpSetup(password: string): Promise<TotpSetup> {
    await this.reauth(password);
    const secret = base32Encode(randomBytes(20));
    this.totpSetup = { secret, expiresAt: Date.now() + TOTP_SETUP_TTL_MS };
    return { secret, otpauthUri: otpauthUri(this.session.email!, secret) };
  }

  async confirmTotpSetup(code: string): Promise<{ recoveryCodes?: string[] }> {
    this.vault();
    const setup = this.totpSetup;
    await this.network();
    if (!setup || setup.expiresAt < Date.now()) throw new VaultError('twoStepExpired');
    if (!(await totpMatches(this.session.email!, setup.secret, code))) throw new VaultError('invalidTwoStepCode');
    this.totpSetup = undefined;
    const account = this.serverAccount();
    if (account.twoStep) {
      account.twoStep.totpSecret = setup.secret;
      await this.saveServer('authenticator-changed');
      return {};
    }
    const recoveryCodes = newRecoveryCodes();
    account.twoStep = { totpSecret: setup.secret, recoveryCodes, securityKeys: [] };
    await this.saveServer('two-step-enabled');
    return { recoveryCodes: recoveryCodes.map(showRecoveryCode) };
  }

  async addSecurityKey(input: { password: string; name: string }): Promise<SecurityKeyInfo> {
    await this.reauth(input.password);
    const twoStep = this.serverAccount().twoStep;
    if (!twoStep) throw new VaultError('serverError', 'Turn on two-step sign-in with an authenticator app first.');
    if (!this.securityKeysWork()) throw new VaultError('securityKeyUnsupported');
    const { credentialId } = await createSecurityKey({
      challenge: base64UrlEncode(randomBytes(32)),
      rp: { id: location.hostname, name: 'Octa Pass' },
      user: { id: base64UrlEncode(randomBytes(16)), name: this.session.email!, displayName: this.session.email! },
      algorithms: [-7, -8],
      excludeCredentials: twoStep.securityKeys.map((k) => k.credentialId),
      timeout: 120_000,
    });
    if (twoStep.securityKeys.some((k) => k.credentialId === credentialId)) throw new VaultError('alreadyExists');
    const key = { id: uuidv7(), name: input.name.trim().slice(0, 64) || 'Security key', createdAt: new Date().toISOString(), credentialId };
    twoStep.securityKeys.push(key);
    await this.saveServer('security-key-added');
    const { credentialId: _credentialId, ...info } = key;
    return info;
  }

  async removeSecurityKey(input: { id: string; password: string }): Promise<void> {
    await this.reauth(input.password);
    const twoStep = this.serverAccount().twoStep;
    if (!twoStep?.securityKeys.some((k) => k.id === input.id)) throw new VaultError('notFound');
    twoStep.securityKeys = twoStep.securityKeys.filter((k) => k.id !== input.id);
    await this.saveServer('security-key-removed');
  }

  async renewRecoveryCodes(password: string): Promise<string[]> {
    await this.reauth(password);
    const twoStep = this.serverAccount().twoStep;
    if (!twoStep) throw new VaultError('serverError', 'Two-step sign-in is off.');
    twoStep.recoveryCodes = newRecoveryCodes();
    await this.saveServer('recovery-codes-renewed');
    return twoStep.recoveryCodes.map(showRecoveryCode);
  }

  async disableTwoStep(password: string): Promise<void> {
    await this.reauth(password);
    const account = this.serverAccount();
    if (!account.twoStep) return;
    delete account.twoStep;
    await this.saveServer('two-step-disabled');
  }

  /** The mock has only this browser's device, which stays trusted. */
  async forgetTrustedDevices(): Promise<void> {
    this.serverAccount();
    await this.saveServer('trusted-devices-forgotten');
  }

  // ---------- Device unlock ----------

  async getUnlockMethods(): Promise<UnlockMethods> {
    const platform = detectPlatform();
    const record = this.currentDeviceUnlock();
    return {
      deviceUnlockSupported: await isPlatformAuthenticatorAvailable(),
      deviceUnlockEnabled: Boolean(record),
      label: DEVICE_LABELS[platform],
      platform,
      passwordRequired: record ? Date.now() - Date.parse(record.lastPasswordUnlockAt) > PASSWORD_RECHECK_MS : false,
    };
  }

  async enableDeviceUnlock(): Promise<void> {
    const state = this.unlockedState();
    const key = accountKey(this.session.serverUrl!, this.session.email!);
    // A copy: the prompts can take minutes, and locking meanwhile zeroes the session's ASK.
    const ask = state.ask.slice();
    try {
      const { id: credentialId, prf } = await setUpDeviceCredential(this.session.email!);
      if (this.unlocked !== state) throw new VaultError('locked');
      const deviceSalt = randomBytes(16);
      const wrappedAsk = await sealBytes(await deriveDeviceKey(prf, deviceSalt), ask, 'device-unlock');
      prf.fill(0);
      this.deviceUnlock[key] = {
        accountId: key,
        credentialId: toBase64(credentialId),
        deviceSalt: toBase64(deviceSalt),
        wrappedAsk,
        enabledAt: new Date().toISOString(),
        // The last real master password check, so turning this off and on can't skip the 14-day rule.
        lastPasswordUnlockAt: state.passwordCheckedAt,
      };
      await this.store.set(KEYS.deviceUnlock, this.deviceUnlock);
    } finally {
      ask.fill(0);
    }
  }

  async disableDeviceUnlock(): Promise<void> {
    const { email, serverUrl } = this.session;
    if (email && serverUrl) await this.removeDeviceUnlock(accountKey(serverUrl, email));
  }

  async unlockWithDevice(): Promise<void> {
    const { email, serverUrl } = this.session;
    if (this.session.status !== 'locked' || !email || !serverUrl) throw new VaultError('locked');
    const record = this.currentDeviceUnlock();
    const account = this.server[accountKey(serverUrl, email)];
    if (!record || !account) throw new VaultError('deviceUnlockFailed');
    if (Date.now() - Date.parse(record.lastPasswordUnlockAt) > PASSWORD_RECHECK_MS) throw new VaultError('passwordRequired');

    const prf = await evaluatePrf(fromBase64(record.credentialId));
    let unlocked: Unlocked;
    try {
      const ask = await openBytes(await deriveDeviceKey(prf, fromBase64(record.deviceSalt)), record.wrappedAsk, 'device-unlock');
      const vaultKey = await importAsk(ask);
      unlocked = { ask, vaultKey, data: await openJson<VaultData>(vaultKey, account.vault, 'vault'), passwordCheckedAt: record.lastPasswordUnlockAt };
    } catch {
      // A different passkey answered, or the record was tampered with: it can never work again.
      await this.removeDeviceUnlock(record.accountId);
      throw new VaultError('deviceUnlockFailed');
    } finally {
      prf.fill(0);
    }
    // The master password may have unlocked the vault while the device prompt was open.
    if (this.session.status !== 'locked') {
      unlocked.ask.fill(0);
      return;
    }
    this.unlocked = unlocked;
    this.purgeExpiredTrash();
    this.setSession({ ...this.session, status: 'unlocked' });
    this.emitItems();
  }

  // ---------- Vault ----------

  async listVaults(): Promise<Vault[]> {
    return structuredClone(this.vault().vaults);
  }

  async listItems(filter?: ItemFilter): Promise<ItemSummary[]> {
    await this.network(0.3);
    return this.vault()
      .items.map(summarizeItem)
      .filter((s) => matchesFilter(s, filter))
      .sort(compareSummaries);
  }

  async getItem(id: string): Promise<Item> {
    return structuredClone(this.findItem(id));
  }

  async saveItem(draft: ItemDraft): Promise<Item> {
    const saved = await this.write((data) => {
      const vault = data.vaults.find((v) => v.id === draft.vaultId);
      if (!vault) throw new VaultError('notFound');
      if (vault.role === 'read') throw new VaultError('readOnlyVault');
      const now = new Date();
      const existing = draft.id ? data.items.find((i) => i.id === draft.id) : undefined;
      if (draft.id && !existing) throw new VaultError('notFound');

      if (existing && draft.revision !== undefined && draft.revision !== existing.revision) {
        // Someone else changed it first: keep both instead of silently dropping their edit.
        const copy = this.newItem(keepAttachments({ ...draft, overview: { ...draft.overview, title: `${draft.overview.title} (conflicting copy)` } }, undefined), now);
        data.items.push(copy);
        return copy;
      }
      if (existing) {
        const next = keepAttachments(withPasswordHistory(existing, draft, now), existing);
        const updated = { ...existing, vaultId: next.vaultId, overview: next.overview, details: next.details, revision: existing.revision + 1, updatedAt: now.toISOString() };
        data.items[data.items.indexOf(existing)] = updated;
        const { revision, updatedAt, overview, details } = existing;
        this.versions.set(existing.id, [{ revision, updatedAt, overview, details }, ...(this.versions.get(existing.id) ?? [])].slice(0, 10));
        return updated;
      }
      const created = this.newItem(keepAttachments(draft, undefined), now);
      data.items.push(created);
      return created;
    });
    return structuredClone(saved);
  }

  async itemVersions(id: string): Promise<ItemVersion[]> {
    await this.getItem(id);
    return structuredClone(this.versions.get(id) ?? []);
  }

  async restoreItemVersion(id: string, revision: number): Promise<Item> {
    const version = this.versions.get(id)?.find((one) => one.revision === revision);
    if (!version) throw new VaultError('notFound');
    return this.saveItem(restoredVersion(await this.getItem(id), version));
  }

  private async updateTotp(id: string, totp: (current: string) => string | Promise<string>): Promise<Item> {
    const item = await this.getItem(id);
    const login = loginDetails(item);
    if (!login?.totp || !isHotp(login.totp)) throw new VaultError('notFound');
    const next = await totp(login.totp);
    const saved = await this.write((data) => {
      const stored = data.items.find((one) => one.id === id)!;
      stored.details = { ...login, totp: next };
      stored.revision += 1;
      return stored;
    });
    return structuredClone(saved);
  }

  async nextHotpCode(id: string): Promise<HotpCode> {
    let code: HotpCode | undefined;
    await this.updateTotp(id, async (totp) => {
      const next = await nextHotp(totp);
      code = next.code;
      return next.totp;
    });
    return code!;
  }

  setHotpCounter(id: string, counter: number): Promise<Item> {
    return this.updateTotp(id, (totp) => withHotpCounter(totp, counter));
  }

  private equivalentItems(): Promise<ItemSummary[]> {
    return this.listItems({ type: 'equivalentDomains' });
  }

  async equivalentDomains(): Promise<EquivalentDomains> {
    const [first] = await this.equivalentItems();
    const details = first && ((await this.getItem(first.id)).details as EquivalentDomainsDetails);
    return { groups: details?.groups ?? [], excludedDefaults: details?.excludedDefaults ?? [], defaults: [['google.com', 'youtube.com', 'gmail.com'], ['apple.com', 'icloud.com']] };
  }

  /** Stands in for the core: a domain needs a dot and a letter after it, and nothing else is checked. */
  async saveEquivalentDomains(input: { groups: string[][]; excludedDefaults: string[] }): Promise<EquivalentDomains & { rejected: string[] }> {
    const rejected = input.groups.flat().filter((domain) => !/^[\w-]+(\.[\w-]+)*\.[a-z]{2,}$/i.test(domain.trim()));
    const groups = input.groups.map((group) => group.map((domain) => domain.trim().toLowerCase()).filter((domain) => !rejected.includes(domain))).filter((group) => group.length > 1);
    await storeEquivalentDomains(
      {
        items: async () => Promise.all((await this.equivalentItems()).map((summary) => this.getItem(summary.id))),
        vaults: () => this.listVaults(),
        save: (draft) => this.saveItem(draft),
        trash: (id) => this.deleteItem(id),
      },
      { groups, excludedDefaults: input.excludedDefaults },
    );
    return { ...(await this.equivalentDomains()), rejected };
  }

  async generatePasswordForSite(_url: string, options: Extract<GeneratorOptions, { kind: 'password' }>): Promise<string> {
    return generatePassword(options);
  }

  async deleteItem(id: string): Promise<void> {
    await this.updateItem(id, (item, now) => ({ ...item, deletedAt: now }));
  }

  async restoreItem(id: string): Promise<void> {
    await this.updateItem(id, ({ deletedAt: _deletedAt, ...item }, now) => ({ ...item, updatedAt: now }));
  }

  onItemsChange(cb: () => void): () => void {
    this.itemListeners.add(cb);
    return () => this.itemListeners.delete(cb);
  }

  // ---------- Attachments ----------
  // Files are sealed with the vault key and kept in this browser's IndexedDB.

  async addAttachment(itemId: string, file: Blob, name: string): Promise<Item> {
    const item = this.findItem(itemId);
    if (item.deletedAt) throw new VaultError('notFound');
    if (file.size > MOCK_MAX_FILE) throw new VaultError('fileTooLarge');
    if (this.attachmentBytes() + file.size > MOCK_ATTACHMENT_QUOTA) throw new VaultError('quotaExceeded');
    const { vaultKey } = this.unlockedState();
    const id = uuidv7();
    const sealed = await sealBytes(vaultKey, new Uint8Array(await file.arrayBuffer()), attachmentKey(id));
    await this.store.set(attachmentKey(id), sealed);
    const attachment: Attachment = { id, name: name || 'file', type: file.type, size: file.size, key: '' };
    return this.changeAttachments(itemId, (list) => [...list, attachment]);
  }

  async getAttachment(itemId: string, attachmentId: string): Promise<Blob> {
    const attachment = attachmentsOf(this.findItem(itemId)).find((a) => a.id === attachmentId);
    const sealed = attachment && (await this.store.get<Sealed>(attachmentKey(attachmentId)));
    if (!attachment || !sealed) throw new VaultError('notFound');
    await this.network();
    const bytes = await openBytes(this.unlockedState().vaultKey, sealed, attachmentKey(attachmentId));
    return new Blob([bytes], { type: attachment.type });
  }

  async removeAttachment(itemId: string, attachmentId: string): Promise<Item> {
    if (!attachmentsOf(this.findItem(itemId)).some((a) => a.id === attachmentId)) throw new VaultError('notFound');
    const item = await this.changeAttachments(itemId, (list) => list.filter((a) => a.id !== attachmentId));
    await this.store.delete(attachmentKey(attachmentId));
    return item;
  }

  async getStorageUsage(): Promise<StorageUsage> {
    await this.network(0.3);
    return { attachmentBytes: this.attachmentBytes(), maxAttachmentBytes: MOCK_ATTACHMENT_QUOTA, maxFileBytes: MOCK_MAX_FILE };
  }

  private attachmentBytes(): number {
    return this.vault().items.reduce((sum, item) => sum + attachmentsOf(item).reduce((n, a) => n + a.size, 0), 0);
  }

  private async changeAttachments(itemId: string, change: (list: Attachment[]) => Attachment[]): Promise<Item> {
    await this.updateItem(itemId, (item, now) => ({ ...item, details: withAttachments(item.details, change(attachmentsOf(item))), updatedAt: now }));
    return structuredClone(this.findItem(itemId));
  }

  // ---------- Tools ----------

  generatePassword(opts: GeneratorOptions): string {
    return generatePassword(opts);
  }

  estimateStrength(password: string): StrengthEstimate {
    return estimateStrength(password, this.session.email ? [this.session.email, this.session.email.split('@')[0]!] : undefined);
  }

  totpCode(totp: string, at?: number): Promise<TotpCode> {
    return totpCode(totp, at);
  }

  checkBreached(password: string): Promise<number> {
    return this.checkBreachedImpl(password);
  }

  async getHealthReport(): Promise<HealthReport> {
    const items = this.vault().items.filter((i) => !i.deletedAt);
    return buildHealthReport(items, { estimateStrength: (p) => this.estimateStrength(p), checkBreached: (p) => this.checkBreached(p) });
  }

  /** The demo finds one breach for addresses at `pwned.example`. Nothing leaves the page. */
  async lookupEmailBreaches(address: string): Promise<EmailBreach[]> {
    await this.network();
    if (!address.endsWith('@pwned.example')) return [];
    return [{ name: 'DemoBreach', title: 'Demo breach', domain: 'demo.example', breachDate: '2026-01-15', dataClasses: ['Email addresses', 'Passwords'] }];
  }

  /** The demo has no core: CXF and the encrypted export need the real app. */
  async exportVault(format: ExportFormat, options?: ExportOptions): Promise<Blob> {
    if (options?.masterPassword !== undefined) await this.reauth(options.masterPassword);
    const { vaults, items } = this.vault();
    const live = items.filter((i) => !i.deletedAt);
    if (format !== 'json' && format !== 'csv') throw new VaultError('serverError', 'This export isn’t available in the demo.');
    const file = format === 'json' ? new Blob([exportJson(vaults, live)], { type: 'application/json' }) : new Blob([exportCsv(vaults, live)], { type: 'text/csv' });
    const device = this.vault().sharing?.devices.find((d) => d.current);
    await this.write((data) => {
      const event: SecurityEvent = { type: 'vault-exported', createdAt: new Date().toISOString(), exportFormat: format, exportAttachments: false };
      if (device) Object.assign(event, { deviceName: device.name, devicePlatform: device.platform });
      (data.sharing ??= emptySharing()).log.push(event);
    });
    return file;
  }

  async importFile(source: ImportSource, file: File, _options?: ImportOptions): Promise<ImportResult> {
    this.vault();
    const parsed = parseImport(source, await file.text());
    await this.write((data) => {
      const personal = data.vaults.find((v) => v.type === 'personal')!;
      const now = new Date();
      for (const entry of parsed.items) data.items.push(this.newItem({ vaultId: personal.id, ...entry }, now));
    });
    return { imported: parsed.items.length, skipped: parsed.skipped, warnings: parsed.warnings };
  }

  async reviewImport(source: ImportSource, file: Blob, _options?: ImportOptions): Promise<ImportReview> {
    this.vault();
    if (source !== 'otpauth') throw new VaultError('invalidImportFile', 'The demo reviews otpauth:// links only.');
    const logins = await this.listItems();
    const { codes, skipped } = parseOtpLinks(await file.text(), logins);
    const id = uuidv7();
    this.reviews.set(id, codes);
    const warnings = skipped ? [`${skipped} ${skipped === 1 ? 'line isn’t' : 'lines aren’t'} an otpauth:// link.`] : [];
    return { id, codes: codes.map(({ uri: _uri, ...code }, index) => ({ index, ...code })), otherItems: 0, skipped, warnings };
  }

  async finishImport(reviewId: string, links: CodeLink[]): Promise<ImportResult> {
    const codes = this.reviews.get(reviewId);
    if (!codes) throw new VaultError('importReviewExpired');
    this.reviews.delete(reviewId);
    const chosen = codes.map((code, index) => {
      const link = links.find((l) => l.code === index);
      return link ? { ...code, loginId: link.loginId } : code;
    });
    const used = new Set<string>();
    let imported = 0;
    for (const code of chosen) {
      if (code.loginId && !used.has(code.loginId)) {
        used.add(code.loginId);
        const item = await this.getItem(code.loginId);
        await this.saveItem({ ...item, details: { ...(item.details as LoginDetails), totp: code.uri } });
      } else {
        const vault = (await this.listVaults()).find((v) => v.type === 'personal')!;
        await this.saveItem({
          vaultId: vault.id,
          overview: { schemaVersion: 1, type: 'login', title: code.title, ...(code.account ? { subtitle: code.account } : {}) },
          details: { schemaVersion: 1, ...(code.account ? { username: code.account } : {}), totp: code.uri },
        });
      }
      imported++;
    }
    return { imported, skipped: 0, warnings: [] };
  }

  async cancelImport(reviewId: string): Promise<void> {
    this.reviews.delete(reviewId);
  }

  readQrCodes(image: Blob): Promise<string[]> {
    return readMockQrCodes(image);
  }

  async summarizeQrScans(texts: string[]): Promise<QrScan> {
    return summarizeLinks(texts);
  }

  // ---------- Internals ----------

  private network(scale = 1): Promise<void> {
    const [min, max] = this.options.latency;
    const ms = (min + Math.random() * (max - min)) * scale;
    return ms > 0 ? new Promise((resolve) => setTimeout(resolve, ms)) : Promise.resolve();
  }

  private deviceAccount(serverUrl: string, email: string): DeviceAccount | undefined {
    return this.device.find((d) => d.serverUrl === serverUrl && d.email === email);
  }

  private async rememberDevice(account: DeviceAccount): Promise<void> {
    this.device = [...this.device.filter((d) => accountKey(d.serverUrl, d.email) !== accountKey(account.serverUrl, account.email)), account];
    await this.store.set(KEYS.device, this.device);
  }

  private async openVault(account: ServerAccount, password: string, secretKey: string): Promise<Unlocked> {
    let ask: Uint8Array<ArrayBuffer>;
    try {
      ask = await openBytes(await derivePasswordKey(password, secretKey, account.salt), account.wrappedAsk, 'ask');
    } catch {
      throw new VaultError('invalidCredentials');
    }
    const vaultKey = await importAsk(ask);
    return { ask, vaultKey, data: await openJson<VaultData>(vaultKey, account.vault, 'vault'), passwordCheckedAt: new Date().toISOString() };
  }

  private serverAccount(): ServerAccount {
    return this.server[accountKey(this.session.serverUrl!, this.session.email!)]!;
  }

  /** A fresh proof of the master password or device unlock (SSH private keys, reveal/copy/export). */
  async confirmIdentity(proof: SshKeyConfirmation): Promise<void> {
    if ('password' in proof) return this.reauth(proof.password);
    this.vault();
    const record = this.currentDeviceUnlock();
    if (!record) throw new VaultError('deviceUnlockFailed');
    const prf = await evaluatePrf(fromBase64(record.credentialId));
    try {
      (await openBytes(await deriveDeviceKey(prf, fromBase64(record.deviceSalt)), record.wrappedAsk, 'device-unlock')).fill(0);
    } catch {
      throw new VaultError('deviceUnlockFailed');
    }
  }

  async canConfirmIdentityWithDevice(): Promise<boolean> {
    return this.currentDeviceUnlock() !== undefined;
  }

  private async reauth(password: string): Promise<void> {
    this.vault();
    const device = this.deviceAccount(this.session.serverUrl!, this.session.email!)!;
    (await this.openVault(this.serverAccount(), normalizePassword(password), device.secretKey)).ask.fill(0);
    await this.network();
  }

  /** Saves a two-step change on the pretend server and notes it in the security log. */
  private async saveServer(event: SecurityEventType): Promise<void> {
    await this.store.set(KEYS.server, this.server);
    await this.logEvent(event);
  }

  private logEvent(type: SecurityEventType): Promise<void> {
    return this.write((data) => void (data.sharing ??= emptySharing()).log.push({ type, createdAt: new Date().toISOString() }));
  }

  /** The mock's security keys belong to this page's own host, so only WebAuthn support matters. */
  private securityKeysWork(): boolean {
    return typeof location !== 'undefined' && securityKeysSupported(location.hostname);
  }

  private dropWaitingTwoStep(): void {
    this.waitingTwoStep?.unlocked.ask.fill(0);
    this.waitingTwoStep = undefined;
  }

  private unlockedState(): Unlocked {
    if (!this.unlocked) throw new VaultError('locked');
    return this.unlocked;
  }

  private forgetKeys(): void {
    this.unlocked?.ask.fill(0);
    this.unlocked = undefined;
    this.totpSetup = undefined;
  }

  private currentDeviceUnlock(): DeviceUnlockRecord | undefined {
    const { email, serverUrl } = this.session;
    return email && serverUrl ? this.deviceUnlock[accountKey(serverUrl, email)] : undefined;
  }

  private async notePasswordUnlock(key: string): Promise<void> {
    const record = this.deviceUnlock[key];
    if (!record) return;
    record.lastPasswordUnlockAt = new Date().toISOString();
    await this.store.set(KEYS.deviceUnlock, this.deviceUnlock);
  }

  private async removeDeviceUnlock(key: string): Promise<void> {
    if (!this.deviceUnlock[key]) return;
    delete this.deviceUnlock[key];
    await this.store.set(KEYS.deviceUnlock, this.deviceUnlock);
  }

  private async startSession(serverUrl: string, email: string, unlocked: Unlocked): Promise<void> {
    this.unlocked = unlocked;
    this.purgeExpiredTrash();
    await this.store.set(KEYS.session, { email, serverUrl } satisfies RememberedAccount);
    this.setSession({ status: 'unlocked', email, serverUrl });
    this.emitItems();
  }

  /** Every way the mock opens a vault is the user's own check, so an unlocked session is `confirmed`. */
  private setSession(session: SessionState): void {
    session = withConfirmed(session, session.status === 'unlocked');
    this.session = session;
    for (const cb of this.sessionListeners) cb(session);
  }

  private emitItems(): void {
    for (const cb of this.itemListeners) cb();
  }

  private vault(): VaultData {
    return this.unlockedState().data;
  }

  private findItem(id: string): Item {
    const item = this.vault().items.find((i) => i.id === id);
    if (!item) throw new VaultError('notFound');
    return item;
  }

  private newItem(draft: ItemDraft, now: Date): Item {
    const at = now.toISOString();
    return { id: uuidv7(now.getTime()), vaultId: draft.vaultId, revision: 1, createdAt: at, updatedAt: at, overview: draft.overview, details: draft.details };
  }

  private async updateItem(id: string, change: (item: Item, now: string) => Item): Promise<void> {
    this.findItem(id);
    await this.write((data) => {
      const item = data.items.find((i) => i.id === id);
      if (!item) throw new VaultError('notFound');
      if (data.vaults.find((v) => v.id === item.vaultId)?.role === 'read') throw new VaultError('readOnlyVault');
      data.items[data.items.indexOf(item)] = { ...change(item, new Date().toISOString()), revision: item.revision + 1 };
    });
  }

  private purgeExpiredTrash(): void {
    if (!this.unlocked) return;
    const cutoff = Date.now() - TRASH_DAYS * 86_400_000;
    const expired = (i: Item) => Boolean(i.deletedAt) && Date.parse(i.deletedAt!) <= cutoff;
    for (const attachment of this.unlocked.data.items.filter(expired).flatMap(attachmentsOf)) {
      void this.store.delete(attachmentKey(attachment.id));
    }
    this.unlocked.data.items = this.unlocked.data.items.filter((i) => !expired(i));
  }

  /**
   * Runs a change after the simulated round trip, against the session that started it. If the vault
   * locked in between, the change is refused rather than applied to a session that no longer exists.
   * The seal uses that session's key, so a lock during sealing can't lose or misplace the write.
   */
  private async write<T>(change: (data: VaultData) => T): Promise<T> {
    const state = this.unlockedState();
    const { email, serverUrl } = this.session;
    await this.network();
    if (this.unlocked !== state) throw new VaultError('locked');
    const result = change(state.data);
    this.server[accountKey(serverUrl!, email!)]!.vault = await sealJson(state.vaultKey, state.data, 'vault');
    await this.store.set(KEYS.server, this.server);
    this.emitItems();
    return result;
  }
}
