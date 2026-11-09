// The real vault service logic: account, session, sync and item encryption through the WASM core.
// It's host-neutral on purpose: no window, document or Worker. Whoever hosts it (the web vault's
// worker today, an extension service worker or a desktop shell later) passes in storage, fetch, a
// cross-context lock and an event sink, and keeps the secrets on its side of the boundary.

import type * as CoreModule from '@octapass/core';
import type { DerivedKeys, OpenedInbox, RandomGeneratorOptions, Session } from '@octapass/core';
import { isVaultError, VaultError } from '../errors';
import type { KeyValueStore } from '../idb';
import { attachmentsOf, compareSummaries, isValidEmail, keepAttachments, loginDetails, matchesFilter, normalizeEmail, restoredVersion, summarizeItem, withAttachments, withPasswordHistory } from '../items';
import { storeEquivalentDomains } from '../equivalentDomains';
import { serverOrigin } from '../serverUrl';
import { createBreachChecker } from '../tools/breach';
import { buildHealthReport } from '../tools/health';
import { estimateStrength } from '../tools/strength';
import { createHealthDataStore, healthDataDownload, type HealthDataStore } from '../tools/healthData';
import { isHotp } from '../tools/totp';
import { sshCall } from '../sshKeys';
import { existingLogins, exportVaultFile, importVaultFile, PendingImports, readQrCodes, summarizeQrScans, type ImportTarget, type QrImages } from '../tools/transfer';
import { isLocalServer, withConfirmed, type ConnectEventDetail, type ServiceAccount } from '../types';
import type {
  AccountLookup,
  AccountSummary,
  Attachment,
  CreatedShareLink,
  Device,
  EmergencyAccessLevel,
  EmergencyContact,
  EmergencyContacts,
  EmergencyScope,
  EmergencyVaultView,
  NewRecoveryKit,
  ExportFormat,
  ExportOptions,
  FamilyState,
  Fingerprint,
  EmailBreach,
  KeyLogState,
  HealthReport,
  CodeLink,
  ImportOptions,
  ImportResult,
  ImportReview,
  ImportSource,
  QrScan,
  Item,
  ItemDraft,
  ItemFilter,
  ItemSummary,
  LoginDetails,
  RecoveryKit,
  RememberedAccount,
  ServerInfo,
  SessionState,
  SecurityEvent,
  SessionStatus,
  ShareLinkEnvelope,
  ShareLinkInfo,
  ShareLinkOptions,
  SharedItem,
  SshKeyKind,
  SshKeyMaterial,
  StorageUsage,
  SecurityKeyInfo,
  TotpCode,
  TotpSetup,
  OrgAccessGrant,
  OrgPolicies,
  OrgRole,
  OrgSamlInput,
  SsoRequired,
  TwoStepMethod,
  TwoStepProof,
  TwoStepStatus,
  Vault,
  VaultMember,
  VaultRole,
  EquivalentDomains,
  EquivalentDomainsDetails,
  HotpCode,
  ItemVersion,
} from '../types';
import {
  createApi,
  type Api,
  type BatchOperation,
  type ItemRecord,
  type LoginFinishResponse,
  type ReauthPurpose,
  type SecondFactorChallenge,
  type SecondFactorProof,
  type SsoChallenge,
  type SyncResponse,
  type WebAuthnAssertion,
  type WebAuthnAttestation,
  type WebAuthnCreationOptions,
  type WebAuthnRequestOptions,
} from './api';
import { Attachments } from './attachments';
import { runBatch } from './batch';
import { EmergencyAccess } from './emergency';
import { ApiProblem, HttpClient } from './http';
import { KeyLogEngine, type KeyLogCore } from './keyLog';
import { LiveConnection, type LiveMessage } from './live';
import { OrganisationEngine } from './organisations';
import { SharingEngine } from './sharing';
import { ShareLinks } from './shareLinks';
import { accountKey, LocalStore, type DeviceAccount, type StoredSession } from './store';
import { VaultIndex } from './vaultIndex';

export type Core = Pick<
  typeof CoreModule,
  | 'Signup'
  | 'DerivedKeys'
  | 'Session'
  | 'newId'
  | 'normalizeSecretKey'
  | 'totpCode'
  | 'keyFingerprint'
  | 'createShareLink'
  | 'openShareLink'
  | 'attachmentEncryptedSize'
  | 'importFile'
  | 'ExportWriter'
  | 'ExportReader'
  | 'exportCxf'
  | 'isEncryptedExport'
  | 'relinkImportedItems'
  | 'linkImportedCodes'
  | 'readQrPixels'
  | 'summarizeQrScans'
  | 'generateSshKey'
  | 'readSshKey'
  | 'writeSshKey'
  | 'nextHotpCode'
  | 'withHotpCounter'
  | 'cleanEquivalentGroups'
  | 'defaultEquivalentDomains'
  | 'equivalentMatchOptions'
  | 'generateForSite'
> &
  QrImages &
  KeyLogCore;

/** The toolkit's part of the WASM core: in the tools and full builds, not in the web vault's own. */
export interface ToolsCore {
  toolRun(op: string, input: string): string;
  StreamHasher: new (algorithms: string[]) => { update(chunk: Uint8Array): void; finish(): string };
}

/** The core's error code travels in the message: apps translate it. */
function toolCall<T>(fn: () => T): T {
  try {
    return fn();
  } catch (error) {
    throw new VaultError('toolFailed', (error as { code?: string }).code ?? 'unknown');
  }
}

async function hashStream(core: ToolsCore, file: Blob, algorithms: string[]): Promise<string> {
  const hasher = new core.StreamHasher(algorithms);
  const reader = file.stream().getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    hasher.update(value);
  }
  return hasher.finish();
}

/** Device unlock asks for the master password again after this long (plan 11). */
export const PASSWORD_RECHECK_MS = 14 * 86_400_000;
const SIGNUP_TTL_MS = 15 * 60_000;
/** The server keeps a master password reset this long. */
const RESET_TTL_MS = 15 * 60_000;
/** Guards against a server that never stops saying `hasMore`. */
const MAX_SYNC_PAGES = 1000;

export interface Snapshot {
  session: SessionState;
  remembered: RememberedAccount[];
}

/**
 * What `signIn` ended with, before the page drops the methods it can't use: security keys only work
 * where WebAuthn runs for `webauthn.rpId`, which only the page knows.
 */
export type EngineSignInResult = { status: 'signedIn' } | { status: 'twoStepRequired'; methods: TwoStepMethod[]; webauthn?: WebAuthnRequestOptions } | SsoRequired;

/** A security key's answer comes from the page, which runs the WebAuthn prompt. */
export type EngineTwoStepProof = Exclude<TwoStepProof, { method: 'securityKey' }> | { method: 'securityKey'; assertion: WebAuthnAssertion };

/** The page works out `securityKeysSupported` from `rpId`. */
export type EngineTwoStepStatus = Omit<TwoStepStatus, 'securityKeysSupported'> & { rpId: string };

/** `sharing`: members, families, invitations, share links or emergency contacts changed. */
export type EngineEvent = { type: 'session'; snapshot: Snapshot } | { type: 'items' } | { type: 'sharing' };

export interface EngineOptions {
  /** Loads and initialises the WASM core. Called once, on first need. */
  loadCore: () => Promise<Core>;
  /**
   * Loads the full WASM core (`@octapass/core/full`), for imports `loadCore`'s build can't read
   * (Proton Pass's PGP-encrypted export: the web vault's core leaves OpenPGP out for size). Only
   * called for such a file.
   */
  loadFullCore?: () => Promise<Pick<Core, 'importFile'>>;
  /** The developer toolkit, for a host whose `loadCore` build leaves it out (the web vault). */
  loadToolsCore?: () => Promise<ToolsCore>;
  storage: KeyValueStore;
  emit: (event: EngineEvent) => void;
  fetch?: typeof fetch;
  /** Runs `fn` while holding a lock shared with every other context of this app (other tabs). */
  withLock?: <T>(name: string, fn: () => Promise<T>) => Promise<T>;
  /** How this device appears in the account's device list. */
  device?: { name: string; platform: string };
  /** Pwned Passwords base URL, for tests. */
  breachApiUrl?: string;
  now?: () => number;
  /** For live notifications (`GET /v1/ws`); `false` turns them off. Defaults to the global WebSocket. */
  WebSocket?: typeof WebSocket | false;
  /** The encrypted export's Argon2id settings, for tests. Default: the core's (256 MiB). */
  exportKdf?: CoreModule.KdfParams;
}

interface PendingSignup {
  serverUrl: string;
  email: string;
  signup: CoreModule.Signup;
  registerFinish: CoreModule.RegisterFinish;
  expiresAt: number;
}

/** A master password reset with the recovery code, from the emailed code to the new password. */
interface PendingReset {
  serverUrl: string;
  email: string;
  expiresAt: number;
  /** After `verifyPasswordReset`: the account bundle and the server's challenge to sign. */
  verified?: { account: CoreModule.AccountBundle; challenge: string };
}

/**
 * What `finishPasswordReset` ended with: the new Recovery Kit, and how signing in went. No `signIn`
 * when signing in failed (offline, say): the new password is set, so sign in by hand.
 */
export type EngineResetResult = { recoveryKit: RecoveryKit; signIn?: EngineSignInResult };

/** A sign-in waiting for its second step. The derived keys wait with it, in memory only. */
interface WaitingTwoStep {
  result: Extract<EngineSignInResult, { status: 'twoStepRequired' }>;
  serverUrl: string;
  email: string;
  secretKey: string;
  keys: DerivedKeys;
  challengeId: string;
  expiresAt: number;
}

/** A sign-in waiting for the identity provider. The derived keys wait with it, in memory only. */
interface WaitingSso {
  result: Extract<EngineSignInResult, { status: 'ssoRequired' }>;
  serverUrl: string;
  email: string;
  secretKey: string;
  keys: DerivedKeys;
  challengeId: string;
  expiresAt: number;
}

/** The challenge in an `sso-required` answer, if that's what `error` is. */
function ssoChallenge(error: unknown): SsoChallenge | undefined {
  if (!(error instanceof ApiProblem) || error.status !== 401 || error.type !== 'sso-required') return undefined;
  return error.body.sso as SsoChallenge | undefined;
}

const TWO_STEP_METHODS: Record<SecondFactorChallenge['methods'][number], TwoStepMethod> = { totp: 'totp', webauthn: 'securityKey', 'recovery-code': 'recoveryCode' };

/** The challenge in a `second-factor-required` answer, if that's what `error` is. */
function secondFactorChallenge(error: unknown): SecondFactorChallenge | undefined {
  if (!(error instanceof ApiProblem) || error.status !== 401 || error.type !== 'second-factor-required') return undefined;
  return error.body.secondFactor as SecondFactorChallenge | undefined;
}

interface Unlocked {
  session: Session;
  index: VaultIndex;
  /** When the master password was last proven, carried through device unlocks for the 14-day rule. */
  passwordCheckedAt: string;
}

/** Transient failures that shouldn't stop an unlock: the vault opens from the local copy instead. */
function isOffline(error: unknown): boolean {
  return error instanceof VaultError && (error.code === 'serverUnreachable' || error.code === 'rateLimited' || error.code === 'serverError');
}

function isProblem(error: unknown, status: number, type: string): error is ApiProblem {
  return error instanceof ApiProblem && error.status === status && error.type === type;
}

/** The server no longer takes this device's refresh token (expired, revoked, or gone from storage). */
function isRejected(error: unknown): boolean {
  return isProblem(error, 401, 'unauthorized') || isVaultError(error, 'sessionExpired');
}

let inProcessLock: Promise<unknown> = Promise.resolve();
const lockInProcess = <T>(_name: string, fn: () => Promise<T>): Promise<T> => {
  const run = inProcessLock.then(fn, fn);
  inProcessLock = run.catch(() => undefined);
  return run;
};

export class VaultEngine {
  private readonly store: LocalStore;
  private readonly checkBreachedImpl: (password: string) => Promise<number>;
  private core?: Promise<Core>;
  private status: SessionStatus = 'signedOut';
  private current: StoredSession | undefined;
  private accounts: DeviceAccount[] = [];
  private unlocked: Unlocked | undefined;
  /** The health report's site lists: the bundled ones, or a newer signed file from the server. */
  private readonly healthData: HealthDataStore;
  private accessToken: string | undefined;
  private readonly signups = new Map<string, PendingSignup>();
  private readonly resets = new Map<string, PendingReset>();
  private readonly imports = new PendingImports();
  private waitingTwoStep: WaitingTwoStep | undefined;
  private waitingSso: WaitingSso | undefined;
  /** The authenticator app being added, until its first code is confirmed. */
  private totpSetupId: string | undefined;
  private syncTail: Promise<void> = Promise.resolve();
  private queuedSync: Promise<void> | undefined;
  /** The server asked us to back off (429 with Retry-After) until this time. */
  private syncPausedUntil = 0;
  private live: LiveConnection | undefined;
  private readonly sharing: SharingEngine;
  private readonly keyLog: KeyLogEngine;
  private readonly organisations: OrganisationEngine;
  private readonly links: ShareLinks;
  private readonly emergency: EmergencyAccess;
  private readonly attachments: Attachments;

  constructor(private readonly options: EngineOptions) {
    this.store = new LocalStore(options.storage);
    this.checkBreachedImpl = createBreachChecker({
      ...(options.fetch ? { fetch: options.fetch } : {}),
      ...(options.breachApiUrl ? { baseUrl: options.breachApiUrl } : {}),
    });
    const changed = () => this.options.emit({ type: 'sharing' });
    this.healthData = createHealthDataStore(options.storage);
    const accountId = () => this.requireAccount().accountId;
    this.keyLog = new KeyLogEngine({
      core: () => this.loadCore(),
      session: () => this.requireUnlocked().session,
      api: () => this.sessionApi(),
      account: () => this.requireAccount().account,
      setAccount: async (account) => {
        this.current = { ...this.requireAccount(), account };
        await this.store.setSession(this.current);
      },
      accountId,
      store: this.store,
      now: () => this.now(),
      changed,
    });
    this.sharing = new SharingEngine({
      core: () => this.loadCore(),
      unlocked: () => this.requireUnlocked(),
      api: () => this.sessionApi(),
      accountId,
      serverUrl: () => this.requireAccount().serverUrl,
      store: this.store,
      sync: () => this.sync(),
      changed,
      keyLog: this.keyLog,
      createItem: (vaultId, draft) => {
        const state = this.requireUnlocked();
        this.writableVault(state, vaultId);
        return this.createItem(state, vaultId, draft);
      },
      saveItem: (draft) => this.saveItem(draft),
      deleteItem: (id) => this.deleteItem(id),
      listVaults: () => this.listVaults(),
      copyAttachments: (fromItemId, toItemId) => this.attachments.copyAll(fromItemId, toItemId),
    });
    this.organisations = new OrganisationEngine({
      core: () => this.loadCore(),
      unlocked: () => this.requireUnlocked(),
      api: () => this.sessionApi(),
      accountId,
      store: this.store,
      sync: () => this.sync(),
      changed,
      reauth: (password, purpose) => this.reauth(this.requireUnlocked().session, password, purpose),
      rotate: (vaultId) => this.sharing.rotate(vaultId),
      nameVault: (vaultId, name) => this.sharing.renameVault(vaultId, name),
      listVaults: () => this.listVaults(),
      keyLog: this.keyLog,
    });
    this.attachments = new Attachments({
      core: () => this.loadCore(),
      unlocked: () => this.requireUnlocked(),
      api: () => this.sessionApi(),
      writable: (vaultId) => this.writableVault(this.requireUnlocked(), vaultId),
      updateAttachments: (itemId, change) => this.updateAttachments(itemId, change),
    });
    this.links = new ShareLinks({
      core: () => this.loadCore(),
      index: () => this.requireUnlocked().index,
      api: () => this.sessionApi(),
      publicApi: (serverUrl) => this.api(serverUrl),
      accountId,
      store: this.store,
      now: () => this.now(),
      changed,
    });
    this.emergency = new EmergencyAccess({
      core: () => this.loadCore(),
      session: () => this.requireUnlocked().session,
      api: () => this.sessionApi(),
      changed,
      sync: () => this.sync(),
      reauth: (password, purpose) => this.reauth(this.requireUnlocked().session, password, purpose),
      serverUrl: () => this.current!.serverUrl,
      now: () => this.now(),
    });
  }

  // ---------- Lifecycle ----------

  /** Reads what this browser remembers. A stored session comes back locked: keys live in memory only. */
  async init(): Promise<Snapshot> {
    this.accounts = await this.store.accounts();
    const stored = await this.store.session();
    if (stored && this.deviceAccount(stored)) {
      this.current = stored;
      this.status = 'locked';
    }
    return this.snapshot();
  }

  /** Starts loading the WASM core in the background, so the first unlock doesn't wait for it. */
  async preload(): Promise<void> {
    await this.loadCore();
  }

  // ---------- Server + account ----------

  async getServerInfo(serverUrl: string): Promise<ServerInfo> {
    const info = await this.api(serverOrigin(serverUrl)).serverInfo();
    if (info.apiVersion !== 1) throw new VaultError('serverError', `Unsupported API version ${String(info.apiVersion)}`);
    return info;
  }

  async startSignup(input: { serverUrl: string; email: string; password: string }): Promise<{ signupId: string; devVerificationCode?: string }> {
    const serverUrl = serverOrigin(input.serverUrl);
    const email = normalizeEmail(input.email);
    if (!isValidEmail(email)) throw new VaultError('invalidEmail');
    const core = await this.loadCore();
    const signup = core.Signup.create(email, input.password);
    try {
      const { registrationResponse, devVerificationCode } = await this.api(serverUrl).registerStart(signup.email, signup.registrationRequest);
      // `finish` works once, so its result is kept for retries with a corrected code.
      const registerFinish = signup.finish(registrationResponse);
      const signupId = core.newId();
      this.dropExpiredSignups();
      this.signups.set(signupId, { serverUrl, email, signup, registerFinish, expiresAt: this.now() + SIGNUP_TTL_MS });
      return devVerificationCode ? { signupId, devVerificationCode } : { signupId };
    } catch (error) {
      signup.free();
      throw error;
    }
  }

  async finishSignup(input: { signupId: string; verificationCode: string }): Promise<{ recoveryKit: RecoveryKit }> {
    const pending = this.signups.get(input.signupId);
    if (!pending || pending.expiresAt < this.now()) throw new VaultError('signupExpired');
    const api = this.api(pending.serverUrl);
    await api.registerFinish({ email: pending.email, verificationCode: input.verificationCode.replace(/\s/g, ''), ...pending.registerFinish });
    this.signups.delete(input.signupId);

    const { signup } = pending;
    const recoveryKit: RecoveryKit = {
      email: pending.email,
      serverUrl: pending.serverUrl,
      secretKey: signup.secretKey,
      recoveryCode: signup.recoveryCode,
      createdAt: new Date(this.now()).toISOString(),
    };
    const keys = signup.derivedKeys();
    signup.free();
    // A new account has no second step.
    await this.signInWithKeys(api, pending.serverUrl, pending.email, recoveryKit.secretKey, keys);
    return { recoveryKit };
  }

  async signIn(input: { serverUrl: string; email: string; password: string; secretKey?: string }): Promise<EngineSignInResult> {
    const serverUrl = serverOrigin(input.serverUrl);
    const email = normalizeEmail(input.email);
    const core = await this.loadCore();
    // One the user typed wins: this device's copy is out of date after a rotation elsewhere.
    const typed = input.secretKey?.trim();
    const secretKey = typed ? core.normalizeSecretKey(typed) : this.deviceAccount({ serverUrl, email })?.secretKey;
    if (!secretKey) throw new VaultError('secretKeyRequired');
    const api = this.api(serverUrl);
    const keys = core.DerivedKeys.derive(email, input.password, secretKey, await api.prelogin(email));
    return this.signInWithKeys(api, serverUrl, email, secretKey, keys);
  }

  /** The sign-in waiting for its next step, if any: the extension popup closes while the user reads a code. */
  async pendingTwoStep(): Promise<EngineSignInResult | { status: 'twoStepExpired' } | undefined> {
    const waiting = this.waitingTwoStep ?? this.waitingSso;
    if (!waiting) return undefined;
    if (waiting.expiresAt < this.now()) {
      this.dropWaitingTwoStep();
      return { status: 'twoStepExpired' };
    }
    return waiting.result;
  }

  async cancelTwoStep(): Promise<void> {
    this.dropWaitingTwoStep();
  }

  /**
   * Finishes the SSO step with the code the browser showed. A wrong code leaves it waiting for
   * another try, and `ssoPending` means the browser hasn't finished yet. Two-step sign-in, if the
   * account has it, comes after. `twoStepExpired`: it's gone, so start over.
   */
  async finishSso(code: string): Promise<EngineSignInResult> {
    const pending = this.waitingSso;
    if (!pending || pending.expiresAt < this.now()) {
      this.dropWaitingTwoStep();
      throw new VaultError('twoStepExpired');
    }
    let login: LoginFinishResponse;
    try {
      login = await this.api(pending.serverUrl).loginSso(pending.challengeId, code.replace(/\s/g, ''));
    } catch (error) {
      const challenge = secondFactorChallenge(error);
      if (challenge && this.waitingSso === pending) {
        this.waitingSso = undefined;
        return this.waitForSecondFactor(pending.serverUrl, pending.email, pending.secretKey, pending.keys, challenge);
      }
      if (!isProblem(error, 401, 'login-failed')) throw error;
      if (this.waitingSso === pending) this.dropWaitingTwoStep();
      throw new VaultError('twoStepExpired');
    }
    if (this.waitingSso !== pending) throw new VaultError('twoStepExpired');
    this.waitingSso = undefined;
    try {
      await this.completeSignIn(pending.serverUrl, pending.email, pending.secretKey, pending.keys, login);
    } finally {
      pending.keys.free();
    }
    return { status: 'signedIn' };
  }

  /**
   * Finishes a sign-in that asked for a second step. A wrong code leaves it waiting for another try;
   * `twoStepExpired` means it's gone (too slow, too many tries, or a newer sign-in): start over.
   */
  async finishTwoStep(proof: EngineTwoStepProof): Promise<void> {
    const pending = this.waitingTwoStep;
    if (!pending || pending.expiresAt < this.now()) {
      this.dropWaitingTwoStep();
      throw new VaultError('twoStepExpired');
    }
    let body: SecondFactorProof;
    if (proof.method === 'securityKey') body = { webauthn: proof.assertion };
    else {
      const code = proof.code.trim();
      if (!code) throw new VaultError('invalidTwoStepCode');
      body = proof.method === 'totp' ? { totpCode: code.replace(/\s/g, '') } : { recoveryCode: code };
    }
    let login: LoginFinishResponse;
    try {
      login = await this.api(pending.serverUrl).loginSecondFactor(pending.challengeId, body);
    } catch (error) {
      if (!isProblem(error, 401, 'login-failed')) throw error;
      if (this.waitingTwoStep === pending) this.dropWaitingTwoStep();
      throw new VaultError('twoStepExpired');
    }
    if (this.waitingTwoStep !== pending) throw new VaultError('twoStepExpired');
    this.waitingTwoStep = undefined;
    try {
      await this.completeSignIn(pending.serverUrl, pending.email, pending.secretKey, pending.keys, login);
    } finally {
      pending.keys.free();
    }
  }

  lock(): void {
    if (this.status !== 'unlocked') return;
    this.dropKeys();
    this.setStatus('locked');
  }

  async unlock(password: string): Promise<void> {
    const current = this.lockedAccount();
    const core = await this.loadCore();
    const { secretKey } = this.deviceAccount(current)!;
    const keys = core.DerivedKeys.derive(current.email, password, secretKey, { kdf: current.account.kdf, accountSalt: current.account.accountSalt });
    try {
      const session = keys.unlock(current.account);
      if (this.status !== 'locked' || this.unlocked) {
        // Device unlock won the race while Argon2id ran.
        session.free();
        return;
      }
      const checkedAt = new Date(this.now()).toISOString();
      await this.notePasswordUnlock(current.accountId, checkedAt);
      await this.open(session, checkedAt, keys);
    } finally {
      keys.free();
    }
  }

  /** Derives the keys again from `password` (Argon2id) and checks they open the account. */
  private async checkMasterPassword(password: string): Promise<void> {
    const current = this.requireAccount();
    const core = await this.loadCore();
    const { secretKey } = this.deviceAccount(current)!;
    const keys = core.DerivedKeys.derive(current.email, password, secretKey, { kdf: current.account.kdf, accountSalt: current.account.accountSalt });
    try {
      keys.unlock(current.account).free();
    } catch {
      throw new VaultError('invalidCredentials');
    } finally {
      keys.free();
    }
  }

  /** Revokes this device's tokens and removes everything this browser holds for the account, Secret Key included. */
  async signOut(): Promise<void> {
    const current = this.current;
    if (current) {
      await this.sessionApi()
        .logout()
        .catch(() => undefined);
      await this.store.wipeAccount(current.accountId);
      this.accounts = await this.store.forgetAccount(current);
    }
    this.endSession();
  }

  async getSecretKey(): Promise<string> {
    this.requireUnlocked();
    return this.deviceAccount(this.current!)!.secretKey;
  }

  async getAccountSummary(): Promise<AccountSummary> {
    const { index } = this.requireUnlocked();
    const api = this.sessionApi();
    const me = this.current!.accountId;
    const owned = index.vaults().filter((v) => v.type !== 'personal' && v.role === 'owner');
    const [devices, soleOwner] = await Promise.all([
      api.devices(),
      Promise.all(owned.map(async (v) => ((await api.members(v.id)).members.some((m) => m.role === 'owner' && m.accountId !== me) ? [] : [index.vaultName(v)]))),
    ]);
    return {
      email: this.current!.email,
      itemCount: index.items().filter((i) => !i.deletedAt).length,
      vaultCount: index.vaults().length,
      deviceCount: devices.length,
      sharedVaultsOwned: soleOwner.flat(),
    };
  }

  async deleteAccount(input: { confirmEmail: string; password: string }): Promise<void> {
    const { session } = this.requireUnlocked();
    const current = this.current!;
    if (normalizeEmail(input.confirmEmail) !== current.email) throw new VaultError('emailMismatch');
    const reauthToken = await this.reauth(session, input.password, 'delete-account');
    await this.sessionApi().deleteAccount(reauthToken, current.email);
    await this.forgetEverything(current);
  }

  /**
   * A new master password, after checking the current one. The Secret Key and recovery code stay;
   * every other device is signed out, and device unlock has to be turned on again.
   */
  async changeMasterPassword(input: { currentPassword: string; newPassword: string }): Promise<void> {
    const { session } = this.requireUnlocked();
    const current = this.current!;
    const reauthToken = await this.reauth(session, input.currentPassword, 'change-password');
    const change = session.newCredentials(input.newPassword, this.deviceAccount(current)!.secretKey, false);
    try {
      const api = this.sessionApi();
      const { registrationResponse } = await api.passwordRegistration(change.registrationRequest);
      await api.changePassword(reauthToken, change.finish(registrationResponse));
      session.acceptCredentials(change);
    } finally {
      change.free();
    }
    if (this.current === current) {
      this.current = { ...this.current, account: session.account };
      await this.store.setSession(this.current);
    }
    await this.store.removeDeviceUnlock(current.accountId);
    if (this.unlocked?.session === session) this.unlocked.passwordCheckedAt = new Date(this.now()).toISOString();
  }

  /**
   * A new Secret Key with the same master password. The account key stays, so nothing is
   * re-encrypted; the recovery code stays unless `newRecoveryCode` is set. Every other device is
   * signed out, and device unlock has to be turned on again.
   */
  async rotateSecretKey(input: { password: string; newRecoveryCode: boolean }): Promise<NewRecoveryKit> {
    const { session } = this.requireUnlocked();
    const current = this.current!;
    const reauthToken = await this.reauth(session, input.password, 'rotate-secret-key');
    const change = session.newCredentials(input.password, undefined, input.newRecoveryCode);
    try {
      const api = this.sessionApi();
      const { registrationResponse } = await api.passwordRegistration(change.registrationRequest);
      const body = change.finish(registrationResponse);
      try {
        await api.rotateSecretKey(reauthToken, body);
      } catch (error) {
        // A lost answer must not lose the only copy of the new key: ask whether it landed.
        const stored = await api.account().catch(() => undefined);
        if (stored?.accountSalt !== body.account.accountSalt) throw error;
      }
      session.acceptCredentials(change);
      const kit: NewRecoveryKit = { email: current.email, serverUrl: current.serverUrl, secretKey: change.secretKey, createdAt: new Date(this.now()).toISOString() };
      if (change.recoveryCode) kit.recoveryCode = change.recoveryCode;
      if (this.current === current) {
        this.current = { ...this.current, account: session.account };
        await this.store.setSession(this.current);
      }
      this.accounts = await this.store.rememberAccount({ ...this.deviceAccount(current)!, secretKey: change.secretKey });
      await this.store.removeDeviceUnlock(current.accountId);
      if (this.unlocked?.session === session) this.unlocked.passwordCheckedAt = new Date(this.now()).toISOString();
      return kit;
    } finally {
      change.free();
    }
  }

  // ---------- Master password reset with the recovery code (plan 03, Recovery) ----------

  /** Emails a code to the account. The answer is the same for an email without an account. */
  async startPasswordReset(input: { serverUrl: string; email: string }): Promise<{ resetId: string; devVerificationCode?: string }> {
    const serverUrl = serverOrigin(input.serverUrl);
    const email = normalizeEmail(input.email);
    if (!isValidEmail(email)) throw new VaultError('invalidEmail');
    const { recoveryId, devVerificationCode } = await this.api(serverUrl).recoverStart(email);
    this.dropExpiredResets();
    this.resets.set(recoveryId, { serverUrl, email, expiresAt: this.now() + RESET_TTL_MS });
    return devVerificationCode ? { resetId: recoveryId, devVerificationCode } : { resetId: recoveryId };
  }

  /** Checks the emailed code. A wrong one throws `invalidVerificationCode`: try again. */
  async verifyPasswordReset(input: { resetId: string; verificationCode: string }): Promise<void> {
    const pending = this.pendingReset(input.resetId);
    const verified = await this.resetCall(input.resetId, () => this.api(pending.serverUrl).recoverVerify(input.resetId, input.verificationCode.replace(/\s/g, '')));
    pending.verified = verified;
  }

  /**
   * Opens the account key with the recovery code, sets the new master password and signs in. The
   * recovery code is replaced, and so is the Secret Key unless this device knows it: show the new
   * Recovery Kit. Every device was signed out. A recovery code that doesn't open this account throws
   * `invalidRecoveryCode`: try another.
   */
  async finishPasswordReset(input: { resetId: string; recoveryCode: string; password: string }): Promise<EngineResetResult> {
    const pending = this.pendingReset(input.resetId);
    if (!pending.verified) throw new VaultError('resetExpired');
    const { account, challenge } = pending.verified;
    const core = await this.loadCore();
    let session: Session;
    try {
      session = core.Session.recover(input.recoveryCode, account);
    } catch {
      throw new VaultError('invalidRecoveryCode');
    }
    const { serverUrl, email } = pending;
    const api = this.api(serverUrl);
    let keys: DerivedKeys;
    let recoveryKit: RecoveryKit;
    try {
      const change = session.newCredentials(input.password, this.deviceAccount({ serverUrl, email })?.secretKey, true);
      try {
        const { registrationResponse } = await this.resetCall(input.resetId, () => api.recoverRegistration(input.resetId, change.registrationRequest));
        const body = change.finish(registrationResponse);
        const signature = session.signRecovery(challenge, body.registrationUpload, body.account);
        await this.resetCall(input.resetId, () => api.recoverFinish({ ...body, recoveryId: input.resetId, signature }));
        recoveryKit = { email, serverUrl, secretKey: change.secretKey, recoveryCode: change.recoveryCode!, createdAt: new Date(this.now()).toISOString() };
        keys = change.derivedKeys();
      } finally {
        change.free();
      }
    } finally {
      session.free();
    }
    this.resets.delete(input.resetId);
    // Every device was signed out, this one included. The device unlock key would still open the
    // account key, but a new master password starts from a clean slate.
    if (account.accountId) await this.store.removeDeviceUnlock(account.accountId);
    // The new kit matters more than signing in, which can be done again by hand.
    const signIn = await this.signInWithKeys(api, serverUrl, email, recoveryKit.secretKey, keys).catch(() => undefined);
    return signIn ? { recoveryKit, signIn } : { recoveryKit };
  }

  /** Drops a reset: "Start over". */
  async cancelPasswordReset(resetId: string): Promise<void> {
    this.resets.delete(resetId);
  }

  // ---------- Two-step sign-in settings (plan 03, "Account 2FA"; the page runs the WebAuthn prompts) ----------

  async getTwoStepStatus(): Promise<EngineTwoStepStatus> {
    this.requireUnlocked();
    const { enabled, securityKeys, recoveryCodesLeft, rpId } = await this.sessionApi().twoStep();
    return { enabled, securityKeys, recoveryCodesLeft, rpId };
  }

  async startTotpSetup(password: string): Promise<TotpSetup> {
    const { session } = this.requireUnlocked();
    const reauthToken = await this.reauth(session, password, 'two-step');
    const { setupId, secret, otpauthUri } = await this.sessionApi().startTotp(reauthToken);
    this.totpSetupId = setupId;
    return { secret, otpauthUri };
  }

  async confirmTotpSetup(code: string): Promise<{ recoveryCodes?: string[] }> {
    this.requireUnlocked();
    const setupId = this.totpSetupId;
    if (!setupId) throw new VaultError('twoStepExpired');
    if (!code.trim()) throw new VaultError('invalidTwoStepCode');
    try {
      const { recoveryCodes } = await this.sessionApi().confirmTotp(setupId, code.replace(/\s/g, ''));
      this.totpSetupId = undefined;
      return recoveryCodes ? { recoveryCodes } : {};
    } catch (error) {
      // The setup expired (10 minutes) or was used up.
      if (!isProblem(error, 400, 'invalid-request')) throw error;
      this.totpSetupId = undefined;
      throw new VaultError('twoStepExpired');
    }
  }

  /** Step one of adding a security key: the options for the page's `navigator.credentials.create`. */
  async securityKeyOptions(password: string): Promise<{ setupId: string; publicKey: WebAuthnCreationOptions }> {
    const { session } = this.requireUnlocked();
    return this.sessionApi().securityKeyOptions(await this.reauth(session, password, 'two-step'));
  }

  async addSecurityKey(input: WebAuthnAttestation & { setupId: string; name: string }): Promise<SecurityKeyInfo> {
    this.requireUnlocked();
    return this.sessionApi().addSecurityKey({ ...input, name: input.name.trim() });
  }

  async removeSecurityKey(input: { id: string; password: string }): Promise<void> {
    const { session } = this.requireUnlocked();
    await this.sessionApi().removeSecurityKey(await this.reauth(session, input.password, 'two-step'), input.id);
  }

  async renewRecoveryCodes(password: string): Promise<string[]> {
    const { session } = this.requireUnlocked();
    return (await this.sessionApi().renewRecoveryCodes(await this.reauth(session, password, 'two-step'))).recoveryCodes;
  }

  async disableTwoStep(password: string): Promise<void> {
    const { session } = this.requireUnlocked();
    await this.sessionApi().disableTwoStep(await this.reauth(session, password, 'two-step'));
  }

  async forgetTrustedDevices(): Promise<void> {
    this.requireUnlocked();
    await this.sessionApi().forgetTrustedDevices();
  }

  // ---------- Device unlock (the page runs the WebAuthn ceremonies; only PRF outputs come here) ----------

  async deviceUnlockStatus(): Promise<{ enabled: boolean; passwordRequired: boolean }> {
    const record = this.current && (await this.store.deviceUnlock(this.current.accountId));
    return { enabled: Boolean(record), passwordRequired: record ? this.passwordDue(record.lastPasswordUnlockAt) : false };
  }

  async enableDeviceUnlock(credentialId: string, prfOutput: Uint8Array): Promise<void> {
    try {
      const { session, passwordCheckedAt } = this.requireUnlocked();
      const { deviceSalt, wrappedAsk } = session.enableDeviceUnlock(prfOutput);
      await this.store.setDeviceUnlock({
        accountId: this.current!.accountId,
        credentialId,
        deviceSalt,
        wrappedAsk,
        enabledAt: new Date(this.now()).toISOString(),
        // The last real master password check, so turning this off and on can't skip the 14-day rule.
        lastPasswordUnlockAt: passwordCheckedAt,
      });
    } finally {
      prfOutput.fill(0);
    }
  }

  async disableDeviceUnlock(): Promise<void> {
    if (this.current) await this.store.removeDeviceUnlock(this.current.accountId);
  }

  /** The passkey to ask for, after checking the 14-day rule. */
  async deviceUnlockCredential(): Promise<string> {
    const current = this.lockedAccount();
    const record = await this.store.deviceUnlock(current.accountId);
    if (!record) throw new VaultError('deviceUnlockFailed');
    if (this.passwordDue(record.lastPasswordUnlockAt)) throw new VaultError('passwordRequired');
    return record.credentialId;
  }

  async unlockWithDevice(prfOutput: Uint8Array): Promise<void> {
    try {
      if (this.status === 'unlocked' || this.unlocked) return; // The master password won the race.
      const current = this.lockedAccount();
      const record = await this.store.deviceUnlock(current.accountId);
      if (!record) throw new VaultError('deviceUnlockFailed');
      const core = await this.loadCore();
      let session: Session;
      try {
        session = core.Session.unlockWithDeviceKey(prfOutput, record.deviceSalt, record.wrappedAsk, current.account);
      } catch {
        // A different passkey answered, or the record was tampered with: it can never work again.
        await this.store.removeDeviceUnlock(current.accountId);
        throw new VaultError('deviceUnlockFailed');
      }
      if (this.status !== 'locked' || this.unlocked) {
        session.free();
        return;
      }
      await this.open(session, record.lastPasswordUnlockAt);
    } finally {
      prfOutput.fill(0);
    }
  }

  // ---------- Vault ----------

  async listVaults(): Promise<Vault[]> {
    // The server has no vault metadata: the personal vault is "Personal", and shared vaults carry
    // their name in an encrypted record of their own (see VAULT_INFO_TYPE).
    const { index } = this.requireUnlocked();
    return index.vaults().map((record) => {
      const vault: Vault = { id: record.id, type: record.type, role: record.role, name: index.vaultName(record) };
      if (index.isUntrusted(record.id)) vault.untrusted = true;
      return vault;
    });
  }

  async listItems(filter?: ItemFilter): Promise<ItemSummary[]> {
    return this.requireUnlocked()
      .index.items()
      .map(summarizeItem)
      .filter((s) => matchesFilter(s, filter))
      .sort(compareSummaries);
  }

  async getItem(id: string): Promise<Item> {
    const entry = this.requireUnlocked().index.get(id);
    if (!entry) throw new VaultError('notFound');
    return structuredClone(entry.item);
  }

  async saveItem(draft: ItemDraft): Promise<Item> {
    const state = this.requireUnlocked();
    const now = new Date(this.now());
    const existing = draft.id ? state.index.get(draft.id) : undefined;
    if (draft.id && !existing) throw new VaultError('notFound');
    this.writableVault(state, existing?.record.vaultId ?? draft.vaultId);

    if (!existing) return this.createItem(state, draft.vaultId, keepAttachments(draft, undefined));
    if (draft.revision !== undefined && draft.revision !== existing.record.revision) {
      // Someone else changed it first: keep both instead of silently dropping their edit.
      return this.createConflictCopy(state, existing.record.vaultId, draft);
    }
    let { record } = existing;
    const next = keepAttachments(withPasswordHistory(existing.item, draft, now), existing.item);
    let encrypted = state.index.encrypt(record.vaultId, record.id, next, record.encryptedItemKey);
    let revision: number;
    try {
      try {
        ({ revision } = await this.sessionApi().updateItem(record.vaultId, record.id, record.revision, encrypted));
      } catch (error) {
        if (!isProblem(error, 409, 'vault-key-changed')) throw error;
        // A rotation re-wrapped every item key and bumped every revision without touching item
        // bodies, so the edit still applies on top of the rotated record.
        await this.sync();
        const rotated = state.index.get(record.id);
        if (this.unlocked !== state || !rotated) throw error;
        record = rotated.record;
        encrypted = state.index.encrypt(record.vaultId, record.id, next, record.encryptedItemKey);
        ({ revision } = await this.sessionApi().updateItem(record.vaultId, record.id, record.revision, encrypted));
      }
    } catch (error) {
      if (!isProblem(error, 409, 'conflict')) throw error;
      this.applyCurrent(state, error);
      return this.createConflictCopy(state, record.vaultId, draft);
    }
    const saved = record;
    return this.afterWrite(state, () => state.index.put({ ...saved, ...encrypted, revision, updatedAt: now.toISOString() }, next));
  }

  async deleteItem(id: string): Promise<void> {
    const state = this.requireUnlocked();
    const entry = state.index.get(id);
    if (!entry) throw new VaultError('notFound');
    this.writableVault(state, entry.record.vaultId);
    const trash = (revision: number) => this.sessionApi().trashItem(entry.record.vaultId, id, revision);
    let revision: number;
    try {
      ({ revision } = await trash(entry.record.revision));
    } catch (error) {
      // Changed elsewhere since we last synced; the user still wants it in the trash.
      if (!isProblem(error, 409, 'conflict')) throw error;
      ({ revision } = await trash(this.applyCurrent(state, error).revision));
    }
    const now = new Date(this.now()).toISOString();
    this.afterWrite(state, () => {
      const latest = state.index.get(id)!;
      state.index.put({ ...latest.record, revision, updatedAt: now, deletedAt: now }, latest.item);
    });
  }

  async restoreItem(id: string): Promise<void> {
    const state = this.requireUnlocked();
    const entry = state.index.get(id);
    if (!entry) throw new VaultError('notFound');
    this.writableVault(state, entry.record.vaultId);
    const { revision } = await this.sessionApi().restoreItem(entry.record.vaultId, id);
    const { deletedAt: _deletedAt, ...record } = entry.record;
    this.afterWrite(state, () => state.index.put({ ...record, revision, updatedAt: new Date(this.now()).toISOString() }, entry.item));
  }

  // ---------- Version history and one-time counters ----------

  /** Decrypted here with the item's current key. A version it can't open is left out, not an error. */
  async itemVersions(id: string): Promise<ItemVersion[]> {
    const state = this.requireUnlocked();
    const entry = state.index.get(id);
    if (!entry) throw new VaultError('notFound');
    const { revisions } = await this.sessionApi().itemHistory(entry.record.vaultId, id);
    return revisions.flatMap(({ revision, overview, details, updatedAt }) => {
      try {
        const version = state.index.decrypt({ ...entry.record, overview, details });
        return [{ revision, updatedAt, overview: version.overview, details: version.details }];
      } catch {
        return [];
      }
    });
  }

  async restoreItemVersion(id: string, revision: number): Promise<Item> {
    const version = (await this.itemVersions(id)).find((one) => one.revision === revision);
    const entry = this.requireUnlocked().index.get(id);
    if (!version || !entry) throw new VaultError('notFound');
    return this.saveItem(restoredVersion(entry.item, version));
  }

  async nextHotpCode(id: string): Promise<HotpCode> {
    const core = await this.loadCore();
    let code: HotpCode | undefined;
    await this.updateTotp(id, (totp) => {
      const next = core.nextHotpCode(totp);
      code = { code: next.code, counter: next.counter };
      return next.totp;
    });
    return code!;
  }

  async setHotpCounter(id: string, counter: number): Promise<Item> {
    const core = await this.loadCore();
    return this.updateTotp(id, (totp) => core.withHotpCounter(totp, counter));
  }

  /**
   * Writes a change to an item's one-time code that isn't an edit: no history entry and no conflict
   * copy. The change runs again on whatever is current when another device got there first, so two
   * phones using a code at once end on different counters, never the same one.
   */
  private async updateTotp(id: string, change: (totp: string) => string): Promise<Item> {
    const state = this.requireUnlocked();
    for (let attempt = 0; ; attempt++) {
      const entry = state.index.get(id);
      const login = entry && loginDetails(entry.item);
      if (!entry || !login?.totp || !isHotp(login.totp)) throw new VaultError('notFound');
      const { record } = entry;
      this.writableVault(state, record.vaultId);
      const next = { ...entry.item, details: { ...login, totp: change(login.totp) } };
      const encrypted = state.index.encrypt(record.vaultId, id, next, record.encryptedItemKey);
      try {
        const { revision } = await this.sessionApi().updateItem(record.vaultId, id, record.revision, { ...encrypted, skipHistory: true });
        return this.afterWrite(state, () => state.index.put({ ...record, ...encrypted, revision, updatedAt: new Date(this.now()).toISOString() }, next));
      } catch (error) {
        if (attempt >= 4) throw error;
        if (isProblem(error, 409, 'conflict')) this.applyCurrent(state, error);
        else if (isProblem(error, 409, 'vault-key-changed')) await this.sync();
        else throw error;
      }
    }
  }

  // ---------- Saving while locked (plan 03) ----------

  /**
   * Pins this account's own public keys, from its private keys, as the key of a device's save
   * inbox: the inbox JSON in, the new JSON out. Hosts that offer saving while locked call it at
   * every unlock.
   */
  async pinInbox(inbox: string): Promise<string> {
    const { session } = this.requireUnlocked();
    return session.inboxPin(inbox, this.requireAccount().accountId);
  }

  /** The inbox's entries, opened with this account's private keys, oldest first. */
  async openInbox(inbox: string): Promise<OpenedInbox> {
    const { session } = this.requireUnlocked();
    return session.inboxOpen(inbox, this.requireAccount().accountId);
  }

  // ---------- Equivalent domains and suggested passwords ----------

  async equivalentDomains(): Promise<EquivalentDomains> {
    const core = await this.loadCore();
    const settings = this.requireUnlocked()
      .index.items()
      .filter((item) => item.overview.type === 'equivalentDomains' && !item.deletedAt)
      .map((item) => item.details as EquivalentDomainsDetails)
      .map(({ groups, excludedDefaults }) => ({ groups, ...(excludedDefaults && { excludedDefaults }) }));
    const options = core.equivalentMatchOptions(settings);
    return { groups: options.equivalentDomains ?? [], excludedDefaults: options.excludedDefaults ?? [], defaults: core.defaultEquivalentDomains() };
  }

  async saveEquivalentDomains(input: { groups: string[][]; excludedDefaults: string[] }): Promise<EquivalentDomains & { rejected: string[] }> {
    const core = await this.loadCore();
    const { groups, rejected } = core.cleanEquivalentGroups(input.groups);
    await storeEquivalentDomains(
      { items: async () => this.requireUnlocked().index.items(), vaults: () => this.listVaults(), save: (draft) => this.saveItem(draft), trash: (id) => this.deleteItem(id) },
      { groups, excludedDefaults: input.excludedDefaults },
    );
    return { ...(await this.equivalentDomains()), rejected };
  }

  async generatePasswordForSite(url: string, options: RandomGeneratorOptions): Promise<string> {
    return (await this.loadCore()).generateForSite(url, undefined, options);
  }

  // ---------- Attachments ----------

  addAttachment(itemId: string, file: Blob, name: string): Promise<Item> {
    return this.attachments.add(itemId, file, name);
  }

  getAttachment(itemId: string, attachmentId: string): Promise<Blob> {
    return this.attachments.get(itemId, attachmentId);
  }

  removeAttachment(itemId: string, attachmentId: string): Promise<Item> {
    return this.attachments.remove(itemId, attachmentId);
  }

  getStorageUsage(): Promise<StorageUsage> {
    return this.attachments.usage();
  }

  /** The page's periodic poll: only needed while live notifications aren't arriving. */
  async backgroundSync(): Promise<void> {
    if (!this.live?.connected) await this.sync();
  }

  /** Pulls changes from the server. Calls made while one is waiting share it. */
  sync(full = false): Promise<void> {
    if (this.queuedSync && !full) return this.queuedSync;
    const run: Promise<void> = this.syncTail
      .catch(() => undefined)
      .then(() => {
        if (this.queuedSync === run) this.queuedSync = undefined;
        return this.syncOnce(full);
      });
    this.queuedSync = run;
    this.syncTail = run;
    return run;
  }

  // ---------- Tools ----------

  async totpCode(totp: string, at?: number): Promise<TotpCode> {
    const core = await this.loadCore();
    return core.totpCode(totp, Math.floor((at ?? this.now()) / 1000));
  }

  checkBreached(password: string): Promise<number> {
    return this.checkBreachedImpl(password);
  }

  async getHealthReport(): Promise<HealthReport> {
    const items = this.requireUnlocked()
      .index.items()
      .filter((i) => !i.deletedAt);
    const { email, serverUrl } = this.current!;
    // At most once a day; a server that doesn't answer leaves the lists as they were.
    if (!isLocalServer(serverUrl)) await this.healthData.update(healthDataDownload(serverOrigin(serverUrl), this.options.fetch), { now: new Date(this.now()) });
    return buildHealthReport(items, {
      estimateStrength: (p) => estimateStrength(p, [email, email.split('@')[0]!]),
      checkBreached: (p) => this.checkBreached(p),
    });
  }

  async lookupEmailBreaches(address: string): Promise<EmailBreach[]> {
    this.requireUnlocked();
    return (await this.sessionApi().emailBreaches(address)).breaches;
  }

  /** Plaintext formats, CXF, or everything with the attachments, encrypted with `options.password`. */
  async exportVault(format: ExportFormat, options?: ExportOptions): Promise<Blob> {
    this.requireUnlocked();
    if (options?.masterPassword !== undefined) await this.checkMasterPassword(options.masterPassword);
    const state = this.requireUnlocked();
    const vaults = await this.listVaults();
    // A client-side policy: the organisation's vaults stay out of exports (plan 03).
    const keptOut = await this.organisations.vaultsKeptFromExport();
    const items = state.index.items().filter((i) => !i.deletedAt && !keptOut.has(i.vaultId));
    const { accountId, email, serverUrl } = this.current!;
      data: await this.healthData.current(),
    const exported = await exportVaultFile(
      await this.loadCore(),
      format,
      {
        vaults: vaults.filter((vault) => !keptOut.has(vault.id)),
        items,
        readAttachment: (item, attachment) => this.attachments.get(item.id, attachment.id),
        account: { id: accountId, email },
        exporterRpId: new URL(serverUrl).hostname,
        now: new Date(this.now()),
        kdf: this.options.exportKdf,
      },
      options,
    );
    // "Vault exported" in the security log, with only the format (plan 03). Exporting works offline
    // too; the entry is then missing.
    void (async () => this.sessionApi().recordExport(format, format === 'encrypted'))().catch(() => {});
    return exported;
  }

  /**
   * Imports into the personal vault with `POST /v1/batch`, up to 1,000 items a request. An Open
   * Pass encrypted export brings its attachments back too, uploaded once their items are saved.
   */
  async importFile(source: ImportSource, file: Blob, options: ImportOptions = {}): Promise<ImportResult> {
    const core = await this.loadCore();
    return importVaultFile(core, source, file, options, this.importTarget(core), this.options.loadFullCore);
  }

  async reviewImport(source: ImportSource, file: Blob, options: ImportOptions = {}): Promise<ImportReview> {
    const state = this.requireUnlocked();
    const personal = state.index.vaults().find((v) => v.type === 'personal');
    const existingItems = personal ? state.index.items().filter((item) => !item.deletedAt) : undefined;
    return this.imports.review(await this.loadCore(), source, file, options, existingLogins(state.index.items()), existingItems, personal?.id);
  }

  async finishImport(reviewId: string, links: CodeLink[]): Promise<ImportResult> {
    const core = await this.loadCore();
    return this.imports.finish(core, reviewId, links, this.importTarget(core));
  }

  cancelImport(reviewId: string): void {
    this.imports.cancel(reviewId);
  }

  async readQrCodes(image: Blob): Promise<string[]> {
    return readQrCodes(await this.loadCore(), image);
  }

  async summarizeQrScans(texts: string[]): Promise<QrScan> {
    return summarizeQrScans(await this.loadCore(), texts);
  }

  // ---------- SSH keys ----------

  async generateSshKey(kind: SshKeyKind, comment: string): Promise<SshKeyMaterial> {
    this.requireUnlocked();
    const core = await this.loadCore();
    return sshCall(() => core.generateSshKey(kind, comment));
  }

  async readSshKey(text: string, passphrase?: string): Promise<SshKeyMaterial> {
    this.requireUnlocked();
    const core = await this.loadCore();
    return sshCall(() => core.readSshKey(text, passphrase));
  }

  async writeSshKey(privateKey: string, comment: string, passphrase?: string): Promise<string> {
    this.requireUnlocked();
    const core = await this.loadCore();
    return sshCall(() => core.writeSshKey(privateKey, comment, passphrase));
  }

  // ---------- Developer toolkit ----------

  private toolsCore?: Promise<ToolsCore>;

  private loadToolsCore(): Promise<ToolsCore> {
    this.toolsCore ??= (this.options.loadToolsCore?.() ?? (this.loadCore() as unknown as Promise<ToolsCore>)).catch((error: unknown) => {
      this.toolsCore = undefined;
      throw error;
    });
    return this.toolsCore;
  }

  /** Runs a tool from the Rust core. Works locked too: only saving results needs the vault. */
  async toolRun(op: string, input: string): Promise<string> {
    const core = await this.loadToolsCore();
    return toolCall(() => core.toolRun(op, input));
  }

  /** Reads `file` in chunks, so a big file never sits in memory at once. */
  async toolHashFile(file: Blob, algorithms: string[]): Promise<string> {
    const core = await this.loadToolsCore();
    return hashStream(core, file, algorithms);
  }

  /** Before a private key is shown or saved (plan 16 §6). Throws `invalidCredentials`. */
  async confirmMasterPassword(password: string): Promise<void> {
    this.requireUnlocked();
    await this.checkMasterPassword(password);
  }

  /** This device's unlock passkey, when device unlock is on: the page asks it for its PRF output. */
  async confirmDeviceCredential(): Promise<string | undefined> {
    this.requireUnlocked();
    const record = await this.store.deviceUnlock(this.requireAccount().accountId);
    return record?.credentialId;
  }

  /** Checks that the passkey's PRF output opens this account, as unlocking would. */
  async confirmWithDevice(prfOutput: Uint8Array): Promise<void> {
    try {
      this.requireUnlocked();
      const current = this.requireAccount();
      const record = await this.store.deviceUnlock(current.accountId);
      if (!record) throw new VaultError('deviceUnlockFailed');
      const core = await this.loadCore();
      try {
        core.Session.unlockWithDeviceKey(prfOutput, record.deviceSalt, record.wrappedAsk, current.account).free();
      } catch {
        throw new VaultError('deviceUnlockFailed');
      }
    } finally {
      prfOutput.fill(0);
    }
  }

  /** Imports go into the personal vault. */
  private importTarget(core: Core): ImportTarget {
    const state = this.requireUnlocked();
    const personal = state.index.vaults().find((v) => v.type === 'personal');
    if (!personal) throw new VaultError('notFound');
    return {
      existingLogins: existingLogins(state.index.items()),
      // Every vault's: an Octa Pass export finds its own items by id wherever they are.
      existingItems: state.index.items().filter((item) => !item.deletedAt),
      vaultId: personal.id,
      updateItem: async (id, item) => {
        const current = await this.getItem(id);
        await this.saveItem({ ...current, overview: item.overview as Item['overview'], details: item.details as Item['details'] });
      },
      newId: () => core.newId(),
      saveItems: async (entries) => {
        const drafts = new Map(entries.map(({ id, item }) => [id!, item as unknown as ItemDraft]));
        const operations: BatchOperation[] = [...drafts].map(([id, draft]) => ({ op: 'put', vaultId: personal.id, itemId: id, item: state.index.encrypt(personal.id, id, draft) }));
        const { applied, failed } = await runBatch(this.sessionApi(), operations);
        const updatedAt = new Date(this.now()).toISOString();
        if (applied.size > 0) {
          this.afterWrite(state, () => {
            for (const operation of operations) {
              const revision = applied.get(operation.itemId);
              if (revision === undefined || operation.op !== 'put') continue;
              state.index.put({ id: operation.itemId, vaultId: personal.id, revision, ...operation.item, updatedAt }, drafts.get(operation.itemId)!);
            }
          });
        }
        const warnings = failed.map(
          ({ itemId, result }) => `“${drafts.get(itemId)!.overview.title}” couldn’t be saved: ${result.problem?.detail ?? result.problem?.type ?? `status ${result.status}`}`,
        );
        return { ids: entries.map(({ id }) => (applied.has(id!) ? id : undefined)), warnings };
      },
      setTotp: async (itemId, totp) => {
        const item = await this.getItem(itemId);
        await this.saveItem({ ...item, details: { ...(item.details as LoginDetails), totp } });
      },
      attach: async (itemId, blob, name) => {
        await this.attachments.add(itemId, blob, name);
      },
    };
  }

  // ---------- Devices ----------

  listDevices(): Promise<Device[]> {
    this.requireUnlocked();
    return this.sessionApi().devices();
  }

  async renameDevice(name: string): Promise<void> {
    this.requireUnlocked();
    const trimmed = name.trim();
    if (!trimmed || trimmed.length > 64) throw new VaultError('serverError', 'A device name is 1 to 64 characters.');
    await this.sessionApi().renameDevice(trimmed);
  }

  async signOutDevice(deviceId: string): Promise<void> {
    this.requireUnlocked();
    await this.sessionApi().deleteDevice(deviceId);
  }

  // ---------- Organisations (./organisations.ts) ----------

  getOrganisation = () => this.organisations.getOrganisation();
  createOrganisation = (name: string) => this.organisations.createOrganisation(name);
  renameOrganisation = (name: string) => this.organisations.renameOrganisation(name);
  deleteOrganisation = (input: { password: string; confirmName: string }) => this.organisations.deleteOrganisation(input);
  acceptOrgInvite = (orgId: string, inviteId: string) => this.organisations.acceptOrgInvite(orgId, inviteId);
  declineOrgInvite = (orgId: string, inviteId: string) => this.organisations.declineOrgInvite(orgId, inviteId);
  listOrgMembers = () => this.organisations.listOrgMembers();
  inviteOrgMember = (email: string, role: OrgRole) => this.organisations.inviteOrgMember(email, role);
  cancelOrgInvite = (inviteId: string) => this.organisations.cancelOrgInvite(inviteId);
  setOrgMemberRole = (accountId: string, role: OrgRole) => this.organisations.setOrgMemberRole(accountId, role);
  removeOrgMember = (accountId: string, options?: { orphanVaults?: boolean }) => this.organisations.removeOrgMember(accountId, options);
  leaveOrganisation = (options?: { orphanVaults?: boolean }) => this.organisations.leaveOrganisation(options);
  listOrgGroups = () => this.organisations.listOrgGroups();
  createOrgGroup = (name: string) => this.organisations.createOrgGroup(name);
  renameOrgGroup = (groupId: string, name: string) => this.organisations.renameOrgGroup(groupId, name);
  deleteOrgGroup = (groupId: string) => this.organisations.deleteOrgGroup(groupId);
  addOrgGroupMember = (groupId: string, accountId: string) => this.organisations.addOrgGroupMember(groupId, accountId);
  removeOrgGroupMember = (groupId: string, accountId: string) => this.organisations.removeOrgGroupMember(groupId, accountId);
  listOrgVaults = () => this.organisations.listOrgVaults();
  createOrgVault = (name: string) => this.organisations.createOrgVault(name);
  deleteOrgVault = (input: { password: string; vaultId: string }) => this.organisations.deleteOrgVault(input);
  linkOrgVaultGroup = (vaultId: string, groupId: string, role: VaultRole) => this.organisations.linkOrgVaultGroup(vaultId, groupId, role);
  unlinkOrgVaultGroup = (vaultId: string, groupId: string) => this.organisations.unlinkOrgVaultGroup(vaultId, groupId);
  getOrgAccess = () => this.organisations.getOrgAccess();
  applyOrgAccess = (vaultId: string, confirmed: Pick<OrgAccessGrant, 'accountId' | 'fingerprint'>[]) => this.organisations.applyOrgAccess(vaultId, confirmed);
  rotateOrgVault = (vaultId: string) => this.organisations.rotateOrgVault(vaultId);
  setOrgPolicies = (policies: OrgPolicies) => this.organisations.setOrgPolicies(policies);
  getOrgSso = () => this.organisations.getOrgSso();
  saveOrgSso = (input: { issuer: string; clientId: string; clientSecret?: string }) => this.organisations.saveOrgSso(input);
  saveOrgSaml = (input: OrgSamlInput) => this.organisations.saveOrgSaml(input);
  removeOrgSso = () => this.organisations.removeOrgSso();
  getOrgScim = () => this.organisations.getOrgScim();
  createOrgScimToken = (name: string) => this.organisations.createOrgScimToken(name);
  revokeOrgScimToken = (tokenId: string) => this.organisations.revokeOrgScimToken(tokenId);
  testOrgSso = () => this.organisations.testOrgSso();
  listOrgEvents = () => this.organisations.listOrgEvents();

  // ---------- Sharing (./sharing.ts, ./shareLinks.ts, ./emergency.ts) ----------

  async getMyFingerprint(): Promise<Fingerprint> {
    this.requireUnlocked();
    const { publicEncKey, publicSignKey } = this.current!.account;
    return this.sharing.fingerprint(publicEncKey, publicSignKey);
  }

  lookupAccount(email: string): Promise<AccountLookup> {
    this.requireUnlocked();
    return this.sharing.lookupAccount(email);
  }

  markVerified(account: Pick<AccountLookup, 'accountId' | 'fingerprint'>): Promise<void> {
    return this.sharing.markVerified(account);
  }

  getKeyLogState(): Promise<KeyLogState> {
    return this.keyLog.state();
  }

  dismissKeyLogAlert(): Promise<void> {
    return this.keyLog.dismissAlert();
  }

  createVault(name: string): Promise<Vault> {
    return this.sharing.createVault(name);
  }

  renameVault(vaultId: string, name: string): Promise<void> {
    return this.sharing.renameVault(vaultId, name);
  }

  listServiceAccounts(vaultId: string): Promise<ServiceAccount[]> {
    this.requireUnlocked();
    return this.sharing.listServiceAccounts(vaultId);
  }

  createServiceAccount(vaultId: string, input: { name: string; role: 'read' | 'write'; expiresAt?: string }): Promise<{ account: ServiceAccount; token: string }> {
    this.requireUnlocked();
    return this.sharing.createServiceAccount(vaultId, input);
  }

  revokeServiceAccount(vaultId: string, id: string): Promise<void> {
    this.requireUnlocked();
    return this.sharing.revokeServiceAccount(vaultId, id);
  }

  listMembers(vaultId: string): Promise<VaultMember[]> {
    this.requireUnlocked();
    return this.sharing.listMembers(vaultId);
  }

  addMember(vaultId: string, account: AccountLookup, role: VaultRole): Promise<void> {
    return this.sharing.addMember(vaultId, account, role);
  }

  changeRole(vaultId: string, accountId: string, role: VaultRole): Promise<void> {
    return this.sharing.changeRole(vaultId, accountId, role);
  }

  removeMember(vaultId: string, accountId: string): Promise<void> {
    return this.sharing.removeMember(vaultId, accountId);
  }

  leaveVault(vaultId: string): Promise<void> {
    return this.sharing.leaveVault(vaultId);
  }

  moveItem(itemId: string, toVaultId: string): Promise<Item> {
    return this.sharing.moveItem(itemId, toVaultId);
  }

  copyItem(itemId: string, toVaultId: string): Promise<Item> {
    return this.sharing.copyItem(itemId, toVaultId);
  }

  getFamily(): Promise<FamilyState> {
    this.requireUnlocked();
    return this.sharing.getFamily();
  }

  createFamily(): Promise<void> {
    return this.sharing.createFamily();
  }

  inviteToFamily(account: AccountLookup): Promise<void> {
    return this.sharing.inviteToFamily(account);
  }

  acceptFamilyInvite(familyId: string): Promise<void> {
    return this.sharing.acceptFamilyInvite(familyId);
  }

  declineFamilyInvite(familyId: string): Promise<void> {
    return this.sharing.declineFamilyInvite(familyId);
  }

  cancelFamilyInvite(accountId: string): Promise<void> {
    return this.sharing.cancelFamilyInvite(accountId);
  }

  removeFamilyMember(accountId: string): Promise<void> {
    return this.sharing.removeFamilyMember(accountId);
  }

  leaveFamily(): Promise<void> {
    return this.sharing.leaveFamily();
  }

  deleteFamily(): Promise<void> {
    return this.sharing.deleteFamily();
  }

  rotateVaultKey(vaultId: string): Promise<void> {
    return this.sharing.rotateVaultKey(vaultId);
  }

  createShareLink(itemId: string, options: ShareLinkOptions): Promise<CreatedShareLink> {
    return this.links.create(itemId, options);
  }

  listShareLinks(): Promise<ShareLinkInfo[]> {
    return this.links.list();
  }

  revokeShareLink(id: string): Promise<void> {
    return this.links.revoke(id);
  }

  fetchShareLink(serverUrl: string, id: string): Promise<ShareLinkEnvelope> {
    return this.links.fetch(serverUrl, id);
  }

  openShareLink(ciphertext: string, key: string, passphrase?: string): Promise<SharedItem> {
    return this.links.open(ciphertext, key, passphrase);
  }

  listEmergencyContacts(): Promise<EmergencyContacts> {
    this.requireUnlocked();
    return this.emergency.list();
  }

  addEmergencyContact(input: { account: AccountLookup; waitDays: number; accessLevel: EmergencyAccessLevel; scope: EmergencyScope }): Promise<EmergencyContact> {
    return this.emergency.add(input);
  }

  removeEmergencyContact(id: string): Promise<void> {
    this.requireUnlocked();
    return this.emergency.remove(id);
  }

  requestEmergencyAccess(id: string): Promise<void> {
    this.requireUnlocked();
    return this.emergency.act(id, 'request');
  }

  denyEmergencyAccess(id: string): Promise<void> {
    this.requireUnlocked();
    return this.emergency.act(id, 'deny');
  }

  approveEmergencyAccess(id: string): Promise<void> {
    this.requireUnlocked();
    return this.emergency.act(id, 'approve');
  }

  openEmergencyAccess(id: string): Promise<EmergencyVaultView> {
    return this.emergency.open(id);
  }

  getEmergencyAttachment(id: string, itemId: string, attachmentId: string): Promise<Blob> {
    return this.emergency.attachment(id, itemId, attachmentId);
  }

  renewEmergencyKey(id: string, account: AccountLookup): Promise<void> {
    this.requireUnlocked();
    return this.emergency.renew(id, account);
  }

  takeOverAccount(id: string, input: { contactPassword: string; newPassword: string }): Promise<NewRecoveryKit> {
    this.requireUnlocked();
    return this.emergency.takeOver(id, input);
  }

  enableOrganiserRecovery(input: { account: AccountLookup; waitDays: number }): Promise<EmergencyContact> {
    this.requireUnlocked();
    return this.emergency.enableOrganiserRecovery(input);
  }

  async getSecurityLog(): Promise<SecurityEvent[]> {
    const { session } = this.requireUnlocked();
    return (await this.sessionApi().securityLog()).events.map(({ sealedDetail, ...event }) => {
      if (!sealedDetail) return event;
      const opened = session.openAuditDetail(sealedDetail);
      return opened ? { ...event, connect: JSON.parse(opened) as ConnectEventDetail } : event;
    });
  }

  // ---------- Internals: session ----------

  private now(): number {
    return this.options.now?.() ?? Date.now();
  }

  private loadCore(): Promise<Core> {
    this.core ??= this.options.loadCore().catch((error: unknown) => {
      this.core = undefined;
      throw error;
    });
    return this.core;
  }

  /**
   * `confirmed` is set whenever the vault is unlocked: every way this engine opens it is the user's
   * own check (the master password, device unlock, signing in). A host that opens it some other
   * way says so itself (the extension's session keeper after a worker restart).
   */
  private snapshot(): Snapshot {
    const session: SessionState = this.current ? withConfirmed({ status: this.status, email: this.current.email, serverUrl: this.current.serverUrl }, this.unlocked !== undefined) : { status: 'signedOut' };
    return { session, remembered: this.accounts.map(({ email, serverUrl }) => ({ email, serverUrl })) };
  }

  private setStatus(status: SessionStatus): void {
    this.status = status;
    this.options.emit({ type: 'session', snapshot: this.snapshot() });
  }

  private deviceAccount(account: RememberedAccount): DeviceAccount | undefined {
    return this.accounts.find((a) => accountKey(a) === accountKey(account));
  }

  private lockedAccount(): StoredSession {
    if (this.status !== 'locked' || !this.current) throw new VaultError('locked');
    return this.current;
  }

  private requireUnlocked(): Unlocked {
    if (!this.unlocked) throw new VaultError('locked');
    return this.unlocked;
  }

  private requireAccount(): StoredSession {
    if (!this.current) throw new VaultError('locked');
    return this.current;
  }

  private passwordDue(lastPasswordUnlockAt: string): boolean {
    return this.now() - Date.parse(lastPasswordUnlockAt) > PASSWORD_RECHECK_MS;
  }

  private async notePasswordUnlock(accountId: string, at: string): Promise<void> {
    const record = await this.store.deviceUnlock(accountId);
    if (record) await this.store.setDeviceUnlock({ ...record, lastPasswordUnlockAt: at });
  }

  private api(serverUrl: string): Api {
    return createApi(
      new HttpClient({
        baseUrl: serverUrl,
        ...(this.options.fetch ? { fetch: this.options.fetch } : {}),
        accessToken: () => this.accessToken,
        refresh: () => this.refreshOrEnd(),
        onAccountDeleted: async () => {
          if (this.current) await this.forgetEverything(this.current);
        },
      }),
    );
  }

  private sessionApi(): Api {
    if (!this.current) throw new VaultError('locked');
    return this.api(this.current.serverUrl);
  }

  /** Throws `second-factor-required` when the account asks this device for a second step. */
  private async login(api: Api, serverUrl: string, email: string, keys: DerivedKeys): Promise<LoginFinishResponse> {
    const flow = keys.startLogin();
    try {
      const { loginId, credentialResponse } = await api.loginStart(email, flow.credentialRequest);
      // Read from storage: another tab may have signed in since this one loaded the list.
      const trusted = (await this.store.accounts()).find((a) => accountKey(a) === accountKey({ serverUrl, email }))?.trustedDeviceToken;
      return await api.loginFinish(loginId, flow.finish(credentialResponse), this.options.device ?? { name: 'Web vault', platform: 'web' }, trusted);
    } finally {
      flow.free();
    }
  }

  /** Takes `keys`: frees them, or keeps them for the second step when the account asks for one. */
  private async signInWithKeys(api: Api, serverUrl: string, email: string, secretKey: string, keys: DerivedKeys): Promise<EngineSignInResult> {
    let login: LoginFinishResponse;
    try {
      login = await this.login(api, serverUrl, email, keys);
    } catch (error) {
      const sso = ssoChallenge(error);
      if (sso) {
        this.dropWaitingTwoStep();
        const result: WaitingSso['result'] = { status: 'ssoRequired', url: sso.url, orgName: sso.orgName };
        this.waitingSso = { result, serverUrl, email, secretKey, keys, challengeId: sso.challengeId, expiresAt: this.now() + sso.expiresIn * 1000 };
        return result;
      }
      const challenge = secondFactorChallenge(error);
      if (!challenge) {
        keys.free();
        throw error;
      }
      this.dropWaitingTwoStep();
      return this.waitForSecondFactor(serverUrl, email, secretKey, keys, challenge);
    }
    try {
      await this.completeSignIn(serverUrl, email, secretKey, keys, login);
    } finally {
      keys.free();
    }
    return { status: 'signedIn' };
  }

  private waitForSecondFactor(serverUrl: string, email: string, secretKey: string, keys: DerivedKeys, challenge: SecondFactorChallenge): WaitingTwoStep['result'] {
    const methods = challenge.methods.map((m) => TWO_STEP_METHODS[m]).filter(Boolean);
    const result: WaitingTwoStep['result'] = challenge.webauthn ? { status: 'twoStepRequired', methods, webauthn: challenge.webauthn } : { status: 'twoStepRequired', methods };
    this.waitingTwoStep = { result, serverUrl, email, secretKey, keys, challengeId: challenge.challengeId, expiresAt: this.now() + challenge.expiresIn * 1000 };
    return result;
  }

  private async completeSignIn(serverUrl: string, email: string, secretKey: string, keys: DerivedKeys, login: LoginFinishResponse): Promise<void> {
    const session = keys.unlock(login.account);
    const stored: StoredSession = { serverUrl, email, accountId: login.account.accountId!, account: login.account, refreshToken: login.refreshToken };
    // Another account signed in before on this browser leaves nothing behind.
    if (this.current && this.current.accountId !== stored.accountId) await this.store.wipeAccount(this.current.accountId);
    this.dropKeys();
    await this.store.setSession(stored);
    const trustedDeviceToken = login.trustedDeviceToken ?? this.deviceAccount({ serverUrl, email })?.trustedDeviceToken;
    this.accounts = await this.store.rememberAccount({ email, serverUrl, secretKey, ...(trustedDeviceToken ? { trustedDeviceToken } : {}) });
    this.current = stored;
    this.accessToken = login.accessToken;
    const checkedAt = new Date(this.now()).toISOString();
    await this.notePasswordUnlock(stored.accountId, checkedAt);
    await this.open(session, checkedAt);
  }

  /**
   * Opens the vault with a fresh session: the local copy first, then the server. Offline, the local
   * copy is all there is, and that's fine. With the derived keys at hand (a password unlock), an
   * expired refresh token is replaced by a fresh login instead of signing out.
   */
  /** Sharing still works without this, so a failure here never stands between the user and the vault. */
  private async publishKeys(): Promise<boolean> {
    try {
      return await this.keyLog.ensurePublished();
    } catch (error) {
      if (isOffline(error)) throw error;
      return false;
    }
  }

  private async open(session: Session, passwordCheckedAt: string, keys?: DerivedKeys): Promise<void> {
    const current = this.current!;
    const index = new VaultIndex(session, current.accountId);
    const cache = await this.store.cache(current.accountId);
    if (cache) index.apply({ ...cache, deleted: [] }, true);
    const state: Unlocked = { session, index, passwordCheckedAt };
    this.unlocked?.session.free();
    this.unlocked = state;
    try {
      await this.connect(keys);
      // The local copy may hold grants sealed to the ML-KEM key this device only has now.
      if ((await this.publishKeys()) && cache) index.apply({ ...cache, deleted: [] }, true);
      await this.sync(true);
      // In the background: a long log mustn't hold up the vault, and what it finds shows as an alert.
      void this.keyLog.monitor({ stillOpen: () => this.unlocked === state }).catch(() => undefined);
    } catch (error) {
      if (!isOffline(error)) {
        if (this.unlocked === state) this.dropKeys();
        throw error;
      }
    }
    if (this.unlocked !== state) return;
    this.setStatus('unlocked');
    this.startLive();
  }

  // ---------- Internals: live notifications ----------

  private startLive(): void {
    const Socket = this.options.WebSocket ?? (typeof WebSocket === 'undefined' ? false : WebSocket);
    if (!Socket || this.live) return;
    const live = new LiveConnection({
      serverUrl: this.current!.serverUrl,
      WebSocket: Socket,
      accessToken: async (fresh) => {
        if (fresh || !this.accessToken) await this.refreshOrEnd();
        if (this.live !== live || !this.accessToken) throw new VaultError('locked');
        return this.accessToken;
      },
      onConnected: () => void this.sync().catch(() => undefined),
      onMessage: (message) => void this.onLiveMessage(message).catch(() => undefined),
    });
    this.live = live;
    live.start();
  }

  private stopLive(): void {
    this.live?.stop();
    this.live = undefined;
  }

  private async onLiveMessage(message: LiveMessage): Promise<void> {
    switch (message.type) {
      case 'vault-changed': {
        const known = this.unlocked?.index.vault(message.vaultId);
        if (!known || known.revision < message.revision) await this.sync();
        return;
      }
      case 'membership-changed':
        this.options.emit({ type: 'sharing' });
        await this.sync();
        return;
      case 'session-revoked':
        // Signed out remotely: this browser keeps nothing but the Secret Key, as after an expired session.
        await this.expireSession();
        return;
      case 'account-deleted':
        if (this.current) await this.forgetEverything(this.current);
    }
  }

  private async connect(keys?: DerivedKeys): Promise<void> {
    if (this.accessToken) return;
    try {
      await this.refreshTokens();
    } catch (error) {
      if (!isRejected(error)) throw error;
      if (!keys) {
        await this.expireSession();
        throw new VaultError('sessionExpired');
      }
      const current = this.current!;
      let login: LoginFinishResponse;
      try {
        login = await this.login(this.api(current.serverUrl), current.serverUrl, current.email, keys);
      } catch (loginError) {
        if (!secondFactorChallenge(loginError) && !ssoChallenge(loginError)) throw loginError;
        // This device isn't trusted any more (two-step sign-in was turned off and on, or the trust
        // expired), or its SSO sign-in is too old: like a session that can't be resumed, so the user
        // signs in again, every step included.
        await this.expireSession();
        throw new VaultError('sessionExpired');
      }
      this.current = { ...current, account: login.account, refreshToken: login.refreshToken };
      await this.store.setSession(this.current);
      if (login.trustedDeviceToken) this.accounts = await this.store.setTrustedDeviceToken(current, login.trustedDeviceToken);
      this.accessToken = login.accessToken;
    }
  }

  /**
   * Rotates the refresh token. Every tab shares it through storage, so the rotation runs under a
   * lock and always starts from the stored token: two tabs refreshing at once must not present the
   * same token twice, which the server treats as theft and answers by revoking the session.
   */
  private async refreshTokens(): Promise<void> {
    const withLock = this.options.withLock ?? lockInProcess;
    await withLock('octapass-refresh', async () => {
      const stored = await this.store.session();
      if (!stored || stored.accountId !== this.current?.accountId) throw new VaultError('sessionExpired');
      const tokens = await this.api(stored.serverUrl).refresh(stored.refreshToken);
      this.current = { ...stored, refreshToken: tokens.refreshToken };
      await this.store.setSession(this.current);
      // Devices signed in before the server issued trusted-device tokens get one here.
      if (tokens.trustedDeviceToken) this.accounts = await this.store.setTrustedDeviceToken(stored, tokens.trustedDeviceToken);
      this.accessToken = tokens.accessToken;
    });
  }

  private async refreshOrEnd(): Promise<void> {
    try {
      await this.refreshTokens();
    } catch (error) {
      if (!isRejected(error)) throw error;
      await this.expireSession();
      throw new VaultError('sessionExpired');
    }
  }

  /** The server no longer accepts this device's tokens: sign out here, but keep the Secret Key. */
  private async expireSession(): Promise<void> {
    if (!this.current) return;
    await this.store.wipeAccount(this.current.accountId);
    this.endSession();
  }

  private async forgetEverything(account: StoredSession): Promise<void> {
    await this.store.wipeAccount(account.accountId);
    this.accounts = await this.store.forgetAccount(account);
    if (typeof caches !== 'undefined') {
      for (const name of await caches.keys()) await caches.delete(name);
    }
    this.endSession();
  }

  private endSession(): void {
    this.dropKeys();
    this.dropWaitingTwoStep();
    for (const pending of this.signups.values()) pending.signup.free();
    this.signups.clear();
    this.current = undefined;
    this.setStatus('signedOut');
  }

  private dropKeys(): void {
    this.imports.clear();
    this.stopLive();
    this.unlocked?.session.free();
    this.unlocked = undefined;
    this.accessToken = undefined;
    this.totpSetupId = undefined;
  }

  private dropWaitingTwoStep(): void {
    this.waitingTwoStep?.keys.free();
    this.waitingTwoStep = undefined;
    this.waitingSso?.keys.free();
    this.waitingSso = undefined;
  }

  /** A fresh proof of the master password for one dangerous change. A wrong password fails here, before anything is sent. */
  private async reauth(session: Session, password: string, purpose: ReauthPurpose): Promise<string> {
    const api = this.sessionApi();
    const reauth = session.startReauth(password, this.deviceAccount(this.current!)!.secretKey);
    try {
      const { reauthId, credentialResponse } = await api.reauthStart(reauth.credentialRequest);
      return (await api.reauthFinish(reauthId, reauth.finish(credentialResponse), purpose)).reauthToken;
    } finally {
      reauth.free();
    }
  }

  private pendingReset(resetId: string): PendingReset {
    const pending = this.resets.get(resetId);
    if (!pending || pending.expiresAt < this.now()) {
      this.resets.delete(resetId);
      throw new VaultError('resetExpired');
    }
    return pending;
  }

  /** A reset call; when the server no longer knows the reset, it's gone here too. */
  private async resetCall<T>(resetId: string, call: () => Promise<T>): Promise<T> {
    try {
      return await call();
    } catch (error) {
      if (isProblem(error, 400, 'recovery-expired') || isProblem(error, 401, 'login-failed')) {
        this.resets.delete(resetId);
        throw new VaultError('resetExpired');
      }
      throw error;
    }
  }

  private dropExpiredResets(): void {
    for (const [id, pending] of this.resets) if (pending.expiresAt < this.now()) this.resets.delete(id);
  }

  private dropExpiredSignups(): void {
    for (const [id, pending] of this.signups) {
      if (pending.expiresAt >= this.now()) continue;
      pending.signup.free();
      this.signups.delete(id);
    }
  }

  // ---------- Internals: vault ----------

  private async syncOnce(full: boolean): Promise<void> {
    const state = this.unlocked;
    if (!state || this.now() < this.syncPausedUntil) return;
    // Sync is paged. A full sync replaces the index, so all its pages are collected before applying.
    const merged: SyncResponse = { vaults: [], items: [], deleted: [] };
    let since = full ? [] : state.index.since();
    for (let page = 1; ; page++) {
      let response: SyncResponse;
      try {
        response = await this.sessionApi().sync(since);
      } catch (error) {
        if (error instanceof ApiProblem && error.retryAfter !== undefined) this.syncPausedUntil = this.now() + error.retryAfter * 1000;
        throw error;
      }
      if (this.unlocked !== state) return;
      merged.vaults = response.vaults;
      merged.items.push(...response.items);
      merged.deleted.push(...response.deleted);
      if (!response.hasMore) break;
      if (page >= MAX_SYNC_PAGES) throw new VaultError('serverError');
      since = response.vaults.map(({ id, revision }) => ({ id, revision }));
    }
    const changed = state.index.apply(merged, full);
    await this.store.setCache(this.current!.accountId, state.index.toCache());
    if (changed) this.options.emit({ type: 'items' });
  }

  private writableVault(state: Unlocked, vaultId: string): void {
    const vault = state.index.vault(vaultId);
    if (!vault) throw new VaultError('notFound');
    if (state.index.isUntrusted(vaultId)) throw new VaultError('untrustedVault');
    if (vault.role === 'read') throw new VaultError('readOnlyVault');
  }

  private async createItem(state: Unlocked, vaultId: string, draft: Pick<ItemDraft, 'overview' | 'details'>): Promise<Item> {
    const core = await this.loadCore();
    const id = core.newId();
    let encrypted = state.index.encrypt(vaultId, id, draft);
    let revision: number;
    try {
      ({ revision } = await this.sessionApi().createItem(vaultId, id, encrypted));
    } catch (error) {
      // Another member rotated the vault key: sync to open the new grant, then encrypt again.
      if (!isProblem(error, 409, 'vault-key-changed')) throw error;
      await this.sync();
      if (this.unlocked !== state) throw new VaultError('locked');
      encrypted = state.index.encrypt(vaultId, id, draft);
      ({ revision } = await this.sessionApi().createItem(vaultId, id, encrypted));
    }
    const record: ItemRecord = { id, vaultId, revision, ...encrypted, updatedAt: new Date(this.now()).toISOString() };
    return this.afterWrite(state, () => state.index.put(record, draft));
  }

  private createConflictCopy(state: Unlocked, vaultId: string, draft: ItemDraft): Promise<Item> {
    // A copy has its own item key, so the original's files wouldn't open from it; they stay there.
    const copy = keepAttachments(draft, undefined);
    return this.createItem(state, vaultId, { ...copy, overview: { ...copy.overview, title: `${copy.overview.title} (conflicting copy)` } });
  }

  /**
   * Rewrites an item's attachment list on top of the server's current version, never as a conflict
   * copy: a copy couldn't open the files, which are bound to this item and its key.
   */
  private async updateAttachments(itemId: string, change: (list: Attachment[]) => Attachment[]): Promise<Item> {
    const state = this.requireUnlocked();
    for (let attempt = 1; ; attempt++) {
      const entry = state.index.get(itemId);
      if (!entry) throw new VaultError('notFound');
      const { record } = entry;
      const next = { overview: entry.item.overview, details: withAttachments(entry.item.details, change(attachmentsOf(entry.item))) };
      const encrypted = state.index.encrypt(record.vaultId, record.id, next, record.encryptedItemKey);
      try {
        const { revision } = await this.sessionApi().updateItem(record.vaultId, record.id, record.revision, encrypted);
        const updatedAt = new Date(this.now()).toISOString();
        return this.afterWrite(state, () => state.index.put({ ...record, ...encrypted, revision, updatedAt }, next));
      } catch (error) {
        if (attempt >= 3) throw error;
        if (isProblem(error, 409, 'conflict')) this.applyCurrent(state, error);
        else if (isProblem(error, 409, 'vault-key-changed')) await this.sync();
        else throw error;
        if (this.unlocked !== state) throw new VaultError('locked');
      }
    }
  }

  /** Takes the server's version from a 409 into the index. */
  private applyCurrent(state: Unlocked, conflict: ApiProblem): ItemRecord {
    const current = conflict.body.current as ItemRecord;
    if (this.unlocked === state) state.index.apply({ vaults: state.index.vaults(), items: [current], deleted: [] }, false);
    return current;
  }

  /** Updates the index if the vault is still open, tells the UI, and checks for other changes. */
  private afterWrite<T>(state: Unlocked, update: () => T, sync = true): T {
    if (this.unlocked !== state) throw new VaultError('locked');
    const result = update();
    void this.store.setCache(this.current!.accountId, state.index.toCache()).catch(() => undefined);
    this.options.emit({ type: 'items' });
    if (sync) void this.sync().catch(() => undefined);
    return structuredClone(result);
  }
}
