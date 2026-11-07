// The vault in the service worker: the milestone 1 engine (WASM core, sync, item encryption) with
// the session kept across worker restarts, or a vault on this device only (local.ts), and the
// calls the extension's pages may make. Turning on sync moves a local vault into a new account.

import type * as Full from '@octapass/core/full';
import type { Item, ItemDraft, ItemSummary, RecoveryKit } from '@octapass/vault-client';
import { createUsageTracker, isValidEmail, isVaultError, normalizeEmail, serverOrigin, VaultError, withConfirmed } from '@octapass/vault-client';
import { directClient, VaultEngine, type Core, type EngineClient } from '@octapass/vault-client/remote';
import { apiRequest, putItems, TokenTap } from './api';
import type { DesktopLink } from './desktop';
import type { LocalEngineOptions } from './local';
import { LocalEngine } from './local';
import { withoutPasskeyKeys, withPasskeyKeys } from './passkeyKeys';
import { SESSION_CREDENTIAL, SessionKeeper, type Unlocker } from './sessionKeeper';
import type { KeyValueStore } from './storage';

export type EngineEvent = Parameters<Parameters<EngineClient['onEvent']>[0]>[0];
export type Snapshot = Extract<EngineEvent, { type: 'session' }>['snapshot'];
type EngineMethod = Parameters<EngineClient['call']>[0];

/** Engine methods the extension's pages may call, as in the web vault's worker protocol. */
export const PAGE_METHODS = [
  'init',
  'preload',
  'getServerInfo',
  'startSignup',
  'finishSignup',
  'signIn',
  'finishTwoStep',
  'finishSso',
  'pendingTwoStep',
  'cancelTwoStep',
  'lock',
  'unlock',
  'signOut',
  'getSecretKey',
  'getOrganisation',
  'createOrganisation',
  'renameOrganisation',
  'deleteOrganisation',
  'acceptOrgInvite',
  'declineOrgInvite',
  'listOrgMembers',
  'inviteOrgMember',
  'cancelOrgInvite',
  'setOrgMemberRole',
  'removeOrgMember',
  'leaveOrganisation',
  'listOrgGroups',
  'createOrgGroup',
  'renameOrgGroup',
  'deleteOrgGroup',
  'addOrgGroupMember',
  'removeOrgGroupMember',
  'listOrgVaults',
  'createOrgVault',
  'deleteOrgVault',
  'linkOrgVaultGroup',
  'unlinkOrgVaultGroup',
  'getOrgAccess',
  'applyOrgAccess',
  'rotateOrgVault',
  'setOrgPolicies',
  'getOrgSso',
  'saveOrgSso',
  'removeOrgSso',
  'testOrgSso',
  'listOrgEvents',
  'getAccountSummary',
  'deleteAccount',
  // "Forgot your master password?" on the sign-in and lock screens. Changing it is the web vault's.
  'startPasswordReset',
  'verifyPasswordReset',
  'finishPasswordReset',
  'cancelPasswordReset',
  // Two-step sign-in settings. Security keys belong to the web vault's site, so pages here can't add
  // them (no `securityKeyOptions` or `addSecurityKey`), only list and remove them.
  'getTwoStepStatus',
  'startTotpSetup',
  'confirmTotpSetup',
  'removeSecurityKey',
  'renewRecoveryCodes',
  'disableTwoStep',
  'forgetTrustedDevices',
  'deviceUnlockStatus',
  'enableDeviceUnlock',
  'disableDeviceUnlock',
  'deviceUnlockCredential',
  'unlockWithDevice',
  // Reveal/copy/export re-authentication, and the autofill confirmation window.
  'confirmMasterPassword',
  'confirmDeviceCredential',
  'confirmWithDevice',
  'listVaults',
  'listItems',
  'getItem',
  'saveItem',
  'deleteItem',
  'restoreItem',
  'itemVersions',
  'restoreItemVersion',
  'nextHotpCode',
  'setHotpCounter',
  'equivalentDomains',
  'saveEquivalentDomains',
  'generatePasswordForSite',
  'sync',
  'totpCode',
  'checkBreached',
  'getHealthReport',
  'lookupEmailBreaches',
  'exportVault',
  'importFile',
  'reviewImport',
  'finishImport',
  'cancelImport',
  'readQrCodes',
  'summarizeQrScans',
] as const satisfies readonly EngineMethod[];

/** Calls that don't count as the user doing something, for auto-lock. */
const BACKGROUND_METHODS = new Set<string>(['init', 'preload', 'sync', 'deviceUnlockStatus', 'getServerInfo', 'pendingTwoStep']);

/**
 * In `chrome.storage.session` while a sign-in waits for its second step. The sign-in itself (and its
 * derived keys) lives only in the engine's memory; this marker outlasts a worker restart, so the
 * popup can say the sign-in was lost instead of silently showing the password form.
 */
const TWO_STEP_WAITING = 'two-step-waiting';

/** In `chrome.storage.session` after "Lock now": stay unlocked doesn't open the vault by itself (plan 18). */
const HELD = 'stay-unlocked-held';

export interface VaultHostOptions {
  /** The full WASM build (`@octapass/core/full`): local vaults need it. */
  loadCore: () => Promise<typeof Full>;
  disk: KeyValueStore;
  /** `chrome.storage.session`. */
  memory: KeyValueStore;
  device: { name: string; platform: string };
  fetch?: typeof fetch;
  now?: () => number;
  /** The desktop app's chip for local vaults (plan 05). */
  chip?: LocalEngineOptions['chip'];
}

/** Stands in for a passkey credential ID when the desktop app's key unlocks the engine. */
const DESKTOP_CREDENTIAL = 'octapass-desktop-app';

/** How long a started "Turn on sync" waits for its verification code, like a sign-up (plan 11). */
const UPGRADE_TTL_MS = 15 * 60_000;

interface PendingUpgrade {
  serverUrl: string;
  email: string;
  /** Needed once more, to sign in to the new account after the code is checked. */
  password: string;
  signup: Full.Signup;
  registerFinish: Full.RegisterFinish;
  expiresAt: number;
}

export class VaultHost {
  readonly keeper: SessionKeeper;
  /** The account engine, which also keeps working (signed out) while a local vault is in use. */
  readonly account: EngineClient;
  readonly localVault: LocalEngine;
  readonly tap = new TokenTap();
  private mode: 'account' | 'local' = 'account';
  private current: Snapshot = { session: { status: 'signedOut' }, remembered: [] };
  private accountSnapshot: Snapshot = this.current;
  private restoring = false;
  /**
   * The account's session was opened by the user (`SessionState.confirmed`). The engine says so for
   * its own unlocks; a restore after a worker restart is the same session, so it keeps what the
   * session wrap remembered rather than the engine's word.
   */
  private confirmed = false;
  /** The next unlock is stay unlocked's, through the desktop app: not the user's own check (plan 18). */
  private openedUnconfirmed = false;
  private readonly upgrades = new Map<string, PendingUpgrade>();
  private readonly listeners = new Set<(event: EngineEvent) => void>();
  private readonly activity = new Set<() => void>();
  private readonly localClient: EngineClient;
  /**
   * Fills and the popup's copies count as uses of the item, for Frequently used and Recently used.
   * Counted here, where the vault stays open longer than the popup, and saved a few seconds later.
   */
  readonly usage = createUsageTracker({
    listItems: (filter) => this.engine.call('listItems', [filter ?? {}]),
    getItem: (id) => this.engine.call('getItem', [id]),
    saveItem: (draft) => this.engine.call('saveItem', [draft]),
    deleteItem: (id) => this.engine.call('deleteItem', [id]),
    listVaults: () => this.engine.call('listVaults', []),
  });

  private constructor(private readonly options: VaultHostOptions) {
    this.keeper = new SessionKeeper(options.disk, options.memory);
    const loadCore = options.loadCore as unknown as () => Promise<Core>;
    this.account = directClient(
      (emit) =>
        new VaultEngine({
          loadCore,
          storage: this.keeper.storage,
          emit,
          device: options.device,
          fetch: this.tap.fetch,
          ...(options.now ? { now: options.now } : {}),
        }),
    );
    this.account.onEvent((event) => this.handleAccount(event));
    this.localVault = new LocalEngine({
      loadCore: options.loadCore,
      disk: options.disk,
      emit: (event) => this.handleLocal(event),
      ...(options.now ? { now: options.now } : {}),
      ...(options.chip ? { chip: options.chip } : {}),
    });
    this.localClient = { call: (method, args) => this.localVault.call(method, args) as never, onEvent: () => undefined };
  }

  /** Reads what this browser remembers and, unless `expired`, unlocks an account again where it left off. */
  static async start(options: VaultHostOptions, expired: () => Promise<boolean> = async () => false): Promise<VaultHost> {
    const host = new VaultHost(options);
    host.accountSnapshot = await host.account.call('init', []);
    const local = await host.localVault.init();
    if (host.localVault.exists) {
      host.mode = 'local';
      host.current = local;
      await host.keeper.clear();
      return host;
    }
    host.current = host.accountSnapshot;
    if (host.current.session.status === 'locked') {
      if (await expired()) await host.keeper.clear();
      else {
        host.restoring = true;
        host.confirmed = (await host.keeper.read())?.confirmed === true;
        try {
          await host.keeper.restore(host.unlocker);
        } finally {
          host.restoring = false;
        }
      }
    } else await host.keeper.clear();
    return host;
  }

  get snapshot(): Snapshot {
    return this.current;
  }

  get unlocked(): boolean {
    return this.current.session.status === 'unlocked';
  }

  /** A vault on this device only is in use. */
  get local(): boolean {
    return this.mode === 'local';
  }

  /** The engine in use: the account's, or the local vault. */
  get engine(): EngineClient {
    return this.mode === 'local' ? this.localClient : this.account;
  }

  onEvent(listener: (event: EngineEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Called on every call that counts as using the vault. */
  onActivity(listener: () => void): void {
    this.activity.add(listener);
  }

  lock(): void {
    this.usage.clear();
    if (this.unlocked) void this.engine.call('lock', []);
  }

  /** A call from one of the extension's pages. */
  async pageCall(method: string, args: unknown[]): Promise<unknown> {
    if (!(PAGE_METHODS as readonly string[]).includes(method)) throw new Error(`Unknown method ${method}`);
    if (!BACKGROUND_METHODS.has(method)) for (const listener of this.activity) listener();
    switch (method) {
      // The engine is already running: `init` would forget the unlocked session.
      case 'init':
        return this.current;
      // "Lock now" holds while staying unlocked (plan 18).
      case 'lock':
        await this.holdLocked(true);
        break;
      // A check the user answered covers revealing and copying until the vault (or, staying
      // unlocked, the computer) locks: plan 03 History 2026-11-05, plan 18.
      case 'confirmMasterPassword':
      case 'confirmDeviceCredential':
      case 'confirmWithDevice': {
        const result = await (this.engine.call as (m: string, a: unknown[]) => Promise<unknown>)(method, args);
        this.markConfirmed();
        return result;
      }
      case 'enableDeviceUnlock':
        if (args[0] === SESSION_CREDENTIAL) throw new VaultError('deviceUnlockFailed');
        break;
      case 'getItem':
        return withoutPasskeyKeys(await this.engine.call('getItem', [args[0] as string]));
      case 'saveItem': {
        const draft = args[0] as ItemDraft;
        const existing = draft.id ? await this.engine.call('getItem', [draft.id]) : undefined;
        return withoutPasskeyKeys(await this.engine.call('saveItem', [withPasskeyKeys(draft, existing)]));
      }
      // With a local vault, "sign up" is Turn on sync: the same screens, keeping the vault.
      case 'startSignup':
        if (this.local) return this.startUpgrade(args[0] as { serverUrl: string; email: string; password: string });
        break;
      case 'finishSignup':
        if (this.local) return this.finishUpgrade(args[0] as { signupId: string; verificationCode: string });
        break;
      case 'getServerInfo':
        // Turn on sync checks the server before starting.
        return this.account.call('getServerInfo', [args[0] as string]);
      // The popup closes when the user switches away to read a code; it reopens onto the second step.
      case 'signIn': {
        const result = await this.engine.call('signIn', args as Parameters<VaultEngine['signIn']>);
        if (result.status !== 'signedIn') await this.options.memory.set(TWO_STEP_WAITING, true);
        else await this.options.memory.delete(TWO_STEP_WAITING);
        return result;
      }
      // Signing in after a reset can wait for the second step too.
      case 'finishPasswordReset': {
        const result = await this.account.call('finishPasswordReset', args as Parameters<VaultEngine['finishPasswordReset']>);
        if (result.signIn && result.signIn.status !== 'signedIn') await this.options.memory.set(TWO_STEP_WAITING, true);
        return result;
      }
      // Two-step sign-in can follow, and the popup can close while the user reads either code.
      case 'finishSso': {
        try {
          const result = await this.account.call('finishSso', args as Parameters<VaultEngine['finishSso']>);
          if (result.status === 'signedIn') await this.options.memory.delete(TWO_STEP_WAITING);
          return result;
        } catch (error) {
          if (isVaultError(error, 'twoStepExpired')) await this.options.memory.delete(TWO_STEP_WAITING);
          throw error;
        }
      }
      case 'finishTwoStep':
        try {
          await this.account.call('finishTwoStep', args as Parameters<VaultEngine['finishTwoStep']>);
        } catch (error) {
          if (isVaultError(error, 'twoStepExpired')) await this.options.memory.delete(TWO_STEP_WAITING);
          throw error;
        }
        await this.options.memory.delete(TWO_STEP_WAITING);
        return undefined;
      case 'pendingTwoStep': {
        const waiting = await this.account.call('pendingTwoStep', []);
        if (waiting) return waiting;
        // The worker restarted (or the sign-in timed out) since: it's gone.
        return (await this.options.memory.get(TWO_STEP_WAITING)) ? { status: 'twoStepExpired' } : undefined;
      }
      case 'cancelTwoStep':
        await this.options.memory.delete(TWO_STEP_WAITING);
        return this.account.call('cancelTwoStep', []);
    }
    return (this.engine.call as (m: string, a: unknown[]) => Promise<unknown>)(method, args);
  }

  /**
   * Plan 18, the extension with the desktop app: opens this browser's vault through the app with
   * no prompt, when the app stays unlocked and is unlocked to the same account. False when it
   * can't (no app, the app's switch off or the app locked, another account, "Lock now" holding):
   * then the lock screen asks as before. A session opened this way isn't `confirmed`: the first
   * reveal asks.
   */
  async unlockStayUnlocked(link: DesktopLink): Promise<boolean> {
    const { status, email, serverUrl } = this.accountSnapshot.session;
    if (status === 'unlocked') return true;
    if (this.local || status !== 'locked' || (await this.options.memory.get<boolean>(HELD))) return false;
    const app = await link.status();
    if (!app.appRunning || !app.stayUnlocked || app.status !== 'unlocked') return false;
    if (normalizeEmail(app.email ?? '') !== email || serverOrigin(app.serverUrl ?? '') !== serverUrl) return false;
    const wrap = await link.sessionKey().catch(() => undefined);
    if (!wrap || normalizeEmail(wrap.email) !== email || serverOrigin(wrap.serverUrl) !== serverUrl) return false;
    const now = new Date(this.now()).toISOString();
    this.openedUnconfirmed = true;
    try {
      await this.keeper.unlockWith({ credentialId: DESKTOP_CREDENTIAL, deviceSalt: wrap.deviceSalt, wrappedAsk: wrap.wrappedAsk, enabledAt: now, lastPasswordUnlockAt: now }, wrap.key, this.unlocker);
    } catch {
      this.openedUnconfirmed = false;
      return false;
    }
    return this.unlocked;
  }

  /**
   * "Lock now": with stay unlocked on, the vault stays locked until the user unlocks it (or the
   * browser closes: the hold is in `chrome.storage.session`).
   */
  async holdLocked(held: boolean): Promise<void> {
    if (held) await this.options.memory.set(HELD, true);
    else await this.options.memory.delete(HELD);
  }

  /** The user answered the device lock or the master password since the unlock (plan 18). */
  markConfirmed(): void {
    this.setConfirmed(true);
  }

  /** Staying unlocked, the computer locked or slept: revealing and copying ask again (plan 18). */
  resetConfirmed(): void {
    this.setConfirmed(false);
  }

  private setConfirmed(confirmed: boolean): void {
    const session = this.accountSnapshot.session;
    if (session.status !== 'unlocked' || this.confirmed === confirmed) return;
    this.confirmed = confirmed;
    void this.keeper.setConfirmed(confirmed).catch(() => undefined);
    this.accountSnapshot = { ...this.accountSnapshot, session: withConfirmed(session, confirmed) };
    if (this.mode === 'account') this.publish({ type: 'session', snapshot: this.accountSnapshot });
  }

  /**
   * Unlocks with the desktop app (Touch ID, Windows Hello) over native messaging: the app must be
   * signed in to the same account. Unlocks the app first if it's locked.
   */
  async unlockWithDesktop(link: DesktopLink): Promise<void> {
    const { status, email, serverUrl } = this.accountSnapshot.session;
    if (this.local || status !== 'locked') throw new VaultError('locked');
    const app = await link.status();
    if (!app.appRunning) throw new VaultError('deviceUnlockUnsupported', app.browserNotTrusted ? 'browserNotTrusted' : 'appNotRunning');
    if (app.status === 'locked') await link.unlockApp();
    const wrap = await link.sessionKey();
    if (normalizeEmail(wrap.email) !== email || serverOrigin(wrap.serverUrl) !== serverUrl) throw new VaultError('deviceUnlockFailed', 'The desktop app is signed in to another account.');
    // The browser's own 14-day master password check is the app's business here: it asked for the device lock.
    const now = new Date(this.now()).toISOString();
    await this.keeper.unlockWith({ credentialId: DESKTOP_CREDENTIAL, deviceSalt: wrap.deviceSalt, wrappedAsk: wrap.wrappedAsk, enabledAt: now, lastPasswordUnlockAt: now }, wrap.key, this.unlocker);
  }

  // ---------- Local mode ----------

  /** "Use on this device only": a new local vault, unlocked. Returns its backup recovery code. */
  async createLocal(password: string): Promise<string> {
    this.requireSignedOut();
    const code = await this.localVault.create(password);
    this.useLocal();
    return code;
  }

  async restoreLocal(file: Uint8Array, secret: Full.BackupSecret, password: string): Promise<void> {
    this.requireSignedOut();
    await this.localVault.restore(file, secret, password);
    this.useLocal();
  }

  private requireSignedOut(): void {
    if (this.local || this.accountSnapshot.session.status !== 'signedOut') throw new VaultError('serverError', 'This browser already has a vault.');
  }

  private useLocal(): void {
    this.mode = 'local';
    this.publish({ type: 'session', snapshot: this.localVault.snapshot() });
  }

  private async startUpgrade(input: { serverUrl: string; email: string; password: string }): Promise<{ signupId: string; devVerificationCode?: string }> {
    const serverUrl = serverOrigin(input.serverUrl);
    const email = normalizeEmail(input.email);
    if (!isValidEmail(email)) throw new VaultError('invalidEmail');
    const signup = this.localVault.upgrade(email, input.password);
    try {
      const { registrationResponse, devVerificationCode } = await apiRequest<{ registrationResponse: string; devVerificationCode?: string }>(serverUrl, 'POST', '/v1/auth/register/start', {
        body: { email: signup.email, registrationRequest: signup.registrationRequest },
      });
      const registerFinish = signup.finish(registrationResponse);
      const signupId = crypto.randomUUID();
      this.upgrades.set(signupId, { serverUrl, email, password: input.password, signup, registerFinish, expiresAt: this.now() + UPGRADE_TTL_MS });
      return devVerificationCode ? { signupId, devVerificationCode } : { signupId };
    } catch (error) {
      signup.free();
      throw error;
    }
  }

  /**
   * Creates the account, signs in to it, uploads every local item unchanged into its personal vault
   * (same keys: `upgradeToAccount` kept them), then forgets the local vault.
   */
  private async finishUpgrade(input: { signupId: string; verificationCode: string }): Promise<{ recoveryKit: RecoveryKit }> {
    const pending = this.upgrades.get(input.signupId);
    if (!pending || pending.expiresAt < this.now()) throw new VaultError('signupExpired');
    const { serverUrl, email, signup, registerFinish } = pending;
    await apiRequest(serverUrl, 'POST', '/v1/auth/register/finish', { body: { email, verificationCode: input.verificationCode.replace(/\s/g, ''), ...registerFinish } });
    this.upgrades.delete(input.signupId);
    const recoveryKit: RecoveryKit = { email, serverUrl, secretKey: signup.secretKey, recoveryCode: signup.recoveryCode, createdAt: new Date(this.now()).toISOString() };
    signup.free();

    await this.account.call('signIn', [{ serverUrl, email, password: pending.password, secretKey: recoveryKit.secretKey }]);
    const vaultId = registerFinish.personalVault.id;
    const operations = this.localVault.storedItems().map(({ id, encryptedItemKey, overview, details }) => ({ vaultId, itemId: id, item: { encryptedItemKey, overview, details } }));
    const token = async () => {
      const current = this.tap.token(serverUrl);
      if (!current) throw new VaultError('sessionExpired');
      return current;
    };
    const uploaded = await putItems(serverUrl, token, operations);
    if (uploaded !== operations.length) throw new VaultError('serverError', `Only ${uploaded} of ${operations.length} items were uploaded. Your vault is still on this device.`);
    await this.account.call('sync', []);
    await this.localVault.forget();
    this.mode = 'account';
    this.publish({ type: 'session', snapshot: this.accountSnapshot });
    this.publish({ type: 'items' });
    return { recoveryKit };
  }

  // Helpers for the content script and the passkey authenticator.

  listItems(): Promise<ItemSummary[]> {
    return this.engine.call('listItems', [{}]);
  }

  getItem(id: string): Promise<Item> {
    return this.engine.call('getItem', [id]);
  }

  private now(): number {
    return this.options.now?.() ?? Date.now();
  }

  private readonly unlocker: Unlocker = {
    wrap: (credentialId, key) => this.account.call('enableDeviceUnlock', [credentialId, key]),
    unwrap: (key) => this.account.call('unlockWithDevice', [key]),
  };

  private handleAccount(event: EngineEvent): void {
    if (event.type === 'session') {
      const before = this.accountSnapshot.session;
      const was = before.status;
      const session = event.snapshot.session;
      const status = session.status;
      const opened = status === 'unlocked' && (was !== 'unlocked' || before.email !== session.email || before.serverUrl !== session.serverUrl);
      const byStayUnlocked = opened && this.openedUnconfirmed;
      if (status !== 'unlocked') this.confirmed = false;
      else if (opened && !this.restoring) this.confirmed = !byStayUnlocked && session.confirmed === true;
      if (opened) this.openedUnconfirmed = false;
      // The user's own unlock ends "Lock now"'s hold.
      if (opened && !this.restoring && !byStayUnlocked) void this.holdLocked(false).catch(() => undefined);
      event = { type: 'session', snapshot: { ...event.snapshot, session: withConfirmed(session, this.confirmed) } };
      this.accountSnapshot = event.snapshot;
      if (status === 'unlocked' && was !== 'unlocked' && !this.restoring) void this.keeper.save(this.unlocker, this.confirmed).catch(() => undefined);
      if (status !== 'unlocked') void this.keeper.clear();
    }
    if (this.mode === 'account') this.publish(event);
  }

  private handleLocal(event: EngineEvent): void {
    if (this.mode === 'local') this.publish(event);
  }

  private publish(event: EngineEvent): void {
    if (event.type === 'session') this.current = event.snapshot;
    for (const listener of this.listeners) listener(event);
  }
}
