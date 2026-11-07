// The page side of the real vault service. It holds no keys and no vault data: everything secret
// stays with the engine (in the web vault, a dedicated worker). The page keeps only what it must
// answer synchronously (the session state and remembered accounts), runs the WebAuthn prompts the
// worker can't, and computes password strength and generated passwords, which never leave it.

import { VaultError } from '../errors';
import { normalizeEmail } from '../items';
import { base64UrlDecode, base64UrlEncode } from '../tools/encoding';
import { generatePassword } from '../tools/generator';
import { estimateStrength } from '../tools/strength';
import { withConfirmed, type ServiceAccount } from '../types';
import type {
  EquivalentDomains,
  HotpCode,
  ItemVersion,
  AccountLookup,
  AccountSummary,
  AttachmentService,
  CreatedShareLink,
  Device,
  EmergencyAccessLevel,
  EmergencyContact,
  EmergencyContacts,
  EmergencyScope,
  EmergencyVaultView,
  NewRecoveryKit,
  FamilyState,
  Fingerprint,
  KeyLogState,
  GeneratorOptions,
  ExportFormat,
  ExportOptions,
  EmailBreach,
  HealthReport,
  ImportOptions,
  QrCaptureService,
  QrScan,
  ImportReview,
  CodeLink,
  ImportResult,
  IdentityConfirmation,
  ImportSource,
  Item,
  ItemDraft,
  ItemFilter,
  ItemSummary,
  MaskedEmailService,
  PasswordResetResult,
  PendingTwoStep,
  RecoveryKit,
  RememberedAccount,
  SecurityEvent,
  SecurityKeyInfo,
  ServerInfo,
  SessionState,
  ShareLinkEnvelope,
  ShareLinkInfo,
  ShareLinkOptions,
  SharedItem,
  OrgAccessGrant,
  OrgAccessReview,
  OrgEvent,
  OrgGroup,
  OrgMembers,
  OrgPolicies,
  OrgRole,
  OrgSsoSettings,
  OrgVault,
  OrganisationService,
  OrganisationState,
  SharingService,
  SshKeyService,
  ToolHash,
  ToolkitService,
  StorageUsage,
  SignInResult,
  StrengthEstimate,
  TotpCode,
  TotpSetup,
  TwoStepProof,
  TwoStepService,
  TwoStepStatus,
  UnlockMethods,
  Vault,
  VaultMember,
  VaultRole,
  VaultService,
} from '../types';
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
import type { WebAuthnRequestOptions } from './api';
import type { EngineEvent, EngineSignInResult, Snapshot } from './engine';
import { createMaskedEmailService, type MaskedEmailOptions } from '../maskedEmail';
import { watchPage } from './pageSync';
import type { EngineClient } from './protocol';

export interface RemoteOptions {
  /**
   * Starts watching for moments to sync while unlocked; returns a stop function. Defaults to page
   * focus, visibility and a 30 s timer, which the engine skips while live notifications arrive.
   */
  watch?: (sync: () => void) => () => void;
  /** Where masked email calls run (default: a web page, with `fetch`). */
  maskedEmail?: MaskedEmailOptions;
  /** The extension's "Scan QR code on this page". */
  qrCapture?: QrCaptureService;
  /** `false` leaves out file hashing: extension messages can't carry a `Blob`. */
  toolkitFiles?: boolean;
  /** `false` leaves out `sshKeys`: the extension keeps private keys out of its pages. */
  sshKeys?: boolean;
}

export class RemoteVaultService implements VaultService, SharingService, AttachmentService, TwoStepService, OrganisationService {
  private session: SessionState = { status: 'signedOut' };
  private remembered: RememberedAccount[] = [];
  private readonly sessionListeners = new Set<(s: SessionState) => void>();
  private readonly itemListeners = new Set<() => void>();
  private readonly sharingListeners = new Set<() => void>();

  get sharing(): SharingService {
    return this;
  }

  get organisations(): OrganisationService {
    return this;
  }

  get attachments(): AttachmentService {
    return this;
  }

  get twoStep(): TwoStepService {
    return this;
  }

  readonly maskedEmail: MaskedEmailService;
  readonly qrCapture: QrCaptureService | undefined;
  readonly sshKeys: SshKeyService | undefined;
  readonly toolkit: ToolkitService;
  /** The security key challenge of a sign-in waiting for its second step, when this page can answer it. */
  private pendingWebAuthn: WebAuthnRequestOptions | undefined;
  private stopWatching: (() => void) | undefined;

  private constructor(
    private readonly engine: EngineClient,
    private readonly options: RemoteOptions,
  ) {
    engine.onEvent((event) => this.handle(event));
    this.maskedEmail = createMaskedEmailService(this, options.maskedEmail ?? { context: 'browser' });
    this.qrCapture = options.qrCapture;
    this.sshKeys = options.sshKeys === false ? undefined : this.sshKeyService();
    this.toolkit = this.toolkitService(options.toolkitFiles !== false);
  }

  /** Tools run in the worker. JWKS URLs are fetched from there too, with no credentials or referrer. */
  private toolkitService(files: boolean): ToolkitService {
    return {
      run: async <T,>(op: string, input: object) => JSON.parse(await this.engine.call('toolRun', [op, JSON.stringify(input)])) as T,
      ...(files ? { hashFile: async (file: Blob, algorithms: string[]) => JSON.parse(await this.engine.call('toolHashFile', [file, algorithms])) as ToolHash[] } : {}),
      fetchJwks: async (url) => {
        const response = await fetch(url, { credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error' });
        if (!response.ok) throw new VaultError('serverError');
        return response.text();
      },
    };
  }

  /** SSH key operations run in the worker; confirming uses the master password or this device's unlock passkey. */
  private sshKeyService(): SshKeyService {
    return {
      generate: (kind, comment) => this.engine.call('generateSshKey', [kind, comment.trim()]),
      read: (text, passphrase) => this.engine.call('readSshKey', [text, passphrase || undefined]),
      write: (privateKey, comment, passphrase) => this.engine.call('writeSshKey', [privateKey, comment.trim(), passphrase || undefined]),
      confirm: async (proof) => {
        if ('password' in proof) return this.engine.call('confirmMasterPassword', [proof.password]);
        const credentialId = await this.engine.call('confirmDeviceCredential', []);
        if (!credentialId) throw new VaultError('deviceUnlockFailed');
        const prf = await evaluatePrf(base64UrlDecode(credentialId));
        await this.engine.call('confirmWithDevice', [prf], [prf.buffer]);
      },
      canConfirmWithDevice: async () => (await this.engine.call('confirmDeviceCredential', [])) !== undefined,
    };
  }

  static async create(engine: EngineClient, options: RemoteOptions = {}): Promise<RemoteVaultService> {
    const service = new RemoteVaultService(engine, options);
    service.apply(await engine.call('init', []));
    // Fetch and compile the WASM core while the user types; nothing waits for it yet.
    void engine.call('preload', []).catch(() => undefined);
    return service;
  }

  // ---------- Server + account ----------

  getServerInfo(serverUrl: string): Promise<ServerInfo> {
    return this.engine.call('getServerInfo', [serverUrl]);
  }

  startSignup(input: { serverUrl: string; email: string; password: string }) {
    return this.engine.call('startSignup', [input]);
  }

  finishSignup(input: { signupId: string; verificationCode: string }): Promise<{ recoveryKit: RecoveryKit }> {
    return this.engine.call('finishSignup', [input]);
  }

  async signIn(input: { serverUrl: string; email: string; password: string; secretKey?: string }): Promise<SignInResult> {
    this.pendingWebAuthn = undefined;
    const result = await this.engine.call('signIn', [input]);
    return result.status === 'twoStepRequired' ? this.offer(result) : result;
  }

  async finishSso(code: string): Promise<SignInResult> {
    const result = await this.engine.call('finishSso', [code]);
    return result.status === 'twoStepRequired' ? this.offer(result) : result;
  }

  async pendingTwoStep(): Promise<PendingTwoStep | undefined> {
    const waiting = await this.engine.call('pendingTwoStep', []);
    if (waiting?.status === 'twoStepRequired') return this.offer(waiting);
    return waiting?.status === 'twoStepExpired' || waiting?.status === 'ssoRequired' ? waiting : undefined;
  }

  cancelTwoStep(): Promise<void> {
    this.pendingWebAuthn = undefined;
    return this.engine.call('cancelTwoStep', []);
  }

  async finishTwoStep(proof: TwoStepProof): Promise<void> {
    if (proof.method === 'securityKey') {
      if (!this.pendingWebAuthn) throw new VaultError('securityKeyUnsupported');
      const assertion = await getSecurityKeyAssertion(this.pendingWebAuthn);
      await this.engine.call('finishTwoStep', [{ method: 'securityKey', assertion }]);
    } else {
      await this.engine.call('finishTwoStep', [proof]);
    }
    this.pendingWebAuthn = undefined;
  }

  rememberedAccounts(): RememberedAccount[] {
    return this.remembered;
  }

  lock(): void {
    if (this.session.status !== 'unlocked') return;
    // The page is locked at once; the worker frees the keys right behind it.
    this.setSession(withConfirmed({ ...this.session, status: 'locked' }, false));
    void this.engine.call('lock', []);
  }

  unlock(password: string): Promise<void> {
    return this.engine.call('unlock', [password]);
  }

  signOut(): Promise<void> {
    return this.engine.call('signOut', []);
  }

  getSession(): SessionState {
    return this.session;
  }

  onSessionChange(cb: (s: SessionState) => void): () => void {
    this.sessionListeners.add(cb);
    return () => this.sessionListeners.delete(cb);
  }

  getSecretKey(): Promise<string> {
    return this.engine.call('getSecretKey', []);
  }

  getAccountSummary(): Promise<AccountSummary> {
    return this.engine.call('getAccountSummary', []);
  }

  deleteAccount(input: { confirmEmail: string; password: string }): Promise<void> {
    if (normalizeEmail(input.confirmEmail) !== this.session.email) return Promise.reject(new VaultError('emailMismatch'));
    return this.engine.call('deleteAccount', [input]);
  }

  changeMasterPassword(input: { currentPassword: string; newPassword: string }): Promise<void> {
    return this.engine.call('changeMasterPassword', [input]);
  }

  rotateSecretKey(input: { password: string; newRecoveryCode: boolean }): Promise<NewRecoveryKit> {
    return this.engine.call('rotateSecretKey', [input]);
  }

  startPasswordReset(input: { serverUrl: string; email: string }): Promise<{ resetId: string; devVerificationCode?: string }> {
    return this.engine.call('startPasswordReset', [input]);
  }

  verifyPasswordReset(input: { resetId: string; verificationCode: string }): Promise<void> {
    return this.engine.call('verifyPasswordReset', [input]);
  }

  async finishPasswordReset(input: { resetId: string; recoveryCode: string; password: string }): Promise<PasswordResetResult> {
    this.pendingWebAuthn = undefined;
    const { recoveryKit, signIn } = await this.engine.call('finishPasswordReset', [input]);
    if (!signIn) return { recoveryKit };
    return { recoveryKit, signIn: signIn.status === 'twoStepRequired' ? this.offer(signIn) : signIn };
  }

  cancelPasswordReset(resetId: string): Promise<void> {
    return this.engine.call('cancelPasswordReset', [resetId]);
  }

  /** Security keys answer only on the server's own site: not in the extension, or on another host. */
  private offer(result: Extract<EngineSignInResult, { status: 'twoStepRequired' }>): Extract<SignInResult, { status: 'twoStepRequired' }> {
    const keys = result.webauthn !== undefined && securityKeysSupported(result.webauthn.rpId);
    this.pendingWebAuthn = keys ? result.webauthn : undefined;
    return { status: 'twoStepRequired', methods: result.methods.filter((m) => m !== 'securityKey' || keys) };
  }

  // ---------- Two-step sign-in settings ----------

  async getTwoStepStatus(): Promise<TwoStepStatus> {
    const { rpId, ...status } = await this.engine.call('getTwoStepStatus', []);
    return { ...status, securityKeysSupported: securityKeysSupported(rpId) };
  }

  startTotpSetup(password: string): Promise<TotpSetup> {
    return this.engine.call('startTotpSetup', [password]);
  }

  confirmTotpSetup(code: string): Promise<{ recoveryCodes?: string[] }> {
    return this.engine.call('confirmTotpSetup', [code]);
  }

  async addSecurityKey(input: { password: string; name: string }): Promise<SecurityKeyInfo> {
    const { setupId, publicKey } = await this.engine.call('securityKeyOptions', [input.password]);
    if (!securityKeysSupported(publicKey.rp.id)) throw new VaultError('securityKeyUnsupported');
    const attestation = await createSecurityKey(publicKey);
    return this.engine.call('addSecurityKey', [{ ...attestation, setupId, name: input.name }]);
  }

  removeSecurityKey(input: { id: string; password: string }): Promise<void> {
    return this.engine.call('removeSecurityKey', [input]);
  }

  renewRecoveryCodes(password: string): Promise<string[]> {
    return this.engine.call('renewRecoveryCodes', [password]);
  }

  disableTwoStep(password: string): Promise<void> {
    return this.engine.call('disableTwoStep', [password]);
  }

  forgetTrustedDevices(): Promise<void> {
    return this.engine.call('forgetTrustedDevices', []);
  }

  // ---------- Device unlock ----------

  async getUnlockMethods(): Promise<UnlockMethods> {
    const platform = detectPlatform();
    const [supported, status] = await Promise.all([isPlatformAuthenticatorAvailable(), this.engine.call('deviceUnlockStatus', [])]);
    return { deviceUnlockSupported: supported, deviceUnlockEnabled: status.enabled, label: DEVICE_LABELS[platform], platform, passwordRequired: status.passwordRequired };
  }

  async enableDeviceUnlock(): Promise<void> {
    if (this.session.status !== 'unlocked') throw new VaultError('locked');
    const { id, prf } = await setUpDeviceCredential(this.session.email!);
    await this.engine.call('enableDeviceUnlock', [base64UrlEncode(id), prf], [prf.buffer]);
  }

  disableDeviceUnlock(): Promise<void> {
    return this.engine.call('disableDeviceUnlock', []);
  }

  async unlockWithDevice(): Promise<void> {
    const credentialId = await this.engine.call('deviceUnlockCredential', []);
    const prf = await evaluatePrf(base64UrlDecode(credentialId));
    await this.engine.call('unlockWithDevice', [prf], [prf.buffer]);
  }

  /** Reveal/copy/export: device auth where this device has it, else the master password. */
  async confirmIdentity(proof: IdentityConfirmation): Promise<void> {
    if ('password' in proof) return this.engine.call('confirmMasterPassword', [proof.password]);
    const credentialId = await this.engine.call('confirmDeviceCredential', []);
    if (!credentialId) throw new VaultError('deviceUnlockFailed');
    const prf = await evaluatePrf(base64UrlDecode(credentialId));
    await this.engine.call('confirmWithDevice', [prf], [prf.buffer]);
  }

  async canConfirmIdentityWithDevice(): Promise<boolean> {
    return (await this.engine.call('confirmDeviceCredential', [])) !== undefined;
  }

  // ---------- Vault ----------

  listVaults(): Promise<Vault[]> {
    return this.engine.call('listVaults', []);
  }

  listItems(filter?: ItemFilter): Promise<ItemSummary[]> {
    return this.engine.call('listItems', [filter]);
  }

  itemVersions(id: string): Promise<ItemVersion[]> {
    return this.engine.call('itemVersions', [id]);
  }

  restoreItemVersion(id: string, revision: number): Promise<Item> {
    return this.engine.call('restoreItemVersion', [id, revision]);
  }

  nextHotpCode(id: string): Promise<HotpCode> {
    return this.engine.call('nextHotpCode', [id]);
  }

  setHotpCounter(id: string, counter: number): Promise<Item> {
    return this.engine.call('setHotpCounter', [id, counter]);
  }

  equivalentDomains(): Promise<EquivalentDomains> {
    return this.engine.call('equivalentDomains', []);
  }

  saveEquivalentDomains(input: { groups: string[][]; excludedDefaults: string[] }): Promise<EquivalentDomains & { rejected: string[] }> {
    return this.engine.call('saveEquivalentDomains', [input]);
  }

  generatePasswordForSite(url: string, options: Extract<GeneratorOptions, { kind: 'password' }>): Promise<string> {
    const { kind: _kind, ...random } = options;
    return this.engine.call('generatePasswordForSite', [url, random]);
  }

  getItem(id: string): Promise<Item> {
    return this.engine.call('getItem', [id]);
  }

  saveItem(item: ItemDraft): Promise<Item> {
    return this.engine.call('saveItem', [item]);
  }

  deleteItem(id: string): Promise<void> {
    return this.engine.call('deleteItem', [id]);
  }

  restoreItem(id: string): Promise<void> {
    return this.engine.call('restoreItem', [id]);
  }

  onItemsChange(cb: () => void): () => void {
    this.itemListeners.add(cb);
    return () => this.itemListeners.delete(cb);
  }

  // ---------- Attachments ----------

  addAttachment(itemId: string, file: Blob, name: string): Promise<Item> {
    // A File or Blob crosses to the worker by reference; it reads the bytes there.
    return this.engine.call('addAttachment', [itemId, file, name]);
  }

  getAttachment(itemId: string, attachmentId: string): Promise<Blob> {
    return this.engine.call('getAttachment', [itemId, attachmentId]);
  }

  removeAttachment(itemId: string, attachmentId: string): Promise<Item> {
    return this.engine.call('removeAttachment', [itemId, attachmentId]);
  }

  getStorageUsage(): Promise<StorageUsage> {
    return this.engine.call('getStorageUsage', []);
  }

  // ---------- Tools ----------

  generatePassword(opts: GeneratorOptions): string {
    return generatePassword(opts);
  }

  estimateStrength(password: string): StrengthEstimate {
    const email = this.session.email;
    return estimateStrength(password, email ? [email, email.split('@')[0]!] : undefined);
  }

  totpCode(totp: string, at?: number): Promise<TotpCode> {
    return this.engine.call('totpCode', [totp, at]);
  }

  checkBreached(password: string): Promise<number> {
    return this.engine.call('checkBreached', [password]);
  }

  getHealthReport(): Promise<HealthReport> {
    return this.engine.call('getHealthReport', []);
  }

  lookupEmailBreaches(address: string): Promise<EmailBreach[]> {
    return this.engine.call('lookupEmailBreaches', [address]);
  }

  exportVault(format: ExportFormat, options?: ExportOptions): Promise<Blob> {
    return this.engine.call('exportVault', [format, options]);
  }

  importFile(source: ImportSource, file: File, options?: ImportOptions): Promise<ImportResult> {
    return this.engine.call('importFile', [source, file, options]);
  }

  reviewImport(source: ImportSource, file: Blob, options?: ImportOptions): Promise<ImportReview> {
    // Ports that speak JSON turn a missing argument into `null`.
    return this.engine.call('reviewImport', [source, file, options ?? {}]);
  }

  finishImport(reviewId: string, links: CodeLink[]): Promise<ImportResult> {
    return this.engine.call('finishImport', [reviewId, links]);
  }

  async cancelImport(reviewId: string): Promise<void> {
    await this.engine.call('cancelImport', [reviewId]);
  }

  readQrCodes(image: Blob): Promise<string[]> {
    return this.engine.call('readQrCodes', [image]);
  }

  summarizeQrScans(texts: string[]): Promise<QrScan> {
    return this.engine.call('summarizeQrScans', [texts]);
  }

  // ---------- Organisations ----------

  getOrganisation(): Promise<OrganisationState> {
    return this.engine.call('getOrganisation', []);
  }

  createOrganisation(name: string): Promise<void> {
    return this.engine.call('createOrganisation', [name]);
  }

  renameOrganisation(name: string): Promise<void> {
    return this.engine.call('renameOrganisation', [name]);
  }

  deleteOrganisation(input: { password: string; confirmName: string }): Promise<void> {
    return this.engine.call('deleteOrganisation', [input]);
  }

  acceptOrgInvite(orgId: string, inviteId: string): Promise<void> {
    return this.engine.call('acceptOrgInvite', [orgId, inviteId]);
  }

  declineOrgInvite(orgId: string, inviteId: string): Promise<void> {
    return this.engine.call('declineOrgInvite', [orgId, inviteId]);
  }

  listOrgMembers(): Promise<OrgMembers> {
    return this.engine.call('listOrgMembers', []);
  }

  inviteOrgMember(email: string, role: OrgRole): Promise<void> {
    return this.engine.call('inviteOrgMember', [email, role]);
  }

  cancelOrgInvite(inviteId: string): Promise<void> {
    return this.engine.call('cancelOrgInvite', [inviteId]);
  }

  setOrgMemberRole(accountId: string, role: OrgRole): Promise<void> {
    return this.engine.call('setOrgMemberRole', [accountId, role]);
  }

  removeOrgMember(accountId: string, options?: { orphanVaults?: boolean }): Promise<void> {
    return this.engine.call('removeOrgMember', [accountId, options]);
  }

  leaveOrganisation(options?: { orphanVaults?: boolean }): Promise<void> {
    return this.engine.call('leaveOrganisation', [options]);
  }

  listOrgGroups(): Promise<OrgGroup[]> {
    return this.engine.call('listOrgGroups', []);
  }

  createOrgGroup(name: string): Promise<OrgGroup> {
    return this.engine.call('createOrgGroup', [name]);
  }

  renameOrgGroup(groupId: string, name: string): Promise<void> {
    return this.engine.call('renameOrgGroup', [groupId, name]);
  }

  deleteOrgGroup(groupId: string): Promise<void> {
    return this.engine.call('deleteOrgGroup', [groupId]);
  }

  addOrgGroupMember(groupId: string, accountId: string): Promise<void> {
    return this.engine.call('addOrgGroupMember', [groupId, accountId]);
  }

  removeOrgGroupMember(groupId: string, accountId: string): Promise<void> {
    return this.engine.call('removeOrgGroupMember', [groupId, accountId]);
  }

  listOrgVaults(): Promise<OrgVault[]> {
    return this.engine.call('listOrgVaults', []);
  }

  createOrgVault(name: string): Promise<void> {
    return this.engine.call('createOrgVault', [name]);
  }

  deleteOrgVault(input: { password: string; vaultId: string }): Promise<void> {
    return this.engine.call('deleteOrgVault', [input]);
  }

  linkOrgVaultGroup(vaultId: string, groupId: string, role: VaultRole): Promise<void> {
    return this.engine.call('linkOrgVaultGroup', [vaultId, groupId, role]);
  }

  unlinkOrgVaultGroup(vaultId: string, groupId: string): Promise<void> {
    return this.engine.call('unlinkOrgVaultGroup', [vaultId, groupId]);
  }

  getOrgAccess(): Promise<OrgAccessReview[]> {
    return this.engine.call('getOrgAccess', []);
  }

  applyOrgAccess(vaultId: string, confirmed: Pick<OrgAccessGrant, 'accountId' | 'fingerprint'>[]): Promise<void> {
    return this.engine.call('applyOrgAccess', [vaultId, confirmed]);
  }

  rotateOrgVault(vaultId: string): Promise<void> {
    return this.engine.call('rotateOrgVault', [vaultId]);
  }

  setOrgPolicies(policies: OrgPolicies): Promise<void> {
    return this.engine.call('setOrgPolicies', [policies]);
  }

  getOrgSso(): Promise<OrgSsoSettings> {
    return this.engine.call('getOrgSso', []);
  }

  saveOrgSso(input: { issuer: string; clientId: string; clientSecret?: string }): Promise<OrgSsoSettings> {
    return this.engine.call('saveOrgSso', [input]);
  }

  removeOrgSso(): Promise<void> {
    return this.engine.call('removeOrgSso', []);
  }

  testOrgSso(): Promise<string> {
    return this.engine.call('testOrgSso', []);
  }

  listOrgEvents(): Promise<OrgEvent[]> {
    return this.engine.call('listOrgEvents', []);
  }

  // ---------- Sharing ----------

  listDevices(): Promise<Device[]> {
    return this.engine.call('listDevices', []);
  }

  renameDevice(name: string): Promise<void> {
    return this.engine.call('renameDevice', [name]);
  }

  signOutDevice(deviceId: string): Promise<void> {
    return this.engine.call('signOutDevice', [deviceId]);
  }

  getMyFingerprint(): Promise<Fingerprint> {
    return this.engine.call('getMyFingerprint', []);
  }

  lookupAccount(email: string): Promise<AccountLookup> {
    return this.engine.call('lookupAccount', [email]);
  }

  markVerified(account: Pick<AccountLookup, 'accountId' | 'fingerprint'>): Promise<void> {
    return this.engine.call('markVerified', [account]);
  }

  getKeyLogState(): Promise<KeyLogState> {
    return this.engine.call('getKeyLogState', []);
  }

  dismissKeyLogAlert(): Promise<void> {
    return this.engine.call('dismissKeyLogAlert', []);
  }

  createVault(name: string): Promise<Vault> {
    return this.engine.call('createVault', [name]);
  }

  renameVault(vaultId: string, name: string): Promise<void> {
    return this.engine.call('renameVault', [vaultId, name]);
  }

  listMembers(vaultId: string): Promise<VaultMember[]> {
    return this.engine.call('listMembers', [vaultId]);
  }

  listServiceAccounts(vaultId: string): Promise<ServiceAccount[]> {
    return this.engine.call('listServiceAccounts', [vaultId]);
  }

  createServiceAccount(vaultId: string, input: { name: string; role: 'read' | 'write'; expiresAt?: string }): Promise<{ account: ServiceAccount; token: string }> {
    return this.engine.call('createServiceAccount', [vaultId, input]);
  }

  revokeServiceAccount(vaultId: string, id: string): Promise<void> {
    return this.engine.call('revokeServiceAccount', [vaultId, id]);
  }

  addMember(vaultId: string, account: AccountLookup, role: VaultRole): Promise<void> {
    return this.engine.call('addMember', [vaultId, account, role]);
  }

  changeRole(vaultId: string, accountId: string, role: VaultRole): Promise<void> {
    return this.engine.call('changeRole', [vaultId, accountId, role]);
  }

  removeMember(vaultId: string, accountId: string): Promise<void> {
    return this.engine.call('removeMember', [vaultId, accountId]);
  }

  leaveVault(vaultId: string): Promise<void> {
    return this.engine.call('leaveVault', [vaultId]);
  }

  moveItem(itemId: string, toVaultId: string): Promise<Item> {
    return this.engine.call('moveItem', [itemId, toVaultId]);
  }

  copyItem(itemId: string, toVaultId: string): Promise<Item> {
    return this.engine.call('copyItem', [itemId, toVaultId]);
  }

  getFamily(): Promise<FamilyState> {
    return this.engine.call('getFamily', []);
  }

  createFamily(): Promise<void> {
    return this.engine.call('createFamily', []);
  }

  inviteToFamily(account: AccountLookup): Promise<void> {
    return this.engine.call('inviteToFamily', [account]);
  }

  acceptFamilyInvite(familyId: string): Promise<void> {
    return this.engine.call('acceptFamilyInvite', [familyId]);
  }

  declineFamilyInvite(familyId: string): Promise<void> {
    return this.engine.call('declineFamilyInvite', [familyId]);
  }

  cancelFamilyInvite(accountId: string): Promise<void> {
    return this.engine.call('cancelFamilyInvite', [accountId]);
  }

  removeFamilyMember(accountId: string): Promise<void> {
    return this.engine.call('removeFamilyMember', [accountId]);
  }

  leaveFamily(): Promise<void> {
    return this.engine.call('leaveFamily', []);
  }

  deleteFamily(): Promise<void> {
    return this.engine.call('deleteFamily', []);
  }

  createShareLink(itemId: string, options: ShareLinkOptions): Promise<CreatedShareLink> {
    return this.engine.call('createShareLink', [itemId, options]);
  }

  listShareLinks(): Promise<ShareLinkInfo[]> {
    return this.engine.call('listShareLinks', []);
  }

  revokeShareLink(id: string): Promise<void> {
    return this.engine.call('revokeShareLink', [id]);
  }

  fetchShareLink(serverUrl: string, id: string): Promise<ShareLinkEnvelope> {
    return this.engine.call('fetchShareLink', [serverUrl, id]);
  }

  openShareLink(ciphertext: string, key: string, passphrase?: string): Promise<SharedItem> {
    return this.engine.call('openShareLink', [ciphertext, key, passphrase]);
  }

  listEmergencyContacts(): Promise<EmergencyContacts> {
    return this.engine.call('listEmergencyContacts', []);
  }

  addEmergencyContact(input: { account: AccountLookup; waitDays: number; accessLevel: EmergencyAccessLevel; scope: EmergencyScope }): Promise<EmergencyContact> {
    return this.engine.call('addEmergencyContact', [input]);
  }

  removeEmergencyContact(id: string): Promise<void> {
    return this.engine.call('removeEmergencyContact', [id]);
  }

  requestEmergencyAccess(id: string): Promise<void> {
    return this.engine.call('requestEmergencyAccess', [id]);
  }

  denyEmergencyAccess(id: string): Promise<void> {
    return this.engine.call('denyEmergencyAccess', [id]);
  }

  approveEmergencyAccess(id: string): Promise<void> {
    return this.engine.call('approveEmergencyAccess', [id]);
  }

  openEmergencyAccess(id: string): Promise<EmergencyVaultView> {
    return this.engine.call('openEmergencyAccess', [id]);
  }

  getEmergencyAttachment(id: string, itemId: string, attachmentId: string): Promise<Blob> {
    return this.engine.call('getEmergencyAttachment', [id, itemId, attachmentId]);
  }

  renewEmergencyKey(id: string, account: AccountLookup): Promise<void> {
    return this.engine.call('renewEmergencyKey', [id, account]);
  }

  takeOverAccount(id: string, input: { contactPassword: string; newPassword: string }): Promise<NewRecoveryKit> {
    return this.engine.call('takeOverAccount', [id, input]);
  }

  enableOrganiserRecovery(input: { account: AccountLookup; waitDays: number }): Promise<EmergencyContact> {
    return this.engine.call('enableOrganiserRecovery', [input]);
  }

  rotateVaultKey(vaultId: string): Promise<void> {
    return this.engine.call('rotateVaultKey', [vaultId]);
  }

  getSecurityLog(): Promise<SecurityEvent[]> {
    return this.engine.call('getSecurityLog', []);
  }

  onSharingChange(cb: () => void): () => void {
    this.sharingListeners.add(cb);
    return () => this.sharingListeners.delete(cb);
  }

  // ---------- Internals ----------

  private handle(event: EngineEvent): void {
    if (event.type === 'session') this.apply(event.snapshot);
    else if (event.type === 'sharing') for (const cb of this.sharingListeners) cb();
    else for (const cb of this.itemListeners) cb();
  }

  private apply(snapshot: Snapshot): void {
    this.remembered = snapshot.remembered;
    this.setSession(snapshot.session);
  }

  private setSession(session: SessionState): void {
    if (session.status === 'unlocked') {
      this.stopWatching ??= (this.options.watch ?? watchPage)(() => void this.engine.call('backgroundSync', []).catch(() => undefined));
    } else {
      this.stopWatching?.();
      this.stopWatching = undefined;
    }
    const { status, email, serverUrl, confirmed } = this.session;
    // Same state, same object: React's useSyncExternalStore compares snapshots by identity.
    if (session.status === status && session.email === email && session.serverUrl === serverUrl && session.confirmed === confirmed) return;
    this.session = session;
    for (const cb of this.sessionListeners) cb(session);
    if (session.status === 'unlocked') for (const cb of this.itemListeners) cb();
  }
}
