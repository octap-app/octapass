import {
  appShareLinkUrl,
  base64UrlEncode,
  compareSummaries,
  buildHealthReport,
  createMaskedEmailService,
  estimateStrength,
  exportCsv,
  exportJson,
  fetchHttp,
  generatePassword,
  iconAnswer,
  matchesFilter,
  PROVIDER_API_HOSTS,
  VaultError,
  withConfirmed,
  type AccountLookup,
  type AccountSummary,
  type AttachmentService,
  type AutoTypeService,
  type BackgroundService,
  type BrowserExtensionService,
  type CodeLink,
  type CreatedShareLink,
  type Device,
  type EmergencyContact,
  type EmergencyContacts,
  type EmergencyVaultView,
  type NewRecoveryKit,
  type FamilyState,
  type Fingerprint,
  type KeyLogState,
  type ExportFormat,
  type ExportOptions,
  type FileRecipient,
  type FileResult,
  type FileMenuStatus,
  type FileSource,
  type EquivalentDomains,
  type Here,
  type NearbyPlace,
  type FilesService,
  type LocalFile,
  type SafeEntry,
  type SafeSummary,
  type SafeSyncReport,
  type GeneratorOptions,
  type EmailBreach,
  type HotpCode,
  type ItemVersion,
  type HealthReport,
  type HealthSettingsDetails,
  type IconAnswer,
  type IdentityConfirmation,
  type StayUnlockedStatus,
  type LocalCapabilities,
  type LocalVaultInfo,
  type LocalVaultService,
  type ImportOptions,
  type ImportResult,
  type ImportReview,
  type NativeFiles,
  type PickedFile,
  type QrCaptureService,
  type QrScan,
  type ImportSource,
  type Item,
  type ItemDraft,
  type ItemFilter,
  type ItemSummary,
  type ItemDetails,
  type ItemType,
  type MaskedEmailHttp,
  type MaskedEmailService,
  type RecoveryInfo,
  type PasswordResetResult,
  type RecoveryKit,
  type RememberedAccount,
  type SecurityEvent,
  type SecurityKeyInfo,
  type ServerInfo,
  type SessionState,
  type ShareLinkEnvelope,
  type ShareLinkInfo,
  type SharedItem,
  type SharingService,
  type StorageUsage,
  type SignInResult,
  type StrengthEstimate,
  type TotpCode,
  type TotpSetup,
  type TwoStepProof,
  type TwoStepService,
  type TwoStepStatus,
  type UnlockMethods,
  type Vault,
  type VaultErrorCode,
  type VaultMember,
  type VaultService,
  type SshAgentService,
  type SshHomeService,
  type SshKeyService,
  type WifiService,
  type HostCertificates,
  type ToolHash,
  type ToolkitService,
} from '@octapass/vault-client';
import type { ConnectClient, ConnectService, ServiceAccount } from '@octapass/vault-client';
import type {
  OrgAccessReview,
  OrgEvent,
  OrgGroup,
  OrgMembers,
  OrgScim,
  OrgScimToken,
  OrgSsoSettings,
  OrgVault,
  OrganisationService,
  OrganisationState,
} from '@octapass/vault-client';
import type { DesktopSsh } from './ssh';
import type { Transport } from './transport';

/** What the Rust side pushes on `vault://session` and answers to `session_snapshot`. */
export interface SessionSnapshot {
  session: SessionState;
  rememberedAccounts: RememberedAccount[];
}

/** The inputs to the security dashboard: rows and password groups, never the passwords. */
export interface HealthInputs {
  logins: {
    itemId: string;
    vaultId: string;
    type: ItemType;
    title: string;
    subtitle?: string;
    urls?: string[];
    hasTotp: boolean;
    hasPasskey: boolean;
    twoFactorMethod?: string;
    username?: string;
    /** Recovery email and phone, and where they came from; never backup codes. */
    recovery?: Pick<RecoveryInfo, 'email' | 'emailSource' | 'phone' | 'phoneSource'>;
    passwordGroup?: number;
    /** When the password was last set, or the item first saved. */
    passwordDate?: string;
    /** How many backup codes are saved, and how many unused; never the codes. */
    backupCodes?: { total: number; unused: number };
  }[];
  /** Cards, IDs, passports, software licences and API credentials with an expiry date. */
  expiries?: { itemId: string; vaultId: string; type: ItemType; title: string; subtitle?: string; expiry: string }[];
  groups: { score: StrengthEstimate['score']; breachCount?: number }[];
  breachCheckCompleted: boolean;
  /** Dismissed warnings and email breach results, from the hidden settings item. */
  settings?: HealthSettingsDetails;
}

interface CommandError {
  code: VaultErrorCode | 'unexpected';
  message: string;
}

function isCommandError(error: unknown): error is CommandError {
  return typeof error === 'object' && error !== null && typeof (error as CommandError).code === 'string';
}

export interface TauriOptions {
  /** The Rust side has the attachment commands. */
  attachments?: boolean;
  /**
   * The Rust side has the sharing commands: shared vaults, families, share links, emergency
   * access, devices and the security log (the desktop app).
   */
  sharing?: boolean;
  /**
   * The Rust side has the organisation commands (the desktop app): the same engine as the CLI,
   * which seals grants only to the people confirmed on screen.
   */
  organisations?: boolean;
  /** The Rust side has local vaults: "Use on this device only" (the desktop app). */
  local?: boolean;
  /** The Rust side fills, and asks plan 03's autofill gate first (the desktop app). */
  fillGate?: boolean;
  /** The app auto-types (the desktop app), so the item editor shows its settings. */
  autoType?: boolean;
  /** The Rust side has the file commands: encrypting files, Safes (the desktop app). */
  files?: boolean;
  /**
   * Files go through the phone's own pickers and viewer, never through this page (the phone app):
   * `attachments.native`. Its Rust side has no commands for raw file bytes.
   */
  nativeFiles?: boolean;
  /** SSH keys, `~/.ssh` and the agent (the desktop app). */
  ssh?: DesktopSsh | undefined;
  /** Ways this app reads QR codes besides images (the desktop app's screen region, the phone's camera). */
  qrCapture?: QrCaptureService;
  /** The device's Wi-Fi (`desktopWifi`, or the phone app's), for the connected and in-range marks. */
  wifi?: WifiService | undefined;
  /** The tray icon and opening at login (`desktopBackground`, the desktop app). */
  background?: BackgroundService | undefined;
  /** Connecting the browser extension and offering it (`desktopBrowserExtension`, the desktop app). */
  browserExtension?: BrowserExtensionService | undefined;
}

/** `src-tauri/src/autotype.rs`'s shortcut, as the keyboard shows it. */
const AUTO_TYPE_SHORTCUT = typeof navigator !== 'undefined' && /Mac/.test(navigator.platform) ? '⌘⇧\\' : 'Ctrl+Shift+\\';

/**
 * `VaultService` over the desktop app's Tauri commands. The keys live in the Rust process
 * (`octapass-desktop-vault`); this side only receives what the UI renders.
 */
export class TauriVaultService implements VaultService, AttachmentService {
  private snapshot: SessionSnapshot = { session: { status: 'signedOut' }, rememberedAccounts: [] };
  private readonly sessionListeners = new Set<(s: SessionState) => void>();
  private readonly itemListeners = new Set<() => void>();
  private readonly sharingListeners = new Set<() => void>();
  /**
   * The media type of each file in what released emergency contacts opened, keyed
   * `contact/item/file`. Only types: the items themselves aren't kept, and locking clears this.
   */
  private readonly emergencyFileTypes = new Map<string, string>();
  private nativeFiles?: NativeFiles;

  /** The developer toolkit, in the Rust core rather than this web view (`src-tauri/src/toolkit.rs`). */
  readonly toolkit: ToolkitService = {
    run: async <T,>(op: string, input: object) => JSON.parse(await this.call<string>('toolkit_run', { op, input: JSON.stringify(input) })) as T,
    hashFile: async (file, algorithms) => {
      const id = await this.call<number>('toolkit_hash_begin', { algorithms });
      const chunkSize = 1 << 20;
      for (let start = 0; start < file.size; start += chunkSize) {
        const chunk = new Uint8Array(await file.slice(start, start + chunkSize).arrayBuffer());
        let text = '';
        for (let index = 0; index < chunk.length; index += 0x8000) text += String.fromCharCode(...chunk.subarray(index, index + 0x8000));
        await this.call('toolkit_hash_update', { id, chunk: btoa(text) });
      }
      return this.call<ToolHash[]>('toolkit_hash_finish', { id });
    },
    fetchJwks: (url) => this.call<string>('toolkit_fetch_jwks', { url }),
    fetchHostCertificates: (target) => this.call<HostCertificates>('toolkit_fetch_host', { target }),
    setCaTrust: (certificate, trusted) => this.call('toolkit_set_ca_trust', { certificate, trusted }),
  };

  private constructor(
    private readonly transport: Transport,
    private readonly options: TauriOptions,
  ) {}

  static async create(transport: Transport, options: TauriOptions = {}): Promise<TauriVaultService> {
    const service = new TauriVaultService(transport, options);
    await transport.listen<SessionSnapshot>('vault://session', (snapshot) => service.apply(snapshot));
    await transport.listen('vault://items-changed', () => service.emitItems());
    if (options.sharing) await transport.listen('vault://sharing-changed', () => service.emitSharing());
    service.apply(await service.call<SessionSnapshot>('session_snapshot'));
    if (options.nativeFiles) service.nativeFiles = service.phoneFiles(await service.call<FileSource[]>('file_sources'));
    return service;
  }

  // ---------- Server + account ----------

  getServerInfo(serverUrl: string): Promise<ServerInfo> {
    return this.call('server_info', { serverUrl });
  }

  startSignup(input: { serverUrl: string; email: string; password: string }): Promise<{ signupId: string; devVerificationCode?: string }> {
    return this.call('start_signup', input);
  }

  async finishSignup(input: { signupId: string; verificationCode: string }): Promise<{ recoveryKit: RecoveryKit }> {
    return { recoveryKit: await this.call<RecoveryKit>('finish_signup', input) };
  }

  signIn(input: { serverUrl: string; email: string; password: string; secretKey?: string }): Promise<SignInResult> {
    return this.call('sign_in', { ...input, secretKey: input.secretKey ?? null });
  }

  finishTwoStep(proof: TwoStepProof): Promise<void> {
    return this.call('finish_two_step', { proof });
  }

  finishSso(code: string): Promise<SignInResult> {
    return this.call('finish_sso', { code });
  }

  rememberedAccounts(): RememberedAccount[] {
    return this.snapshot.rememberedAccounts;
  }

  lock(): void {
    if (this.snapshot.session.status !== 'unlocked') return;
    // The page locks at once; the Rust side drops the keys right behind it.
    this.apply({ ...this.snapshot, session: { ...this.snapshot.session, status: 'locked' } });
    void this.call('lock').catch(() => {});
  }

  unlock(password: string): Promise<void> {
    return this.call('unlock', { password });
  }

  signOut(): Promise<void> {
    return this.call('sign_out');
  }

  getSession(): SessionState {
    return this.snapshot.session;
  }

  onSessionChange(cb: (s: SessionState) => void): () => void {
    this.sessionListeners.add(cb);
    return () => this.sessionListeners.delete(cb);
  }

  getSecretKey(): Promise<string> {
    return this.call('secret_key');
  }

  getAccountSummary(): Promise<AccountSummary> {
    return this.call('account_summary');
  }

  deleteAccount(input: { confirmEmail: string; password: string }): Promise<void> {
    return this.call('delete_account', input);
  }

  // ---------- Master password ----------

  changeMasterPassword(input: { currentPassword: string; newPassword: string }): Promise<void> {
    return this.call('change_master_password', input);
  }

  /** Desktop only: the phone app's Rust side has no such command. */
  get rotateSecretKey(): VaultService['rotateSecretKey'] {
    if (!this.options.sharing) return undefined;
    return (input) => this.call<NewRecoveryKit>('rotate_secret_key', input);
  }

  startPasswordReset(input: { serverUrl: string; email: string }): Promise<{ resetId: string; devVerificationCode?: string }> {
    return this.call('start_password_reset', input);
  }

  verifyPasswordReset(input: { resetId: string; verificationCode: string }): Promise<void> {
    return this.call('verify_password_reset', input);
  }

  finishPasswordReset(input: { resetId: string; recoveryCode: string; password: string }): Promise<PasswordResetResult> {
    return this.call('finish_password_reset', input);
  }

  cancelPasswordReset(resetId: string): Promise<void> {
    return this.call('cancel_password_reset', { resetId });
  }

  // ---------- Vaults on this computer only ----------

  private readonly localVaults: LocalVaultService = {
    capabilities: () => this.call<LocalCapabilities>('local_capabilities'),
    list: () => this.call<LocalVaultInfo[]>('local_vaults'),
    create: (input) => this.call<string>('create_local_vault', input),
    restore: (file, key) => {
      const headers: Record<string, string> =
        'password' in key
          ? { 'x-backup-password': encodeURIComponent(key.password) }
          : { 'x-backup-code': encodeURIComponent(key.recoveryCode), 'x-backup-new-password': encodeURIComponent(key.newPassword) };
      return this.run(() => this.transport.invokeBytes<void>('restore_local_vault', file, headers));
    },
    switchTo: (id) => this.call('switch_local_vault', { id }),
    leave: () => this.call('leave_local_vault'),
    rename: (name) => this.call('rename_local_vault', { name }),
    remove: (password) => this.call('delete_local_vault', { password }),
    saveBackup: async () => (await this.call<string | null>('save_local_backup')) ?? undefined,
    recoveryCode: () => this.call<string>('local_recovery_code'),
    chooseBackupFolder: async () => (await this.call<string | null>('choose_backup_folder')) ?? undefined,
    clearBackupFolder: () => this.call('clear_backup_folder'),
    startTurnOnSync: (input) => this.call('start_turn_on_sync', input),
    finishTurnOnSync: (input) => this.call<RecoveryKit>('finish_turn_on_sync', input),
  };

  /** Auto-type and the AutoFill provider ask in Rust, so the switch has to reach there. The phone app has neither. */
  get setFillGate(): ((on: boolean) => Promise<void>) | undefined {
    return this.options.fillGate ? (on) => this.call('set_fill_gate', { on }) : undefined;
  }

  get local(): LocalVaultService | undefined {
    return this.options.local ? this.localVaults : undefined;
  }

  // ---------- Two-step sign-in ----------

  /** Security keys can't be used in the app's web view (they belong to the web vault's site), so they can't be added here. */
  readonly twoStep: TwoStepService = {
    getTwoStepStatus: () => this.call<TwoStepStatus>('two_step_status'),
    startTotpSetup: (password) => this.call<TotpSetup>('start_totp_setup', { password }),
    confirmTotpSetup: (code) => this.call<{ recoveryCodes?: string[] }>('confirm_totp_setup', { code }),
    addSecurityKey: (): Promise<SecurityKeyInfo> => Promise.reject(new VaultError('securityKeyUnsupported')),
    removeSecurityKey: (input) => this.call('remove_security_key', input),
    renewRecoveryCodes: (password) => this.call<string[]>('renew_recovery_codes', { password }),
    disableTwoStep: (password) => this.call('disable_two_step', { password }),
  };

  // ---------- Files ----------

  /** Reading and writing local files is the Rust side's; the page only ever sends paths back. */
  private readonly desktopFiles: FilesService = {
    describe: (paths) => this.call<LocalFile[]>('describe_files', { paths }),
    choose: (folder) => this.call<string[]>('choose_files', { folder }),
    onDrop: (handler) => this.transport.listen<string[]>('files://dropped', handler),
    onRequest: (handler) => this.transport.listen<{ action: 'encrypt' | 'decrypt'; paths: string[] }>('files://request', handler),
    encrypt: (input) => this.call<FileResult[]>('encrypt_files', input),
    decrypt: (input) => this.call<FileResult[]>('decrypt_files', { paths: input.paths, passphrase: input.passphrase ?? null }),
    findRecipient: (email) => this.call<FileRecipient>('find_file_recipient', { email }),
    ownRecipient: () => this.call<string>('own_file_recipient'),
    menuStatus: () => this.call<FileMenuStatus[]>('context_menu_status'),
    installMenu: (language) => this.call('install_context_menu', { language }),
    removeMenu: () => this.call('remove_context_menu'),
    listSafes: () => this.call<SafeSummary[]>('list_safes'),
    createSafe: (input) => this.call<SafeSummary>('create_safe', input),
    setSafeSync: (input) => this.call<SafeSummary>('set_safe_sync', input),
    syncSafe: (itemId) => this.call<SafeSyncReport>('sync_safe', { itemId }),
    safeEntries: (input) => this.call<SafeEntry[]>('safe_entries', input),
    safeAddFiles: (input) => this.call('safe_add_files', input),
    safeCreateFolder: (input) => this.call<SafeEntry>('safe_create_folder', input),
    safeRename: (input) => this.call('safe_rename', input),
    safeDelete: (input) => this.call('safe_delete', input),
    safeSaveFile: (input) => this.call<boolean>('safe_save_file', input),
    safeLock: (itemId) => this.call('safe_lock', { itemId }),
    safeMount: (itemId) => this.call<string>('safe_mount', { itemId }),
    deleteSafe: (itemId) => this.call('delete_safe', { itemId }),
    lockProblems: () => this.call<string[]>('safe_lock_problems'),
  };

  get files(): FilesService | undefined {
    return this.options.files ? this.desktopFiles : undefined;
  }

  // ---------- Masked email ----------

  /**
   * The providers' own APIs are called from the Rust side, where CORS doesn't apply (Firefox Relay
   * and DuckDuckGo don't allow web pages); self-hosted servers go through the web view.
   */
  readonly maskedEmail: MaskedEmailService = createMaskedEmailService(this, {
    context: 'app',
    http: (request) => {
      const native = PROVIDER_API_HOSTS.includes(new URL(request.url).hostname);
      return native ? this.call<Awaited<ReturnType<MaskedEmailHttp>>>('masked_email_request', { request }) : fetchHttp()(request);
    },
  });

  // ---------- Website icons ----------

  /** The web view may only talk to the app, so the server is asked from the Rust side. */
  async fetchSiteIcon(serverUrl: string, domain: string): Promise<IconAnswer> {
    try {
      const answer = await this.call<{ status: number; contentType: string; retryAfter?: string | null; body: number[] }>('site_icon', { serverUrl, domain });
      return await iconAnswer(answer.status, answer.contentType, answer.retryAfter ?? null, async () => new Uint8Array(answer.body));
    } catch {
      return { kind: 'none' };
    }
  }

  // ---------- Organisations (grants sealed in Rust, after review on screen) ----------

  get organisations(): OrganisationService | undefined {
    return this.options.organisations ? this.organisationService : undefined;
  }

  private readonly organisationService: OrganisationService = {
    getOrganisation: () => this.call<OrganisationState>('get_organisation'),
    createOrganisation: (name) => this.call('create_organisation', { name }),
    renameOrganisation: (name) => this.call('rename_organisation', { name }),
    deleteOrganisation: ({ password, confirmName }) => this.call('delete_organisation', { password, confirmName }),
    acceptOrgInvite: (orgId, inviteId) => this.call('accept_org_invite', { orgId, inviteId }),
    declineOrgInvite: (orgId, inviteId) => this.call('decline_org_invite', { orgId, inviteId }),
    listOrgMembers: () => this.call<OrgMembers>('list_org_members'),
    inviteOrgMember: (email, role) => this.call('invite_org_member', { email, role }),
    cancelOrgInvite: (inviteId) => this.call('cancel_org_invite', { inviteId }),
    setOrgMemberRole: (accountId, role) => this.call('set_org_member_role', { accountId, role }),
    removeOrgMember: (accountId, options) => this.call('remove_org_member', { accountId, orphanVaults: options?.orphanVaults ?? false }),
    leaveOrganisation: (options) => this.call('leave_organisation', { orphanVaults: options?.orphanVaults ?? false }),
    listOrgGroups: () => this.call<OrgGroup[]>('list_org_groups'),
    createOrgGroup: (name) => this.call<OrgGroup>('create_org_group', { name }),
    renameOrgGroup: (groupId, name) => this.call('rename_org_group', { groupId, name }),
    deleteOrgGroup: (groupId) => this.call('delete_org_group', { groupId }),
    addOrgGroupMember: (groupId, accountId) => this.call('add_org_group_member', { groupId, accountId }),
    removeOrgGroupMember: (groupId, accountId) => this.call('remove_org_group_member', { groupId, accountId }),
    listOrgVaults: () => this.call<OrgVault[]>('list_org_vaults'),
    createOrgVault: async (name) => {
      await this.call('create_org_vault', { name });
    },
    deleteOrgVault: ({ password, vaultId }) => this.call('delete_org_vault', { password, vaultId }),
    linkOrgVaultGroup: (vaultId, groupId, role) => this.call('link_org_vault_group', { vaultId, groupId, role }),
    unlinkOrgVaultGroup: (vaultId, groupId) => this.call('unlink_org_vault_group', { vaultId, groupId }),
    getOrgAccess: () => this.call<OrgAccessReview[]>('get_org_access'),
    applyOrgAccess: (vaultId, confirmed) =>
      this.call('apply_org_access', { vaultId, confirmed: confirmed.map(({ accountId, fingerprint }) => ({ accountId, fingerprint })) }),
    rotateOrgVault: (vaultId) => this.call('rotate_org_vault', { vaultId }),
    setOrgPolicies: (policies) => this.call('set_org_policies', { policies }),
    getOrgSso: () => this.call<OrgSsoSettings>('get_org_sso'),
    saveOrgSso: (input) => this.call<OrgSsoSettings>('save_org_sso', { input: { ...input, clientSecret: input.clientSecret || null } }),
    saveOrgSaml: (input) => this.call<OrgSsoSettings>('save_org_saml', { input }),
    removeOrgSso: () => this.call('remove_org_sso'),
    testOrgSso: () => this.call<string>('test_org_sso'),
    listOrgEvents: () => this.call<OrgEvent[]>('list_org_events'),
    getOrgScim: () => this.call<OrgScim>('get_org_scim'),
    createOrgScimToken: (name) => this.call<{ token: OrgScimToken; secret: string }>('create_org_scim_token', { name }),
    revokeOrgScimToken: (tokenId) => this.call('revoke_org_scim_token', { tokenId }),
  };

  // ---------- Sharing (sealed, signed and opened in Rust) ----------

  get sharing(): SharingService | undefined {
    return this.options.sharing ? this.sharingService : undefined;
  }

  private readonly sharingService: SharingService = {
    listDevices: () => this.call<Device[]>('list_devices'),
    renameDevice: (name) => this.call('rename_device', { name }),
    signOutDevice: (deviceId) => this.call('sign_out_device', { deviceId }),

    getMyFingerprint: () => this.call<Fingerprint>('my_fingerprint'),
    lookupAccount: (email) => this.call<AccountLookup>('lookup_account', { email }),
    markVerified: ({ accountId, fingerprint }) => this.call('mark_verified', { accountId, fingerprint }),
    getKeyLogState: () => this.call<KeyLogState>('key_log_state'),
    dismissKeyLogAlert: () => this.call('dismiss_key_log_alert'),

    createVault: (name) => this.call<Vault>('create_vault', { name }),
    renameVault: (vaultId, name) => this.call('rename_vault', { vaultId, name }),
    listMembers: (vaultId) => this.call<VaultMember[]>('list_members', { vaultId }),
    listServiceAccounts: (vaultId) => this.call<ServiceAccount[]>('list_service_accounts', { vaultId }),
    createServiceAccount: (vaultId, input) => this.call<{ account: ServiceAccount; token: string }>('create_service_account', { vaultId, ...input }),
    revokeServiceAccount: (vaultId, id) => this.call('revoke_service_account', { vaultId, id }),
    addMember: (vaultId, account, role) => this.call('add_member', { vaultId, account, role }),
    changeRole: (vaultId, accountId, role) => this.call('change_role', { vaultId, accountId, role }),
    removeMember: (vaultId, accountId) => this.call('remove_member', { vaultId, accountId }),
    leaveVault: (vaultId) => this.call('leave_vault', { vaultId }),
    moveItem: (itemId, toVaultId) => this.call<Item>('move_item', { itemId, toVaultId }),
    copyItem: (itemId, toVaultId) => this.call<Item>('copy_item', { itemId, toVaultId }),

    getFamily: () => this.call<FamilyState>('get_family'),
    createFamily: () => this.call('create_family'),
    inviteToFamily: (account) => this.call('invite_to_family', { account }),
    acceptFamilyInvite: (familyId) => this.call('accept_family_invite', { familyId }),
    declineFamilyInvite: (familyId) => this.call('decline_family_invite', { familyId }),
    cancelFamilyInvite: (accountId) => this.call('cancel_family_invite', { accountId }),
    removeFamilyMember: (accountId) => this.call('remove_family_member', { accountId }),
    leaveFamily: () => this.call('leave_family'),
    deleteFamily: () => this.call('delete_family'),

    /** This page isn't on the web vault's origin, so the link's address is made here. */
    createShareLink: async (itemId, options) => {
      const link = await this.call<CreatedShareLink>('create_share_link', { itemId, options: { ...options, passphrase: options.passphrase || null } });
      const serverUrl = this.snapshot.session.serverUrl;
      return serverUrl ? { ...link, url: appShareLinkUrl(serverUrl, link) } : link;
    },
    listShareLinks: () => this.call<ShareLinkInfo[]>('list_share_links'),
    revokeShareLink: (id) => this.call('revoke_share_link', { id }),
    fetchShareLink: (serverUrl, id) => this.call<ShareLinkEnvelope>('fetch_share_link', { serverUrl, id }),
    openShareLink: (ciphertext, key, passphrase) => this.call<SharedItem>('open_share_link', { ciphertext, key, passphrase: passphrase || null }),

    rotateVaultKey: (vaultId) => this.call('rotate_vault_key', { vaultId }),
    listEmergencyContacts: () => this.call<EmergencyContacts>('list_emergency_contacts'),
    renewEmergencyKey: (id, account) => this.call('renew_emergency_key', { id, account }),
    takeOverAccount: (id, input) => this.call<NewRecoveryKit>('take_over_account', { id, ...input }),
    enableOrganiserRecovery: (input) => this.call<EmergencyContact>('enable_organiser_recovery', input),
    addEmergencyContact: (input) => this.call<EmergencyContact>('add_emergency_contact', input),
    removeEmergencyContact: (id) => this.call('remove_emergency_contact', { id }),
    requestEmergencyAccess: (id) => this.call('emergency_action', { id, action: 'request' }),
    denyEmergencyAccess: (id) => this.call('emergency_action', { id, action: 'deny' }),
    approveEmergencyAccess: (id) => this.call('emergency_action', { id, action: 'approve' }),
    openEmergencyAccess: async (id) => {
      const view = await this.call<EmergencyVaultView>('open_emergency_access', { id });
      for (const item of view.items) for (const file of item.details.attachments ?? []) this.emergencyFileTypes.set(`${id}/${item.id}/${file.id}`, file.type);
      return view;
    },
    getEmergencyAttachment: async (id, itemId, attachmentId) => {
      const bytes = await this.call<ArrayBuffer>('emergency_attachment', { id, itemId, attachmentId });
      return new Blob([bytes], { type: this.emergencyFileTypes.get(`${id}/${itemId}/${attachmentId}`) ?? '' });
    },

    getSecurityLog: () => this.call<SecurityEvent[]>('security_log'),

    onSharingChange: (cb) => {
      this.sharingListeners.add(cb);
      return () => this.sharingListeners.delete(cb);
    },
  };

  // ---------- Device unlock (Touch ID or the Mac password, Windows Hello, polkit) ----------

  getUnlockMethods(): Promise<UnlockMethods> {
    return this.call('unlock_methods');
  }

  enableDeviceUnlock(): Promise<void> {
    return this.call('enable_device_unlock');
  }

  disableDeviceUnlock(): Promise<void> {
    return this.call('disable_device_unlock');
  }

  unlockWithDevice(): Promise<void> {
    return this.call('unlock_with_device');
  }

  /** Plan 18: the key and the switch live in Rust, which also answers the browser extension. */
  getStayUnlocked(): Promise<StayUnlockedStatus> {
    return this.call<StayUnlockedStatus>('stay_unlocked_status');
  }

  setStayUnlocked(on: boolean): Promise<StayUnlockedStatus> {
    return this.call<StayUnlockedStatus>('set_stay_unlocked', { on });
  }

  unlockStayUnlocked(): Promise<boolean> {
    return this.call<boolean>('unlock_stay_unlocked');
  }

  /** Reveal/copy/export: the device lock where it's on, else the master password (plan 03). */
  confirmIdentity(proof: IdentityConfirmation): Promise<void> {
    return 'password' in proof ? this.call('confirm_master_password', { password: proof.password }) : this.call('confirm_with_device');
  }

  canConfirmIdentityWithDevice(): Promise<boolean> {
    return this.call<UnlockMethods>('unlock_methods').then((methods) => methods?.deviceUnlockEnabled ?? false).catch(() => false);
  }

  // ---------- Vault ----------

  listVaults(): Promise<Vault[]> {
    return this.call('list_vaults');
  }

  async listItems(filter?: ItemFilter): Promise<ItemSummary[]> {
    const rows = await this.call<ItemSummary[]>('list_items');
    return rows.filter((row) => matchesFilter(row, filter)).sort(compareSummaries);
  }

  getItem(id: string): Promise<Item> {
    return this.call('get_item', { id });
  }

  saveItem(draft: ItemDraft): Promise<Item> {
    return this.call('save_item', { draft });
  }

  itemVersions(id: string): Promise<ItemVersion[]> {
    return this.call('item_versions', { id });
  }

  restoreItemVersion(id: string, revision: number): Promise<Item> {
    return this.call('restore_item_version', { id, revision });
  }

  nextHotpCode(id: string): Promise<HotpCode> {
    return this.call('next_hotp_code', { id });
  }

  setHotpCounter(id: string, counter: number): Promise<Item> {
    return this.call('set_hotp_counter', { id, counter });
  }

  nearby(here: Here): Promise<NearbyPlace[]> {
    return this.call('nearby', { here });
  }

  async suggestPlace(itemId: string, here: Here): Promise<string | undefined> {
    return (await this.call<string | null>('suggest_place', { itemId, here })) ?? undefined;
  }

  equivalentDomains(): Promise<EquivalentDomains> {
    return this.call('equivalent_domains');
  }

  saveEquivalentDomains(input: { groups: string[][]; excludedDefaults: string[] }): Promise<EquivalentDomains & { rejected: string[] }> {
    return this.call('save_equivalent_domains', { input });
  }

  generatePasswordForSite(url: string, options: Extract<GeneratorOptions, { kind: 'password' }>): Promise<string> {
    const { kind: _kind, ...random } = options;
    return this.call('generate_password_for_site', { url, options: random });
  }

  deleteItem(id: string): Promise<void> {
    return this.call('delete_item', { id });
  }

  restoreItem(id: string): Promise<void> {
    return this.call('restore_item', { id });
  }

  onItemsChange(cb: () => void): () => void {
    this.itemListeners.add(cb);
    return () => this.itemListeners.delete(cb);
  }

  // ---------- Attachments (encrypted and decrypted in Rust) ----------

  get attachments(): AttachmentService | undefined {
    return this.options.attachments ? this : undefined;
  }

  readonly offerDeviceUnlock = true;

  get autoType(): AutoTypeService | undefined {
    return this.options.autoType ? { shortcut: AUTO_TYPE_SHORTCUT } : undefined;
  }

  get qrCapture(): QrCaptureService | undefined {
    const capture = this.options.qrCapture;
    // Command errors (`screenCaptureDenied`) become VaultErrors like every other command's.
    return capture && { sources: capture.sources, capture: (source) => this.run(() => capture.capture(source)) };
  }

  get sshKeys(): SshKeyService | undefined {
    const ssh = this.options.ssh;
    return (
      ssh && {
        ...ssh.keys,
        confirm: (proof) => this.confirmIdentity(proof),
        canConfirmWithDevice: () => this.canConfirmIdentityWithDevice(),
      }
    );
  }

  get sshHome(): SshHomeService | undefined {
    return this.options.ssh?.home;
  }

  get sshAgent(): SshAgentService | undefined {
    return this.options.ssh?.agent;
  }

  get wifi(): WifiService | undefined {
    return this.options.wifi;
  }

  get background(): BackgroundService | undefined {
    return this.options.background;
  }

  get browserExtension(): BrowserExtensionService | undefined {
    return this.options.browserExtension;
  }

  readonly connect: ConnectService = {
    getState: () => this.call<{ enabled: boolean; clients: ConnectClient[] }>('connect_state'),
    setEnabled: (enabled) => this.call('set_connect_enabled', { enabled }),
    revokeClient: (id) => this.call('connect_revoke_client', { id }),
  };

  get native(): NativeFiles | undefined {
    return this.nativeFiles;
  }

  private phoneFiles(sources: FileSource[]): NativeFiles {
    return {
      sources,
      pick: (source) => this.call<PickedFile[]>('pick_files', { source }),
      attachPicked: (itemId, file) => this.call<Item>('attach_picked', { itemId, pickedId: file.id }),
      discardPicked: (files) => this.call('discard_picked', { pickedIds: files.map((file) => file.id) }),
      open: (itemId, attachmentId) => this.call('open_attachment', { itemId, attachmentId }),
    };
  }

  async addAttachment(itemId: string, file: Blob, name: string): Promise<Item> {
    // Raw bytes, so a large file isn't turned into JSON; header values must be ASCII.
    const headers = { 'x-attachment-item': encodeURIComponent(itemId), 'x-attachment-name': encodeURIComponent(name), 'x-attachment-type': encodeURIComponent(file.type) };
    const bytes = new Uint8Array(await file.arrayBuffer());
    return this.run(() => this.transport.invokeBytes<Item>('add_attachment', bytes, headers));
  }

  async getAttachment(itemId: string, attachmentId: string): Promise<Blob> {
    const [item, bytes] = await Promise.all([this.getItem(itemId), this.call<ArrayBuffer>('get_attachment', { itemId, attachmentId })]);
    const type = item.details.attachments?.find((a) => a.id === attachmentId)?.type ?? '';
    return new Blob([bytes], { type });
  }

  removeAttachment(itemId: string, attachmentId: string): Promise<Item> {
    return this.call('remove_attachment', { itemId, attachmentId });
  }

  getStorageUsage(): Promise<StorageUsage> {
    return this.call('storage_usage');
  }

  // ---------- Tools ----------

  generatePassword(opts: GeneratorOptions): string {
    return generatePassword(opts);
  }

  estimateStrength(password: string): StrengthEstimate {
    const email = this.snapshot.session.email;
    return estimateStrength(password, email ? [email, email.split('@')[0]!] : undefined);
  }

  totpCode(totp: string, at?: number): Promise<TotpCode> {
    return this.call('totp_code', { totp, at: at ?? null });
  }

  checkBreached(password: string): Promise<number> {
    return this.call('check_breached', { password });
  }

  /**
   * The shared report builder runs on stand-ins: each login's password is replaced by its group
   * token, and strength and breach counts are looked up by token.
   */
  async getHealthReport(): Promise<HealthReport> {
    const inputs = await this.call<HealthInputs>('health_inputs');
    // Checked in Rust against the pinned key: the bundled lists, or a newer signed file from the server.
    const lists = await this.call<{ version: number; passkeyDomains: string[]; twoFactorDomains: string[] }>('health_data').catch(() => undefined);
    const token = (group: number) => `#${group}`;
    const group = (password: string) => inputs.groups[Number(password.slice(1))]!;
    const items: Item[] = inputs.logins.map((login) => ({
      id: login.itemId,
      vaultId: login.vaultId,
      revision: 0,
      createdAt: '',
      updatedAt: '',
      overview: { schemaVersion: 1, type: login.type, title: login.title, subtitle: login.subtitle, urls: login.urls },
      details: {
        schemaVersion: 1,
        password: login.passwordGroup === undefined ? undefined : token(login.passwordGroup),
        totp: login.hasTotp ? 'present' : undefined,
        passkeys: login.hasPasskey ? [{ rpId: '', userName: '', createdAt: '' }] : undefined,
        username: login.username,
        passwordChangedAt: login.passwordDate,
        recovery:
          login.twoFactorMethod || login.recovery || login.backupCodes
            ? {
                ...login.recovery,
                ...(login.twoFactorMethod ? { twoFactorMethod: login.twoFactorMethod as never } : {}),
                ...(login.backupCodes ? { backupCodes: Array.from({ length: login.backupCodes.total }, (_, i) => ({ code: '', used: i >= login.backupCodes!.unused })) } : {}),
              }
            : undefined,
      },
    }));
    for (const entry of inputs.expiries ?? []) {
      items.push({
        id: entry.itemId,
        vaultId: entry.vaultId,
        revision: 0,
        createdAt: '',
        updatedAt: '',
        overview: { schemaVersion: 1, type: entry.type, title: entry.title, subtitle: entry.subtitle },
        details: { schemaVersion: 1, expiry: entry.expiry } as ItemDetails,
      });
    }
    return buildHealthReport(items, {
      ...(inputs.settings ? { settings: inputs.settings } : {}),
      ...(lists ? { data: { version: lists.version, issuedAt: '', passkeyDomains: new Set(lists.passkeyDomains), twoFactorDomains: new Set(lists.twoFactorDomains) } } : {}),
      estimateStrength: (password) => ({ score: group(password).score, guessesLog10: 0 }),
      checkBreached: async (password) => {
        const count = group(password).breachCount;
        if (!inputs.breachCheckCompleted || count === undefined) throw new Error('breach check unavailable');
        return count;
      },
    });
  }

  /** Through the signed-in server. Only `HealthSettings` calls this, after the user opted in. */
  async lookupEmailBreaches(address: string): Promise<EmailBreach[]> {
    return this.call('lookup_email_breaches', { address });
  }

  /** JSON and CSV are made here; CXF and the encrypted export (with every file) in the native vault. */
  async exportVault(format: ExportFormat, options: ExportOptions = {}): Promise<Blob> {
    const file = await this.exportFile(format, options);
    // "Vault exported" in the security log. Exporting works offline too; the entry is then missing.
    void this.call('record_export', { format }).catch(() => {});
    return file;
  }

  private async exportFile(format: ExportFormat, options: ExportOptions): Promise<Blob> {
    if (format === 'cxf' || format === 'encrypted') {
      const bytes = await this.call<ArrayBuffer>('export_file', { format, password: options.password, masterPassword: options.masterPassword });
      return new Blob([bytes], { type: format === 'cxf' ? 'application/json' : 'application/octet-stream' });
    }
    if (options.masterPassword !== undefined) await this.call('unlock', { password: options.masterPassword });
    const [vaults, items] = await Promise.all([this.listVaults(), this.call<Item[]>('export_items')]);
    return format === 'json'
      ? new Blob([exportJson(vaults, items)], { type: 'application/json' })
      : new Blob([exportCsv(vaults, items)], { type: 'text/csv' });
  }

  /** Every source, read by the core in the native vault; the file goes over as raw bytes. */
  importFile(source: ImportSource, file: File, options: ImportOptions = {}): Promise<ImportResult> {
    return this.sendImport<ImportResult>('import_file', source, file, options);
  }

  /** The parsed file stays in the native vault until it's finished or cancelled; Rust forgets it on lock. */
  reviewImport(source: ImportSource, file: Blob, options: ImportOptions = {}): Promise<ImportReview> {
    return this.sendImport<ImportReview>('review_import', source, file, options);
  }

  finishImport(reviewId: string, links: CodeLink[]): Promise<ImportResult> {
    return this.call('finish_import', { reviewId, links });
  }

  cancelImport(reviewId: string): Promise<void> {
    return this.call('cancel_import', { reviewId });
  }

  async readQrCodes(image: Blob): Promise<string[]> {
    const bytes = new Uint8Array(await image.arrayBuffer());
    return this.run(() => this.transport.invokeBytes<string[]>('read_qr_codes', bytes, {}));
  }

  summarizeQrScans(texts: string[]): Promise<QrScan> {
    return this.call('summarize_qr_scans', { texts });
  }

  private async sendImport<T>(command: string, source: ImportSource, file: Blob, options: ImportOptions): Promise<T> {
    const headers: Record<string, string> = { 'x-import-source': encodeURIComponent(source) };
    if (options.password) headers['x-import-password'] = encodeURIComponent(options.password);
    if (options.keyFile) headers['x-import-key-file'] = base64UrlEncode(new Uint8Array(await options.keyFile.arrayBuffer()));
    const bytes = new Uint8Array(await file.arrayBuffer());
    return this.run(() => this.transport.invokeBytes<T>(command, bytes, headers));
  }

  // ---------- Internals ----------

  /** Runs a command; the vault's error codes come back as `VaultError`s the UI translates. */
  private call<T = void>(command: string, args?: Record<string, unknown>): Promise<T> {
    return this.run(() => this.transport.invoke<T>(command, args));
  }

  private async run<T>(command: () => Promise<T>): Promise<T> {
    try {
      return await command();
    } catch (error) {
      if (isCommandError(error)) {
        if (error.code === 'unexpected') throw new Error(error.message);
        throw new VaultError(error.code, error.message);
      }
      throw error;
    }
  }

  /**
   * `confirmed` comes from the Rust side: true when the master password or the device lock opened
   * the session (plan 03 History, 2026-11-05), false when stay unlocked opened it until the first
   * reveal asks, and false again after a screen lock or sleep while staying unlocked (plan 18).
   */
  private apply(snapshot: SessionSnapshot): void {
    const before = this.snapshot.session;
    snapshot = { ...snapshot, session: withConfirmed(snapshot.session, snapshot.session.confirmed === true) };
    this.snapshot = snapshot;
    const after = snapshot.session;
    if (after.status !== 'unlocked') this.emergencyFileTypes.clear();
    if (before.status === after.status && before.email === after.email && before.serverUrl === after.serverUrl && before.confirmed === after.confirmed) return;
    for (const cb of this.sessionListeners) cb(after);
  }

  private emitItems(): void {
    for (const cb of this.itemListeners) cb();
  }

  private emitSharing(): void {
    for (const cb of this.sharingListeners) cb();
  }
}
