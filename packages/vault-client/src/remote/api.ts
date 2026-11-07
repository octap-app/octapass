// The sync API v1 endpoints (plan 11, "HTTP API v1"), typed.

import type { AccountBundle, CredentialsFinish, EncryptedItem, KeyLogHeadUpdate, KeyLogPage, KeyLogProof, KeyRecord, NewServiceAccount, NewSharedVault, Prelogin, PublishKeys, RegisterFinish, SignedGrant, VaultRotation } from '@octapass/core';
import type {
  Device,
  EmailBreach,
  EmergencyAccessLevel,
  EmergencyContact,
  EmergencyContacts,
  EmergencyScope,
  ExportFormat,
  FamilyInvite,
  OrgEvent,
  OrgGroup,
  OrgMember,
  OrgMembers,
  OrgPolicies,
  OrgRole,
  OrgSsoSettings,
  OrgVault,
  Organisation,
  OrganisationState,
  SecurityEvent,
  ServerInfo,
  ShareLinkEnvelope,
  VaultRole,
  VaultType,
} from '../types';
import type { HttpClient } from './http';

export interface VaultRecord {
  id: string;
  type: VaultType;
  revision: number;
  wrappedVaultKey: string;
  role: VaultRole;
  /** The id of the current vault key. A personal vault has one from its first rotation. */
  keyId?: string;
  /** Shared and family vaults: the rest of this account's signed grant. */
  grant?: VaultGrant;
  /** The organisation this shared vault belongs to. It opens like any shared vault. */
  orgId?: string;
}

/** With the vault id, this account's id, `role` and `wrappedVaultKey`, the whole signed grant. */
export interface VaultGrant {
  grantedBy: string;
  granterPublicSignKey: string;
  grantedAt: number;
  signature: string;
}

/** A past version of an item: ciphertext under the item's own key. */
export interface ItemRevisionRecord {
  revision: number;
  overview: string;
  details: string;
  updatedAt: string;
}

export interface ItemRecord extends EncryptedItem {
  id: string;
  vaultId: string;
  revision: number;
  updatedAt: string;
  deletedAt?: string;
}

export interface SyncResponse {
  vaults: VaultRecord[];
  items: ItemRecord[];
  deleted: { vaultId: string; itemId: string; revision: number }[];
  /** The server stopped early; sync again from the returned vault revisions. */
  hasMore?: boolean;
}

/** Someone a vault's key should be sealed to, as the server says. Never sealed to unreviewed. */
export interface OrgPendingGrantRecord {
  accountId: string;
  email: string;
  role: VaultRole;
  publicEncKey: string;
  publicSignKey: string;
  keyRecord?: KeyRecord;
  upgrade: boolean;
}

export interface OrgVaultPlanRecord {
  vaultId: string;
  canApply: boolean;
  keyId?: string;
  grants: OrgPendingGrantRecord[];
  rotate: boolean;
}

export interface ServiceAccountRecord {
  id: string;
  vaultId: string;
  createdBy: string;
  role: VaultRole;
  publicEncKey: string;
  encryptedName: string;
  grantedBy: string;
  createdAt: string;
  expiresAt?: string;
  lastUsedAt?: string;
  revokedAt?: string;
}

export interface MemberRecord {
  accountId: string;
  email: string;
  role: VaultRole;
  publicEncKey: string;
  publicSignKey: string;
  keyRecord?: KeyRecord;
  fingerprint: string;
  grantedBy?: string;
  addedAt: string;
}

export interface LookupRecord {
  accountId: string;
  email: string;
  publicEncKey: string;
  publicSignKey: string;
  keyRecord?: KeyRecord;
  fingerprint: string;
}

export interface FamilyRecord {
  id: string;
  organiserId: string;
  vaultId: string;
  maxMembers: number;
  members: { accountId: string; email: string; role: 'organiser' | 'member'; joinedAt: string }[];
  invites: FamilyInvite[];
  createdAt: string;
}

export interface ShareLinkRecord {
  id: string;
  expiresAt: string;
  maxViews: number;
  views: number;
  passphraseRequired: boolean;
  createdAt: string;
}

export type BatchOperation =
  | { op: 'put'; vaultId: string; itemId: string; ifMatch?: number | '*'; item: EncryptedItem }
  | { op: 'delete'; vaultId: string; itemId: string; ifMatch: number | '*' }
  | { op: 'restore'; vaultId: string; itemId: string };

export interface BatchResult {
  itemId: string;
  status: number;
  revision?: number;
  problem?: { type: string; status: number; detail?: string; current?: ItemRecord };
}

export interface AttachmentRecord {
  id: string;
  vaultId: string;
  itemId: string;
  /** Stored (encrypted) bytes. */
  size: number;
  createdAt: string;
}

export interface UsageRecord {
  items: number;
  maxItems: number;
  itemBytes: number;
  maxItemBytes: number;
  attachmentBytes: number;
  maxAttachmentBytes: number;
  /** As stored, encrypted. */
  maxFileBytes: number;
}

export interface Tokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface LoginFinishResponse extends Tokens {
  account: AccountBundle;
  /** Sent on the next sign-in from this device, so it skips the second step. */
  trustedDeviceToken?: string;
}

export interface RefreshResponse extends Tokens {
  /** Only when this device had none yet. */
  trustedDeviceToken?: string;
}

/** WebAuthn request options for the second step, binary values as base64url. */
export interface WebAuthnRequestOptions {
  challenge: string;
  rpId: string;
  allowCredentials: string[];
  timeout: number;
  userVerification: 'discouraged';
}

/** The `sso` member of an `sso-required` problem. */
export interface SsoChallenge {
  /** For `login/sso`. Stays on the device. */
  challengeId: string;
  /** Opens in a browser. */
  url: string;
  orgName: string;
  expiresIn: number;
}

/** The `secondFactor` member of a `second-factor-required` problem. */
export interface SecondFactorChallenge {
  challengeId: string;
  methods: ('totp' | 'webauthn' | 'recovery-code')[];
  webauthn?: WebAuthnRequestOptions;
  expiresIn: number;
}

/** An `AuthenticatorAssertionResponse`, binary values as base64url. */
export interface WebAuthnAssertion {
  credentialId: string;
  clientDataJson: string;
  authenticatorData: string;
  signature: string;
}

export type SecondFactorProof = { totpCode: string } | { recoveryCode: string } | { webauthn: WebAuthnAssertion };

export interface SecurityKeyRecord {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt?: string;
}

export interface TwoStepStatusRecord {
  enabled: boolean;
  methods: SecondFactorChallenge['methods'];
  securityKeys: SecurityKeyRecord[];
  recoveryCodesLeft: number;
  rpId: string;
}

/** WebAuthn creation options for a new security key, binary values as base64url. */
export interface WebAuthnCreationOptions {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  algorithms: number[];
  excludeCredentials: string[];
  timeout: number;
}

/** An `AuthenticatorAttestationResponse`, binary values as base64url. */
export interface WebAuthnAttestation {
  credentialId: string;
  clientDataJson: string;
  attestationObject: string;
}

export type ReauthPurpose = 'delete-account' | 'two-step' | 'change-password' | 'rotate-secret-key' | 'emergency-takeover' | 'organisation';

const vault = (vaultId: string) => `/v1/vaults/${encodeURIComponent(vaultId)}`;
const family = (familyId: string) => `/v1/families/${encodeURIComponent(familyId)}`;
const org = (orgId: string) => `/v1/orgs/${encodeURIComponent(orgId)}`;
const emergency = (id: string) => `/v1/emergency-contacts/${encodeURIComponent(id)}`;
const sinceQuery = (since: { id: string; revision: number }[]) => (since.length ? `?since=${since.map((v) => `${v.id}:${v.revision}`).join(',')}` : '');
const item = (vaultId: string, itemId: string) => `/v1/vaults/${encodeURIComponent(vaultId)}/items/${encodeURIComponent(itemId)}`;
const ifMatch = (revision: number) => ({ 'If-Match': `"${revision}"` });
const attachment = (vaultId: string, itemId: string, id: string) => `${item(vaultId, itemId)}/attachments/${encodeURIComponent(id)}`;
const reauthHeader = (reauthToken: string) => ({ 'X-Reauth-Token': reauthToken });

export function createApi(http: HttpClient) {
  const anonymous = { auth: false } as const;
  return {
    serverInfo: () => http.request<ServerInfo>('GET', '/v1/server-info', anonymous),
    prelogin: (email: string) => http.request<Prelogin>('POST', '/v1/auth/prelogin', { ...anonymous, body: { email } }),
    registerStart: (email: string, registrationRequest: string) =>
      http.request<{ registrationResponse: string; devVerificationCode?: string }>('POST', '/v1/auth/register/start', {
        ...anonymous,
        body: { email, registrationRequest },
      }),
    registerFinish: (body: RegisterFinish & { email: string; verificationCode: string }) =>
      http.request<{ accountId: string }>('POST', '/v1/auth/register/finish', { ...anonymous, body }),
    loginStart: (email: string, credentialRequest: string) =>
      http.request<{ loginId: string; credentialResponse: string }>('POST', '/v1/auth/login/start', { ...anonymous, body: { email, credentialRequest } }),
    /** Throws `second-factor-required` when the account asks this device for a second step. */
    loginFinish: (loginId: string, credentialFinalization: string, device: { name: string; platform: string }, trustedDeviceToken?: string) =>
      http.request<LoginFinishResponse>('POST', '/v1/auth/login/finish', { ...anonymous, body: { loginId, credentialFinalization, device, trustedDeviceToken } }),
    loginSecondFactor: (challengeId: string, proof: SecondFactorProof) =>
      http.request<LoginFinishResponse>('POST', '/v1/auth/login/second-factor', { ...anonymous, body: { challengeId, ...proof } }),
    /** Finishes the SSO step; a second step may still follow, as `second-factor-required`. */
    loginSso: (challengeId: string, code: string) => http.request<LoginFinishResponse>('POST', '/v1/auth/login/sso', { ...anonymous, body: { challengeId, code } }),
    refresh: (refreshToken: string) => http.request<RefreshResponse>('POST', '/v1/auth/refresh', { ...anonymous, body: { refreshToken } }),
    logout: () => http.request<void>('POST', '/v1/auth/logout'),
    reauthStart: (credentialRequest: string) =>
      http.request<{ reauthId: string; credentialResponse: string }>('POST', '/v1/auth/reauth/start', { body: { credentialRequest } }),
    reauthFinish: (reauthId: string, credentialFinalization: string, purpose: ReauthPurpose) =>
      http.request<{ reauthToken: string; expiresIn: number }>('POST', '/v1/auth/reauth/finish', {
        body: { reauthId, credentialFinalization, purpose },
      }),
    deleteAccount: (reauthToken: string, confirmEmail: string) =>
      http.request<void>('DELETE', '/v1/account', { headers: reauthHeader(reauthToken), body: { confirmEmail } }),
    passwordRegistration: (registrationRequest: string) =>
      http.request<{ registrationResponse: string }>('POST', '/v1/account/password/registration', { body: { registrationRequest } }),
    /** Every other device is signed out. */
    changePassword: (reauthToken: string, body: CredentialsFinish) => http.request<void>('PUT', '/v1/account/password', { headers: reauthHeader(reauthToken), body }),
    /** Every other device is signed out. */
    rotateSecretKey: (reauthToken: string, body: CredentialsFinish) => http.request<void>('PUT', '/v1/account/secret-key', { headers: reauthHeader(reauthToken), body }),
    account: () => http.request<AccountBundle>('GET', '/v1/account'),
    recoverStart: (email: string) =>
      http.request<{ recoveryId: string; devVerificationCode?: string }>('POST', '/v1/auth/recover/start', { ...anonymous, body: { email } }),
    recoverVerify: (recoveryId: string, verificationCode: string) =>
      http.request<{ account: AccountBundle; challenge: string }>('POST', '/v1/auth/recover/verify', { ...anonymous, body: { recoveryId, verificationCode } }),
    recoverRegistration: (recoveryId: string, registrationRequest: string) =>
      http.request<{ registrationResponse: string }>('POST', '/v1/auth/recover/registration', { ...anonymous, body: { recoveryId, registrationRequest } }),
    /** Every device is signed out; sign in with the new password. */
    recoverFinish: (body: CredentialsFinish & { recoveryId: string; signature: string }) =>
      http.request<void>('POST', '/v1/auth/recover/finish', { ...anonymous, body }),
    sync: (since: { id: string; revision: number }[]) => http.request<SyncResponse>('GET', `/v1/sync${sinceQuery(since)}`),
    createItem: (vaultId: string, itemId: string, body: EncryptedItem) =>
      http.request<{ revision: number }>('PUT', item(vaultId, itemId), { headers: { 'If-None-Match': '*' }, body }),
    updateItem: (vaultId: string, itemId: string, revision: number, body: EncryptedItem & { skipHistory?: boolean }) =>
      http.request<{ revision: number }>('PUT', item(vaultId, itemId), { headers: ifMatch(revision), body }),
    itemHistory: (vaultId: string, itemId: string) => http.request<{ revisions: ItemRevisionRecord[] }>('GET', `${item(vaultId, itemId)}/history`),
    trashItem: (vaultId: string, itemId: string, revision: number) =>
      http.request<{ revision: number }>('DELETE', item(vaultId, itemId), { headers: ifMatch(revision) }),
    restoreItem: (vaultId: string, itemId: string) => http.request<{ revision: number }>('POST', `${item(vaultId, itemId)}/restore`),
    usage: () => http.request<UsageRecord>('GET', '/v1/account/usage'),
    /** In the body, so the address stays out of URLs and access logs. */
    emailBreaches: (email: string) => http.request<{ breaches: EmailBreach[] }>('POST', '/v1/health/breach-email', { body: { email } }),
    uploadAttachment: (vaultId: string, itemId: string, id: string, file: Blob) =>
      http.request<AttachmentRecord>('PUT', attachment(vaultId, itemId, id), { binary: file }),
    /** The encrypted file, as a response to stream. */
    downloadAttachment: (vaultId: string, itemId: string, id: string) => http.request<Response>('GET', attachment(vaultId, itemId, id), { raw: true }),
    deleteAttachment: (vaultId: string, itemId: string, id: string) => http.request<void>('DELETE', attachment(vaultId, itemId, id)),
    batch: (operations: BatchOperation[]) => http.request<{ results: BatchResult[] }>('POST', '/v1/batch', { body: { operations } }),

    devices: () => http.request<Device[]>('GET', '/v1/devices'),
    renameDevice: (name: string) => http.request<void>('PATCH', '/v1/devices/current', { body: { name } }),
    deleteDevice: (deviceId: string) => http.request<void>('DELETE', `/v1/devices/${encodeURIComponent(deviceId)}`),

    lookup: (email: string) => http.request<LookupRecord>('GET', `/v1/accounts/lookup?email=${encodeURIComponent(email)}`),
    keyLogHead: (since: number) => http.request<KeyLogHeadUpdate>('GET', `/v1/transparency/head?since=${since}`),
    keyLogLabel: (blinded: string) => http.request<{ evaluated: string; proof: string }>('POST', '/v1/transparency/label', { body: { blinded } }),
    keyLogProof: (label: string, since: number) => http.request<KeyLogProof>('GET', `/v1/transparency/proof?label=${label}&since=${since}`),
    keyLogEntries: (start: number, end: number) => http.request<KeyLogPage>('GET', `/v1/transparency/entries?start=${start}&end=${end}`),
    publishKeys: (body: PublishKeys) => http.request<{ leafIndex: number }>('POST', '/v1/transparency/publish', { body }),
    getAccount: () => http.request<AccountBundle>('GET', '/v1/account'),
    createVault: (body: NewSharedVault) => http.request<VaultRecord>('POST', '/v1/vaults', { body }),
    members: (vaultId: string) => http.request<{ members: MemberRecord[] }>('GET', `${vault(vaultId)}/members`),
    /** `keyId` names the vault key the grant seals: refused with `vault-key-changed` once it's rotated. */
    invite: (vaultId: string, email: string, grant: SignedGrant, keyId?: string) =>
      http.request<void>('POST', `${vault(vaultId)}/members`, { body: { email, grant, keyId } }),
    removeMember: (vaultId: string, accountId: string) => http.request<void>('DELETE', `${vault(vaultId)}/members/${encodeURIComponent(accountId)}`),
    /** Family vaults: `invites` re-seals pending invites to the new key; the ones left out are cancelled. Personal vaults: `wrappedVaultKey` and no grants. */
    rotate: (vaultId: string, body: VaultRotation & { revision: number; invites?: SignedGrant[]; serviceGrants?: SignedGrant[] }) =>
      http.request<{ revision: number }>('POST', `${vault(vaultId)}/rotate`, { body }),
    serviceAccounts: (vaultId: string) => http.request<{ serviceAccounts: ServiceAccountRecord[] }>('GET', `${vault(vaultId)}/service-accounts`),
    createServiceAccount: (vaultId: string, body: Omit<NewServiceAccount, 'token'> & { expiresAt?: string }) =>
      http.request<ServiceAccountRecord>('POST', `${vault(vaultId)}/service-accounts`, { body }),
    revokeServiceAccount: (vaultId: string, id: string) => http.request<void>('DELETE', `${vault(vaultId)}/service-accounts/${encodeURIComponent(id)}`),

    orgs: () => http.request<OrganisationState>('GET', '/v1/orgs'),
    createOrg: (id: string, name: string) => http.request<Organisation>('POST', '/v1/orgs', { body: { id, name } }),
    renameOrg: (orgId: string, name: string) => http.request<void>('PATCH', org(orgId), { body: { name } }),
    deleteOrg: (orgId: string, reauthToken: string, confirmName: string) => http.request<void>('DELETE', org(orgId), { headers: reauthHeader(reauthToken), body: { confirmName } }),
    orgMembers: (orgId: string) => http.request<Pick<OrgMembers, 'invites'> & { members: Omit<OrgMember, 'isYou'>[] }>('GET', `${org(orgId)}/members`),
    inviteToOrg: (orgId: string, email: string, role: OrgRole) => http.request<void>('POST', `${org(orgId)}/invites`, { body: { email, role } }),
    deleteOrgInvite: (orgId: string, inviteId: string) => http.request<void>('DELETE', `${org(orgId)}/invites/${encodeURIComponent(inviteId)}`),
    acceptOrgInvite: (orgId: string, inviteId: string) => http.request<Organisation>('POST', `${org(orgId)}/invites/${encodeURIComponent(inviteId)}/accept`),
    setOrgRole: (orgId: string, accountId: string, role: OrgRole) => http.request<void>('PATCH', `${org(orgId)}/members/${encodeURIComponent(accountId)}`, { body: { role } }),
    removeOrgMember: (orgId: string, accountId: string, orphanVaults: boolean) =>
      http.request<void>('DELETE', `${org(orgId)}/members/${encodeURIComponent(accountId)}${orphanVaults ? '?orphanVaults=true' : ''}`),
    orgGroups: (orgId: string) => http.request<{ groups: OrgGroup[] }>('GET', `${org(orgId)}/groups`),
    createOrgGroup: (orgId: string, id: string, name: string) => http.request<OrgGroup>('POST', `${org(orgId)}/groups`, { body: { id, name } }),
    renameOrgGroup: (orgId: string, groupId: string, name: string) => http.request<void>('PATCH', `${org(orgId)}/groups/${encodeURIComponent(groupId)}`, { body: { name } }),
    deleteOrgGroup: (orgId: string, groupId: string) => http.request<void>('DELETE', `${org(orgId)}/groups/${encodeURIComponent(groupId)}`),
    addOrgGroupMember: (orgId: string, groupId: string, accountId: string) =>
      http.request<void>('PUT', `${org(orgId)}/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(accountId)}`),
    removeOrgGroupMember: (orgId: string, groupId: string, accountId: string) =>
      http.request<void>('DELETE', `${org(orgId)}/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(accountId)}`),
    orgVaults: (orgId: string) => http.request<{ vaults: Omit<OrgVault, 'name' | 'shortId'>[] }>('GET', `${org(orgId)}/vaults`),
    createOrgVault: (orgId: string, body: NewSharedVault) => http.request<VaultRecord>('POST', `${org(orgId)}/vaults`, { body }),
    deleteOrgVault: (orgId: string, vaultId: string, reauthToken: string) =>
      http.request<void>('DELETE', `${org(orgId)}/vaults/${encodeURIComponent(vaultId)}`, { headers: reauthHeader(reauthToken) }),
    linkOrgVaultGroup: (orgId: string, vaultId: string, groupId: string, role: VaultRole) =>
      http.request<void>('PUT', `${org(orgId)}/vaults/${encodeURIComponent(vaultId)}/groups/${encodeURIComponent(groupId)}`, { body: { role } }),
    unlinkOrgVaultGroup: (orgId: string, vaultId: string, groupId: string) =>
      http.request<void>('DELETE', `${org(orgId)}/vaults/${encodeURIComponent(vaultId)}/groups/${encodeURIComponent(groupId)}`),
    orgAccess: (orgId: string) => http.request<{ vaults: OrgVaultPlanRecord[] }>('GET', `${org(orgId)}/access`),
    grantOrgAccess: (orgId: string, vaultId: string, keyId: string, grants: SignedGrant[]) =>
      http.request<void>('POST', `${org(orgId)}/vaults/${encodeURIComponent(vaultId)}/grants`, { body: { keyId, grants } }),
    setOrgPolicies: (orgId: string, policies: OrgPolicies) => http.request<OrgPolicies>('PUT', `${org(orgId)}/policies`, { body: policies }),
    orgEvents: (orgId: string) => http.request<{ events: OrgEvent[] }>('GET', `${org(orgId)}/events`),
    orgSso: (orgId: string) => http.request<OrgSsoSettings>('GET', `${org(orgId)}/sso`),
    saveOrgSso: (orgId: string, body: { issuer: string; clientId: string; clientSecret?: string }) => http.request<OrgSsoSettings>('PUT', `${org(orgId)}/sso`, { body }),
    removeOrgSso: (orgId: string) => http.request<void>('DELETE', `${org(orgId)}/sso`),
    testOrgSso: (orgId: string) => http.request<{ url: string; expiresIn: number }>('POST', `${org(orgId)}/sso/test`),
    families: () => http.request<{ family?: FamilyRecord; invitations: FamilyInvite[] }>('GET', '/v1/families'),
    createFamily: (id: string, vaultBody: NewSharedVault) => http.request<FamilyRecord>('POST', '/v1/families', { body: { id, vault: vaultBody } }),
    deleteFamily: (familyId: string) => http.request<void>('DELETE', family(familyId)),
    inviteToFamily: (familyId: string, email: string, grant: SignedGrant, keyId?: string) =>
      http.request<void>('POST', `${family(familyId)}/invites`, { body: { email, grant, keyId } }),
    acceptFamilyInvite: (familyId: string) => http.request<void>('POST', `${family(familyId)}/invites/accept`),
    deleteFamilyInvite: (familyId: string, accountId: string) => http.request<void>('DELETE', `${family(familyId)}/invites/${encodeURIComponent(accountId)}`),
    removeFamilyMember: (familyId: string, accountId: string) => http.request<void>('DELETE', `${family(familyId)}/members/${encodeURIComponent(accountId)}`),

    shareLinks: () => http.request<{ links: ShareLinkRecord[] }>('GET', '/v1/share-links'),
    createShareLink: (body: { ciphertext: string; expiresAt: string; maxViews: number; passphraseRequired: boolean }) =>
      http.request<{ id: string; expiresAt: string }>('POST', '/v1/share-links', { body }),
    viewShareLink: (id: string) => http.request<ShareLinkEnvelope>('GET', `/v1/share-links/${encodeURIComponent(id)}`, anonymous),
    deleteShareLink: (id: string) => http.request<void>('DELETE', `/v1/share-links/${encodeURIComponent(id)}`),

    emergencyContacts: () => http.request<EmergencyContacts>('GET', '/v1/emergency-contacts'),
    addEmergencyContact: (body: { contactAccountId: string; sealedKey: string; scope: EmergencyScope; accessLevel: EmergencyAccessLevel; waitDays: number }) =>
      http.request<EmergencyContact>('POST', '/v1/emergency-contacts', { body }),
    removeEmergencyContact: (id: string) => http.request<void>('DELETE', emergency(id)),
    emergencyAction: (id: string, action: 'request' | 'deny' | 'approve') => http.request<EmergencyContact>('POST', `${emergency(id)}/${action}`),
    /** `grantor` comes with an account scope only. */
    emergencyRelease: (id: string) => http.request<{ contact: EmergencyContact; sealedKey: string; grantor?: AccountBundle }>('GET', `${emergency(id)}/release`),
    emergencySync: (id: string, since: { id: string; revision: number }[]) => http.request<SyncResponse>('GET', `${emergency(id)}/sync${sinceQuery(since)}`),
    /** Refused with `vault-key-changed` once `keyId` is rotated away. */
    renewEmergencyKey: (id: string, body: { sealedKey: string; keyId: string }) => http.request<EmergencyContact>('PUT', `${emergency(id)}/key`, { body }),
    takeoverRegistration: (id: string, registrationRequest: string) =>
      http.request<{ registrationResponse: string }>('POST', `${emergency(id)}/takeover/registration`, { body: { registrationRequest } }),
    /** Every device of the grantor is signed out, and the record is gone. */
    emergencyTakeover: (id: string, reauthToken: string, body: CredentialsFinish & { signature: string }) =>
      http.request<void>('POST', `${emergency(id)}/takeover`, { headers: reauthHeader(reauthToken), body }),
    enableOrganiserRecovery: (familyId: string, body: { sealedKey: string; waitDays: number }) =>
      http.request<EmergencyContact>('POST', `${family(familyId)}/organiser-recovery`, { body }),
    /** One of the grantor's encrypted files, as a response to stream. */
    emergencyAttachment: (id: string, vaultId: string, itemId: string, attachmentId: string) =>
      http.request<Response>('GET', `${emergency(id)}${attachment(vaultId, itemId, attachmentId).slice('/v1'.length)}`, { raw: true }),

    twoStep: () => http.request<TwoStepStatusRecord>('GET', '/v1/account/two-step'),
    startTotp: (reauthToken: string) =>
      http.request<{ setupId: string; secret: string; otpauthUri: string; expiresIn: number }>('POST', '/v1/account/two-step/totp', { headers: reauthHeader(reauthToken) }),
    confirmTotp: (setupId: string, code: string) =>
      http.request<{ recoveryCodes?: string[] }>('POST', '/v1/account/two-step/totp/confirm', { body: { setupId, code } }),
    renewRecoveryCodes: (reauthToken: string) =>
      http.request<{ recoveryCodes: string[] }>('POST', '/v1/account/two-step/recovery-codes', { headers: reauthHeader(reauthToken) }),
    disableTwoStep: (reauthToken: string) => http.request<void>('DELETE', '/v1/account/two-step', { headers: reauthHeader(reauthToken) }),
    forgetTrustedDevices: () => http.request<void>('DELETE', '/v1/account/two-step/trusted-devices'),
    securityKeyOptions: (reauthToken: string) =>
      http.request<{ setupId: string; publicKey: WebAuthnCreationOptions }>('POST', '/v1/account/two-step/security-keys/options', { headers: reauthHeader(reauthToken) }),
    addSecurityKey: (body: WebAuthnAttestation & { setupId: string; name: string }) =>
      http.request<SecurityKeyRecord>('POST', '/v1/account/two-step/security-keys', { body }),
    removeSecurityKey: (reauthToken: string, id: string) =>
      http.request<void>('DELETE', `/v1/account/two-step/security-keys/${encodeURIComponent(id)}`, { headers: reauthHeader(reauthToken) }),

    securityLog: () => http.request<{ events: (SecurityEvent & { sealedDetail?: string })[] }>('GET', '/v1/security-log'),
    /** A "vault exported" entry in the security log, naming this device. */
    recordExport: (format: ExportFormat, attachments: boolean) => http.request<void>('POST', '/v1/security-log/exports', { body: { format, attachments } }),
  };
}

export type Api = ReturnType<typeof createApi>;
