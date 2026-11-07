// The mock's organisation features, for UI work and tests. In memory, one organisation, with a
// pretend colleague. Nothing here is a key: as on the real server, a group adds nobody to a vault
// until a key holder applies it.

import { VaultError } from '../errors';
import { uuidv7 } from '../ids';
import type {
  OrgAccessGrant,
  OrgAccessReview,
  OrgEvent,
  OrgGroup,
  OrgInvitation,
  OrgMember,
  OrgMembers,
  OrgPolicies,
  OrgRole,
  OrgSsoSettings,
  OrgVault,
  Organisation,
  OrganisationService,
  OrganisationState,
  VaultRole,
} from '../types';

const NOW = () => new Date().toISOString();
const FINGERPRINT = { digits: '1234 5678 9012 3456 7890 1234', emoji: [{ emoji: '🔑', name: 'key' }, { emoji: '🌿', name: 'herb' }, { emoji: '🦉', name: 'owl' }] };

const DEFAULT_POLICIES: OrgPolicies = {
  requireTwoStep: false,
  requireSso: false,
  ssoMaxAgeHours: 168,
  disableShareLinks: false,
  disableEmergencyAccess: false,
  disableExport: false,
};

function shortId(id: string): string {
  return id.slice(-8);
}

export class MockOrganisations implements OrganisationService {
  private organisation: Organisation | undefined;
  private invitations: OrgInvitation[] = [];
  private members: OrgMember[] = [];
  private invites: OrgMembers['invites'] = [];
  private groups: OrgGroup[] = [];
  private vaults: OrgVault[] = [];
  /** vault id → people waiting for a key holder, and whether a rotation is due. */
  private pending = new Map<string, { grants: OrgAccessGrant[]; rotate: boolean }>();
  private sso: OrgSsoSettings = { hasClientSecret: false, callbackUrl: 'https://vault.example.com/v1/sso/callback' };
  private events: OrgEvent[] = [];

  /** `changed` tells screens to load again, as the real service does. */
  constructor(private readonly changed: () => void = () => undefined) {}

  private log(type: string, subject?: string): void {
    this.events.unshift({ id: uuidv7(), type, actor: 'you@example.com', subject, createdAt: NOW() });
  }

  private org(): Organisation {
    if (!this.organisation) throw new VaultError('notFound');
    return this.organisation;
  }

  private entitlementChanged(): void {
    for (const vault of this.vaults) {
      const grants: OrgAccessGrant[] = [];
      for (const link of vault.groups) {
        const group = this.groups.find((g) => g.id === link.groupId);
        for (const accountId of group?.members ?? []) {
          const member = this.members.find((m) => m.accountId === accountId);
          if (member && !member.isYou) grants.push({ accountId, email: member.email, role: link.role, upgrade: false, fingerprint: FINGERPRINT, verified: false, keyChanged: false });
        }
      }
      this.pending.set(vault.id, { grants, rotate: this.pending.get(vault.id)?.rotate ?? false });
    }
  }

  /** A pretend invitation, for tests of the screen an invitee sees. */
  seedInvitation(invitation: Partial<OrgInvitation> = {}): void {
    this.invitations.push({
      id: uuidv7(),
      orgId: uuidv7(),
      orgName: 'Acme',
      role: 'member',
      invitedBy: 'owner@example.com',
      policies: { ...DEFAULT_POLICIES, requireSso: true, requireTwoStep: true },
      invitedAt: NOW(),
      expiresAt: NOW(),
      ...invitation,
    });
  }

  async getOrganisation(): Promise<OrganisationState> {
    return { organisation: this.organisation, invitations: this.invitations };
  }

  async createOrganisation(name: string): Promise<void> {
    queueMicrotask(this.changed);
    if (this.organisation) throw new VaultError('alreadyExists');
    this.organisation = { id: uuidv7(), name, role: 'owner', policies: { ...DEFAULT_POLICIES }, memberCount: 2, accessWithheld: false, createdAt: NOW() };
    this.members = [
      { accountId: uuidv7(), email: 'you@example.com', role: 'owner', twoStep: true, ssoLinked: false, joinedAt: NOW(), isYou: true },
      { accountId: uuidv7(), email: 'sam@example.com', role: 'member', twoStep: false, ssoLinked: false, joinedAt: NOW(), isYou: false },
    ];
    this.log('org-created', name);
  }

  async renameOrganisation(name: string): Promise<void> {
    queueMicrotask(this.changed);
    this.org().name = name;
  }

  async deleteOrganisation(input: { password: string; confirmName: string }): Promise<void> {
    queueMicrotask(this.changed);
    if (input.confirmName !== this.org().name) throw new VaultError('invalidCredentials');
    this.organisation = undefined;
    this.members = [];
    this.groups = [];
    this.vaults = [];
  }

  async acceptOrgInvite(_orgId: string, inviteId: string): Promise<void> {
    queueMicrotask(this.changed);
    const invitation = this.invitations.find((i) => i.id === inviteId);
    if (!invitation) throw new VaultError('notFound');
    this.invitations = this.invitations.filter((i) => i !== invitation);
    this.organisation = { id: invitation.orgId, name: invitation.orgName, role: invitation.role, policies: invitation.policies, memberCount: 2, accessWithheld: false, createdAt: NOW() };
  }

  async declineOrgInvite(_orgId: string, inviteId: string): Promise<void> {
    queueMicrotask(this.changed);
    this.invitations = this.invitations.filter((i) => i.id !== inviteId);
  }

  async listOrgMembers(): Promise<OrgMembers> {
    return { members: this.members, invites: this.invites };
  }

  async inviteOrgMember(email: string, role: OrgRole): Promise<void> {
    queueMicrotask(this.changed);
    this.invites.push({ id: uuidv7(), email, role, invitedAt: NOW(), expiresAt: NOW() });
    this.log('member-invited', email);
  }

  async cancelOrgInvite(inviteId: string): Promise<void> {
    queueMicrotask(this.changed);
    this.invites = this.invites.filter((i) => i.id !== inviteId);
  }

  async setOrgMemberRole(accountId: string, role: OrgRole): Promise<void> {
    queueMicrotask(this.changed);
    const member = this.members.find((m) => m.accountId === accountId);
    if (!member) throw new VaultError('notFound');
    member.role = role;
  }

  async removeOrgMember(accountId: string): Promise<void> {
    queueMicrotask(this.changed);
    this.members = this.members.filter((m) => m.accountId !== accountId);
    for (const group of this.groups) group.members = group.members.filter((id) => id !== accountId);
    for (const vault of this.pending.values()) vault.rotate = true;
    this.entitlementChanged();
    this.log('member-removed');
  }

  async leaveOrganisation(): Promise<void> {
    queueMicrotask(this.changed);
    this.organisation = undefined;
  }

  async listOrgGroups(): Promise<OrgGroup[]> {
    return this.groups;
  }

  async createOrgGroup(name: string): Promise<OrgGroup> {
    queueMicrotask(this.changed);
    if (this.groups.some((g) => g.name === name)) throw new VaultError('alreadyExists');
    const group = { id: uuidv7(), name, members: [], createdAt: NOW() };
    this.groups.push(group);
    this.log('group-created', name);
    return group;
  }

  async renameOrgGroup(groupId: string, name: string): Promise<void> {
    queueMicrotask(this.changed);
    const group = this.groups.find((g) => g.id === groupId);
    if (group) group.name = name;
  }

  async deleteOrgGroup(groupId: string): Promise<void> {
    queueMicrotask(this.changed);
    this.groups = this.groups.filter((g) => g.id !== groupId);
    for (const vault of this.vaults) vault.groups = vault.groups.filter((g) => g.groupId !== groupId);
    this.entitlementChanged();
  }

  async addOrgGroupMember(groupId: string, accountId: string): Promise<void> {
    queueMicrotask(this.changed);
    this.groups.find((g) => g.id === groupId)?.members.push(accountId);
    this.entitlementChanged();
  }

  async removeOrgGroupMember(groupId: string, accountId: string): Promise<void> {
    queueMicrotask(this.changed);
    const group = this.groups.find((g) => g.id === groupId);
    if (group) group.members = group.members.filter((id) => id !== accountId);
    this.entitlementChanged();
  }

  async listOrgVaults(): Promise<OrgVault[]> {
    return this.vaults;
  }

  async createOrgVault(name: string): Promise<void> {
    queueMicrotask(this.changed);
    const id = uuidv7();
    this.vaults.push({ id, name, shortId: shortId(id), groups: [], memberCount: 1, managerCount: 1, role: 'owner', rotationPending: false, createdAt: NOW() });
    this.log('vault-created', id);
  }

  async deleteOrgVault(input: { password: string; vaultId: string }): Promise<void> {
    queueMicrotask(this.changed);
    this.vaults = this.vaults.filter((v) => v.id !== input.vaultId);
    this.pending.delete(input.vaultId);
  }

  async linkOrgVaultGroup(vaultId: string, groupId: string, role: VaultRole): Promise<void> {
    queueMicrotask(this.changed);
    const vault = this.vaults.find((v) => v.id === vaultId);
    if (!vault) throw new VaultError('notFound');
    vault.groups = [...vault.groups.filter((g) => g.groupId !== groupId), { groupId, role }];
    this.entitlementChanged();
  }

  async unlinkOrgVaultGroup(vaultId: string, groupId: string): Promise<void> {
    queueMicrotask(this.changed);
    const vault = this.vaults.find((v) => v.id === vaultId);
    if (vault) vault.groups = vault.groups.filter((g) => g.groupId !== groupId);
    this.entitlementChanged();
  }

  async getOrgAccess(): Promise<OrgAccessReview[]> {
    return this.vaults.flatMap((vault) => {
      const pending = this.pending.get(vault.id);
      if (!pending || (pending.grants.length === 0 && !pending.rotate)) return [];
      return [{ vaultId: vault.id, vaultName: vault.name, shortId: vault.shortId, canApply: true, rotate: pending.rotate, grants: pending.grants }];
    });
  }

  async applyOrgAccess(vaultId: string, confirmed: Pick<OrgAccessGrant, 'accountId' | 'fingerprint'>[]): Promise<void> {
    queueMicrotask(this.changed);
    const pending = this.pending.get(vaultId);
    if (!pending) throw new VaultError('notFound');
    const done = new Set(confirmed.map((c) => c.accountId));
    pending.grants = pending.grants.filter((g) => !done.has(g.accountId));
    const vault = this.vaults.find((v) => v.id === vaultId);
    if (vault) vault.memberCount += done.size;
    this.log('access-granted', vaultId);
  }

  async rotateOrgVault(vaultId: string): Promise<void> {
    queueMicrotask(this.changed);
    const pending = this.pending.get(vaultId);
    if (pending) pending.rotate = false;
  }

  async setOrgPolicies(policies: OrgPolicies): Promise<void> {
    queueMicrotask(this.changed);
    if (policies.requireSso && !this.sso.testedAt) throw new VaultError('ssoConfig');
    this.org().policies = policies;
    this.log('policies-changed');
  }

  async getOrgSso(): Promise<OrgSsoSettings> {
    return this.sso;
  }

  async saveOrgSso(input: { issuer: string; clientId: string; clientSecret?: string }): Promise<OrgSsoSettings> {
    queueMicrotask(this.changed);
    this.sso = { ...this.sso, issuer: input.issuer, clientId: input.clientId, hasClientSecret: this.sso.hasClientSecret || Boolean(input.clientSecret), testedAt: undefined };
    return this.sso;
  }

  async removeOrgSso(): Promise<void> {
    queueMicrotask(this.changed);
    this.sso = { hasClientSecret: false, callbackUrl: this.sso.callbackUrl };
  }

  async testOrgSso(): Promise<string> {
    queueMicrotask(this.changed);
    this.sso = { ...this.sso, testedAt: NOW() };
    return 'https://idp.example.com/test';
  }

  async listOrgEvents(): Promise<OrgEvent[]> {
    return this.events;
  }
}
