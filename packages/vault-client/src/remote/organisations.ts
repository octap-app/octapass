// Organisations (plan 03, "Organisations and single sign-on"; docs/developers/sync-api.md,
// "Organisations"). Nothing here is a key: roles, groups and policies live on the server, and a
// vault key reaches someone only through a grant sealed on this device, after a person reviewed it.

import type * as CoreModule from '@octapass/core';
import type { Session } from '@octapass/core';
import { VaultError } from '../errors';
import { normalizeEmail } from '../items';
import type {
  Fingerprint,
  OrgAccessGrant,
  OrgAccessReview,
  OrgEvent,
  OrgGroup,
  OrgMembers,
  OrgPolicies,
  OrgRole,
  OrgSamlInput,
  OrgScim,
  OrgScimToken,
  OrgSsoSettings,
  OrgVault,
  OrganisationState,
  Vault,
  VaultRole,
} from '../types';
import type { Api, OrgPendingGrantRecord, ReauthPurpose } from './api';
import type { KeyLogEngine } from './keyLog';
import { asNotAllowed } from './errors';
import { ApiProblem } from './http';
import type { LocalStore } from './store';
import type { VaultIndex } from './vaultIndex';

/** A shared vault's name lives inside it, so an admin without the key sees part of its id. */
const SHORT_ID = 8;

export interface OrganisationHost {
  core(): Promise<Pick<typeof CoreModule, 'newId' | 'keyFingerprint'>>;
  unlocked(): { session: Session; index: VaultIndex };
  api(): Api;
  accountId(): string;
  store: LocalStore;
  sync(): Promise<void>;
  changed(): void;
  reauth(password: string, purpose: ReauthPurpose): Promise<string>;
  /** Rotates a vault's key as plan 15 describes. */
  rotate(vaultId: string): Promise<void>;
  /** Writes a vault's encrypted name. */
  nameVault(vaultId: string, name: string): Promise<void>;
  /** Checks recipients against the key log before anything is sealed to them. */
  keyLog: Pick<KeyLogEngine, 'require'>;
  listVaults(): Promise<Vault[]>;
}

export class OrganisationEngine {
  constructor(private readonly host: OrganisationHost) {}

  private async orgId(): Promise<string> {
    const { organisation } = await this.host.api().orgs();
    if (!organisation) throw new VaultError('notFound');
    return organisation.id;
  }

  async getOrganisation(): Promise<OrganisationState> {
    return this.host.api().orgs();
  }

  async createOrganisation(name: string): Promise<void> {
    const core = await this.host.core();
    await this.host.api().createOrg(core.newId(), name);
    this.host.changed();
  }

  async renameOrganisation(name: string): Promise<void> {
    await asNotAllowed(this.host.api().renameOrg(await this.orgId(), name));
    this.host.changed();
  }

  async deleteOrganisation(input: { password: string; confirmName: string }): Promise<void> {
    const id = await this.orgId();
    const token = await this.host.reauth(input.password, 'organisation');
    await asNotAllowed(this.host.api().deleteOrg(id, token, input.confirmName));
    await this.host.sync();
    this.host.changed();
  }

  async acceptOrgInvite(orgId: string, inviteId: string): Promise<void> {
    await this.host.api().acceptOrgInvite(orgId, inviteId);
    await this.host.sync();
    this.host.changed();
  }

  async declineOrgInvite(orgId: string, inviteId: string): Promise<void> {
    await this.host.api().deleteOrgInvite(orgId, inviteId);
    this.host.changed();
  }

  async listOrgMembers(): Promise<OrgMembers> {
    const me = this.host.accountId();
    const { members, invites } = await asNotAllowed(this.host.api().orgMembers(await this.orgId()));
    return { members: members.map((member) => ({ ...member, isYou: member.accountId === me })), invites };
  }

  async inviteOrgMember(email: string, role: OrgRole): Promise<void> {
    await asNotAllowed(this.host.api().inviteToOrg(await this.orgId(), normalizeEmail(email), role));
    this.host.changed();
  }

  async cancelOrgInvite(inviteId: string): Promise<void> {
    await asNotAllowed(this.host.api().deleteOrgInvite(await this.orgId(), inviteId));
    this.host.changed();
  }

  async setOrgMemberRole(accountId: string, role: OrgRole): Promise<void> {
    await asNotAllowed(this.host.api().setOrgRole(await this.orgId(), accountId, role));
    this.host.changed();
  }

  /** `orphanVaults`: go ahead even if a vault is left with nobody able to manage it. */
  async removeOrgMember(accountId: string, options?: { orphanVaults?: boolean }): Promise<void> {
    await asNotAllowed(this.host.api().removeOrgMember(await this.orgId(), accountId, options?.orphanVaults ?? false));
    this.host.changed();
  }

  async leaveOrganisation(options?: { orphanVaults?: boolean }): Promise<void> {
    await this.host.api().removeOrgMember(await this.orgId(), this.host.accountId(), options?.orphanVaults ?? false);
    await this.host.sync();
    this.host.changed();
  }

  async listOrgGroups(): Promise<OrgGroup[]> {
    return (await asNotAllowed(this.host.api().orgGroups(await this.orgId()))).groups;
  }

  async createOrgGroup(name: string): Promise<OrgGroup> {
    const core = await this.host.core();
    const group = await asNotAllowed(this.host.api().createOrgGroup(await this.orgId(), core.newId(), name));
    this.host.changed();
    return group;
  }

  async renameOrgGroup(groupId: string, name: string): Promise<void> {
    await asNotAllowed(this.host.api().renameOrgGroup(await this.orgId(), groupId, name));
    this.host.changed();
  }

  async deleteOrgGroup(groupId: string): Promise<void> {
    await asNotAllowed(this.host.api().deleteOrgGroup(await this.orgId(), groupId));
    this.host.changed();
  }

  async addOrgGroupMember(groupId: string, accountId: string): Promise<void> {
    await asNotAllowed(this.host.api().addOrgGroupMember(await this.orgId(), groupId, accountId));
    this.host.changed();
  }

  async removeOrgGroupMember(groupId: string, accountId: string): Promise<void> {
    await asNotAllowed(this.host.api().removeOrgGroupMember(await this.orgId(), groupId, accountId));
    this.host.changed();
  }

  /** Vaults this account can open show their names; the rest show part of their id. */
  async listOrgVaults(): Promise<OrgVault[]> {
    const [{ vaults }, mine] = await Promise.all([asNotAllowed(this.host.api().orgVaults(await this.orgId())), this.host.listVaults()]);
    const names = new Map(mine.map((vault) => [vault.id, vault.name]));
    return vaults.map((vault) => ({ ...vault, name: names.get(vault.id), shortId: vault.id.slice(-SHORT_ID) }));
  }

  async createOrgVault(name: string): Promise<void> {
    const { session, index } = this.host.unlocked();
    const created = session.createSharedVault();
    const record = await asNotAllowed(this.host.api().createOrgVault(await this.orgId(), created));
    index.apply({ vaults: [...index.vaults(), record], items: [], deleted: [] }, false);
    if (index.isUntrusted(record.id)) throw new VaultError('untrustedVault');
    await this.host.nameVault(record.id, name);
    this.host.changed();
  }

  async deleteOrgVault(input: { password: string; vaultId: string }): Promise<void> {
    const id = await this.orgId();
    const token = await this.host.reauth(input.password, 'organisation');
    await asNotAllowed(this.host.api().deleteOrgVault(id, input.vaultId, token));
    await this.host.sync();
    this.host.changed();
  }

  async linkOrgVaultGroup(vaultId: string, groupId: string, role: VaultRole): Promise<void> {
    await asNotAllowed(this.host.api().linkOrgVaultGroup(await this.orgId(), vaultId, groupId, role));
    this.host.changed();
  }

  async unlinkOrgVaultGroup(vaultId: string, groupId: string): Promise<void> {
    await asNotAllowed(this.host.api().unlinkOrgVaultGroup(await this.orgId(), vaultId, groupId));
    this.host.changed();
  }

  /**
   * What vaults are waiting for from a key holder. The list comes from the server, so each person
   * gets a fingerprint computed here, and the screen shows them for a person to confirm.
   */
  async getOrgAccess(): Promise<OrgAccessReview[]> {
    await this.host.sync();
    const me = this.host.accountId();
    const { vaults } = await this.host.api().orgAccess(await this.orgId());
    const verified = await this.host.store.verified(me);
    const names = new Map((await this.host.listVaults()).map((vault) => [vault.id, vault.name]));
    return Promise.all(
      vaults.map(async (vault) => ({
        vaultId: vault.vaultId,
        vaultName: names.get(vault.vaultId),
        shortId: vault.vaultId.slice(-SHORT_ID),
        canApply: vault.canApply,
        rotate: vault.rotate,
        grants: await Promise.all(vault.grants.map((grant) => this.reviewed(grant, verified))),
      })),
    );
  }

  private async reviewed(grant: OrgPendingGrantRecord, verified: Record<string, string>): Promise<OrgAccessGrant> {
    const fingerprint = await this.fingerprint(grant.publicEncKey, grant.publicSignKey);
    const known = verified[grant.accountId];
    return {
      accountId: grant.accountId,
      email: grant.email,
      role: grant.role,
      upgrade: grant.upgrade,
      fingerprint,
      verified: known === fingerprint.digits,
      keyChanged: known !== undefined && known !== fingerprint.digits,
    };
  }

  private async fingerprint(publicEncKey: string, publicSignKey: string): Promise<Fingerprint> {
    return (await this.host.core()).keyFingerprint(publicEncKey, publicSignKey);
  }

  /**
   * Seals the vault to exactly the people a person confirmed. Each is checked against the plan as
   * the server says it now: anyone whose keys differ from the fingerprint that was on screen, or
   * from one verified earlier on this device, is refused rather than sealed to. Anyone the server
   * added since the review isn't sealed to at all.
   */
  async applyOrgAccess(vaultId: string, confirmed: Pick<OrgAccessGrant, 'accountId' | 'fingerprint'>[]): Promise<void> {
    if (confirmed.length === 0) return;
    const orgId = await this.orgId();
    for (let attempt = 1; ; attempt++) {
      await this.host.sync();
      const { session, index } = this.host.unlocked();
      const vault = index.vault(vaultId);
      if (!vault?.keyId) throw new VaultError('notFound');
      if (index.isUntrusted(vaultId)) throw new VaultError('untrustedVault');
      const { vaults } = await this.host.api().orgAccess(orgId);
      const plan = vaults.find((entry) => entry.vaultId === vaultId);
      if (!plan?.canApply) throw new VaultError('notAllowed');
      const verified = await this.host.store.verified(this.host.accountId());
      const grants = [];
      for (const { accountId, fingerprint } of confirmed) {
        const pending = plan.grants.find((grant) => grant.accountId === accountId);
        if (!pending) continue;
        const actual = await this.reviewed(pending, verified);
        if (actual.fingerprint.digits !== fingerprint.digits || actual.keyChanged) throw new VaultError('untrustedVault');
        // As for any share: the keys must not contradict the key log, and a valid record makes the grant hybrid (plan 03).
        const { publicEncKey, publicSignKey, keyRecord, email, role } = pending;
        await this.host.keyLog.require({ accountId, email, publicEncKey, publicSignKey, keyRecord });
        grants.push(session.grantVault(vaultId, { accountId, publicEncKey, publicSignKey, keyRecord, role }));
      }
      if (grants.length === 0) return;
      try {
        await asNotAllowed(this.host.api().grantOrgAccess(orgId, vaultId, vault.keyId, grants));
        break;
      } catch (error) {
        const stale = error instanceof ApiProblem && error.status === 409 && error.type === 'vault-key-changed';
        if (!stale || attempt >= 2) throw error;
      }
    }
    await this.host.sync();
    this.host.changed();
  }

  async rotateOrgVault(vaultId: string): Promise<void> {
    await this.host.rotate(vaultId);
    this.host.changed();
  }

  async setOrgPolicies(policies: OrgPolicies): Promise<void> {
    await asNotAllowed(this.host.api().setOrgPolicies(await this.orgId(), policies));
    this.host.changed();
  }

  async getOrgSso(): Promise<OrgSsoSettings> {
    return asNotAllowed(this.host.api().orgSso(await this.orgId()));
  }

  async saveOrgSso(input: { issuer: string; clientId: string; clientSecret?: string }): Promise<OrgSsoSettings> {
    const saved = await asNotAllowed(this.host.api().saveOrgSso(await this.orgId(), input));
    this.host.changed();
    return saved;
  }

  async saveOrgSaml(input: OrgSamlInput): Promise<OrgSsoSettings> {
    const saved = await asNotAllowed(this.host.api().saveOrgSaml(await this.orgId(), input));
    this.host.changed();
    return saved;
  }

  async getOrgScim(): Promise<OrgScim> {
    return asNotAllowed(this.host.api().orgScim(await this.orgId()));
  }

  async createOrgScimToken(name: string): Promise<{ token: OrgScimToken; secret: string }> {
    const created = await asNotAllowed(this.host.api().createOrgScimToken(await this.orgId(), name.trim()));
    this.host.changed();
    return created;
  }

  async revokeOrgScimToken(tokenId: string): Promise<void> {
    await asNotAllowed(this.host.api().revokeOrgScimToken(await this.orgId(), tokenId));
    this.host.changed();
  }

  async removeOrgSso(): Promise<void> {
    await asNotAllowed(this.host.api().removeOrgSso(await this.orgId()));
    this.host.changed();
  }

  async testOrgSso(): Promise<string> {
    return (await asNotAllowed(this.host.api().testOrgSso(await this.orgId()))).url;
  }

  async listOrgEvents(): Promise<OrgEvent[]> {
    return (await asNotAllowed(this.host.api().orgEvents(await this.orgId()))).events;
  }

  /** The vaults an export leaves out under the organisation's `disableExport` policy. */
  async vaultsKeptFromExport(): Promise<Set<string>> {
    try {
      const { organisation } = await this.host.api().orgs();
      if (!organisation?.policies.disableExport) return new Set();
    } catch {
      // Offline: the policy can't be read, and the vault is already on this device.
      return new Set();
    }
    const { index } = this.host.unlocked();
    return new Set(index.vaults().flatMap((vault) => (vault.orgId ? [vault.id] : [])));
  }
}
