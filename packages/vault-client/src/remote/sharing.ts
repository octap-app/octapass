// Shared vaults, members, key rotation and families (plan 15; docs/developers/sync-api.md,
// "Sharing" and "Families"). Every vault key a member gets is sealed to their public key and signed
// on this device; the server only stores grants and checks who may give them.

import type * as CoreModule from '@octapass/core';
import type { GrantRecipient, Session, SignedGrant } from '@octapass/core';
import { isVaultError, VaultError } from '../errors';
import { normalizeEmail, withAttachments, withoutPin } from '../items';
import type { AccountLookup, FamilyInvite, FamilyState, Fingerprint, Item, ItemDraft, ServiceAccount, Vault, VaultMember, VaultRole } from '../types';
import type { Api, MemberRecord, ServiceAccountRecord } from './api';
import type { KeyLogEngine } from './keyLog';
import { asNotAllowed } from './errors';
import { ApiProblem } from './http';
import type { LocalStore } from './store';
import { DEFAULT_VAULT_NAMES, VAULT_INFO_TYPE, type VaultIndex } from './vaultIndex';

export type SharingCore = Pick<typeof CoreModule, 'newId' | 'keyFingerprint'>;

/** What the engine lends the sharing code: the unlocked session and its own item writes. */
export interface SharingHost {
  core(): Promise<SharingCore>;
  unlocked(): { session: Session; index: VaultIndex };
  api(): Api;
  accountId(): string;
  /** The server this account is on, which a service account's token names. */
  serverUrl(): string;
  store: LocalStore;
  sync(): Promise<void>;
  /** Members, families or invitations changed. */
  changed(): void;
  keyLog: KeyLogEngine;
  createItem(vaultId: string, draft: Pick<ItemDraft, 'overview' | 'details'>): Promise<Item>;
  saveItem(draft: ItemDraft): Promise<Item>;
  deleteItem(id: string): Promise<void>;
  listVaults(): Promise<Vault[]>;
  /** Re-encrypts the files of one item for another (its copy in another vault). */
  copyAttachments(fromItemId: string, toItemId: string): Promise<Item | undefined>;
}

/** A rotation races other members' writes; after this many `vault-changed` answers, give up. */
const ROTATION_ATTEMPTS = 3;

const VAULT_INFO_DETAILS = { schemaVersion: 1 } as const;

/**
 * Creates under a client-chosen id, trying once more after a 500. Creating a vault fails as a whole,
 * so a retry can't make two; the SQLite server answers 500 when a concurrent write invalidates its
 * snapshot mid-transaction (plan 15 history).
 */
async function createOnce<T>(create: () => Promise<T>): Promise<T> {
  try {
    return await create();
  } catch (error) {
    if (!(error instanceof ApiProblem && error.status === 500)) throw error;
    return create();
  }
}

export function isProblem(error: unknown, status: number, type: string): boolean {
  return error instanceof ApiProblem && error.status === status && error.type === type;
}

export class SharingEngine {
  constructor(private readonly host: SharingHost) {}

  // ---------- Identity ----------

  async fingerprint(publicEncKey: string, publicSignKey: string): Promise<Fingerprint> {
    return (await this.host.core()).keyFingerprint(publicEncKey, publicSignKey);
  }

  async lookupAccount(email: string): Promise<AccountLookup> {
    let record;
    try {
      record = await this.host.api().lookup(normalizeEmail(email));
    } catch (error) {
      if (isVaultError(error, 'notFound') || isProblem(error, 404, 'not-found')) throw new VaultError('accountNotFound');
      throw error;
    }
    const { accountId, publicEncKey, publicSignKey, keyRecord } = record;
    return {
      accountId,
      email: record.email,
      publicEncKey,
      publicSignKey,
      ...(keyRecord ? { keyRecord } : {}),
      fingerprint: await this.fingerprint(publicEncKey, publicSignKey),
      keyLog: await this.host.keyLog.check(record),
    };
  }

  async markVerified(account: Pick<AccountLookup, 'accountId' | 'fingerprint'>): Promise<void> {
    const me = this.host.accountId();
    const verified = await this.host.store.verified(me);
    await this.host.store.setVerified(me, { ...verified, [account.accountId]: account.fingerprint.digits });
    this.host.changed();
  }

  // ---------- Shared vaults ----------

  async createVault(name: string): Promise<Vault> {
    const { session, index } = this.host.unlocked();
    const created = session.createSharedVault();
    const record = await createOnce(() => this.host.api().createVault(created));
    index.apply({ vaults: [...index.vaults(), record], items: [], deleted: [] }, false);
    if (index.isUntrusted(record.id)) throw new VaultError('untrustedVault');
    await this.writeVaultName(record.id, name);
    this.host.changed();
    return (await this.host.listVaults()).find((v) => v.id === record.id)!;
  }

  async renameVault(vaultId: string, name: string): Promise<void> {
    await this.writeVaultName(vaultId, name);
  }

  async listMembers(vaultId: string): Promise<VaultMember[]> {
    const me = this.host.accountId();
    const [{ members }, verified] = await Promise.all([this.host.api().members(vaultId), this.host.store.verified(me)]);
    return Promise.all(
      members.map(async (m): Promise<VaultMember> => {
        const fingerprint = await this.fingerprint(m.publicEncKey, m.publicSignKey);
        return {
          name: m.email,
          email: m.email,
          role: m.role,
          accountId: m.accountId,
          fingerprint,
          verified: m.accountId === me || verified[m.accountId] === fingerprint.digits,
          ...(m.accountId === me ? {} : { keyLog: await this.host.keyLog.check(m) }),
          isYou: m.accountId === me,
          addedAt: m.addedAt,
        };
      }),
    );
  }

  async addMember(vaultId: string, account: AccountLookup, role: VaultRole): Promise<void> {
    await this.checkFingerprint(account);
    await this.host.keyLog.require(account);
    await this.sendGrant(vaultId, { ...account, role }, (grant, keyId) => this.host.api().invite(vaultId, account.email, grant, keyId));
    this.host.changed();
  }

  /** A new grant with the new role replaces the old one. */
  async changeRole(vaultId: string, accountId: string, role: VaultRole): Promise<void> {
    const member = await this.member(vaultId, accountId);
    if (accountId !== this.host.accountId()) await this.host.keyLog.require(member);
    await this.sendGrant(vaultId, { ...member, role }, (grant, keyId) => this.host.api().invite(vaultId, member.email, grant, keyId));
    this.host.changed();
  }

  async removeMember(vaultId: string, accountId: string): Promise<void> {
    if (accountId === this.host.accountId()) return this.leaveVault(vaultId);
    await asNotAllowed(this.host.api().removeMember(vaultId, accountId));
    this.host.changed();
    await this.rotate(vaultId);
  }

  async leaveVault(vaultId: string): Promise<void> {
    await asNotAllowed(this.host.api().removeMember(vaultId, this.host.accountId()));
    await this.host.sync();
    this.host.changed();
  }

  /**
   * The removed member still knows the old vault key, so everyone who stays gets a new one and
   * every item key is re-wrapped under it. The item bodies don't change. `invitees` (a family's
   * pending invites) get the new key in the same request; the server cancels any invite left out.
   */
  async rotate(vaultId: string, invitees: GrantRecipient[] = []): Promise<void> {
    for (let attempt = 1; ; attempt++) {
      await this.host.sync();
      const { session, index } = this.host.unlocked();
      const vault = index.vault(vaultId);
      if (!vault) throw new VaultError('notFound');
      const { members } = await this.host.api().members(vaultId);
      // Left out, a service account keeps a key that no longer opens the vault: it fails closed.
      const service = await this.activeServiceAccounts(vaultId);
      // A rotation seals to everyone again, so it's where a swapped key would do the most harm.
      for (const member of members) if (member.accountId !== this.host.accountId()) await this.host.keyLog.require(member);
      const { grants, ...rotation } = session.rotateVaultKey(
        vaultId,
        [...members.map(({ accountId, publicEncKey, publicSignKey, keyRecord, role }) => ({ accountId, publicEncKey, publicSignKey, keyRecord, role })), ...invitees, ...service],
        index.records(vaultId).map(({ id, encryptedItemKey }) => ({ itemId: id, encryptedItemKey })),
      );
      const invitesEnd = members.length + invitees.length;
      const body = {
        revision: vault.revision,
        ...rotation,
        grants: grants.slice(0, members.length),
        invites: grants.slice(members.length, invitesEnd),
        serviceGrants: grants.slice(invitesEnd),
      };
      try {
        await asNotAllowed(this.host.api().rotate(vaultId, body));
        break;
      } catch (error) {
        if (!isProblem(error, 409, 'vault-changed') || attempt >= ROTATION_ATTEMPTS) throw error;
      }
    }
    // The new grant comes with the next sync, and with it the new key.
    await this.host.sync();
  }

  /**
   * A new key for a vault, on demand. A family vault's pending invites come along, as when a
   * member leaves. A personal vault's key is wrapped by the account key: there are no grants.
   */
  async rotateVaultKey(vaultId: string): Promise<void> {
    const { index } = this.host.unlocked();
    const vault = index.vault(vaultId);
    if (!vault) throw new VaultError('notFound');
    if (index.isUntrusted(vaultId)) throw new VaultError('untrustedVault');
    if (vault.role !== 'owner' && vault.role !== 'manage') throw new VaultError('notAllowed');
    if (vault.type === 'personal') await this.rotatePersonal(vaultId);
    else if (vault.type === 'family') await this.rotate(vaultId, await this.invitees((await this.requireFamily()).invites));
    else await this.rotate(vaultId);
    this.host.changed();
  }

  private async rotatePersonal(vaultId: string): Promise<void> {
    for (let attempt = 1; ; attempt++) {
      await this.host.sync();
      const { session, index } = this.host.unlocked();
      const vault = index.vault(vaultId);
      if (!vault) throw new VaultError('notFound');
      const items = index.records(vaultId).map(({ id, encryptedItemKey }) => ({ itemId: id, encryptedItemKey }));
      const rotation = session.rotatePersonalVaultKey(vaultId, items);
      try {
        await asNotAllowed(this.host.api().rotate(vaultId, { revision: vault.revision, ...rotation }));
        break;
      } catch (error) {
        if (!isProblem(error, 409, 'vault-changed') || attempt >= ROTATION_ATTEMPTS) throw error;
      }
    }
    // The new wrapped key comes with the next sync, and with it the new key.
    await this.host.sync();
  }

  private async activeServiceAccounts(vaultId: string): Promise<GrantRecipient[]> {
    try {
      const { serviceAccounts } = await this.host.api().serviceAccounts(vaultId);
      return serviceAccounts.filter((s) => !s.revokedAt).map((s) => ({ accountId: s.id, publicEncKey: s.publicEncKey, role: s.role }));
    } catch {
      return []; // A server that doesn't know them yet.
    }
  }

  private serviceAccountView(record: ServiceAccountRecord): ServiceAccount {
    const { session } = this.host.unlocked();
    return {
      id: record.id,
      vaultId: record.vaultId,
      name: session.openServiceAccountName(record.vaultId, record.id, record.encryptedName),
      role: record.role === 'write' ? 'write' : 'read',
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      lastUsedAt: record.lastUsedAt,
      revokedAt: record.revokedAt,
      needsNewToken: record.grantedBy !== record.createdBy,
    };
  }

  async listServiceAccounts(vaultId: string): Promise<ServiceAccount[]> {
    const { serviceAccounts } = await asNotAllowed(this.host.api().serviceAccounts(vaultId));
    return serviceAccounts.map((record) => this.serviceAccountView(record));
  }

  async createServiceAccount(vaultId: string, input: { name: string; role: 'read' | 'write'; expiresAt?: string }): Promise<{ account: ServiceAccount; token: string }> {
    await this.host.sync();
    const { session } = this.host.unlocked();
    const { token, ...body } = session.createServiceAccount(vaultId, input.role, input.name, this.host.serverUrl());
    const record = await asNotAllowed(this.host.api().createServiceAccount(vaultId, { ...body, expiresAt: input.expiresAt }));
    this.host.changed();
    return { account: this.serviceAccountView(record), token };
  }

  async revokeServiceAccount(vaultId: string, id: string): Promise<void> {
    await asNotAllowed(this.host.api().revokeServiceAccount(vaultId, id));
    this.host.changed();
    await this.rotate(vaultId);
  }

  async moveItem(itemId: string, toVaultId: string): Promise<Item> {
    const copy = await this.copyItem(itemId, toVaultId);
    await this.host.deleteItem(itemId);
    return copy;
  }

  async copyItem(itemId: string, toVaultId: string): Promise<Item> {
    const entry = this.host.unlocked().index.get(itemId);
    if (!entry) throw new VaultError('notFound');
    const { overview, details } = entry.item;
    // Files are bound to their item and its key, so the copy gets its own copies of them.
    const copy = await this.host.createItem(toVaultId, {
      overview: { ...withoutPin(overview), favorite: false },
      details: withAttachments(structuredClone(details), []),
    });
    return (await this.host.copyAttachments(itemId, copy.id)) ?? copy;
  }

  // ---------- Families ----------

  async getFamily(): Promise<FamilyState> {
    const me = this.host.accountId();
    const { family, invitations } = await this.host.api().families();
    if (!family) return { invitations };
    return {
      invitations,
      family: {
        id: family.id,
        vaultId: family.vaultId,
        organiserId: family.organiserId,
        isOrganiser: family.organiserId === me,
        maxMembers: family.maxMembers,
        members: family.members.map((m) => ({ ...m, isYou: m.accountId === me })),
        invites: family.invites,
        createdAt: family.createdAt,
      },
    };
  }

  async createFamily(): Promise<void> {
    const { session } = this.host.unlocked();
    const core = await this.host.core();
    const id = core.newId();
    const vault = session.createSharedVault();
    await createOnce(() => this.host.api().createFamily(id, vault));
    await this.host.sync();
    this.host.changed();
  }

  /** Invites carry a `write` grant for the Family vault, which turns into membership on accepting. */
  async inviteToFamily(account: AccountLookup): Promise<void> {
    await this.checkFingerprint(account);
    const family = await this.requireFamily();
    await this.sendGrant(family.vaultId, { ...account, role: 'write' }, (grant, keyId) =>
      this.host.api().inviteToFamily(family.id, account.email, grant, keyId),
    );
    this.host.changed();
  }

  async acceptFamilyInvite(familyId: string): Promise<void> {
    await this.host.api().acceptFamilyInvite(familyId);
    await this.host.sync();
    this.host.changed();
  }

  async declineFamilyInvite(familyId: string): Promise<void> {
    await this.host.api().deleteFamilyInvite(familyId, this.host.accountId());
    this.host.changed();
  }

  async cancelFamilyInvite(accountId: string): Promise<void> {
    const family = await this.requireFamily();
    await asNotAllowed(this.host.api().deleteFamilyInvite(family.id, accountId));
    this.host.changed();
  }

  async removeFamilyMember(accountId: string): Promise<void> {
    const family = await this.requireFamily();
    await asNotAllowed(this.host.api().removeFamilyMember(family.id, accountId));
    this.host.changed();
    await this.rotate(family.vaultId, await this.invitees(family.invites));
  }

  /**
   * Pending invites hold the Family vault key from before a rotation, which would open nothing, so
   * the rotation seals the new key to each invitee too. An invitee whose account is gone, or whose
   * keys no longer match the fingerprint this device verified, is left out: the server cancels
   * that invite.
   */
  private async invitees(invites: FamilyInvite[]): Promise<GrantRecipient[]> {
    const verified = await this.host.store.verified(this.host.accountId());
    const recipients: GrantRecipient[] = [];
    for (const invite of invites) {
      let account;
      try {
        account = await this.lookupAccount(invite.email);
      } catch (error) {
        if (isVaultError(error, 'accountNotFound')) continue;
        throw error;
      }
      if (account.accountId !== invite.accountId) continue;
      const digits = verified[account.accountId];
      if (digits && digits !== account.fingerprint.digits) continue;
      if (account.keyLog === 'failed') continue;
      const { accountId, publicEncKey, publicSignKey, keyRecord } = account;
      recipients.push({ accountId, publicEncKey, publicSignKey, ...(keyRecord ? { keyRecord } : {}), role: 'write' });
    }
    return recipients;
  }

  async leaveFamily(): Promise<void> {
    const family = await this.requireFamily();
    await this.host.api().removeFamilyMember(family.id, this.host.accountId());
    await this.host.sync();
    this.host.changed();
  }

  async deleteFamily(): Promise<void> {
    const family = await this.requireFamily();
    await asNotAllowed(this.host.api().deleteFamily(family.id));
    await this.host.sync();
    this.host.changed();
  }

  // ---------- Internals ----------

  /** The lookup's keys must be the ones whose fingerprint the user saw. */
  private async checkFingerprint(account: AccountLookup): Promise<void> {
    const actual = await this.fingerprint(account.publicEncKey, account.publicSignKey);
    if (actual.digits !== account.fingerprint.digits) throw new VaultError('untrustedVault');
  }

  /**
   * Seals the vault's current key: synced first, so a key rotated elsewhere isn't handed out. The
   * request names the key's id, so a rotation that lands before it arrives refuses it with
   * `vault-key-changed`; then it syncs and seals once more.
   */
  private async sendGrant(vaultId: string, recipient: GrantRecipient, send: (grant: SignedGrant, keyId?: string) => Promise<void>): Promise<void> {
    for (let attempt = 1; ; attempt++) {
      await this.host.sync();
      const { session, index } = this.host.unlocked();
      const vault = index.vault(vaultId);
      if (!vault) throw new VaultError('notFound');
      if (index.isUntrusted(vaultId)) throw new VaultError('untrustedVault');
      if (vault.role !== 'owner' && vault.role !== 'manage') throw new VaultError('notAllowed');
      if (recipient.role === 'owner' && vault.role !== 'owner') throw new VaultError('notAllowed');
      const { accountId, publicEncKey, publicSignKey, keyRecord, role } = recipient;
      const grant = session.grantVault(vaultId, { accountId, publicEncKey, publicSignKey, keyRecord, role });
      try {
        return await asNotAllowed(send(grant, vault.keyId));
      } catch (error) {
        if (!isProblem(error, 409, 'vault-key-changed') || attempt >= 2) throw error;
      }
    }
  }

  private async member(vaultId: string, accountId: string): Promise<MemberRecord> {
    const { members } = await this.host.api().members(vaultId);
    const member = members.find((m) => m.accountId === accountId);
    if (!member) throw new VaultError('notFound');
    return member;
  }

  private async requireFamily() {
    const { family } = await this.getFamily();
    if (!family) throw new VaultError('notFound');
    return family;
  }

  private async writeVaultName(vaultId: string, name: string): Promise<void> {
    const title = name.trim() || DEFAULT_VAULT_NAMES.shared;
    const existing = this.host.unlocked().index.vaultInfo(vaultId);
    // The core keeps unknown item types as they are, so other clients round-trip this record.
    const overview = { schemaVersion: 1, type: VAULT_INFO_TYPE, title } as unknown as Item['overview'];
    if (existing) await this.host.saveItem({ ...existing.item, overview: { ...existing.item.overview, title } });
    else await this.host.createItem(vaultId, { overview, details: VAULT_INFO_DETAILS });
  }
}
