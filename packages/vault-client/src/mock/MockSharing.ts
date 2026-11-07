// The mock's sharing features, for UI work and demos. The other people are pretend accounts
// (./identities.ts) that never act on their own; everything the user owns is kept inside their
// sealed vault data, and share links in a separate "server" record any visitor can fetch.

import { VaultError } from '../errors';
import { uuidv7 } from '../ids';
import { isValidEmail, normalizeEmail, shareableSnapshot, withAttachments, withoutPin } from '../items';
import { generateRecoveryCode, generateSecretKey } from '../secretKey';
import { base64UrlDecode, base64UrlEncode } from '../tools/encoding';
import type {
  AccountLookup,
  NewRecoveryKit,
  CreatedShareLink,
  Device,
  EmergencyAccessLevel,
  EmergencyContact,
  EmergencyContacts,
  EmergencyScope,
  EmergencyVaultView,
  FamilyInvite,
  FamilyMember,
  FamilyState,
  Fingerprint,
  KeyLogState,
  Item,
  SecurityEvent,
  SecurityEventType,
  ServiceAccount,
  ShareLinkEnvelope,
  ShareLinkInfo,
  ShareLinkOptions,
  SharedItem,
  SharingService,
  Vault,
  VaultMember,
  VaultRole,
} from '../types';
import type { KeyValueStore } from '../idb';
import { hasMockAccount, mockAccountId, mockFingerprint, mockLookup } from './identities';
import { derivePasswordKey, openJson, randomBytes, sealJson, toBase64, type Sealed } from './sealing';
import type { VaultData } from './seed';

/** Sharing state inside the sealed vault data. */
export interface MockSharingData {
  devices: Device[];
  family?: { id: string; vaultId: string; organiserId: string; createdAt: string; members: Omit<FamilyMember, 'isYou'>[]; invites: FamilyInvite[] };
  invitations: FamilyInvite[];
  emergency: EmergencyContacts;
  log: SecurityEvent[];
  serviceAccounts?: ServiceAccount[];
  /** Account id → fingerprint digits the user verified. */
  verified: Record<string, string>;
}

/** What the pretend server keeps for a share link: ciphertext, limits, and whose link it is. */
interface StoredLink {
  owner: string;
  itemId: string;
  ciphertext: string;
  passphraseRequired: boolean;
  expiresAt: string;
  maxViews: number;
  views: number;
  createdAt: string;
}

export interface MockSharingHost {
  store: KeyValueStore;
  /** The unlocked vault; throws `locked`. */
  vault(): VaultData;
  /** Changes the unlocked vault after a round trip, and saves it. */
  write<T>(change: (data: VaultData) => T): Promise<T>;
  network(scale?: number): Promise<void>;
  /** The signed-in account: email, and its server|email key. */
  account(): { email: string; key: string };
}

const LINKS_KEY = 'share-links';
const FAMILY_MAX = 6;
const DAY = 86_400_000;

export function emptySharing(): MockSharingData {
  return { devices: [], invitations: [], emergency: { granted: [], received: [] }, log: [], verified: {} };
}

const sharingOf = (data: VaultData) => (data.sharing ??= emptySharing());

export class MockSharing implements SharingService {
  private readonly listeners = new Set<() => void>();

  constructor(private readonly host: MockSharingHost) {}

  // ---------- Devices ----------

  async listDevices(): Promise<Device[]> {
    await this.host.network(0.5);
    return structuredClone(sharingOf(this.host.vault()).devices);
  }

  async renameDevice(name: string): Promise<void> {
    const trimmed = name.trim();
    if (!trimmed || trimmed.length > 64) throw new VaultError('serverError', 'A device name is 1 to 64 characters.');
    await this.host.write((data) => {
      const current = sharingOf(data).devices.find((d) => d.current);
      if (current) current.name = trimmed;
    });
  }

  async signOutDevice(deviceId: string): Promise<void> {
    await this.host.write((data) => {
      const sharing = sharingOf(data);
      if (!sharing.devices.some((d) => d.id === deviceId && !d.current)) throw new VaultError('notFound');
      sharing.devices = sharing.devices.filter((d) => d.id !== deviceId);
    });
  }

  // ---------- Identity ----------

  async getMyFingerprint(): Promise<Fingerprint> {
    this.host.vault();
    return mockFingerprint(this.host.account().email);
  }

  async lookupAccount(email: string): Promise<AccountLookup> {
    this.host.vault();
    const normalized = normalizeEmail(email);
    await this.host.network(0.5);
    if (!isValidEmail(normalized)) throw new VaultError('invalidEmail');
    if (!hasMockAccount(normalized)) throw new VaultError('accountNotFound');
    return mockLookup(normalized);
  }

  async getKeyLogState(): Promise<KeyLogState> {
    return { published: true };
  }

  async dismissKeyLogAlert(): Promise<void> {}

  async markVerified(account: Pick<AccountLookup, 'accountId' | 'fingerprint'>): Promise<void> {
    await this.host.write((data) => void (sharingOf(data).verified[account.accountId] = account.fingerprint.digits));
    this.emit();
  }

  // ---------- Shared vaults ----------

  async createVault(name: string): Promise<Vault> {
    const { email } = this.host.account();
    const vault: Vault = { id: uuidv7(), name: name.trim() || 'Shared vault', type: 'shared', role: 'owner', members: [{ name: 'You', email, role: 'owner' }] };
    await this.host.write((data) => void data.vaults.push(vault));
    this.emit();
    return structuredClone(vault);
  }

  async renameVault(vaultId: string, name: string): Promise<void> {
    await this.host.write((data) => {
      const vault = this.writable(data, vaultId);
      vault.name = name.trim() || vault.name;
    });
  }

  async listMembers(vaultId: string): Promise<VaultMember[]> {
    const data = this.host.vault();
    const vault = data.vaults.find((v) => v.id === vaultId);
    if (!vault) throw new VaultError('notFound');
    await this.host.network(0.5);
    const { email: me } = this.host.account();
    const verified = sharingOf(data).verified;
    return Promise.all(
      (vault.members ?? []).map(async (m) => {
        const accountId = await mockAccountId(m.email);
        const fingerprint = await mockFingerprint(m.email);
        const isYou = m.email === me;
        return { ...m, accountId, fingerprint, isYou, verified: isYou || verified[accountId] === fingerprint.digits };
      }),
    );
  }

  async addMember(vaultId: string, account: AccountLookup, role: VaultRole): Promise<void> {
    await this.host.write((data) => {
      const vault = this.managed(data, vaultId, role);
      const members = (vault.members ??= []);
      const existing = members.find((m) => m.email === account.email);
      if (existing) existing.role = role;
      else members.push({ name: account.email, email: account.email, role });
    });
    this.emit();
  }

  async changeRole(vaultId: string, accountId: string, role: VaultRole): Promise<void> {
    const email = await this.memberEmail(vaultId, accountId);
    await this.host.write((data) => {
      const member = this.managed(data, vaultId, role).members!.find((m) => m.email === email)!;
      member.role = role;
    });
    this.emit();
  }

  /** The real service also rotates the vault key here; the mock has none to rotate. */
  async removeMember(vaultId: string, accountId: string): Promise<void> {
    const email = await this.memberEmail(vaultId, accountId);
    if (email === this.host.account().email) return this.leaveVault(vaultId);
    await this.host.write((data) => {
      const vault = this.managed(data, vaultId, 'write');
      vault.members = vault.members!.filter((m) => m.email !== email);
    });
    this.emit();
  }

  async leaveVault(vaultId: string): Promise<void> {
    await this.host.write((data) => {
      const vault = data.vaults.find((v) => v.id === vaultId);
      if (!vault || vault.type === 'personal') throw new VaultError('notFound');
      const owners = vault.members?.filter((m) => m.role === 'owner') ?? [];
      if (vault.role === 'owner' && owners.length <= 1) throw new VaultError('notAllowed');
      dropVault(data, vaultId);
    });
    this.emit();
  }

  async moveItem(itemId: string, toVaultId: string): Promise<Item> {
    return this.host.write((data) => {
      const original = findItem(data, itemId);
      this.writable(data, original.vaultId);
      const copy = copyInto(data, this.writable(data, toVaultId), original);
      data.items[data.items.indexOf(original)] = { ...original, deletedAt: new Date().toISOString(), revision: original.revision + 1 };
      return structuredClone(copy);
    });
  }

  async copyItem(itemId: string, toVaultId: string): Promise<Item> {
    return this.host.write((data) => structuredClone(copyInto(data, this.writable(data, toVaultId), findItem(data, itemId))));
  }

  // ---------- Families ----------

  /** The mock has no keys to rotate. */
  async rotateVaultKey(vaultId: string): Promise<void> {
    await this.host.network(1);
    if (!this.host.vault().vaults.some((v) => v.id === vaultId)) throw new VaultError('notFound');
    this.emit();
  }

  async getFamily(): Promise<FamilyState> {
    const sharing = sharingOf(this.host.vault());
    await this.host.network(0.5);
    const { email } = this.host.account();
    const { family } = sharing;
    if (!family) return { invitations: structuredClone(sharing.invitations) };
    const isOrganiser = isOrganisedBy(family, email);
    return {
      invitations: [],
      family: {
        ...structuredClone(family),
        isOrganiser,
        maxMembers: FAMILY_MAX,
        members: family.members.map((m) => ({ ...m, isYou: m.email === email })),
        invites: isOrganiser ? structuredClone(family.invites) : [],
      },
    };
  }

  async createFamily(): Promise<void> {
    const { email } = this.host.account();
    const me = await mockAccountId(email);
    await this.host.write((data) => {
      const sharing = sharingOf(data);
      if (sharing.family) throw new VaultError('alreadyExists');
      const vault: Vault = { id: uuidv7(), name: 'Family', type: 'family', role: 'owner', members: [{ name: 'You', email, role: 'owner' }] };
      data.vaults.push(vault);
      const now = new Date().toISOString();
      sharing.family = { id: uuidv7(), vaultId: vault.id, organiserId: me, createdAt: now, members: [{ accountId: me, email, role: 'organiser', joinedAt: now }], invites: [] };
    });
    this.emit();
  }

  async inviteToFamily(account: AccountLookup): Promise<void> {
    const { email } = this.host.account();
    await this.host.write((data) => {
      const family = this.organised(data);
      if (family.members.length + family.invites.length >= FAMILY_MAX) throw new VaultError('familyFull');
      if (family.members.some((m) => m.accountId === account.accountId) || family.invites.some((i) => i.accountId === account.accountId)) return;
      family.invites.push({ familyId: family.id, accountId: account.accountId, email: account.email, organiserEmail: email, invitedAt: new Date().toISOString() });
    });
    this.emit();
  }

  async acceptFamilyInvite(familyId: string): Promise<void> {
    const { email } = this.host.account();
    const me = await mockAccountId(email);
    await this.host.write((data) => {
      const sharing = sharingOf(data);
      const invite = sharing.invitations.find((i) => i.familyId === familyId);
      if (!invite) throw new VaultError('notFound');
      if (sharing.family) throw new VaultError('alreadyExists');
      const organiserId = `acct-organiser-${familyId}`;
      const vault: Vault = {
        id: uuidv7(),
        name: 'Family',
        type: 'family',
        role: 'write',
        members: [
          { name: invite.organiserEmail, email: invite.organiserEmail, role: 'owner' },
          { name: 'You', email, role: 'write' },
        ],
      };
      data.vaults.push(vault);
      const now = new Date().toISOString();
      sharing.family = {
        id: familyId,
        vaultId: vault.id,
        organiserId,
        createdAt: invite.invitedAt,
        members: [
          { accountId: organiserId, email: invite.organiserEmail, role: 'organiser', joinedAt: invite.invitedAt },
          { accountId: me, email, role: 'member', joinedAt: now },
        ],
        invites: [],
      };
      sharing.invitations = sharing.invitations.filter((i) => i !== invite);
    });
    this.emit();
  }

  async declineFamilyInvite(familyId: string): Promise<void> {
    await this.host.write((data) => {
      const sharing = sharingOf(data);
      sharing.invitations = sharing.invitations.filter((i) => i.familyId !== familyId);
    });
    this.emit();
  }

  async cancelFamilyInvite(accountId: string): Promise<void> {
    await this.host.write((data) => {
      const family = this.organised(data);
      family.invites = family.invites.filter((i) => i.accountId !== accountId);
    });
    this.emit();
  }

  async removeFamilyMember(accountId: string): Promise<void> {
    await this.host.write((data) => {
      const family = this.organised(data);
      const member = family.members.find((m) => m.accountId === accountId && m.role !== 'organiser');
      if (!member) throw new VaultError('notFound');
      family.members = family.members.filter((m) => m !== member);
      const vault = data.vaults.find((v) => v.id === family.vaultId);
      if (vault) vault.members = vault.members?.filter((m) => m.email !== member.email);
    });
    this.emit();
  }

  async leaveFamily(): Promise<void> {
    await this.host.write((data) => {
      const sharing = sharingOf(data);
      if (!sharing.family) throw new VaultError('notFound');
      if (isOrganisedBy(sharing.family, this.host.account().email)) throw new VaultError('notAllowed');
      dropVault(data, sharing.family.vaultId);
      delete sharing.family;
    });
    this.emit();
  }

  async deleteFamily(): Promise<void> {
    await this.host.write((data) => {
      const family = this.organised(data);
      dropVault(data, family.vaultId);
      delete sharingOf(data).family;
    });
    this.emit();
  }

  // ---------- Share links ----------

  async createShareLink(itemId: string, options: ShareLinkOptions): Promise<CreatedShareLink> {
    const { expiresInHours, maxViews, passphrase } = options;
    if (!(expiresInHours >= 1 && expiresInHours <= 720) || !Number.isInteger(maxViews) || maxViews < 1 || maxViews > 100) {
      throw new VaultError('serverError', 'Share links last 1 hour to 30 days and allow 1 to 100 views.');
    }
    const item = findItem(this.host.vault(), itemId);
    if (item.deletedAt) throw new VaultError('notFound');
    const key = base64UrlEncode(randomBytes(32));
    const salt = toBase64(randomBytes(16));
    const sealed = await sealJson(await derivePasswordKey(passphrase ?? '', key, salt), shareableSnapshot(item), 'share-link');
    const ciphertext = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ v: 1, passphraseRequired: Boolean(passphrase), salt, sealed })));
    await this.host.network();
    const id = base64UrlEncode(randomBytes(16));
    const now = Date.now();
    const link: StoredLink = {
      owner: this.host.account().key,
      itemId,
      ciphertext,
      passphraseRequired: Boolean(passphrase),
      expiresAt: new Date(now + expiresInHours * 3_600_000).toISOString(),
      maxViews,
      views: 0,
      createdAt: new Date(now).toISOString(),
    };
    await this.saveLinks({ ...(await this.links()), [id]: link });
    this.emit();
    return { id, key, expiresAt: link.expiresAt };
  }

  async listShareLinks(): Promise<ShareLinkInfo[]> {
    const data = this.host.vault();
    const { key } = this.host.account();
    await this.host.network(0.5);
    return Object.entries(await this.links())
      .filter(([, link]) => link.owner === key)
      .map(([id, link]) => {
        const item = data.items.find((i) => i.id === link.itemId && !i.deletedAt);
        const info: ShareLinkInfo = { id, expiresAt: link.expiresAt, maxViews: link.maxViews, views: link.views, passphraseRequired: link.passphraseRequired, createdAt: link.createdAt };
        return item ? { ...info, itemId: item.id, itemTitle: item.overview.title } : info;
      })
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async revokeShareLink(id: string): Promise<void> {
    this.host.vault();
    await this.host.network();
    const { [id]: _gone, ...rest } = await this.links();
    await this.saveLinks(rest);
    this.emit();
  }

  async fetchShareLink(_serverUrl: string, id: string): Promise<ShareLinkEnvelope> {
    await this.host.network();
    const links = await this.links();
    const link = links[id];
    if (!link) throw new VaultError('notFound');
    link.views++;
    const viewsLeft = link.maxViews - link.views;
    if (viewsLeft <= 0) delete links[id];
    await this.saveLinks(links);
    this.emit();
    return { ciphertext: link.ciphertext, passphraseRequired: link.passphraseRequired, expiresAt: link.expiresAt, viewsLeft };
  }

  async openShareLink(ciphertext: string, key: string, passphrase?: string): Promise<SharedItem> {
    let envelope: { passphraseRequired: boolean; salt: string; sealed: Sealed };
    try {
      envelope = JSON.parse(new TextDecoder().decode(base64UrlDecode(ciphertext)));
    } catch {
      throw new VaultError('invalidShareLink');
    }
    if (envelope.passphraseRequired && !passphrase) throw new VaultError('wrongPassphrase');
    try {
      return await openJson<SharedItem>(await derivePasswordKey(envelope.passphraseRequired ? passphrase! : '', key, envelope.salt), envelope.sealed, 'share-link');
    } catch {
      throw new VaultError(envelope.passphraseRequired ? 'wrongPassphrase' : 'invalidShareLink');
    }
  }

  // ---------- Emergency access ----------

  async listEmergencyContacts(): Promise<EmergencyContacts> {
    this.host.vault();
    await this.host.network(0.5);
    // The server releases a waiting request once its time is up; the mock does so when asked.
    const now = new Date().toISOString();
    const due = (c: EmergencyContact) => c.status === 'requested' && c.releasesAt! <= now;
    const { emergency } = sharingOf(this.host.vault());
    if ([...emergency.granted, ...emergency.received].some(due)) {
      await this.host.write((data) => {
        const sharing = sharingOf(data);
        for (const contact of [...sharing.emergency.granted, ...sharing.emergency.received].filter(due)) {
          Object.assign(contact, { status: 'released', releasedAt: contact.releasesAt });
          if (sharing.emergency.granted.includes(contact)) log(sharing, 'emergency-access-released', contact.contactEmail, contact.id);
        }
      });
    }
    return structuredClone(sharingOf(this.host.vault()).emergency);
  }

  async addEmergencyContact(input: { account: AccountLookup; waitDays: number; accessLevel: EmergencyAccessLevel; scope: EmergencyScope }): Promise<EmergencyContact> {
    const { account, waitDays, accessLevel, scope } = input;
    if (!Number.isInteger(waitDays) || waitDays < 1 || waitDays > 30) throw new VaultError('serverError', 'The waiting period is 1 to 30 days.');
    const { email } = this.host.account();
    const me = await mockAccountId(email);
    const contact = await this.host.write((data) => {
      const sharing = sharingOf(data);
      if (sharing.emergency.granted.some((c) => c.contactId === account.accountId)) throw new VaultError('alreadyExists');
      if (scope.type === 'vault' && data.vaults.find((v) => v.id === scope.vaultId)?.role !== 'owner') throw new VaultError('notAllowed');
      if (scope.type === 'vault' && accessLevel === 'takeover') throw new VaultError('notAllowed');
      const created: EmergencyContact = {
        id: uuidv7(),
        grantorId: me,
        grantorEmail: email,
        contactId: account.accountId,
        contactEmail: account.email,
        scope,
        accessLevel,
        waitDays,
        status: 'idle',
        createdAt: new Date().toISOString(),
      };
      sharing.emergency.granted.push(created);
      log(sharing, 'emergency-contact-added', account.email, created.id);
      return created;
    });
    this.emit();
    return structuredClone(contact);
  }

  async removeEmergencyContact(id: string): Promise<void> {
    await this.host.write((data) => {
      const sharing = sharingOf(data);
      const granted = sharing.emergency.granted.find((c) => c.id === id);
      if (granted) log(sharing, granted.organiserRecovery ? 'organiser-recovery-disabled' : 'emergency-contact-removed', granted.contactEmail, id);
      sharing.emergency.granted = sharing.emergency.granted.filter((c) => c.id !== id);
      sharing.emergency.received = sharing.emergency.received.filter((c) => c.id !== id);
    });
    this.emit();
  }

  async requestEmergencyAccess(id: string): Promise<void> {
    await this.updateContact('received', id, (contact, now) => {
      if (contact.status !== 'idle') return;
      Object.assign(contact, { status: 'requested', requestedAt: now.toISOString(), releasesAt: new Date(now.getTime() + contact.waitDays * DAY).toISOString() });
    });
  }

  async denyEmergencyAccess(id: string): Promise<void> {
    // Denying also takes back access that was already released.
    await this.updateContact('granted', id, (contact, _now, sharing) => {
      delete contact.requestedAt;
      delete contact.releasesAt;
      delete contact.releasedAt;
      contact.status = 'idle';
      log(sharing, 'emergency-access-denied', contact.contactEmail, id);
    });
  }

  async approveEmergencyAccess(id: string): Promise<void> {
    await this.updateContact('granted', id, (contact, now, sharing) => {
      if (contact.status !== 'requested') throw new VaultError('notAllowed');
      Object.assign(contact, { status: 'released', releasedAt: now.toISOString() });
      log(sharing, 'emergency-access-approved', contact.contactEmail, id);
      log(sharing, 'emergency-access-released', contact.contactEmail, id);
    });
  }

  async openEmergencyAccess(id: string): Promise<EmergencyVaultView> {
    const contact = sharingOf(this.host.vault()).emergency.received.find((c) => c.id === id);
    if (!contact) throw new VaultError('notFound');
    if (contact.status !== 'released') throw new VaultError('notAllowed');
    await this.host.network();
    const vault: Vault = { id: `emergency-${id}`, name: 'Personal', type: 'personal', role: 'read' };
    return { contact: structuredClone(contact), vaults: [vault], items: grantorItems(contact.grantorEmail, vault.id) };
  }

  async getEmergencyAttachment(id: string, _itemId: string, attachmentId: string): Promise<Blob> {
    const contact = sharingOf(this.host.vault()).emergency.received.find((c) => c.id === id);
    if (!contact) throw new VaultError('notFound');
    if (contact.status !== 'released') throw new VaultError('notAllowed');
    if (attachmentId !== STATEMENT.id) throw new VaultError('notFound');
    await this.host.network();
    return new Blob(['Pension statement\nPolicy number: PX-4471-0932\n'], { type: STATEMENT.type });
  }

  /** Renewing only clears the mark here: the mock has no sealed keys. */
  async renewEmergencyKey(id: string, account: AccountLookup): Promise<void> {
    await this.updateContact('granted', id, (contact) => {
      if (contact.contactId !== account.accountId) throw new VaultError('notAllowed');
      delete contact.keyStale;
    });
  }

  async takeOverAccount(id: string, input: { contactPassword: string; newPassword: string }): Promise<NewRecoveryKit> {
    if (!input.contactPassword) throw new VaultError('invalidCredentials');
    const recoveryCode = generateRecoveryCode();
    const secretKey = generateSecretKey();
    const taken = await this.host.write((data) => {
      const sharing = sharingOf(data);
      const contact = sharing.emergency.received.find((c) => c.id === id);
      if (!contact) throw new VaultError('notFound');
      if (contact.status !== 'released' || contact.accessLevel !== 'takeover' || contact.scope.type !== 'account') throw new VaultError('notAllowed');
      sharing.emergency.received = sharing.emergency.received.filter((c) => c.id !== id);
      return contact;
    });
    this.emit();
    return { email: taken.grantorEmail, serverUrl: 'https://mock.octapass.invalid', secretKey, recoveryCode, createdAt: new Date().toISOString() };
  }

  async enableOrganiserRecovery(input: { account: AccountLookup; waitDays: number }): Promise<EmergencyContact> {
    const { account, waitDays } = input;
    const { family } = sharingOf(this.host.vault());
    if (!family || family.organiserId !== account.accountId) throw new VaultError('notAllowed');
    const { email } = this.host.account();
    const me = await mockAccountId(email);
    const record = await this.host.write((data) => {
      const sharing = sharingOf(data);
      if (sharing.emergency.granted.some((c) => c.contactId === account.accountId)) throw new VaultError('alreadyExists');
      const created: EmergencyContact = {
        id: uuidv7(),
        grantorId: me,
        grantorEmail: email,
        contactId: account.accountId,
        contactEmail: account.email,
        scope: { type: 'account' },
        accessLevel: 'takeover',
        waitDays,
        status: 'idle',
        createdAt: new Date().toISOString(),
        organiserRecovery: true,
      };
      sharing.emergency.granted.push(created);
      log(sharing, 'organiser-recovery-enabled', account.email, created.id);
      return created;
    });
    this.emit();
    return structuredClone(record);
  }

  // ---------- Security log ----------

  async listServiceAccounts(vaultId: string): Promise<ServiceAccount[]> {
    await this.host.network(0.5);
    return structuredClone(sharingOf(this.host.vault()).serviceAccounts ?? []).filter((s) => s.vaultId === vaultId);
  }

  async createServiceAccount(vaultId: string, input: { name: string; role: 'read' | 'write'; expiresAt?: string }): Promise<{ account: ServiceAccount; token: string }> {
    const account: ServiceAccount = { id: crypto.randomUUID(), vaultId, name: input.name.trim(), role: input.role, createdAt: new Date().toISOString(), needsNewToken: false, ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}) };
    await this.host.write((data) => {
      const sharing = sharingOf(data);
      (sharing.serviceAccounts ??= []).push(account);
      sharing.log.push({ type: 'service-account-created', createdAt: account.createdAt, serviceAccountId: account.id });
    });
    this.emit();
    return { account: structuredClone(account), token: `opsa1_mock-${account.id}` };
  }

  async revokeServiceAccount(_vaultId: string, id: string): Promise<void> {
    await this.host.write((data) => {
      const sharing = sharingOf(data);
      const account = sharing.serviceAccounts?.find((s) => s.id === id);
      if (!account) throw new VaultError('notFound');
      account.revokedAt = new Date().toISOString();
      sharing.log.push({ type: 'service-account-revoked', createdAt: account.revokedAt, serviceAccountId: id });
    });
    this.emit();
  }

  async getSecurityLog(): Promise<SecurityEvent[]> {
    const { log: events } = sharingOf(this.host.vault());
    await this.host.network(0.5);
    return structuredClone(events).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  onSharingChange(cb: () => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  // ---------- Internals ----------

  emit(): void {
    for (const cb of this.listeners) cb();
  }

  private async links(): Promise<Record<string, StoredLink>> {
    const links = (await this.host.store.get<Record<string, StoredLink>>(LINKS_KEY)) ?? {};
    const now = new Date().toISOString();
    return Object.fromEntries(Object.entries(links).filter(([, link]) => link.expiresAt > now));
  }

  private saveLinks(links: Record<string, StoredLink>): Promise<void> {
    return this.host.store.set(LINKS_KEY, links);
  }

  private writable(data: VaultData, vaultId: string): Vault {
    const vault = data.vaults.find((v) => v.id === vaultId);
    if (!vault) throw new VaultError('notFound');
    if (vault.role === 'read') throw new VaultError('readOnlyVault');
    return vault;
  }

  /** Managers add and remove members; only owners hand out or take away `owner`. */
  private managed(data: VaultData, vaultId: string, role: VaultRole): Vault {
    const vault = data.vaults.find((v) => v.id === vaultId);
    if (!vault || vault.type === 'personal') throw new VaultError('notFound');
    if (vault.role !== 'owner' && (vault.role !== 'manage' || role === 'owner')) throw new VaultError('notAllowed');
    return vault;
  }

  private organised(data: VaultData) {
    const family = sharingOf(data).family;
    if (!family) throw new VaultError('notFound');
    if (!isOrganisedBy(family, this.host.account().email)) throw new VaultError('notAllowed');
    return family;
  }

  private async memberEmail(vaultId: string, accountId: string): Promise<string> {
    const member = (await this.listMembers(vaultId)).find((m) => m.accountId === accountId);
    if (!member) throw new VaultError('notFound');
    return member.email;
  }

  private async updateContact(side: keyof EmergencyContacts, id: string, change: (contact: EmergencyContact, now: Date, sharing: MockSharingData) => void): Promise<void> {
    await this.host.write((data) => {
      const sharing = sharingOf(data);
      const contact = sharing.emergency[side].find((c) => c.id === id);
      if (!contact) throw new VaultError(side === 'granted' ? 'notAllowed' : 'notFound');
      change(contact, new Date(), sharing);
    });
    this.emit();
  }
}

function isOrganisedBy(family: NonNullable<MockSharingData['family']>, email: string): boolean {
  return family.members.some((m) => m.role === 'organiser' && m.email === email);
}

function findItem(data: VaultData, id: string): Item {
  const item = data.items.find((i) => i.id === id);
  if (!item) throw new VaultError('notFound');
  return item;
}

function copyInto(data: VaultData, vault: Vault, item: Item): Item {
  const at = new Date().toISOString();
  // The demo doesn't copy files: the copy leaves them out, as a real copy does until it re-uploads them.
  const details = withAttachments(structuredClone(item.details), []);
  const copy: Item = { id: uuidv7(), vaultId: vault.id, revision: 1, createdAt: at, updatedAt: at, overview: { ...withoutPin(item.overview), favorite: false }, details };
  data.items.push(copy);
  return copy;
}

function dropVault(data: VaultData, vaultId: string): void {
  data.vaults = data.vaults.filter((v) => v.id !== vaultId);
  data.items = data.items.filter((i) => i.vaultId !== vaultId);
}

function log(sharing: MockSharingData, type: SecurityEventType, otherAccountEmail: string, emergencyContactId: string): void {
  sharing.log.push({ type, createdAt: new Date().toISOString(), otherAccountEmail, emergencyContactId });
}

/** What a released emergency contact sees of a pretend grantor. */
/** The one file among the grantor's items. */
const STATEMENT = { id: 'emergency-statement', name: 'Pension statement.txt', type: 'text/plain', size: 46, key: '' } as const;

function grantorItems(email: string, vaultId: string): Item[] {
  const at = new Date(Date.now() - 30 * DAY).toISOString();
  const item = (title: string, overview: Partial<Item['overview']>, details: Record<string, unknown>): Item => ({
    id: uuidv7(),
    vaultId,
    revision: 1,
    createdAt: at,
    updatedAt: at,
    overview: { schemaVersion: 1, title, type: 'login', ...overview },
    details: { schemaVersion: 1, ...details } as Item['details'],
  });
  return [
    item('Northwind Bank', { subtitle: email, urls: ['https://online.northwind-bank.example'] }, { username: email, password: 'heron-ledger-2290' }),
    item('Pension', { type: 'secureNote', subtitle: 'Policy details' }, { notes: 'Policy number: PX-4471-0932\nAdviser: 0131 496 0555', attachments: [{ ...STATEMENT }] }),
    item('Home insurance', { subtitle: email, urls: ['https://insure.example'] }, { username: email, password: 'quartz-anchor-81' }),
  ];
}
