// Emergency access (plan 06; docs/developers/sync-api.md, "Emergency access"). The grantor seals
// their account key, or one vault's key, to a trusted contact. The server hands it over only after
// a waiting period the grantor didn't cut short with a denial.

import type * as CoreModule from '@octapass/core';
import type { Session } from '@octapass/core';
import { VaultError } from '../errors';
import { attachmentsOf } from '../items';
import type { AccountLookup, EmergencyAccessLevel, EmergencyContact, EmergencyContacts, EmergencyScope, EmergencyVaultView, Item, ItemDetails, ItemOverview, NewRecoveryKit } from '../types';
import type { Api, ItemRecord, ReauthPurpose, SyncResponse } from './api';
import { decryptAttachment } from './attachments';
import { asNotAllowed } from './errors';
import { isProblem } from './sharing';
import { DEFAULT_VAULT_NAMES, isVaultInfo, toItem, VaultIndex } from './vaultIndex';

export type EmergencyCore = Pick<typeof CoreModule, 'keyFingerprint'>;

export interface EmergencyHost {
  core(): Promise<EmergencyCore>;
  session(): Session;
  api(): Api;
  changed(): void;
  sync(): Promise<void>;
  /** A fresh proof of this account's own master password. */
  reauth(password: string, purpose: ReauthPurpose): Promise<string>;
  serverUrl(): string;
  now(): number;
}

export const WAIT_DAYS = { min: 1, max: 30 } as const;
const MAX_PAGES = 1000;

function checkWaitDays(waitDays: number): void {
  if (!Number.isInteger(waitDays) || waitDays < WAIT_DAYS.min || waitDays > WAIT_DAYS.max) throw new VaultError('serverError', 'The waiting period is 1 to 30 days.');
}

export class EmergencyAccess {
  /** What each released contact last opened, to find files in. */
  private readonly opened = new Map<string, SyncResponse>();

  constructor(private readonly host: EmergencyHost) {}

  list(): Promise<EmergencyContacts> {
    return this.host.api().emergencyContacts();
  }

  async add(input: { account: AccountLookup; waitDays: number; accessLevel: EmergencyAccessLevel; scope: EmergencyScope }): Promise<EmergencyContact> {
    const { account, waitDays, accessLevel, scope } = input;
    checkWaitDays(waitDays);
    await this.checkFingerprint(account);
    const sealedKey = this.host.session().sealForEmergencyContact(account.accountId, account.publicEncKey, scope, account.publicSignKey, account.keyRecord);
    const contact = await this.host.api().addEmergencyContact({ contactAccountId: account.accountId, sealedKey, scope, accessLevel, waitDays });
    this.host.changed();
    return contact;
  }

  async remove(id: string): Promise<void> {
    await this.host.api().removeEmergencyContact(id);
    this.host.changed();
  }

  /**
   * After a rotation, the contact's sealed copy is of the old key. Sealing to whichever key the
   * server names, by itself, would let a server collect the vault key, so this only runs for a
   * lookup whose fingerprint the user saw.
   */
  async renew(id: string, account: AccountLookup): Promise<void> {
    await this.checkFingerprint(account);
    const { granted } = await this.host.api().emergencyContacts();
    const contact = granted.find((c) => c.id === id);
    if (!contact) throw new VaultError('notFound');
    if (contact.scope.type !== 'vault' || contact.contactId !== account.accountId) throw new VaultError('notAllowed');
    for (let attempt = 1; ; attempt++) {
      await this.host.sync();
      const session = this.host.session();
      const sealedKey = session.sealForEmergencyContact(account.accountId, account.publicEncKey, contact.scope, account.publicSignKey, account.keyRecord);
      try {
        await asNotAllowed(this.host.api().renewEmergencyKey(id, { sealedKey, keyId: session.vaultKeyId(contact.scope.vaultId) }));
        break;
      } catch (error) {
        if (!isProblem(error, 409, 'vault-key-changed') || attempt >= 2) throw error;
      }
    }
    this.host.changed();
  }

  /** As a family member: seals the account key to the organiser, whose fingerprint the user saw. */
  async enableOrganiserRecovery(input: { account: AccountLookup; waitDays: number }): Promise<EmergencyContact> {
    const { account, waitDays } = input;
    checkWaitDays(waitDays);
    await this.checkFingerprint(account);
    const { family } = await this.host.api().families();
    if (!family) throw new VaultError('notFound');
    if (family.organiserId !== account.accountId) throw new VaultError('notAllowed');
    const sealedKey = this.host.session().sealForEmergencyContact(account.accountId, account.publicEncKey, { type: 'account' }, account.publicSignKey, account.keyRecord);
    const record = await asNotAllowed(this.host.api().enableOrganiserRecovery(family.id, { sealedKey, waitDays }));
    this.host.changed();
    return record;
  }

  /**
   * As the contact of a released takeover record (plan 06, "Takeover design"): opens the grantor's
   * account key, makes new credentials under it and sends them, signed by the grantor's key.
   */
  async takeOver(id: string, input: { contactPassword: string; newPassword: string }): Promise<NewRecoveryKit> {
    const api = this.host.api();
    const reauthToken = await this.host.reauth(input.contactPassword, 'emergency-takeover');
    const { contact, sealedKey, grantor } = await asNotAllowed(api.emergencyRelease(id));
    if (!grantor) throw new VaultError('notAllowed');
    const session = this.host.session().openEmergencyAccount(grantor, sealedKey);
    try {
      const change = session.newCredentials(input.newPassword, undefined, true);
      try {
        const { registrationResponse } = await asNotAllowed(api.takeoverRegistration(id, change.registrationRequest));
        const body = change.finish(registrationResponse);
        const signature = session.signTakeover(id, contact.contactId, body.registrationUpload, body.account);
        try {
          await asNotAllowed(api.emergencyTakeover(id, reauthToken, { ...body, signature }));
        } catch (error) {
          // A takeover whose answer got lost must not lose the only copy of the new kit: the
          // record is gone once it landed.
          const { received } = await api.emergencyContacts().catch(() => ({ received: [contact] }));
          if (error instanceof VaultError || received.some((c) => c.id === id)) throw error;
        }
        this.host.changed();
        return { email: grantor.email, serverUrl: this.host.serverUrl(), secretKey: change.secretKey, recoveryCode: change.recoveryCode, createdAt: new Date(this.host.now()).toISOString() };
      } finally {
        change.free();
      }
    } finally {
      session.free();
    }
  }

  async act(id: string, action: 'request' | 'deny' | 'approve'): Promise<void> {
    await asNotAllowed(this.host.api().emergencyAction(id, action));
    this.host.changed();
  }

  /**
   * As the contact, once released. With the account key, the grantor's own session opens their
   * vaults as they would; with one vault's key, that vault opens in this account's session.
   */
  async open(id: string): Promise<EmergencyVaultView> {
    const api = this.host.api();
    const release = await asNotAllowed(api.emergencyRelease(id));
    const sync = await this.syncAll(id);
    this.opened.set(id, sync);
    const { contact, sealedKey, grantor } = release;
    if (contact.scope.type === 'account') {
      if (!grantor) throw new VaultError('serverError');
      const session = this.host.session().openEmergencyAccount(grantor, sealedKey);
      try {
        const index = new VaultIndex(session, contact.grantorId);
        index.apply(sync, true);
        const vaults = index.vaults().map((v) => ({ id: v.id, name: index.vaultName(v), type: v.type, role: 'read' as const }));
        return { contact, vaults, items: structuredClone(index.items().filter((item) => !item.deletedAt)) };
      } finally {
        session.free();
      }
    }
    const { vaultId } = contact.scope;
    const session = this.host.session();
    session.openEmergencyVault(contact.grantorId, vaultId, sealedKey);
    const vault = sync.vaults.find((v) => v.id === vaultId);
    if (!vault) throw new VaultError('notFound');
    const items: Item[] = [];
    let name: string | undefined;
    for (const record of sync.items.filter((r) => r.vaultId === vaultId && !r.deletedAt)) {
      const item = decrypt(session, record);
      if (!item) continue;
      if (isVaultInfo(item)) name ??= item.overview.title;
      else items.push(item);
    }
    return { contact, vaults: [{ id: vaultId, name: name || DEFAULT_VAULT_NAMES[vault.type], type: vault.type, role: 'read' }], items };
  }

  /**
   * As the contact, once released: one of the grantor's files from an item `open` showed,
   * downloaded and decrypted here. Checks the release again, so a denial or removal stops it.
   */
  async attachment(id: string, itemId: string, attachmentId: string): Promise<Blob> {
    const api = this.host.api();
    const { contact, sealedKey, grantor } = await asNotAllowed(api.emergencyRelease(id));
    let sync = this.opened.get(id);
    if (!sync?.items.some((record) => record.id === itemId)) {
      sync = await this.syncAll(id);
      this.opened.set(id, sync);
    }

    let session: Session;
    let found: { record: ItemRecord; item: Item | undefined } | undefined;
    if (contact.scope.type === 'account') {
      if (!grantor) throw new VaultError('serverError');
      session = this.host.session().openEmergencyAccount(grantor, sealedKey);
      const index = new VaultIndex(session, contact.grantorId);
      index.apply(sync, true);
      found = index.get(itemId);
    } else {
      session = this.host.session();
      const { vaultId } = contact.scope;
      const record = sync.items.find((r) => r.id === itemId && r.vaultId === vaultId);
      if (record) {
        session.openEmergencyVault(contact.grantorId, record.vaultId, sealedKey);
        found = { record, item: decrypt(session, record) };
      }
    }
    try {
      const attachment = found?.item && attachmentsOf(found.item).find((a) => a.id === attachmentId);
      if (!found || found.record.deletedAt || !attachment) throw new VaultError('notFound');
      const { vaultId, encryptedItemKey } = found.record;
      const response = await api.emergencyAttachment(id, vaultId, itemId, attachmentId);
      return await decryptAttachment(session, { vaultId, itemId, encryptedItemKey }, attachment, response);
    } finally {
      if (session !== this.host.session()) session.free();
    }
  }

  /** The lookup's keys must be the ones whose fingerprint the user saw. */
  private async checkFingerprint(account: AccountLookup): Promise<void> {
    const fingerprint = (await this.host.core()).keyFingerprint(account.publicEncKey, account.publicSignKey);
    if (fingerprint.digits !== account.fingerprint.digits) throw new VaultError('untrustedVault');
    // Before sealing anything to them: their keys must not contradict the key log (plan 03).
    if (account.keyLog === 'failed') throw new VaultError('keyLogMismatch');
  }

  private async syncAll(id: string): Promise<SyncResponse> {
    const merged: SyncResponse = { vaults: [], items: [], deleted: [] };
    let since: { id: string; revision: number }[] = [];
    for (let page = 1; page <= MAX_PAGES; page++) {
      // An organiser's record allows the reset and no reading: the server answers 403.
      const response = await asNotAllowed(this.host.api().emergencySync(id, since));
      merged.vaults = response.vaults;
      merged.items.push(...response.items);
      if (!response.hasMore) return merged;
      since = response.vaults.map(({ id: vaultId, revision }) => ({ id: vaultId, revision }));
    }
    throw new VaultError('serverError');
  }
}

function decrypt(session: Session, record: ItemRecord): Item | undefined {
  try {
    const { encryptedItemKey, overview, details } = record;
    const plain = session.decryptItem(record.vaultId, record.id, { encryptedItemKey, overview, details });
    return toItem(record, plain.overview as unknown as ItemOverview, plain.details as unknown as ItemDetails);
  } catch {
    // Tampered with: leave it out, as the vault index does.
    return undefined;
  }
}
