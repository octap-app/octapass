// The unlocked vaults: server records next to their decrypted items, in memory only. It lives as
// long as the WASM session that decrypts it; locking drops both.

import type { EncryptedItem, ItemPlaintext, Session, SignedGrant } from '@octapass/core';
import { uuidv7Time } from '../ids';
import type { Item, ItemDetails, ItemDraft, ItemOverview, VaultType } from '../types';
import type { ItemRecord, SyncResponse, VaultRecord } from './api';
import type { CachedVaults } from './store';

interface Entry {
  record: ItemRecord;
  item: Item;
}

/**
 * The server keeps no vault metadata, so a shared vault's name lives in the vault itself, as an
 * encrypted record of this type that every member can read. It's never listed as an item.
 */
export const VAULT_INFO_TYPE = 'vaultInfo';

export const DEFAULT_VAULT_NAMES: Record<VaultType, string> = { personal: 'Personal', shared: 'Shared vault', family: 'Family' };

const encryptedPart = ({ encryptedItemKey, overview, details }: EncryptedItem): EncryptedItem => ({ encryptedItemKey, overview, details });
export const isVaultInfo = (item: Pick<Item, 'overview'>) => (item.overview.type as string) === VAULT_INFO_TYPE;

/** The member's whole signed grant: the `VaultRecord` holds the rest of what was signed. */
export function grantOf(vault: VaultRecord, recipientAccountId: string): SignedGrant | undefined {
  if (!vault.grant) return undefined;
  const { grantedBy, grantedAt, signature } = vault.grant;
  return { vaultId: vault.id, recipientAccountId, role: vault.role, wrappedVaultKey: vault.wrappedVaultKey, grantedBy, grantedAt, signature };
}

/**
 * Opens a synced vault's key in `session`, as every client must. Personal vaults are sealed by the
 * account key. A shared or family vault's key is only used once its grant verifies: a server that
 * swapped the wrapped key or the role would otherwise go unnoticed. Returns `false` for one whose
 * grant didn't verify (it's `untrusted`: keep its items closed and warn).
 */
export function openVaultKey(session: Session, vault: VaultRecord, accountId: string): boolean {
  if (vault.type === 'personal') {
    session.openVault(vault.id, vault.wrappedVaultKey);
    return true;
  }
  const grant = grantOf(vault, accountId);
  if (!grant) return false;
  try {
    session.openSharedVault(grant, vault.grant!.granterPublicSignKey);
    return true;
  } catch {
    return false;
  }
}

export class VaultIndex {
  private readonly vaultRecords = new Map<string, VaultRecord>();
  private readonly entries = new Map<string, Entry>();
  /** Records this session couldn't decrypt. Kept so a key rotation still covers every item. */
  private readonly opaque = new Map<string, ItemRecord>();
  /** Shared vaults whose grant didn't verify: their key isn't used. */
  private readonly untrusted = new Set<string>();

  constructor(
    private readonly session: Session,
    private readonly accountId: string,
  ) {}

  vaults(): VaultRecord[] {
    return [...this.vaultRecords.values()];
  }

  vault(id: string): VaultRecord | undefined {
    return this.vaultRecords.get(id);
  }

  items(): Item[] {
    return [...this.entries.values()].map((e) => e.item).filter((item) => !isVaultInfo(item));
  }

  /** Every record in a vault, hidden and undecryptable ones included, for a key rotation. */
  records(vaultId: string): ItemRecord[] {
    return [...[...this.entries.values()].map((e) => e.record), ...this.opaque.values()].filter((r) => r.vaultId === vaultId);
  }

  isUntrusted(vaultId: string): boolean {
    return this.untrusted.has(vaultId);
  }

  /** The vault's name record, newest first if there are several (two members renamed it at once). */
  vaultInfo(vaultId: string): Entry | undefined {
    let found: Entry | undefined;
    for (const entry of this.entries.values()) {
      if (entry.record.vaultId !== vaultId || !isVaultInfo(entry.item) || entry.item.deletedAt) continue;
      if (!found || entry.record.revision > found.record.revision) found = entry;
    }
    return found;
  }

  vaultName(vault: VaultRecord): string {
    return this.vaultInfo(vault.id)?.item.overview.title || DEFAULT_VAULT_NAMES[vault.type];
  }

  get(id: string): Entry | undefined {
    return this.entries.get(id);
  }

  /** Where each vault's next incremental sync starts. */
  since(): { id: string; revision: number }[] {
    return this.vaults().map(({ id, revision }) => ({ id, revision }));
  }

  toCache(): CachedVaults {
    return { vaults: this.vaults(), items: [...[...this.entries.values()].map((e) => e.record), ...this.opaque.values()] };
  }

  /**
   * Applies a sync answer. A full one replaces everything: items it doesn't list are gone.
   * Returns whether anything the UI shows changed.
   */
  apply(sync: SyncResponse, full: boolean): boolean {
    let changed = false;
    const liveVaults = new Set<string>();
    for (const vault of sync.vaults) {
      liveVaults.add(vault.id);
      const known = this.vaultRecords.get(vault.id);
      const wasUntrusted = this.untrusted.has(vault.id);
      if (!known || known.wrappedVaultKey !== vault.wrappedVaultKey || known.role !== vault.role || !this.session.isVaultOpen(vault.id)) {
        this.openVault(vault);
      }
      if (!known || known.role !== vault.role || wasUntrusted !== this.untrusted.has(vault.id)) changed = true;
      this.vaultRecords.set(vault.id, vault);
      if (this.untrusted.has(vault.id)) changed = this.dropItems(vault.id) || changed;
    }
    for (const id of this.vaultRecords.keys()) {
      if (liveVaults.has(id)) continue;
      this.vaultRecords.delete(id);
      this.untrusted.delete(id);
      this.dropItems(id);
      changed = true;
    }

    const listed = new Set<string>();
    for (const record of sync.items) {
      if (!this.vaultRecords.has(record.vaultId) || this.untrusted.has(record.vaultId)) continue;
      listed.add(record.id);
      changed = this.applyRecord(record) || changed;
    }
    for (const { itemId } of sync.deleted) {
      this.opaque.delete(itemId);
      changed = this.entries.delete(itemId) || changed;
    }
    if (full) {
      for (const id of this.entries.keys()) {
        if (!listed.has(id)) changed = this.entries.delete(id) || changed;
      }
      for (const id of this.opaque.keys()) if (!listed.has(id)) this.opaque.delete(id);
    }
    return changed;
  }

  /** Stores a record this client just wrote, with the plaintext it already has. */
  put(record: ItemRecord, item: Pick<Item, 'overview' | 'details'>): Item {
    const entry = { record, item: toItem(record, item.overview, item.details) };
    this.entries.set(record.id, entry);
    this.opaque.delete(record.id);
    return entry.item;
  }

  encrypt(vaultId: string, itemId: string, draft: Pick<ItemDraft, 'overview' | 'details'>, existingItemKey?: string): EncryptedItem {
    // The core's item types are open records (unknown fields round-trip); ours are the closed shapes.
    return this.session.encryptItem(vaultId, itemId, { overview: draft.overview, details: draft.details } as unknown as ItemPlaintext, existingItemKey);
  }

  /** Decrypts a record from the server, for example the current version in a conflict. */
  decrypt(record: ItemRecord): Item {
    const plain = this.session.decryptItem(record.vaultId, record.id, encryptedPart(record));
    return toItem(record, plain.overview as unknown as ItemOverview, plain.details as unknown as ItemDetails);
  }

  private openVault(vault: VaultRecord): void {
    if (openVaultKey(this.session, vault, this.accountId)) this.untrusted.delete(vault.id);
    else this.untrusted.add(vault.id);
  }

  private dropItems(vaultId: string): boolean {
    let changed = false;
    for (const [itemId, entry] of this.entries) {
      if (entry.record.vaultId !== vaultId) continue;
      this.entries.delete(itemId);
      changed = true;
    }
    for (const [itemId, record] of this.opaque) if (record.vaultId === vaultId) this.opaque.delete(itemId);
    return changed;
  }

  private applyRecord(record: ItemRecord): boolean {
    const known = this.entries.get(record.id);
    if (known && known.record.revision === record.revision) {
      // Same ciphertext; only the server's timestamps may differ from the ones written locally.
      if (known.record.updatedAt === record.updatedAt && known.record.deletedAt === record.deletedAt) return false;
      this.put(record, known.item);
      return true;
    }
    try {
      this.entries.set(record.id, { record, item: this.decrypt(record) });
      this.opaque.delete(record.id);
      return true;
    } catch {
      // Tampered with, or sealed for a key this account doesn't have: leave it out of the vault.
      this.opaque.set(record.id, record);
      return this.entries.delete(record.id);
    }
  }
}

export function toItem(record: ItemRecord, overview: ItemOverview, details: ItemDetails): Item {
  const item: Item = {
    id: record.id,
    vaultId: record.vaultId,
    revision: record.revision,
    createdAt: new Date(uuidv7Time(record.id)).toISOString(),
    updatedAt: record.updatedAt,
    overview,
    details,
  };
  if (record.deletedAt) item.deletedAt = record.deletedAt;
  return item;
}
