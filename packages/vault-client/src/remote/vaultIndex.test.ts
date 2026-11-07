import type { Session, SignedGrant } from '@octapass/core';
import { uuidv7 } from '../ids';
import type { ItemRecord, VaultRecord } from './api';
import { grantOf, VaultIndex } from './vaultIndex';

const ME = 'acct-me';

/** A session whose "ciphertext" is JSON, and whose grant check accepts only the signature `good`. */
function stubSession() {
  const open = new Set<string>();
  const session = {
    openVault: (vaultId: string) => void open.add(vaultId),
    openSharedVault: (grant: SignedGrant) => {
      if (grant.signature !== 'good' || grant.recipientAccountId !== ME) throw Object.assign(new Error('bad'), { name: 'OctaPassError', code: 'invalid_signature' });
      open.add(grant.vaultId);
    },
    isVaultOpen: (vaultId: string) => open.has(vaultId),
    decryptItem: (vaultId: string, _id: string, encrypted: { overview: string; details: string }) => {
      if (!open.has(vaultId)) throw new Error('vault_not_open');
      return { overview: JSON.parse(encrypted.overview), details: JSON.parse(encrypted.details) };
    },
  };
  return session as unknown as Session;
}

const personal: VaultRecord = { id: 'p', type: 'personal', revision: 1, wrappedVaultKey: 'w', role: 'owner' };
const shared = (signature: string, role: VaultRecord['role'] = 'write'): VaultRecord => ({
  id: 's',
  type: 'shared',
  revision: 3,
  wrappedVaultKey: 'sealed',
  role,
  keyId: 'k1',
  grant: { grantedBy: 'acct-owner', granterPublicSignKey: 'pk', grantedAt: 1, signature },
});

const ids = new Map<string, string>();
const idOf = (name: string) => ids.get(name) ?? ids.set(name, uuidv7()).get(name)!;

function record(name: string, vaultId: string, revision: number, overview: Record<string, unknown>): ItemRecord {
  return { id: idOf(name), vaultId, revision, encryptedItemKey: 'k', overview: JSON.stringify({ schemaVersion: 1, ...overview }), details: '{"schemaVersion":1}', updatedAt: '2026-10-24T00:00:00Z' };
}

describe('VaultIndex', () => {
  it('rebuilds the signed grant from the vault record and this account', () => {
    expect(grantOf(shared('sig'), ME)).toEqual({
      vaultId: 's',
      recipientAccountId: ME,
      role: 'write',
      wrappedVaultKey: 'sealed',
      grantedBy: 'acct-owner',
      grantedAt: 1,
      signature: 'sig',
    });
    expect(grantOf(personal, ME)).toBeUndefined();
  });

  it('names shared vaults from their hidden name record, which never shows as an item', () => {
    const index = new VaultIndex(stubSession(), ME);
    index.apply(
      {
        vaults: [personal, shared('good')],
        items: [record('n1', 's', 1, { type: 'vaultInfo', title: 'Old name' }), record('n2', 's', 2, { type: 'vaultInfo', title: 'Household' }), record('i1', 's', 3, { type: 'login', title: 'Wi-Fi' })],
        deleted: [],
      },
      true,
    );
    expect(index.vaultName(index.vault('s')!)).toBe('Household');
    expect(index.vaultName(personal)).toBe('Personal');
    expect(index.items().map((i) => i.overview.title)).toEqual(['Wi-Fi']);
    expect(index.records('s').map((r) => r.id).sort()).toEqual(['i1', 'n1', 'n2'].map(idOf).sort());
  });

  it('never uses a vault whose grant fails verification, and drops what it showed before', () => {
    const index = new VaultIndex(stubSession(), ME);
    const item = record('i1', 's', 3, { type: 'login', title: 'Wi-Fi' });
    index.apply({ vaults: [shared('good')], items: [item], deleted: [] }, true);
    expect(index.items()).toHaveLength(1);

    const changed = index.apply({ vaults: [shared('forged', 'owner')], items: [{ ...item, revision: 4 }], deleted: [] }, false);
    expect(changed).toBe(true);
    expect(index.isUntrusted('s')).toBe(true);
    expect(index.items()).toEqual([]);

    index.apply({ vaults: [shared('good')], items: [item], deleted: [] }, true);
    expect(index.isUntrusted('s')).toBe(false);
    expect(index.items()).toHaveLength(1);
  });

  it('keeps records it can’t decrypt for rotations, out of the item list', () => {
    const index = new VaultIndex(stubSession(), ME);
    index.apply({ vaults: [shared('good')], items: [{ ...record('bad', 's', 1, {}), overview: 'not json' }], deleted: [] }, true);
    expect(index.items()).toEqual([]);
    expect(index.records('s').map((r) => r.id)).toEqual([idOf('bad')]);
    expect(index.toCache().items.map((r) => r.id)).toEqual([idOf('bad')]);
  });
});
