// The user's equivalent domains (plan 01): one hidden `equivalentDomains` item in a personal vault,
// so the list is as encrypted as a login and follows the account. Devices that each made one before
// they synced are tidied here: the first keeps both lists (they were joined on the way in), the rest
// go to the trash. What a domain may be is the core's decision, not this file's.

import { SCHEMA_VERSION, type EquivalentDomainsDetails, type Item, type ItemDraft, type Vault } from './types';
import { VaultError } from './errors';

export const EQUIVALENT_DOMAINS_TITLE = 'Equivalent domains';

interface Store {
  items(): Promise<Item[]>;
  vaults(): Promise<Vault[]>;
  save(draft: ItemDraft): Promise<Item>;
  trash(id: string): Promise<void>;
}

/** Writes the cleaned list. Nothing at all is removed by saving an empty list: it's kept as a setting. */
export async function storeEquivalentDomains(store: Store, list: { groups: string[][]; excludedDefaults: string[] }): Promise<void> {
  const details = (extra?: EquivalentDomainsDetails): EquivalentDomainsDetails => {
    // Left out, not `undefined`: the core can't read `undefined` as a list.
    const { excludedDefaults: _old, ...kept } = extra ?? { schemaVersion: SCHEMA_VERSION, groups: [] };
    return {
      ...kept,
      schemaVersion: SCHEMA_VERSION,
      groups: list.groups,
      ...(list.excludedDefaults.length ? { excludedDefaults: list.excludedDefaults } : {}),
    };
  };
  const [first, ...rest] = (await store.items()).filter((item) => item.overview.type === 'equivalentDomains' && !item.deletedAt);
  if (first) {
    await store.save({ id: first.id, vaultId: first.vaultId, revision: first.revision, overview: first.overview, details: details(first.details as EquivalentDomainsDetails) });
  } else {
    const vaults = await store.vaults();
    const personal = vaults.find((vault) => vault.type === 'personal') ?? vaults[0];
    if (!personal) throw new VaultError('notFound');
    await store.save({ vaultId: personal.id, overview: { schemaVersion: SCHEMA_VERSION, type: 'equivalentDomains', title: EQUIVALENT_DOMAINS_TITLE }, details: details() });
  }
  for (const copy of rest) await store.trash(copy.id);
}
