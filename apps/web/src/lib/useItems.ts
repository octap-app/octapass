import type { ItemFilter, ItemSummary, Vault } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useService } from '../app/ServiceContext';
import { t } from '../i18n';

/**
 * Re-runs a vault query whenever items change (and, with `sharing`, whenever members, families or
 * links change), ignoring results that arrive out of order.
 */
export function useLive<T>(load: () => Promise<T>, deps: unknown[], { sharing = false } = {}): { data: T | undefined; error: unknown; retry: () => void } {
  const service = useService();
  const [state, setState] = useState<{ data: T | undefined; error: unknown }>({ data: undefined, error: undefined });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let run = 0;
    const refresh = () => {
      const current = ++run;
      load().then(
        (data) => current === run && setState({ data, error: undefined }),
        (error: unknown) => current === run && setState((s) => ({ data: s.data, error })),
      );
    };
    refresh();
    const unsubscribe = service.onItemsChange(refresh);
    const unsubscribeSharing = sharing ? service.sharing?.onSharingChange(refresh) : undefined;
    return () => {
      run = -1;
      unsubscribe();
      unsubscribeSharing?.();
    };
  }, [service, attempt, sharing, ...deps]);

  return { ...state, retry: () => setAttempt((n) => n + 1) };
}

export function useItems(filter: ItemFilter): { items: ItemSummary[] | undefined; error: unknown; retry: () => void } {
  const service = useService();
  const { data, error, retry } = useLive(() => service.listItems(filter), [JSON.stringify(filter)]);
  return { items: data, error, retry };
}

// The names vaults get when nobody named them, stored in English (`DEFAULT_VAULT_NAMES`).
const DEFAULT_NAMES: Record<Vault['type'], string> = { personal: 'Personal', shared: 'Shared vault', family: 'Family' };

/** A vault with the default name for its type shows that name in the reader's language. */
export function displayVault(vault: Vault): Vault {
  return vault.name === DEFAULT_NAMES[vault.type] ? { ...vault, name: t(`vault.names.${vault.type}`) } : vault;
}

export function useVaults(): Vault[] | undefined {
  const service = useService();
  return useLive(async () => (await service.listVaults()).map(displayVault), []).data;
}

export function useCounts(): Record<string, number> | undefined {
  const service = useService();
  return useLive(async () => {
    const all = await service.listItems();
    const trash = await service.listItems({ trash: true });
    const counts: Record<string, number> = { all: all.length, favorites: 0, pinned: 0, passkeys: 0, codes: 0, trash: trash.length };
    for (const item of all) {
      counts[item.type] = (counts[item.type] ?? 0) + 1;
      counts[`v-${item.vaultId}`] = (counts[`v-${item.vaultId}`] ?? 0) + 1;
      if (item.favorite) counts.favorites!++;
      if (item.pinned) counts.pinned!++;
      if (item.hasPasskey) counts.passkeys!++;
      if (item.hasTotp) counts.codes!++;
    }
    // Templates aren't listed with items, so they aren't in `all`.
    counts.customTemplate = (await service.listItems({ type: 'customTemplate' })).length;
    return counts;
  }, []).data;
}
