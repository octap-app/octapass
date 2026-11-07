import { LIST_GROUPINGS, LIST_SORTS, type ListGrouping, type ListSort, type VaultService } from '@octapass/vault-client';
import { useCallback, useState, useSyncExternalStore } from 'react';
import { useService } from '../app/ServiceContext';

export interface ListArrangement {
  sort: ListSort;
  grouping: ListGrouping;
}

/** The list a choice is remembered for: `all`, `favorites`, `pinned`, `passkeys`, `codes`, `vault`, or an item type. */
export type ListView = string;

export const LIST_STORAGE_KEY = 'octapass:list';
export const COMBINE_SITES_STORAGE_KEY = 'octapass:combineSites';

// Lists that mix item types; a list of one type has nothing to group by type.
const MIXED: ReadonlySet<ListView> = new Set(['all', 'favorites', 'pinned', 'vault']);

/** Mixed lists start grouped by type, lists of one type by first letter; both in name order. */
export function defaultArrangement(view: ListView): ListArrangement {
  // Environments are grouped by the project whose stages they belong to.
  if (view === 'environment') return { sort: 'name', grouping: 'project' };
  return { sort: 'name', grouping: MIXED.has(view) ? 'type' : 'letter' };
}

/** What a list can be grouped by: type only when it mixes types, vault only across several vaults. */
export function groupingsFor(view: ListView, vaultCount: number): ListGrouping[] {
  return LIST_GROUPINGS.filter((grouping) =>
    grouping === 'type' ? MIXED.has(view) : grouping === 'vault' ? view !== 'vault' && vaultCount > 1 : grouping === 'project' ? view === 'environment' : true,
  );
}

// A preference of this device only, never synced and never vault data, so plain localStorage is fine.
function load(): Record<ListView, Partial<ListArrangement>> {
  try {
    const saved: unknown = JSON.parse(localStorage.getItem(LIST_STORAGE_KEY) ?? '{}');
    return saved && typeof saved === 'object' ? (saved as Record<ListView, Partial<ListArrangement>>) : {};
  } catch {
    return {};
  }
}

/** The remembered sort and grouping for a list, or its default, limited to the groupings it offers. */
export function useListArrangement(view: ListView, groupings: readonly ListGrouping[]): [ListArrangement, (next: ListArrangement) => void] {
  const [saved, setSaved] = useState(load);
  const fallback = defaultArrangement(view);
  const stored = saved[view] ?? {};
  const sort = stored.sort && LIST_SORTS.includes(stored.sort) ? stored.sort : fallback.sort;
  const grouping = stored.grouping && groupings.includes(stored.grouping) ? stored.grouping : groupings.includes(fallback.grouping) ? fallback.grouping : 'none';

  function choose(next: ListArrangement) {
    const all = { ...load(), [view]: next };
    try {
      localStorage.setItem(LIST_STORAGE_KEY, JSON.stringify(all));
    } catch {
      // Private browsing can refuse storage; the choice still applies until the list closes.
    }
    setSaved(all);
  }

  return [{ sort, grouping }, choose];
}

/** Whether lists show two or more logins for the same website as one row. On unless turned off on this device. */
export function useCombineSites(): [boolean, (on: boolean) => void] {
  const [on, setOn] = useState(() => {
    try {
      return localStorage.getItem(COMBINE_SITES_STORAGE_KEY) !== 'off';
    } catch {
      return true;
    }
  });

  function choose(next: boolean) {
    try {
      localStorage.setItem(COMBINE_SITES_STORAGE_KEY, next ? 'on' : 'off');
    } catch {
      // As above: the choice lasts until the list closes.
    }
    setOn(next);
  }

  return [on, choose];
}

// The sites whose logins are showing, for each service (one per account in this window). Hosts are
// vault data, so they stay in memory, never in browser storage, and are forgotten on lock or sign-out.
interface OpenSites {
  hosts: ReadonlySet<string>;
  listeners: Set<() => void>;
}
const openSites = new WeakMap<VaultService, OpenSites>();

function openSitesFor(service: VaultService): OpenSites {
  let store = openSites.get(service);
  if (!store) {
    const created: OpenSites = { hosts: new Set(), listeners: new Set() };
    service.onSessionChange((session) => {
      if (session.status !== 'unlocked' && created.hosts.size) update(created, new Set());
    });
    openSites.set(service, created);
    store = created;
  }
  return store;
}

function update(store: OpenSites, hosts: ReadonlySet<string>) {
  store.hosts = hosts;
  for (const listener of store.listeners) listener();
}

/** Which site rows are open, for as long as the vault stays unlocked in this window. */
export function useOpenSites(): { isOpen: (host: string) => boolean; setOpen: (host: string, open: boolean) => void } {
  const store = openSitesFor(useService());
  const subscribe = useCallback(
    (listener: () => void) => {
      store.listeners.add(listener);
      return () => store.listeners.delete(listener);
    },
    [store],
  );
  const hosts = useSyncExternalStore(subscribe, () => store.hosts);
  const setOpen = useCallback(
    (host: string, open: boolean) => {
      if (store.hosts.has(host) === open) return;
      const next = new Set(store.hosts);
      if (open) next.add(host);
      else next.delete(host);
      update(store, next);
    },
    [store],
  );
  return { isOpen: (host) => hosts.has(host), setOpen };
}
