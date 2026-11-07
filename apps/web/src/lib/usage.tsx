import { createUsageTracker, matchesQuery, smartListItems, type ItemSummary, type UsageTracker, type VaultService } from '@octapass/vault-client';
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { useService } from '../app/ServiceContext';
import { getLocale } from '../i18n';
import { scopeFilter, type Scope } from './scope';
import { useLive } from './useItems';

// One tracker per service (one per account in this window), so every screen counts into the same
// uses before they're saved. Uses waiting to be saved are forgotten when the vault locks.
const trackers = new WeakMap<VaultService, UsageTracker>();

export function usageTrackerFor(service: VaultService): UsageTracker {
  let tracker = trackers.get(service);
  if (!tracker) {
    const created = createUsageTracker(service);
    service.onSessionChange((session) => {
      if (session.status !== 'unlocked') created.clear();
    });
    // Leaving the tab (to paste what was copied, often) saves at once rather than a few seconds later.
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') void created.flush().catch(() => undefined);
      });
    }
    trackers.set(service, created);
    tracker = created;
  }
  return tracker;
}

export function useUsageTracker(): UsageTracker {
  return usageTrackerFor(useService());
}

/**
 * Where uses go: this window's tracker unless a provider says otherwise. The browser extension's
 * popup sends them to its service worker, which outlives the popup.
 */
export const UsageRecorderContext = createContext<((itemId: string) => void) | undefined>(undefined);

const ItemUseContext = createContext<(() => void) | undefined>(undefined);

/** Everything inside counts as using this item: copying a field (`useCopy`), opening its website. */
export function ItemUseProvider({ itemId, children }: { itemId: string; children: ReactNode }) {
  const tracker = useUsageTracker();
  const recorder = useContext(UsageRecorderContext);
  const record = useCallback(() => (recorder ? recorder(itemId) : tracker.record(itemId)), [recorder, tracker, itemId]);
  return <ItemUseContext.Provider value={record}>{children}</ItemUseContext.Provider>;
}

/** Counts a use of the item showing, or nothing outside an item. */
export function useRecordItemUse(): () => void {
  return useContext(ItemUseContext) ?? noop;
}

const noop = () => undefined;

/**
 * The items a list shows. Most lists are a filter; the smart lists (Recently created, Frequently
 * used, Recently used, Recently modified) put every item in their own order and keep the first
 * ones. A search there looks through what the list shows.
 */
export function useScopeItems(scope: Scope, query: string | undefined): { items: ItemSummary[] | undefined; error: unknown; retry: () => void } {
  const service = useService();
  const tracker = useUsageTracker();
  const list = scope.kind === 'smart' ? scope.list : undefined;
  const byUse = list === 'frequent' || list === 'used';
  // Uses show in their lists at once, before they're saved.
  const [uses, setUses] = useState(0);
  useEffect(() => (byUse ? tracker.onChange(() => setUses((n) => n + 1)) : undefined), [tracker, byUse]);
  const filter = scopeFilter(scope);
  const { data, error, retry } = useLive(async () => {
    if (!list) return service.listItems({ ...filter, query });
    const [items, usage] = await Promise.all([service.listItems(filter), byUse ? tracker.read() : {}]);
    const shown = smartListItems(items, list, usage, { locale: getLocale() });
    return query ? shown.filter((item) => matchesQuery(item, query)) : shown;
  }, [JSON.stringify(filter), list, query, byUse ? uses : 0]);
  return { items: data, error, retry };
}
