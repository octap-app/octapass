// How often and when each item was used, for the Frequently used and Recently used lists. It lives
// in one hidden vault item, as the health settings do, so it's encrypted like the rest of the vault
// and follows the account to its other devices. Using an item never writes the item itself: no new
// version of it, no conflict with an edit elsewhere, and it works in vaults shared read-only.
//
// A use is copying one of the item's fields, filling it in, or opening its website. Uses wait a few
// seconds and are saved together, so copying a username and then a password is one write.

import { nameCollator, sortItems } from './listOrder';
import { SCHEMA_VERSION, type Item, type ItemDetails, type ItemSummary, type VaultService } from './types';

export const USAGE_STATS_TYPE = 'usageStats' as const;
/** The hidden item's title. Nobody sees it; it names the item in an export of the raw records. */
export const USAGE_STATS_TITLE = 'Usage';
/** How long uses wait before they're saved, so a burst of copies is one write. */
export const USAGE_SAVE_DELAY_MS = 5_000;
/** The most items it remembers. The least recently used are forgotten first. */
export const MAX_USAGE_ENTRIES = 500;
/** How many items the Recently created, Recently modified, Frequently used and Recently used lists show. */
export const SMART_LIST_LIMIT = 50;

export interface ItemUse {
  /** Times the item was used. */
  count: number;
  /** When it was last used. */
  lastUsedAt: string;
}

export interface UsageStatsDetails {
  schemaVersion: typeof SCHEMA_VERSION;
  /** By item id. Items in any vault the account can open; the stats item itself is in a personal vault. */
  items?: Record<string, ItemUse>;
  /** Files never go here; this keeps `ItemDetails.attachments` readable on every type. */
  attachments?: never;
}

/** What the usage item says, by item id. */
export type ItemUsage = Readonly<Record<string, ItemUse>>;

export const isUsageStats = (item: Pick<Item, 'overview'>) => item.overview.type === USAGE_STATS_TYPE;

const time = (text: string | undefined) => (text ? Date.parse(text) || 0 : 0);
const later = (a: string, b: string) => (time(b) > time(a) ? b : a);

function validUse(value: unknown): value is ItemUse {
  const use = value as ItemUse | null;
  return Boolean(use) && typeof use === 'object' && Number.isFinite(use!.count) && use!.count > 0 && typeof use!.lastUsedAt === 'string' && time(use!.lastUsedAt) > 0;
}

/**
 * Two records of the same item's uses as one: the higher count and the later use. Two devices
 * saving at once leave a conflict copy; neither device's newest use is lost, though uses both
 * counted since they last synced count once.
 */
export function mergeUsage(...all: ItemUsage[]): Record<string, ItemUse> {
  const merged: Record<string, ItemUse> = {};
  for (const usage of all) {
    for (const [id, use] of Object.entries(usage)) {
      if (!validUse(use)) continue;
      const known = merged[id];
      merged[id] = known ? { count: Math.max(known.count, use.count), lastUsedAt: later(known.lastUsedAt, use.lastUsedAt) } : { count: Math.floor(use.count), lastUsedAt: use.lastUsedAt };
    }
  }
  return merged;
}

/** Merges every live usage item. Entries that don't read as uses are left out. */
export function readUsageStats(items: Pick<Item, 'overview' | 'details' | 'deletedAt'>[]): Record<string, ItemUse> {
  return mergeUsage(...items.filter((item) => isUsageStats(item) && !item.deletedAt).map((item) => (item.details as UsageStatsDetails).items ?? {}));
}

/** `usage` with `uses` added to it: counts add up, and the last use is the later one. */
export function addUses(usage: ItemUsage, uses: ItemUsage): Record<string, ItemUse> {
  const next: Record<string, ItemUse> = { ...usage };
  for (const [id, use] of Object.entries(uses)) {
    const known = next[id];
    next[id] = known ? { count: known.count + use.count, lastUsedAt: later(known.lastUsedAt, use.lastUsedAt) } : { ...use };
  }
  return next;
}

/** At most `limit` entries, keeping the most recently used. */
export function pruneUsage(usage: ItemUsage, limit = MAX_USAGE_ENTRIES): Record<string, ItemUse> {
  const entries = Object.entries(usage);
  if (entries.length <= limit) return { ...usage };
  entries.sort(([a, x], [b, y]) => time(y.lastUsedAt) - time(x.lastUsedAt) || (a < b ? -1 : a > b ? 1 : 0));
  return Object.fromEntries(entries.slice(0, limit));
}

/**
 * The sidebar's lists that put items in an order of their own: Recently created, Recently
 * modified, Frequently used and Recently used. (Pinned and Favorites are filters, sorted like any list.)
 */
export type SmartList = 'created' | 'changed' | 'frequent' | 'used';

export const SMART_LISTS: readonly SmartList[] = ['created', 'frequent', 'used', 'changed'];

export const isSmartList = (value: string | undefined): value is SmartList => SMART_LISTS.includes(value as SmartList);

/**
 * The items a smart list shows, in its order, at most `limit` of them. `items` are the vault's
 * items (not the trash, not settings). Created and modified come from the sync record's dates,
 * as the Newest and Recently changed sorts do. Frequently used is the most uses first, then the
 * latest use; Recently used is the latest use first. Items never used aren't in those two. Equal
 * places fall back to the name, then the id, so the order never jumps.
 */
export function smartListItems(items: readonly ItemSummary[], list: SmartList, usage: ItemUsage, { limit = SMART_LIST_LIMIT, locale }: { limit?: number; locale?: string } = {}): ItemSummary[] {
  if (list === 'created') return sortItems(items, 'newest', locale).slice(0, limit);
  if (list === 'changed') return sortItems(items, 'changed', locale).slice(0, limit);
  const collator = nameCollator(locale);
  const used = items.filter((item) => usage[item.id]);
  const use = (item: ItemSummary) => usage[item.id]!;
  const byName = (a: ItemSummary, b: ItemSummary) => collator.compare(a.title, b.title) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const byLast = (a: ItemSummary, b: ItemSummary) => time(use(b).lastUsedAt) - time(use(a).lastUsedAt);
  used.sort(list === 'frequent' ? (a, b) => use(b).count - use(a).count || byLast(a, b) || byName(a, b) : (a, b) => byLast(a, b) || byName(a, b));
  return used.slice(0, limit);
}

export type UsageVault = Pick<VaultService, 'listItems' | 'getItem' | 'saveItem' | 'deleteItem' | 'listVaults'>;

export interface UsageTracker {
  /** Counts a use of the item now. It's saved a few seconds later, with any others. */
  record(itemId: string): void;
  /** What the vault says, with the uses still waiting to be saved added. */
  read(): Promise<Record<string, ItemUse>>;
  /** Saves the uses that are waiting now. A failed save keeps them for the next one. */
  flush(): Promise<void>;
  /** Forgets the uses that are waiting (the vault locked or the account signed out). */
  clear(): void;
  /** Called when a use is counted, before it's saved, so lists can show it at once. */
  onChange(listener: () => void): () => void;
}

export interface UsageTrackerOptions {
  delayMs?: number;
  now?: () => Date;
}

export function createUsageTracker(vault: UsageVault, { delayMs = USAGE_SAVE_DELAY_MS, now = () => new Date() }: UsageTrackerOptions = {}): UsageTracker {
  let pending: Record<string, ItemUse> = {};
  let timer: ReturnType<typeof setTimeout> | undefined;
  const listeners = new Set<() => void>();
  // One save at a time: a second save must start from the revision of the first.
  let queue: Promise<unknown> = Promise.resolve();
  const inOrder = <T>(work: () => Promise<T>): Promise<T> => {
    const run = queue.then(work, work);
    queue = run.catch(() => undefined);
    return run;
  };

  const stored = async (): Promise<Item[]> => {
    const summaries = await vault.listItems({ type: USAGE_STATS_TYPE });
    return Promise.all(summaries.map((summary) => vault.getItem(summary.id)));
  };

  const save = (uses: ItemUsage) =>
    inOrder(async () => {
      const items = await stored();
      const next = pruneUsage(addUses(readUsageStats(items), uses));
      const [first, ...extras] = items.filter((item) => !item.deletedAt).sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));
      const personal = first?.vaultId ?? (await vault.listVaults()).find((v) => v.type === 'personal')?.id;
      if (!personal) throw new Error('no personal vault');
      const details: UsageStatsDetails = { ...(first?.details as UsageStatsDetails | undefined), schemaVersion: SCHEMA_VERSION, items: next };
      await vault.saveItem({
        ...(first ? { id: first.id, revision: first.revision } : {}),
        vaultId: personal,
        overview: first?.overview ?? { schemaVersion: SCHEMA_VERSION, type: USAGE_STATS_TYPE, title: USAGE_STATS_TITLE },
        details: details as ItemDetails,
      });
      await Promise.all(extras.map((extra) => vault.deleteItem(extra.id)));
    });

  const flush = async () => {
    clearTimeout(timer);
    timer = undefined;
    const uses = pending;
    pending = {};
    if (Object.keys(uses).length === 0) return;
    try {
      await save(uses);
    } catch (error) {
      // Kept for the next save: offline, or locked before the save ran.
      pending = addUses(uses, pending);
      throw error;
    }
  };

  return {
    record(itemId) {
      pending = addUses(pending, { [itemId]: { count: 1, lastUsedAt: now().toISOString() } });
      if (!timer) timer = setTimeout(() => void flush().catch(() => undefined), delayMs);
      for (const listener of listeners) listener();
    },
    read: async () => addUses(readUsageStats(await stored()), pending),
    flush,
    clear() {
      clearTimeout(timer);
      timer = undefined;
      pending = {};
    },
    onChange(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}
