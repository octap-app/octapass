import { matchesFilter, summarizeItem } from './items';
import type { Item, ItemSummary, Vault } from './types';
import { addUses, createUsageTracker, mergeUsage, pruneUsage, readUsageStats, smartListItems, USAGE_STATS_TYPE, type UsageVault } from './usage';

/** Just enough vault: items with revisions; a stale save leaves a conflict copy, as the real ones do. */
function fakeVault() {
  const items = new Map<string, Item>();
  let next = 0;
  const saves: string[] = [];
  const vault: UsageVault = {
    listItems: async (filter) => [...items.values()].filter((item) => item.overview.type === filter?.type && !item.deletedAt).map((item) => ({ id: item.id }) as ItemSummary),
    getItem: async (id) => structuredClone(items.get(id)!),
    saveItem: async (draft) => {
      const stored = draft.id ? items.get(draft.id) : undefined;
      saves.push(draft.id ?? 'new');
      const stale = stored && draft.revision !== stored.revision;
      const id = stored && !stale ? stored.id : `item-${++next}`;
      const item: Item = { id, vaultId: draft.vaultId, revision: (stored?.revision ?? 0) + 1, createdAt: stored?.createdAt ?? `2026-01-0${next}`, updatedAt: '2026-02-01', overview: draft.overview, details: draft.details };
      items.set(id, item);
      return item;
    },
    deleteItem: async (id) => void (items.get(id)!.deletedAt = 'now'),
    listVaults: async () => [{ id: 'personal-1', type: 'personal' } as Vault],
  };
  return { vault, items, saves };
}

let clock = Date.parse('2026-11-04T10:00:00.000Z');
const now = () => new Date((clock += 1000));

let rows = 0;
function row(title: string, overrides: Partial<ItemSummary> = {}): ItemSummary {
  rows += 1;
  return {
    id: `id-${String(rows).padStart(3, '0')}`,
    vaultId: 'v1',
    type: 'login',
    title,
    favorite: false,
    hasTotp: false,
    hasPasskey: false,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}
const titles = (items: ItemSummary[]) => items.map((item) => item.title);

describe('usage tracker', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('saves uses together after a pause, in one hidden item in the personal vault', async () => {
    const { vault, items, saves } = fakeVault();
    const tracker = createUsageTracker(vault, { delayMs: 5000, now });
    tracker.record('a');
    tracker.record('a');
    tracker.record('b');
    expect(saves).toEqual([]);
    // Counted at once, before the save.
    expect((await tracker.read()).a?.count).toBe(2);
    await vi.advanceTimersByTimeAsync(5000);
    expect(saves).toEqual(['new']);
    expect(items.size).toBe(1);
    const [item] = [...items.values()];
    expect(item!.vaultId).toBe('personal-1');
    expect(item!.overview).toEqual({ schemaVersion: 1, type: USAGE_STATS_TYPE, title: 'Usage' });
    const usage = await tracker.read();
    expect(usage.a?.count).toBe(2);
    expect(usage.b?.count).toBe(1);
    expect(Date.parse(usage.b!.lastUsedAt)).toBeGreaterThan(Date.parse(usage.a!.lastUsedAt));
  });

  it('adds to what is saved, and keeps one item', async () => {
    const { vault, items } = fakeVault();
    const tracker = createUsageTracker(vault, { now });
    tracker.record('a');
    await tracker.flush();
    tracker.record('a');
    await tracker.flush();
    expect(items.size).toBe(1);
    expect((await tracker.read()).a?.count).toBe(2);
  });

  it('tells lists when a use is counted', () => {
    const { vault } = fakeVault();
    const tracker = createUsageTracker(vault, { now });
    const listener = vi.fn();
    const stop = tracker.onChange(listener);
    tracker.record('a');
    expect(listener).toHaveBeenCalledTimes(1);
    stop();
    tracker.record('a');
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('keeps uses for the next save when a save fails, and forgets them when cleared', async () => {
    const { vault } = fakeVault();
    const failing: UsageVault = { ...vault, saveItem: vi.fn().mockRejectedValueOnce(new Error('offline')).mockImplementation(vault.saveItem) };
    const tracker = createUsageTracker(failing, { now });
    tracker.record('a');
    await expect(tracker.flush()).rejects.toThrow('offline');
    tracker.record('a');
    await tracker.flush();
    expect((await tracker.read()).a?.count).toBe(2);

    tracker.record('b');
    tracker.clear();
    await tracker.flush();
    expect((await tracker.read()).b).toBeUndefined();
  });

  it('merges conflict copies and moves the extras to the trash', async () => {
    const { vault, items } = fakeVault();
    const base = { schemaVersion: 1 as const, type: USAGE_STATS_TYPE, title: 'Usage' };
    items.set('x', { id: 'x', vaultId: 'personal-1', revision: 1, createdAt: '2026-01-01', updatedAt: '2026-01-01', overview: base, details: { schemaVersion: 1, items: { a: { count: 3, lastUsedAt: '2026-10-01T00:00:00.000Z' } } } as Item['details'] });
    items.set('y', { id: 'y', vaultId: 'personal-1', revision: 1, createdAt: '2026-01-02', updatedAt: '2026-01-02', overview: base, details: { schemaVersion: 1, items: { a: { count: 1, lastUsedAt: '2026-10-05T00:00:00.000Z' }, b: { count: 2, lastUsedAt: '2026-10-02T00:00:00.000Z' } } } as Item['details'] });
    const tracker = createUsageTracker(vault, { now });
    expect(await tracker.read()).toEqual({ a: { count: 3, lastUsedAt: '2026-10-05T00:00:00.000Z' }, b: { count: 2, lastUsedAt: '2026-10-02T00:00:00.000Z' } });
    tracker.record('b');
    await tracker.flush();
    expect(items.get('y')!.deletedAt).toBeDefined();
    expect(items.get('x')!.deletedAt).toBeUndefined();
    expect((await tracker.read()).b?.count).toBe(3);
  });

  it('is kept out of item lists', () => {
    const item: Item = { id: 'u', vaultId: 'p', revision: 1, createdAt: '2026-01-01', updatedAt: '2026-01-01', overview: { schemaVersion: 1, type: USAGE_STATS_TYPE, title: 'Usage' }, details: { schemaVersion: 1 } as Item['details'] };
    expect(matchesFilter(summarizeItem(item))).toBe(false);
    expect(matchesFilter(summarizeItem(item), { type: USAGE_STATS_TYPE })).toBe(true);
  });
});

describe('usage records', () => {
  it('merge to the higher count and the later use, leaving out entries that are not uses', () => {
    expect(
      mergeUsage(
        { a: { count: 2, lastUsedAt: '2026-10-01T00:00:00.000Z' }, bad: { count: 0, lastUsedAt: '2026-10-01T00:00:00.000Z' } },
        { a: { count: 1, lastUsedAt: '2026-10-03T00:00:00.000Z' }, worse: { count: 1, lastUsedAt: 'never' } as never },
      ),
    ).toEqual({ a: { count: 2, lastUsedAt: '2026-10-03T00:00:00.000Z' } });
  });

  it('add up', () => {
    expect(addUses({ a: { count: 2, lastUsedAt: '2026-10-01T00:00:00.000Z' } }, { a: { count: 1, lastUsedAt: '2026-10-03T00:00:00.000Z' }, b: { count: 1, lastUsedAt: '2026-10-02T00:00:00.000Z' } })).toEqual({
      a: { count: 3, lastUsedAt: '2026-10-03T00:00:00.000Z' },
      b: { count: 1, lastUsedAt: '2026-10-02T00:00:00.000Z' },
    });
  });

  it('forget the least recently used past the limit', () => {
    const usage = { a: { count: 9, lastUsedAt: '2026-10-01T00:00:00.000Z' }, b: { count: 1, lastUsedAt: '2026-10-03T00:00:00.000Z' }, c: { count: 1, lastUsedAt: '2026-10-02T00:00:00.000Z' } };
    expect(Object.keys(pruneUsage(usage, 2)).sort()).toEqual(['b', 'c']);
  });

  it('read only live usage items', () => {
    const item = (deletedAt?: string): Item => ({ id: 'u', vaultId: 'p', revision: 1, createdAt: '', updatedAt: '', deletedAt, overview: { schemaVersion: 1, type: USAGE_STATS_TYPE, title: 'Usage' }, details: { schemaVersion: 1, items: { a: { count: 1, lastUsedAt: '2026-10-01T00:00:00.000Z' } } } as Item['details'] });
    expect(readUsageStats([item()])).toHaveProperty('a');
    expect(readUsageStats([item('2026-10-02')])).toEqual({});
  });
});

describe('smart lists', () => {
  const old = row('Old', { createdAt: '2025-01-01T00:00:00.000Z', updatedAt: '2026-10-09T00:00:00.000Z' });
  const mid = row('Mid', { createdAt: '2026-03-01T00:00:00.000Z', updatedAt: '2026-03-01T00:00:00.000Z' });
  const recent = row('Recent', { createdAt: '2026-10-01T00:00:00.000Z', updatedAt: '2026-10-01T00:00:00.000Z' });
  const unused = row('Unused');
  const items = [old, mid, recent, unused];
  const usage = {
    [old.id]: { count: 1, lastUsedAt: '2026-11-03T00:00:00.000Z' },
    [mid.id]: { count: 5, lastUsedAt: '2026-10-01T00:00:00.000Z' },
    [recent.id]: { count: 5, lastUsedAt: '2026-10-20T00:00:00.000Z' },
    gone: { count: 50, lastUsedAt: '2026-11-04T00:00:00.000Z' },
  };

  it('Recently created is newest first', () => {
    expect(titles(smartListItems(items, 'created', usage))).toEqual(['Recent', 'Mid', 'Unused', 'Old']);
  });

  it('Recently modified is the latest change first', () => {
    expect(titles(smartListItems(items, 'changed', usage))).toEqual(['Old', 'Recent', 'Mid', 'Unused']);
  });

  it('Frequently used is the most uses first, then the latest use, and leaves out items never used or gone', () => {
    expect(titles(smartListItems(items, 'frequent', usage))).toEqual(['Recent', 'Mid', 'Old']);
  });

  it('Recently used is the latest use first', () => {
    expect(titles(smartListItems(items, 'used', usage))).toEqual(['Old', 'Recent', 'Mid']);
  });

  it('shows at most the limit', () => {
    expect(titles(smartListItems(items, 'created', usage, { limit: 2 }))).toEqual(['Recent', 'Mid']);
  });
});
