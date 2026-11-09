import { formatDistance, nearbyFrom, nearbyInputs, suggestFrom, withPlace, type PlacesCore } from './places';
import type { ItemSummary } from './types';

const row = (id: string, type: string, title: string, extra: Partial<ItemSummary> = {}): ItemSummary =>
  ({ id, vaultId: 'v', type, title, favorite: false, hasTotp: false, hasPasskey: false, createdAt: '', updatedAt: '', ...extra }) as ItemSummary;

describe('places', () => {
  it('rounds distances the way the list shows them', () => {
    expect(formatDistance(4, 'en')).toBe('10 m');
    expect(formatDistance(874, 'en')).toBe('870 m');
    expect(formatDistance(996, 'en')).toBe('1 km');
    expect(formatDistance(1_234, 'en')).toBe('1.2 km');
    expect(formatDistance(9_960, 'en')).toBe('10 km');
    expect(formatDistance(37_400, 'en')).toBe('37 km');
  });

  it('adds a place once and drops the list when the last one goes', () => {
    expect(withPlace(undefined, 'a', true)).toEqual(['a']);
    expect(withPlace(['a', 'b'], 'a', true)).toEqual(['b', 'a']);
    expect(withPlace(['a'], 'a', false)).toBeUndefined();
  });

  it('hands the core the places and listable items by name, without the trash or settings', () => {
    const rows = [
      row('2', 'place', 'Office'),
      row('1', 'place', 'attic'),
      row('3', 'login', 'VPN'),
      row('4', 'login', 'Gone', { deletedAt: '2026-11-01T00:00:00Z' }),
      row('5', 'usageStats', 'Usage'),
      row('6', 'secureNote', 'Alarm'),
    ];
    const { places, items } = nearbyInputs(rows);
    expect(places.map((p) => p.title)).toEqual(['attic', 'Office']);
    expect(items.map((i) => i.title)).toEqual(['Alarm', 'VPN']);
  });

  it('asks the core with the item’s vault, and whether it is the personal one', () => {
    const calls: unknown[][] = [];
    const core: PlacesCore = {
      nearbyList: (...args) => (calls.push(args), []),
      suggestedPlace: (...args) => (calls.push(args), 'p'),
    };
    const rows = [row('p', 'place', 'Home'), row('i', 'login', 'Router', { vaultId: 'team' })];
    expect(nearbyFrom(core, rows, {})).toEqual([]);
    expect(suggestFrom(core, rows, [{ id: 'team', type: 'shared' }], 'i', { networks: ['Home'] })).toBe('p');
    expect(calls[1]!.slice(4)).toEqual(['team', false]);
    expect(suggestFrom(core, rows, [], 'p', {})).toBeUndefined();
    expect(suggestFrom(core, rows, [], 'missing', {})).toBeUndefined();
  });
});
