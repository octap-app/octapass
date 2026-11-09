import { parseScope, scopeFilter } from './scope';

describe('scopes', () => {
  it('maps URL segments to list filters', () => {
    expect(scopeFilter(parseScope('favorites'))).toEqual({ favorites: true });
    expect(scopeFilter(parseScope('v-0189'))).toEqual({ vaultId: '0189' });
    expect(scopeFilter(parseScope('card'))).toEqual({ type: 'card' });
    expect(scopeFilter(parseScope('trash'))).toEqual({ trash: true });
    expect(scopeFilter(parseScope('passkeys'))).toEqual({ passkeys: true });
    expect(scopeFilter(parseScope('codes'))).toEqual({ totp: true });
    expect(scopeFilter(parseScope('pinned'))).toEqual({ pinned: true });
    expect(scopeFilter(parseScope('nonsense'))).toEqual({});
  });

  it('knows the lists with an order of their own, which start from every item', () => {
    for (const list of ['created', 'frequent', 'used', 'changed'] as const) {
      expect(parseScope(list)).toEqual({ kind: 'smart', list });
      expect(scopeFilter(parseScope(list))).toEqual({});
    }
    // Nearby lists places with their items, from every item.
    expect(parseScope('nearby')).toEqual({ kind: 'nearby' });
    expect(scopeFilter(parseScope('nearby'))).toEqual({});
  });
});
