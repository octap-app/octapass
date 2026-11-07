import { describe, expect, it, vi } from 'vitest';
import { findSameLogin, isSameLogin, loginOrigin, sameSiteLogins } from './duplicates';
import type { Item, ItemDraft, ItemSummary } from './types';

function login(id: string, urls: string[], username: string | undefined, extra: Partial<Item> = {}): Item {
  return {
    id,
    vaultId: 'v1',
    revision: 1,
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
    overview: { schemaVersion: 1, title: id, type: 'login', urls, ...(username ? { subtitle: username } : {}) },
    details: { schemaVersion: 1, ...(username ? { username } : {}), password: 'pw' },
    ...extra,
  } as Item;
}

function summary(item: Item): ItemSummary {
  return {
    id: item.id,
    vaultId: item.vaultId,
    type: item.overview.type,
    title: item.overview.title,
    urls: item.overview.urls,
    favorite: false,
    hasTotp: false,
    hasPasskey: false,
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    ...(item.deletedAt ? { deletedAt: item.deletedAt } : {}),
  } as ItemSummary;
}

function draft(urls: string[], username?: string): ItemDraft {
  return {
    vaultId: 'v1',
    overview: { schemaVersion: 1, title: 'New', type: 'login', urls },
    details: { schemaVersion: 1, ...(username ? { username } : {}), password: 'new' },
  } as ItemDraft;
}

describe('loginOrigin', () => {
  it('keeps the scheme, host and port, without www. or the path', () => {
    expect(loginOrigin('https://www.GitHub.com/login?x=1')).toBe('https://github.com');
    expect(loginOrigin('github.com/login')).toBe('https://github.com');
    expect(loginOrigin('http://router.local:8080/admin')).toBe('http://router.local:8080');
    expect(loginOrigin('androidapp://com.example.app')).toBe('androidapp://com.example.app');
    expect(loginOrigin('not a url')).toBeUndefined();
    expect(loginOrigin('')).toBeUndefined();
  });
});

describe('isSameLogin', () => {
  it('needs a site in common and the same username, ignoring case', () => {
    const saved = login('a', ['https://github.com/login'], 'Octocat');
    expect(isSameLogin(saved, draft(['github.com'], 'octocat '))).toBe(true);
    expect(isSameLogin(saved, draft(['github.com'], 'someone-else'))).toBe(false);
    expect(isSameLogin(saved, draft(['gist.github.com'], 'octocat'))).toBe(false);
    expect(isSameLogin(saved, draft(['http://github.com'], 'octocat'))).toBe(false);
  });

  it('matches two logins without a username for the same site', () => {
    expect(isSameLogin(login('a', ['https://router.local'], undefined), draft(['https://router.local']))).toBe(true);
  });

  it('never compares logins without a website, the item itself or the trash', () => {
    expect(isSameLogin(login('a', [], 'me'), draft([], 'me'))).toBe(false);
    expect(isSameLogin(login('a', ['github.com'], 'me', { deletedAt: '2026-02-01T00:00:00Z' }), draft(['github.com'], 'me'))).toBe(false);
    expect(isSameLogin(login('a', ['github.com'], 'me'), { ...draft(['github.com'], 'me'), id: 'a' })).toBe(false);
  });
});

describe('findSameLogin', () => {
  const items = [login('other', ['https://example.com'], 'me'), login('gh-2', ['https://github.com'], 'second'), login('gh', ['https://github.com'], 'octocat')];

  it('reads only logins for the same site, and returns the one with the same username', async () => {
    const getItem = vi.fn(async (id: string) => items.find((item) => item.id === id)!);
    const found = await findSameLogin(items.map(summary), draft(['https://github.com/session'], 'octocat'), getItem);
    expect(found?.id).toBe('gh');
    expect(getItem.mock.calls.map(([id]) => id)).toEqual(['gh-2', 'gh']);
  });

  it('finds nothing for an edit, another username or an unreadable item', async () => {
    const getItem = vi.fn(async (id: string) => items.find((item) => item.id === id)!);
    expect(await findSameLogin(items.map(summary), { ...draft(['github.com'], 'octocat'), id: 'x' }, getItem)).toBeUndefined();
    expect(await findSameLogin(items.map(summary), draft(['github.com'], 'nobody'), getItem)).toBeUndefined();
    expect(await findSameLogin(items.map(summary), draft(['github.com'], 'octocat'), () => Promise.reject(new Error('locked')))).toBeUndefined();
  });

  it('only looks at logins', () => {
    const note = { ...summary(login('n', ['https://github.com'], 'octocat')), type: 'secureNote' } as ItemSummary;
    expect(sameSiteLogins([note], draft(['github.com'], 'octocat'))).toEqual([]);
  });
});
