import type { ItemSummary } from '@octapass/vault-client';
import { testCore } from '../test/core';
import { Matcher } from './matching';

const matcher = new Matcher(testCore);
const belongs = (saved: string, page: string) => matcher.belongs({ urls: [saved] }, page);

describe('Matcher', () => {
  it('matches subdomains of the same registrable domain, and equivalent domains', () => {
    expect(belongs('https://example.com', 'https://login.example.com/signin')).toBe(true);
    expect(belongs('example.com/login', 'https://www.example.com/')).toBe(true);
    expect(belongs('https://bbc.co.uk', 'https://account.bbc.co.uk')).toBe(true);
    expect(belongs('https://google.com', 'https://www.youtube.com/')).toBe(true);
  });

  it('refuses look-alikes', () => {
    expect(belongs('https://paypal.com', 'https://paypal.com.evil.io/login')).toBe(false);
    expect(belongs('https://paypal.com', 'https://paypa1.com/')).toBe(false);
    expect(belongs('https://example.com', 'https://example.com-account.net/')).toBe(false);
    expect(belongs('https://alice.github.io', 'https://mallory.github.io')).toBe(false);
    expect(belongs('https://a.co.uk', 'https://b.co.uk')).toBe(false);
  });

  it('never offers an https login on plain http, except on this computer', () => {
    expect(belongs('https://example.com', 'http://example.com/login')).toBe(false);
    expect(belongs('http://example.com', 'https://example.com/login')).toBe(true);
    expect(belongs('https://localhost:3000', 'http://localhost:3000/')).toBe(true);
  });

  it('applies a website match rule at fill time too', () => {
    const urls = ['https://app.example.com'];
    const rule = (mode: 'host' | 'never') => ({ urls, urlMatch: { [urls[0]!]: mode } });
    expect(matcher.belongs({ urls }, 'https://www.example.com')).toBe(true);
    expect(matcher.belongs(rule('host'), 'https://www.example.com')).toBe(false);
    expect(matcher.belongs(rule('host'), 'https://app.example.com/login')).toBe(true);
    expect(matcher.belongs(rule('never'), 'https://app.example.com/login')).toBe(false);
  });

  it("uses the user's equivalent domains, and leaves out built-in groups they turned off", () => {
    const own = new Matcher(testCore);
    own.useOptions({ equivalentDomains: [['example.com', 'example.org']], excludedDefaults: ['google.com'] });
    expect(own.belongs({ urls: ['https://example.com'] }, 'https://example.org')).toBe(true);
    expect(own.belongs({ urls: ['https://google.com'] }, 'https://www.youtube.com/')).toBe(false);
    expect(own.belongs({ urls: ['https://apple.com'] }, 'https://icloud.com')).toBe(true);
  });

  it('ignores pages that are not web pages', () => {
    expect(belongs('https://example.com', 'chrome://settings')).toBe(false);
    expect(matcher.site('chrome://settings')).toBeUndefined();
    expect(matcher.site('https://shop.example.co.uk/x')).toBe('example.co.uk');
    expect(matcher.site('http://localhost:8080/')).toBe('localhost:8080');
  });

  it('keeps logins for the site, exact host first, and skips the trash and other types', () => {
    const item = (id: string, urls: string[], extra: Partial<ItemSummary> = {}): ItemSummary => ({
      id,
      vaultId: 'v',
      type: 'login',
      title: id,
      urls,
      favorite: false,
      hasTotp: false,
      hasPasskey: false,
      createdAt: '2026-10-24T00:00:00Z',
      updatedAt: '2026-10-24T00:00:00Z',
      ...extra,
    });
    const items = [
      item('base', ['https://example.com']),
      item('exact', ['https://login.example.com']),
      item('other', ['https://example.org']),
      item('trashed', ['https://example.com'], { deletedAt: '2026-10-24T00:00:00Z' }),
      item('note', ['https://example.com'], { type: 'secureNote' }),
    ];
    expect(matcher.logins(items, 'https://login.example.com/signin').map((i) => i.id)).toEqual(['exact', 'base']);
  });

  describe('other parts of the site', () => {
    const item = (id: string, urls: string[], extra: Partial<ItemSummary> = {}): ItemSummary => ({
      id,
      vaultId: 'v',
      type: 'login',
      title: id,
      urls,
      favorite: false,
      hasTotp: false,
      hasPasskey: false,
      createdAt: '2026-11-05T00:00:00Z',
      updatedAt: '2026-11-05T00:00:00Z',
      ...extra,
    });
    const page = 'https://a.b.example.com/signin';
    const items = [
      item('sibling', ['https://shop.example.com']),
      item('cousin', ['https://c.b.example.com']),
      item('below', ['https://x.a.b.example.com']),
      item('top', ['https://www.example.com']),
      item('parent', ['https://b.example.com']),
      item('own', ['https://a.b.example.com/login']),
      item('elsewhere', ['https://example.org']),
    ];

    it('offers the page’s own host first, then the domains above it, nearest first, then those below', () => {
      expect(matcher.logins(items, page).map((i) => i.id)).toEqual(['own', 'parent', 'top', 'below']);
    });

    it('keeps the other parts apart, by host, with the domain they share', () => {
      expect(matcher.otherLogins(items, page).map(({ item, host, site }) => [item.id, host, site])).toEqual([
        ['cousin', 'c.b.example.com', 'example.com'],
        ['sibling', 'shop.example.com', 'example.com'],
      ]);
      expect(matcher.belongs({ urls: ['https://shop.example.com'] }, page)).toBe(false);
      expect(matcher.otherPart({ urls: ['https://shop.example.com'] }, page)).toMatchObject({ host: 'shop.example.com', site: 'example.com' });
      expect(matcher.otherPart({ urls: ['https://a.b.example.com'] }, page)).toBeUndefined();
      expect(matcher.otherPart({ urls: ['https://example.org'] }, page)).toBeUndefined();
      expect(matcher.otherPart({ urls: ['https://shop.example.com'] }, 'https://shop.example.com.evil.io/')).toBeUndefined();
    });

    it('matches another part when its website says “any host on the domain”', () => {
      const wide = item('wide', ['https://shop.example.com'], { urlMatch: { 'https://shop.example.com': 'baseDomain' } });
      expect(matcher.logins([wide], page).map((i) => i.id)).toEqual(['wide']);
      expect(matcher.otherLogins([wide], page)).toEqual([]);
    });

    it('never lists an https login on the plain-http page, and skips the trash and other types', () => {
      expect(matcher.otherLogins(items, 'http://a.b.example.com/')).toEqual([]);
      expect(matcher.otherLogins([item('plain', ['http://shop.example.com'])], 'http://a.b.example.com/').map((o) => o.item.id)).toEqual(['plain']);
      const skipped = [item('trashed', ['https://shop.example.com'], { deletedAt: '2026-11-05T00:00:00Z' }), item('note', ['https://shop.example.com'], { type: 'secureNote' })];
      expect(matcher.otherLogins(skipped, page)).toEqual([]);
    });

    it('names the website to add for the page: its origin', () => {
      expect(matcher.website('https://login.example.com/signin?next=/')).toBe('https://login.example.com');
      expect(matcher.website('chrome://settings')).toBeUndefined();
    });
  });
});
