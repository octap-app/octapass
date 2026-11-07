import { arrangeItems, combineSites, firstLetter, siteHost, siteOf, sortItems, type ListEntry } from './listOrder';
import type { ItemSummary } from './types';

let next = 0;
function row(title: string, overrides: Partial<ItemSummary> = {}): ItemSummary {
  next += 1;
  return {
    id: `id-${String(next).padStart(3, '0')}`,
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

describe('firstLetter', () => {
  it('files Latin titles under their capital letter without accents', () => {
    expect(firstLetter('github')).toBe('G');
    expect(firstLetter('  Éclair bank')).toBe('E');
    expect(firstLetter('ﬁdelity')).toBe('F');
    expect(firstLetter('Ørsted')).toBe('Ø');
  });

  it('files Arabic titles under the Arabic letter, with every alef form under alef', () => {
    expect(firstLetter('بنك الخليج')).toBe('ب');
    expect(firstLetter('أمازون')).toBe('ا');
    expect(firstLetter('إتصالات')).toBe('ا');
    expect(firstLetter('آبل')).toBe('ا');
    expect(firstLetter('ٱلبريد')).toBe('ا');
  });

  it('files digits, symbols, emoji and empty titles under #', () => {
    for (const title of ['1Password import', '٣ بنوك', '@work', '🔑 keys', '', '   ']) expect(firstLetter(title)).toBe('#');
  });
});

describe('sortItems', () => {
  it('sorts names for the language: accents and case ignored, numbers by value', () => {
    const items = [row('item 10'), row('Item 2'), row('éclair'), row('Apple'), row('apple')];
    expect(titles(sortItems(items, 'name', 'en'))).toEqual(['Apple', 'apple', 'éclair', 'Item 2', 'item 10']);
    expect(titles(sortItems(items, 'nameDesc', 'en'))).toEqual(['item 10', 'Item 2', 'éclair', 'Apple', 'apple']);
  });

  it('breaks ties on the id, so equal names keep one order', () => {
    const a = row('Same', { id: 'b' });
    const b = row('same', { id: 'a' });
    expect(sortItems([a, b], 'name', 'en')).toEqual([b, a]);
    expect(sortItems([b, a], 'name', 'en')).toEqual([b, a]);
  });

  it('puts Arabic titles in Arabic alphabetical order', () => {
    const items = [row('مصرف'), row('بنك'), row('أمازون'), row('تويتر')];
    expect(titles(sortItems(items, 'name', 'ar'))).toEqual(['أمازون', 'بنك', 'تويتر', 'مصرف']);
  });

  it('sorts by date added, newest or oldest first, and by last change', () => {
    const old = row('Old', { createdAt: '2025-01-01T00:00:00Z', updatedAt: '2026-05-01T00:00:00Z' });
    const mid = row('Mid', { createdAt: '2025-06-01T00:00:00.000Z', updatedAt: '2025-06-01T00:00:00Z' });
    const fresh = row('Fresh', { createdAt: '2026-02-01T00:00:00+00:00', updatedAt: '2026-02-01T00:00:00Z' });
    expect(titles(sortItems([mid, old, fresh], 'newest'))).toEqual(['Fresh', 'Mid', 'Old']);
    expect(titles(sortItems([mid, old, fresh], 'oldest'))).toEqual(['Old', 'Mid', 'Fresh']);
    expect(titles(sortItems([mid, old, fresh], 'changed'))).toEqual(['Old', 'Fresh', 'Mid']);
  });

  it('uses the last change for date added when a summary has none', () => {
    const missing = row('No date', { createdAt: '', updatedAt: '2027-01-01T00:00:00Z' });
    expect(titles(sortItems([row('Dated'), missing], 'newest'))).toEqual(['No date', 'Dated']);
  });

  it('leaves the input alone', () => {
    const items = [row('B'), row('A')];
    sortItems(items, 'name');
    expect(titles(items)).toEqual(['B', 'A']);
  });
});

describe('arrangeItems', () => {
  it('groups by type in a fixed order, sorted inside each section', () => {
    const items = [row('Visa', { type: 'card' }), row('Wi-Fi', { type: 'secureNote' }), row('Zoom'), row('Amazon'), row('Work', { type: 'identity' }), row('Next', { type: 'futureType' as never })];
    const sections = arrangeItems(items, { sort: 'name', grouping: 'type', locale: 'en' });
    expect(sections.map((s) => [s.key, titles(s.items)])).toEqual([
      ['login', ['Amazon', 'Zoom']],
      ['card', ['Visa']],
      ['identity', ['Work']],
      ['secureNote', ['Wi-Fi']],
      ['futureType', ['Next']],
    ]);
  });

  it('groups by first letter: Latin A–Z, Arabic letters, then #', () => {
    const items = [row('بنك'), row('Zoom'), row('2FA backup'), row('amazon'), row('أمازون'), row('Apple'), row('#tag')];
    const english = arrangeItems(items, { sort: 'name', grouping: 'letter', locale: 'en' });
    expect(english.map((s) => [s.key, titles(s.items)])).toEqual([
      ['A', ['amazon', 'Apple']],
      ['Z', ['Zoom']],
      ['ا', ['أمازون']],
      ['ب', ['بنك']],
      ['#', ['#tag', '2FA backup']],
    ]);
    // An Arabic reader's collation puts Arabic letters before Latin ones; # stays last.
    const arabic = arrangeItems(items, { sort: 'name', grouping: 'letter', locale: 'ar' });
    expect(arabic.map((s) => s.key)).toEqual(['ا', 'ب', 'A', 'Z', '#']);
  });

  it('runs the letters backwards for Z–A, still with # last', () => {
    const items = [row('Apple'), row('Zoom'), row('42')];
    expect(arrangeItems(items, { sort: 'nameDesc', grouping: 'letter', locale: 'en' }).map((s) => s.key)).toEqual(['Z', 'A', '#']);
  });

  it('keeps the chosen date order inside letter sections', () => {
    const items = [row('Alpha', { createdAt: '2025-01-01T00:00:00Z' }), row('Avocado', { createdAt: '2026-01-01T00:00:00Z' })];
    const [section] = arrangeItems(items, { sort: 'newest', grouping: 'letter', locale: 'en' });
    expect(titles(section!.items)).toEqual(['Avocado', 'Alpha']);
  });

  it('groups by vault in the given order, unknown vaults last', () => {
    const items = [row('A', { vaultId: 'family' }), row('B', { vaultId: 'gone' }), row('C', { vaultId: 'personal' })];
    const sections = arrangeItems(items, { sort: 'name', grouping: 'vault', vaultOrder: ['personal', 'family'] });
    expect(sections.map((s) => s.key)).toEqual(['personal', 'family', 'gone']);
  });

  it('makes one section without grouping, and none for an empty list', () => {
    expect(arrangeItems([row('B'), row('A')], { sort: 'name', grouping: 'none' }).map((s) => [s.key, titles(s.items)])).toEqual([['', ['A', 'B']]]);
    expect(arrangeItems([], { sort: 'name', grouping: 'none' })).toEqual([]);
    expect(arrangeItems([], { sort: 'name', grouping: 'type' })).toEqual([]);
  });
});

const shape = (entries: ListEntry[] | undefined) => entries?.map((entry) => (entry.kind === 'site' ? [entry.host, titles(entry.items)] : entry.item.title));
const site = (title: string, url: string, overrides: Partial<ItemSummary> = {}) => row(title, { urls: [url], ...overrides });

describe('siteHost', () => {
  it('ignores the scheme, case, a leading www., a trailing dot and the path', () => {
    for (const url of ['https://a.example.com/login', 'http://A.Example.COM', 'a.example.com', 'https://www.a.example.com/', 'https://a.example.com./x?y=1']) {
      expect(siteHost(url)).toBe('a.example.com');
    }
  });

  it('keeps subdomains apart, and only drops www. at the start', () => {
    expect(siteHost('https://b.example.com')).toBe('b.example.com');
    expect(siteHost('https://example.com')).toBe('example.com');
    expect(siteHost('https://shop.www.example.com')).toBe('shop.www.example.com');
  });

  it("keeps a port other than the scheme's default", () => {
    expect(siteHost('https://nas.local:5000/')).toBe('nas.local:5000');
    expect(siteHost('nas.local:8080')).toBe('nas.local:8080');
    expect(siteHost('https://example.com:443/')).toBe('example.com');
    expect(siteHost('http://example.com:80')).toBe('example.com');
    expect(siteHost('http://192.168.1.1:8443')).toBe('192.168.1.1:8443');
  });

  it("returns nothing for what isn't a website", () => {
    for (const url of ['', '   ', 'mailto:me@example.com', 'tel:+971500000000', 'not a url']) expect(siteHost(url)).toBeUndefined();
  });
});

describe('siteOf', () => {
  it("is a login's first URL", () => {
    expect(siteOf(row('Work', { urls: ['https://mail.example.com', 'https://example.com'] }))).toBe('mail.example.com');
    expect(siteOf(row('No URL'))).toBeUndefined();
    expect(siteOf(row('Empty URL', { urls: [''] }))).toBeUndefined();
    expect(siteOf(row('Card', { type: 'card', urls: ['https://bank.example'] }))).toBeUndefined();
  });
});

describe('combineSites', () => {
  it('combines two or more logins for the same host, and leaves single logins and items without a URL alone', () => {
    const items = [site('Work', 'https://a.xxx.com'), site('Personal', 'a.xxx.com/login'), site('Old', 'https://WWW.a.xxx.com'), site('Other', 'https://b.xxx.com'), row('Notes'), row('Notes too')];
    expect(shape(combineSites(sortItems(items, 'name'), 'name'))).toEqual([['a.xxx.com', ['Old', 'Personal', 'Work']], 'Notes', 'Notes too', 'Other']);
  });

  it('files a site by its host in name order, backwards for Z to A', () => {
    const items = [site('Zed', 'https://m.example'), site('Alpha', 'https://m.example'), row('Lima'), row('November')];
    expect(shape(combineSites(sortItems(items, 'name'), 'name'))).toEqual(['Lima', ['m.example', ['Alpha', 'Zed']], 'November']);
    expect(shape(combineSites(sortItems(items, 'nameDesc'), 'nameDesc'))).toEqual(['November', ['m.example', ['Zed', 'Alpha']], 'Lima']);
  });

  it('puts a site where its newest login is when sorting by date added', () => {
    const items = [
      site('Old', 'https://m.example', { createdAt: '2026-01-01T00:00:00.000Z' }),
      row('Middle', { createdAt: '2026-02-01T00:00:00.000Z' }),
      site('New', 'https://m.example', { createdAt: '2026-03-01T00:00:00.000Z' }),
    ];
    expect(shape(combineSites(sortItems(items, 'newest'), 'newest'))).toEqual([['m.example', ['New', 'Old']], 'Middle']);
    expect(shape(combineSites(sortItems(items, 'oldest'), 'oldest'))).toEqual([['m.example', ['Old', 'New']], 'Middle']);
  });

  it('puts a site where its last changed login is', () => {
    const items = [
      site('A', 'https://m.example', { updatedAt: '2026-01-01T00:00:00.000Z' }),
      row('B', { updatedAt: '2026-02-01T00:00:00.000Z' }),
      site('C', 'https://m.example', { updatedAt: '2026-03-01T00:00:00.000Z' }),
    ];
    expect(shape(combineSites(sortItems(items, 'changed'), 'changed'))).toEqual([['m.example', ['C', 'A']], 'B']);
  });
});

describe('arrangeItems with combineSites', () => {
  it('leaves entries out unless asked', () => {
    expect(arrangeItems([site('A', 'x.example'), site('B', 'x.example')], { sort: 'name', grouping: 'none' })[0]!.entries).toBeUndefined();
  });

  it('combines inside each type section and keeps every item in the section', () => {
    const sections = arrangeItems([site('A', 'x.example'), site('B', 'x.example'), row('Visa', { type: 'card' }), row('C')], { sort: 'name', grouping: 'type', combineSites: true });
    expect(sections.map((section) => [section.key, titles(section.items), shape(section.entries)])).toEqual([
      ['login', ['A', 'B', 'C'], ['C', ['x.example', ['A', 'B']]]],
      ['card', ['Visa'], ['Visa']],
    ]);
  });

  it('combines inside each vault section, never across vaults', () => {
    const sections = arrangeItems([site('A', 'x.example'), site('B', 'x.example', { vaultId: 'v2' })], { sort: 'name', grouping: 'vault', combineSites: true, vaultOrder: ['v1', 'v2'] });
    expect(sections.map((section) => shape(section.entries))).toEqual([['A'], ['B']]);
  });

  it("files a site under its host's first letter when grouping by letter", () => {
    const sections = arrangeItems([site('Work', 'github.com'), site('Personal', 'github.com'), site('Solo', 'gitlab.com'), row('Alpha')], { sort: 'name', grouping: 'letter', combineSites: true });
    expect(sections.map((section) => [section.key, shape(section.entries)])).toEqual([
      ['A', ['Alpha']],
      ['G', [['github.com', ['Personal', 'Work']]]],
      ['S', ['Solo']],
    ]);
  });
});

describe('project grouping', () => {
  it('groups environments by project, with the project-less last', () => {
    const items = [
      row('Shop API (dev)', { type: 'environment', project: 'shop-api' }),
      row('Blog (prod)', { type: 'environment', project: 'blog' }),
      row('Loose variable', { type: 'environment' }),
      row('Shop API (shared)', { type: 'environment', project: 'shop-api' }),
    ];
    const sections = arrangeItems(items, { sort: 'name', grouping: 'project', locale: 'en' });
    expect(sections.map((section) => [section.key, titles(section.items)])).toEqual([
      ['blog', ['Blog (prod)']],
      ['shop-api', ['Shop API (dev)', 'Shop API (shared)']],
      ['', ['Loose variable']],
    ]);
  });
});
