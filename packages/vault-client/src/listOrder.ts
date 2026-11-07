// How an item list is sorted and split into sections. Pure functions over summaries, so every app
// arranges lists the same way; the labels for sections come from each app's catalog.

import { hostnameOf } from './tools/url';
import type { ItemSummary, ItemType } from './types';

export type ListSort = 'name' | 'nameDesc' | 'newest' | 'oldest' | 'changed';
export type ListGrouping = 'type' | 'letter' | 'vault' | 'project' | 'none';

export const LIST_SORTS: readonly ListSort[] = ['name', 'nameDesc', 'newest', 'oldest', 'changed'];
export const LIST_GROUPINGS: readonly ListGrouping[] = ['type', 'letter', 'vault', 'project', 'none'];

/** The order type sections come in. Types from a newer client follow, by name. */
export const TYPE_SECTION_ORDER: readonly ItemType[] = ['login', 'password', 'card', 'identity', 'secureNote', 'wifi', 'sshKey', 'certificate', 'key', 'document', 'environment', 'bankAccount', 'idDocument', 'cryptoWallet', 'apiCredential', 'database', 'softwareLicense', 'custom', 'customTemplate', 'maskedEmailProvider'];

/** The section for titles that don't start with a letter: digits, symbols, emoji, nothing. */
export const OTHER_LETTER = '#';

/** A row of a list: one item, or the logins for one website shown as a single row. */
export type ListEntry = { kind: 'item'; item: ItemSummary } | SiteEntry;

export interface SiteEntry {
  kind: 'site';
  host: string;
  items: ItemSummary[];
}

export interface ListSection {
  /** The item type, the letter, the vault id, or `''` for the one section of an ungrouped list. */
  key: string;
  items: ItemSummary[];
  /** The rows, when logins for the same website are combined: the same items, in the same order. */
  entries?: ListEntry[];
}

const collators = new Map<string, Intl.Collator>();

/** Name order for the reader's language: accents and case don't matter, and "Item 2" comes before "Item 10". */
export function nameCollator(locale?: string): Intl.Collator {
  const key = locale ?? '';
  let collator = collators.get(key);
  if (!collator) {
    collator = new Intl.Collator(locale, { sensitivity: 'base', numeric: true });
    collators.set(key, collator);
  }
  return collator;
}

const byId = (a: ItemSummary, b: ItemSummary) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
const byKey = (a: ListSection, b: ListSection) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
const time = (text: string | undefined) => (text ? Date.parse(text) || 0 : 0);
// Summaries from an older native host may not carry `createdAt` yet.
const created = (item: ItemSummary) => time(item.createdAt || item.updatedAt);

/** A sorted copy. Equal names and dates fall back to the name, then the id, so the order never jumps. */
export function sortItems(items: readonly ItemSummary[], sort: ListSort, locale?: string): ItemSummary[] {
  const collator = nameCollator(locale);
  const byName = (a: ItemSummary, b: ItemSummary) => collator.compare(a.title, b.title);
  const compare: Record<ListSort, (a: ItemSummary, b: ItemSummary) => number> = {
    name: (a, b) => byName(a, b) || byId(a, b),
    nameDesc: (a, b) => byName(b, a) || byId(a, b),
    newest: (a, b) => created(b) - created(a) || byName(a, b) || byId(a, b),
    oldest: (a, b) => created(a) - created(b) || byName(a, b) || byId(a, b),
    changed: (a, b) => time(b.updatedAt) - time(a.updatedAt) || byName(a, b) || byId(a, b),
  };
  return [...items].sort(compare[sort]);
}

// Letters that are written differently at the start of a word but sorted as one: alef with hamza
// or madda (removed with the marks below) and alef wasla are all filed under alef.
const SAME_LETTER: Record<string, string> = { 'ٱ': 'ا' };

/**
 * The section a title is filed under: its first letter without accents, in capitals where the
 * script has them (É → E, أ → ا), or `#` when it doesn't start with a letter.
 */
export function firstLetter(title: string, locale?: string): string {
  const [first] = title.trim().normalize('NFKD').replace(/\p{M}/gu, '');
  if (!first || !/\p{L}/u.test(first)) return OTHER_LETTER;
  const [upper = first] = first.toLocaleUpperCase(locale);
  return SAME_LETTER[upper] ?? upper;
}

function sectionsBy(items: readonly ItemSummary[], keyOf: (item: ItemSummary) => string): ListSection[] {
  const sections = new Map<string, ItemSummary[]>();
  for (const item of items) {
    const key = keyOf(item);
    const list = sections.get(key);
    if (list) list.push(item);
    else sections.set(key, [item]);
  }
  return [...sections].map(([key, list]) => ({ key, items: list }));
}

/**
 * The website a URL belongs to, for combining logins: its host in lower case, without the scheme,
 * a leading "www." or a trailing dot. A port other than the scheme's default is kept, since
 * `nas.local:5000` and `nas.local:8080` are usually different apps. `a.example.com` and
 * `b.example.com` are different sites.
 */
export function siteHost(url: string): string | undefined {
  const hostname = hostnameOf(url);
  if (!hostname) return undefined;
  const text = url.trim();
  const { port } = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(text) ? text : `https://${text}`);
  return port ? `${hostname}:${port}` : hostname;
}

/** The site a login is combined under: the host of its first URL, its primary website. Other items never are. */
export function siteOf(item: ItemSummary): string | undefined {
  const url = item.urls?.[0];
  return item.type === 'login' && url ? siteHost(url) : undefined;
}

function siteCounts(items: readonly ItemSummary[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const item of items) {
    const site = siteOf(item);
    if (site) counts.set(site, (counts.get(site) ?? 0) + 1);
  }
  return counts;
}

/**
 * Rows for sorted items, with two or more logins for the same site as one row. A site row takes the
 * place of its first login in date order, and its host's place in name order; its logins keep the
 * list's order.
 */
export function combineSites(sorted: readonly ItemSummary[], sort: ListSort, locale?: string): ListEntry[] {
  const counts = siteCounts(sorted);
  const sites = new Map<string, SiteEntry>();
  const entries: ListEntry[] = [];
  for (const item of sorted) {
    const site = siteOf(item);
    if (!site || counts.get(site)! < 2) {
      entries.push({ kind: 'item', item });
      continue;
    }
    const entry = sites.get(site);
    if (entry) entry.items.push(item);
    else {
      const created: SiteEntry = { kind: 'site', host: site, items: [item] };
      sites.set(site, created);
      entries.push(created);
    }
  }
  if (sort !== 'name' && sort !== 'nameDesc') return entries;
  const collator = nameCollator(locale);
  const name = (entry: ListEntry) => (entry.kind === 'site' ? entry.host : entry.item.title);
  const direction = sort === 'nameDesc' ? -1 : 1;
  // A stable sort, so a site and a title that compare equal keep the order they came in.
  return entries.sort((a, b) => direction * collator.compare(name(a), name(b)));
}

export interface ArrangeOptions {
  sort: ListSort;
  grouping: ListGrouping;
  /** Show two or more logins for the same website as one row (see `combineSites`). */
  combineSites?: boolean;
  /** The UI language, for name order and letters. */
  locale?: string;
  /** Vault ids in the order their sections come in; others follow. */
  vaultOrder?: readonly string[];
}

/**
 * Sorts the items, then splits them into sections that keep that order inside. Type sections come in
 * a fixed order, vault sections in `vaultOrder`, letters in name order (backwards for Z–A) with `#`
 * last. An ungrouped list is one section. With `combineSites`, each section's logins for the same
 * website become one entry; by first letter, those logins are filed under their host's letter.
 */
export function arrangeItems(items: readonly ItemSummary[], options: ArrangeOptions): ListSection[] {
  const sections = splitSections(items, options);
  if (!options.combineSites) return sections;
  return sections.map((section) => ({ ...section, entries: combineSites(section.items, options.sort, options.locale) }));
}

function splitSections(items: readonly ItemSummary[], { sort, grouping, locale, vaultOrder = [], combineSites: combine }: ArrangeOptions): ListSection[] {
  const sorted = sortItems(items, sort, locale);
  if (grouping === 'none') return sorted.length ? [{ key: '', items: sorted }] : [];
  const collator = nameCollator(locale);
  const rank = (order: readonly string[], key: string) => {
    const index = order.indexOf(key);
    return index === -1 ? order.length : index;
  };
  switch (grouping) {
    case 'type':
      return sectionsBy(sorted, (item) => item.type).sort((a, b) => rank(TYPE_SECTION_ORDER, a.key) - rank(TYPE_SECTION_ORDER, b.key) || collator.compare(a.key, b.key));
    case 'vault':
      return sectionsBy(sorted, (item) => item.vaultId).sort((a, b) => rank(vaultOrder, a.key) - rank(vaultOrder, b.key) || byKey(a, b));
    case 'project':
      // Environments with no project come last.
      return sectionsBy(sorted, (item) => item.project ?? '').sort((a, b) => Number(a.key === '') - Number(b.key === '') || collator.compare(a.key, b.key));
    case 'letter': {
      const direction = sort === 'nameDesc' ? -1 : 1;
      const counts = combine ? siteCounts(sorted) : undefined;
      const letterOf = (item: ItemSummary) => {
        const site = counts && siteOf(item);
        return firstLetter(site && counts.get(site)! > 1 ? site : item.title, locale);
      };
      return sectionsBy(sorted, letterOf).sort(
        (a, b) => Number(a.key === OTHER_LETTER) - Number(b.key === OTHER_LETTER) || direction * collator.compare(a.key, b.key),
      );
    }
  }
}
