// Logins the vault already has, so saving a new one can say so instead of quietly adding a copy.
// The rule is the importer's (crates/octapass-core `import::reimport`): the same site, told by the
// scheme, host without `www.` and port, and the same username, ignoring case. A login without a
// website isn't compared: two of those are as likely different things as the same one.

import type { Item, ItemDraft, ItemSummary, LoginDetails } from './types';

/** `https://example.com` for `https://www.Example.com/login?x`; `undefined` when it isn't a URL. */
export function loginOrigin(url: string): string | undefined {
  const text = url.trim();
  if (!text || /\s/.test(text)) return undefined;
  let parsed: URL;
  try {
    parsed = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(text) ? text : `https://${text}`);
  } catch {
    return undefined;
  }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
  if (!host) return undefined;
  return `${parsed.protocol}//${host}${parsed.port ? `:${parsed.port}` : ''}`;
}

function origins(urls: readonly string[] | undefined): Set<string> {
  return new Set((urls ?? []).map(loginOrigin).filter((origin): origin is string => Boolean(origin)));
}

const username = (details: unknown) => ((details as LoginDetails | undefined)?.username ?? '').trim().toLowerCase();

/** Live logins among `items` with a website on the same site as one of `draft`'s. */
export function sameSiteLogins(items: readonly ItemSummary[], draft: ItemDraft): ItemSummary[] {
  if (draft.overview.type !== 'login') return [];
  const wanted = origins(draft.overview.urls);
  if (wanted.size === 0) return [];
  return items.filter((item) => item.type === 'login' && !item.deletedAt && item.id !== draft.id && [...origins(item.urls)].some((origin) => wanted.has(origin)));
}

/** Whether `item` is the login `draft` would add again: a website in common and the same username. */
export function isSameLogin(item: Pick<Item, 'id' | 'overview' | 'details' | 'deletedAt'>, draft: ItemDraft): boolean {
  if (item.overview.type !== 'login' || draft.overview.type !== 'login' || item.deletedAt || item.id === draft.id) return false;
  const wanted = origins(draft.overview.urls);
  return [...origins(item.overview.urls)].some((origin) => wanted.has(origin)) && username(item.details) === username(draft.details);
}

/**
 * The login already saved that `draft`, a new login, would copy, or `undefined`. `getItem` reads a
 * candidate's username, which list rows don't carry; only logins for the same site are read.
 */
export async function findSameLogin(items: readonly ItemSummary[], draft: ItemDraft, getItem: (id: string) => Promise<Item>): Promise<Item | undefined> {
  if (draft.id) return undefined;
  for (const summary of sameSiteLogins(items, draft)) {
    const item = await getItem(summary.id).catch(() => undefined);
    if (item && isSameLogin(item, draft)) return item;
  }
  return undefined;
}
