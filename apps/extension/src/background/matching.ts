// Which saved logins belong to a page, through the core's matching module (plan 12, E): registrable
// domain from the Public Suffix List, equivalent domains, per-URL match modes, and look-alikes
// (`paypal.com.evil.io`, homographs) that never match. On top of that the extension is stricter
// than the core's warning: a login saved for an https site is never offered on its plain-http twin.
// Under the default mode (`subdomains`) a login saved for another part of the page's site
// (`shop.example.com` on `login.example.com`) isn't a match: the core lists those apart
// (`otherParts`), to show one tap away and to fill only when the user picks one.

import type { ItemMatch, MatchCandidate, MatchOptions, OtherPart } from '@octapass/core/full';
import type { ItemSummary } from '@octapass/vault-client';

export interface MatchingCore {
  matchItems(url: string, items: MatchCandidate[], options: MatchOptions | undefined): ItemMatch[];
  /** What `matchItems` left out because it's on another part of the page's registrable domain, by host. */
  otherParts(url: string, items: MatchCandidate[], options: MatchOptions | undefined): OtherPart[];
  registrableDomain(url: string): string | undefined;
  /** The page's origin as a login's website (`https://login.example.com`); undefined for what isn't a website. */
  websiteForPage(url: string): string | undefined;
}

/** A login for another part of the page's site, with where it's saved. */
export interface OtherPartLogin {
  item: ItemSummary;
  host: string;
  site: string;
}

type Matchable = { id: string; urls?: string[]; urlMatch?: MatchCandidate['urlMatch'] };
const candidate = ({ id, urls, urlMatch }: Matchable): MatchCandidate => ({ id, urls, ...(urlMatch && { urlMatch }) });

const isLocal = (hostname: string) => hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '127.0.0.1' || hostname === '[::1]';

/** A page Octa Pass may fill: http(s) only. */
export function webPage(url: string): URL | undefined {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/** An https login on its plain-http twin (except on this computer): never offered. */
const downgrade = (m: { schemeMismatch: boolean }, page: URL) => m.schemeMismatch && page.protocol === 'http:' && !isLocal(page.hostname);

const loginsById = (summaries: ItemSummary[]) =>
  new Map(summaries.filter((s) => (s.type === 'login' || s.type === 'password') && !s.deletedAt && s.urls?.length).map((s) => [s.id, s]));

export class Matcher {
  /** The user's equivalent domains, kept current by the service worker as the vault changes. */
  private options: MatchOptions | undefined;

  constructor(private readonly core: MatchingCore) {}

  useOptions(options: MatchOptions | undefined): void {
    this.options = options;
  }

  /** The core's matches for `pageUrl`, without https logins offered on plain http. */
  matches(candidates: MatchCandidate[], pageUrl: string): ItemMatch[] {
    const page = webPage(pageUrl);
    if (!page || !candidates.length) return [];
    let matches: ItemMatch[];
    try {
      matches = this.core.matchItems(pageUrl, candidates, this.options);
    } catch {
      return [];
    }
    return matches.filter((m) => !downgrade(m, page));
  }

  /** The core's other parts of `pageUrl`'s site, by the same https rule. */
  otherParts(candidates: MatchCandidate[], pageUrl: string): OtherPart[] {
    const page = webPage(pageUrl);
    if (!page || !candidates.length) return [];
    try {
      return this.core.otherParts(pageUrl, candidates, this.options).filter((m) => !downgrade(m, page));
    } catch {
      return [];
    }
  }

  /** Logins and passwords for `pageUrl`, best match first. Not those for other parts of its site. */
  logins(summaries: ItemSummary[], pageUrl: string): ItemSummary[] {
    const byId = loginsById(summaries);
    return this.matches([...byId.values()].map(candidate), pageUrl).map((m) => byId.get(m.id)!);
  }

  /**
   * Logins saved for `pageUrl`'s own host (or by a "starts with" or regex rule that takes it), on the
   * same scheme: the only ones a fill on page load may use. Not a domain above or below it.
   */
  ownHostLogins(summaries: ItemSummary[], pageUrl: string): ItemSummary[] {
    const byId = loginsById(summaries);
    return this.matches([...byId.values()].map(candidate), pageUrl)
      .filter((m) => m.quality === 'exact' && !m.schemeMismatch)
      .map((m) => byId.get(m.id)!);
  }

  /** Logins and passwords for other parts of `pageUrl`'s site, by host: offered only when asked for. */
  otherLogins(summaries: ItemSummary[], pageUrl: string): OtherPartLogin[] {
    const byId = loginsById(summaries);
    return this.otherParts([...byId.values()].map(candidate), pageUrl).map((m) => ({ item: byId.get(m.id)!, host: m.host, site: m.site }));
  }

  /** Where an item with these URLs is saved, when it's for another part of `pageUrl`'s site (and not for the page itself). */
  otherPart(item: Omit<Matchable, 'id'>, pageUrl: string): OtherPart | undefined {
    if (!item.urls?.length) return undefined;
    return this.otherParts([candidate({ id: 'item', ...item })], pageUrl)[0];
  }

  /** API credentials for `pageUrl`, by the same rule, best match first. */
  apiCredentials(summaries: ItemSummary[], pageUrl: string): ItemSummary[] {
    const byId = new Map(summaries.filter((s) => s.type === 'apiCredential' && !s.deletedAt && s.urls?.length).map((s) => [s.id, s]));
    return this.matches([...byId.values()].map(candidate), pageUrl).map((m) => byId.get(m.id)!);
  }

  /** Whether an item with these URLs, under their match modes, belongs to `pageUrl`. */
  belongs(item: { urls?: string[]; urlMatch?: MatchCandidate['urlMatch'] }, pageUrl: string): boolean {
    return Boolean(item.urls?.length) && this.matches([candidate({ id: 'item', ...item })], pageUrl).length > 0;
  }

  /** Same registrable domain (or hostname, for IPs and `localhost`), whatever the scheme and port. */
  sameSite(a: string, b: string): boolean {
    const site = (url: string) => {
      const page = webPage(url);
      return page && (this.core.registrableDomain(url) ?? page.hostname);
    };
    const first = site(a);
    return first !== undefined && first === site(b);
  }

  /** What to add to a login so it's for `pageUrl`'s own part of the site: its origin. */
  website(pageUrl: string): string | undefined {
    if (!webPage(pageUrl)) return undefined;
    try {
      return this.core.websiteForPage(pageUrl);
    } catch {
      return undefined;
    }
  }

  /** The registrable domain, or the host for IPs and `localhost`. */
  site(url: string): string | undefined {
    const page = webPage(url);
    if (!page) return undefined;
    return this.core.registrableDomain(url) ?? page.host;
  }
}
