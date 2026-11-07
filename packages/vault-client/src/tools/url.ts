import { URL_MATCH_MODES, type UrlMatchMode } from '../types';

/** The hostname of a URL, tolerating a missing scheme ('github.com/login'); drops a leading 'www.'. */
export function hostnameOf(url: string): string | undefined {
  const text = url.trim();
  // Rejects mailto:, tel: and the like, but not 'example.com:8443'.
  if (!text || /\s/.test(text) || /^[a-z][a-z\d+.-]*:(?!\/\/|\d)/i.test(text)) return undefined;
  let parsed: URL;
  try {
    parsed = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(text) ? text : `https://${text}`);
  } catch {
    return undefined;
  }
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  return hostname ? hostname.replace(/^www\./, '') : undefined;
}

// A stand-in for the Public Suffix List, which lands with autofill. Until then these common two-label
// suffixes keep 'bbc.co.uk' from collapsing to 'co.uk'.
const TWO_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
  'co.nz', 'org.nz', 'net.nz', 'govt.nz', 'ac.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in',
  'co.za', 'org.za', 'com.mx', 'org.mx', 'com.ar', 'com.co', 'com.pe', 'com.cn', 'net.cn', 'org.cn',
  'com.hk', 'com.sg', 'com.tw', 'com.tr', 'com.my', 'com.ph', 'com.vn', 'com.pk', 'com.ng', 'com.eg',
  'com.sa', 'com.ua', 'co.kr', 'or.kr', 'co.il', 'org.il', 'co.id', 'or.id', 'co.th', 'in.th',
]);

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** The registrable domain (eTLD+1) of a hostname, approximated: 'accounts.google.com' → 'google.com'. */
export function registrableDomain(hostname: string): string {
  const host = hostname.trim().toLowerCase().replace(/\.$/, '');
  if (IPV4.test(host) || host.includes(':')) return host;
  const labels = host.split('.');
  const take = labels.length > 2 && TWO_LABEL_SUFFIXES.has(labels.slice(-2).join('.')) ? 3 : 2;
  return labels.slice(-take).join('.');
}

const WELL_KNOWN_CHANGE_PASSWORD = '/.well-known/change-password';

function parsedWebUrl(url: string): URL | undefined {
  const text = url.trim();
  if (!text || /\s/.test(text) || /^[a-z][a-z\d+.-]*:(?!\/\/|\d)/i.test(text)) return undefined;
  try {
    const parsed = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(text) ? text : `https://${text}`);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/** This device or the local network, where a site can't get a public certificate. */
export function isLocalHost(hostname: string): boolean {
  const host = hostname.trim().toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.lan') || host.endsWith('.home.arpa')) return true;
  if (!host.includes('.') && !host.includes(':')) return true;
  if (host.includes(':')) return host === '::1' || /^f[cd]/.test(host) || /^fe[89ab]/.test(host);
  if (!IPV4.test(host)) return false;
  const [a, b] = host.split('.').map(Number) as [number, number];
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
}

/** The first `http://` website in a login's URLs, unless it's on this device or the local network. */
export function insecureUrl(urls: readonly string[] | undefined): string | undefined {
  return urls?.find((url) => {
    const parsed = parsedWebUrl(url);
    return parsed?.protocol === 'http:' && !isLocalHost(parsed.hostname);
  });
}

/**
 * The standard change-password address of a login's first website (W3C well-known URL). Always
 * `https` on the public internet, even for an `http://` login. The site redirects it to its own
 * page where it supports it; nothing is asked of the site before the user opens it.
 */
export function changePasswordUrl(urls: readonly string[] | undefined): string | undefined {
  for (const url of urls ?? []) {
    const parsed = parsedWebUrl(url);
    if (!parsed) continue;
    const scheme = parsed.protocol === 'http:' && isLocalHost(parsed.hostname) ? 'http' : 'https';
    return `${scheme}://${parsed.host}${WELL_KNOWN_CHANGE_PASSWORD}`;
  }
  return undefined;
}

/** How a saved website matches a page; missing means `baseDomain`. An unknown mode compares as text. */
type WebsiteMode = string | undefined;

interface Website {
  url: URL;
  /** Lower case, IDNs as punycode, without a trailing dot. */
  host: string;
  /** The port, or the scheme's default. */
  port: number;
}

/** A saved address as the autofill matcher reads it (`Site::parse` in octapass-core): http(s) only. */
function websiteOf(text: string): Website | undefined {
  const scheme = /^[a-z][a-z\d+.-]*:/i.exec(text);
  let explicit = false;
  if (scheme) {
    const rest = text.slice(scheme[0].length);
    if (rest.startsWith('//')) explicit = true;
    // 'localhost:8080' is a host and port, 'mailto:' a scheme.
    else if (!/^\d/.test(rest)) return undefined;
  }
  let url: URL;
  try {
    url = new URL(explicit ? text : `https://${text}`);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined;
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!host) return undefined;
  return { url, host, port: url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80 };
}

/**
 * Whether `other` is the website `kept` already is, so an item lists each site once (plan 07,
 * History 2026-11-05). The same rule as `same_website` in octapass-core, with the same tests. `kept`
 * is the one that stays; its match mode decides how the two are compared:
 *
 * - `subdomains` (the default) and `baseDomain`: the same host, ignoring case, a leading `www.`, the
 *   scheme, port, path, query and fragment. Hosts, not registrable domains: `a.example.com` and
 *   `b.example.com` stay two sites.
 * - `host`: the same host and port (the scheme's default port when none is written).
 * - `startsWith` and `never`: the same address written the standard way (lower-case scheme and
 *   host, no default port, `/` for an empty path). A trailing slash on a longer path counts.
 * - `regex`, on either URL: the same text.
 *
 * Something that isn't a web address is the same only as the same text.
 */
export function sameWebsite(kept: string, keptMode: WebsiteMode, other: string, otherMode: WebsiteMode): boolean {
  const [a, b] = [kept.trim(), other.trim()];
  if (a === b) return true;
  const known = (mode: WebsiteMode) => mode === undefined || (URL_MATCH_MODES as readonly string[]).includes(mode);
  if (keptMode === 'regex' || otherMode === 'regex' || !known(keptMode) || !known(otherMode)) return false;
  const [first, second] = [websiteOf(a), websiteOf(b)];
  if (!first || !second) return false;
  switch (keptMode ?? 'subdomains') {
    case 'subdomains':
    case 'baseDomain':
      return first.host.replace(/^www\./, '') === second.host.replace(/^www\./, '');
    case 'host':
      return first.host === second.host && first.port === second.port;
    default:
      return first.url.href === second.url.href;
  }
}

/** `urls` with each website once, in their order: the first of each group stays (see `sameWebsite`). */
export function uniqueWebsites(urls: readonly string[], urlMatch?: Readonly<Record<string, string>>): string[] {
  const kept: string[] = [];
  for (const url of urls) {
    if (!kept.some((k) => sameWebsite(k, urlMatch?.[k], url, urlMatch?.[url]))) kept.push(url);
  }
  return kept;
}

/** Whether `url`, with no mode of its own, is a website `urls` already has. */
export function hasWebsite(urls: readonly string[], urlMatch: Readonly<Record<string, string>> | undefined, url: string): boolean {
  return urls.some((k) => sameWebsite(k, urlMatch?.[k], url, undefined));
}

/** An overview's `urls` and `urlMatch` with repeated websites dropped, and their modes with them. */
export function withUniqueWebsites<T extends { urls?: string[]; urlMatch?: Record<string, UrlMatchMode> }>(overview: T): T {
  if (!overview.urls) return overview;
  const urls = uniqueWebsites(overview.urls, overview.urlMatch);
  if (urls.length === overview.urls.length) return overview;
  const next = { ...overview, urls };
  if (overview.urlMatch) {
    const modes = Object.entries(overview.urlMatch).filter(([url]) => urls.includes(url));
    if (modes.length) next.urlMatch = Object.fromEntries(modes);
    else delete next.urlMatch;
  }
  return next;
}
