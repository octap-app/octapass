// Website icons (plan 04, "website icons"): fetched through the user's Octa Pass server, which
// gets them from the sites themselves, and kept on the device so a long list isn't fetched again.
// Nothing here runs while the "Show website icons" setting is off.

import { openKeyValueStore } from './idb';
import { hostnameOf, registrableDomain } from './tools/url';

/** What the server said about one domain. */
export type IconAnswer =
  /** A PNG, at most 128 px a side. */
  | { kind: 'icon'; png: Uint8Array }
  /** The site has no usable icon: keep the initial. */
  | { kind: 'none' }
  /** The server doesn't fetch icons (`OCTAPASS_ICONS=off`): stop asking it. */
  | { kind: 'off' }
  /** Rate limited, offline or a server error: try again later, after `retryAfterMs` if given. */
  | { kind: 'retry'; retryAfterMs?: number };

/** Asks a server for a domain's icon. The apps do it natively, since their web view can't. */
export type IconFetch = (serverUrl: string, domain: string) => Promise<IconAnswer>;

/** How long the device keeps an icon, and a miss. The server keeps them as long. */
export const ICON_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const ICON_MISS_TTL_MS = 24 * 60 * 60 * 1000;
/** Requests in flight at once, so a long list doesn't flood the server. */
export const ICON_CONCURRENCY = 6;

const ICONS_OFF = 'https://octap.app/problems/icons-off';
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * The domain an item's icon is asked for: the registrable domain of its first URL, so the server
 * learns `bank.com` rather than `login.bank.com`. None for IP addresses, `localhost` and names
 * without a dot.
 */
export function iconDomain(urls: readonly string[] | undefined): string | undefined {
  const host = urls?.[0] ? hostnameOf(urls[0]) : undefined;
  if (!host || !host.includes('.') || IPV4.test(host) || host.includes(':') || host.endsWith('.localhost')) return undefined;
  if (!/^[a-z0-9.-]+$/.test(host)) return undefined;
  return registrableDomain(host);
}

/** `GET {server}/v1/icons/{domain}` with `fetch`: no cookies, no referrer, nothing else sent. */
export function serverIconFetch(fetchImpl: typeof fetch = (...args) => fetch(...args)): IconFetch {
  return async (serverUrl, domain) => {
    let response: Response;
    try {
      const origin = new URL(serverUrl).origin;
      response = await fetchImpl(`${origin}/v1/icons/${encodeURIComponent(domain)}`, {
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        headers: { accept: 'image/png' },
      });
    } catch {
      return { kind: 'retry' };
    }
    return iconAnswer(response.status, response.headers.get('content-type') ?? '', response.headers.get('retry-after'), () =>
      response.arrayBuffer().then((b) => new Uint8Array(b)),
    );
  };
}

/** Reads a server response into an answer. Shared with hosts that make the request themselves. */
export async function iconAnswer(status: number, contentType: string, retryAfter: string | null, body: () => Promise<Uint8Array>): Promise<IconAnswer> {
  try {
    if (status === 200 && contentType.startsWith('image/png')) return { kind: 'icon', png: await body() };
    if (status === 404 && contentType.includes('json')) {
      const problem = JSON.parse(new TextDecoder().decode(await body())) as { type?: string };
      return problem.type === ICONS_OFF ? { kind: 'off' } : { kind: 'none' };
    }
    if (status === 404 || status === 400 || status === 200) return { kind: 'none' };
    if (status === 429) {
      const seconds = Number(retryAfter);
      return Number.isFinite(seconds) && seconds > 0 ? { kind: 'retry', retryAfterMs: seconds * 1000 } : { kind: 'retry' };
    }
  } catch {
    // An unreadable body: treat it like a server error.
  }
  return { kind: 'retry' };
}

interface Entry {
  /** Missing for a remembered miss, or for "this server doesn't fetch icons". */
  png?: Uint8Array;
  expires: number;
}

/** Where the device keeps icons. Keys are hashes, so the store isn't a list of the user's sites. */
export interface IconStore {
  get(key: string): Promise<Entry | undefined>;
  set(key: string, entry: Entry): Promise<void>;
  clear(): Promise<void>;
}

export function memoryIconStore(): IconStore {
  const entries = new Map<string, Entry>();
  return {
    get: async (key) => entries.get(key),
    set: async (key, entry) => void entries.set(key, entry),
    clear: async () => entries.clear(),
  };
}

/** The device's icon cache in IndexedDB. The extension's pages and service worker share it. */
export const ICON_DB = 'octapass-icons';

export function idbIconStore(name = ICON_DB): IconStore {
  const store = openKeyValueStore(name).catch(() => undefined);
  return {
    get: async (key) => (await store)?.get<Entry>(key).catch(() => undefined),
    set: async (key, entry) => void (await (await store)?.set(key, entry).catch(() => undefined)),
    clear: async () => void (await (await store)?.clear().catch(() => undefined)),
  };
}

async function hashKey(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`openpass/icon:${text}`));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

export interface SiteIconLoaderOptions {
  fetchIcon: IconFetch;
  store: IconStore;
  concurrency?: number;
  now?: () => number;
}

/**
 * Loads icons for one server: from the device cache, else from the server, at most
 * `concurrency` at a time, once per domain however many rows ask.
 */
export class SiteIconLoader {
  private readonly pending = new Map<string, Promise<Uint8Array | null>>();
  private readonly queue: (() => void)[] = [];
  private running = 0;
  private pausedUntil = 0;
  private off = false;
  private readonly now: () => number;
  private readonly concurrency: number;

  constructor(
    readonly serverUrl: string,
    private readonly options: SiteIconLoaderOptions,
  ) {
    this.now = options.now ?? Date.now;
    this.concurrency = options.concurrency ?? ICON_CONCURRENCY;
  }

  /** The PNG for a domain, or null: none, the server doesn't do icons, or try again later. */
  load(domain: string): Promise<Uint8Array | null> {
    let promise = this.pending.get(domain);
    if (!promise) {
      promise = this.resolve(domain).finally(() => this.pending.delete(domain));
      this.pending.set(domain, promise);
    }
    return promise;
  }

  private async resolve(domain: string): Promise<Uint8Array | null> {
    const { store } = this.options;
    const [key, offKey] = await Promise.all([hashKey(`${this.serverUrl}|${domain}`), hashKey(`${this.serverUrl}|off`)]);
    const cached = await store.get(key);
    if (cached && cached.expires > this.now()) return cached.png ?? null;
    if (this.off) return null;
    const off = await store.get(offKey);
    if (off && off.expires > this.now()) {
      this.off = true;
      return null;
    }
    const answer = await this.limited(() => this.options.fetchIcon(this.serverUrl, domain));
    switch (answer.kind) {
      case 'icon':
        await store.set(key, { png: answer.png, expires: this.now() + ICON_TTL_MS });
        return answer.png;
      case 'none':
        await store.set(key, { expires: this.now() + ICON_MISS_TTL_MS });
        return null;
      case 'off':
        this.off = true;
        await store.set(offKey, { expires: this.now() + ICON_MISS_TTL_MS });
        return null;
      case 'retry':
        // Not remembered: the next screen that shows the row asks again.
        if (answer.retryAfterMs) this.pausedUntil = Math.max(this.pausedUntil, this.now() + answer.retryAfterMs);
        return null;
    }
  }

  private async limited(task: () => Promise<IconAnswer>): Promise<IconAnswer> {
    if (this.running >= this.concurrency) await new Promise<void>((resolve) => this.queue.push(resolve));
    this.running++;
    try {
      if (this.off) return { kind: 'off' };
      // Rate limited a moment ago: skip rather than wait, so scrolling stays quick.
      if (this.now() < this.pausedUntil) return { kind: 'retry' };
      return await task();
    } catch {
      return { kind: 'retry' };
    } finally {
      this.running--;
      this.queue.shift()?.();
    }
  }
}

/** A `data:` URL for showing a PNG: allowed by every client's content security policy. */
export function pngDataUrl(png: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < png.length; i += 0x8000) binary += String.fromCharCode(...png.subarray(i, i + 0x8000));
  return `data:image/png;base64,${btoa(binary)}`;
}
