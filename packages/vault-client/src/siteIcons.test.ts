import { describe, expect, it, vi } from 'vitest';
import {
  ICON_MISS_TTL_MS,
  ICON_TTL_MS,
  iconAnswer,
  iconDomain,
  idbIconStore,
  memoryIconStore,
  pngDataUrl,
  serverIconFetch,
  SiteIconLoader,
  type IconAnswer,
} from './siteIcons';

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47]);
const SERVER = 'https://vault.example.org';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

describe('iconDomain', () => {
  it('uses the registrable domain of the first URL', () => {
    expect(iconDomain(['https://login.bank.com/signin', 'https://other.com'])).toBe('bank.com');
    expect(iconDomain(['www.bbc.co.uk/account'])).toBe('bbc.co.uk');
    expect(iconDomain(['github.com:443'])).toBe('github.com');
  });

  it('skips what has no public icon', () => {
    expect(iconDomain(undefined)).toBeUndefined();
    expect(iconDomain([])).toBeUndefined();
    expect(iconDomain([''])).toBeUndefined();
    expect(iconDomain(['http://192.168.1.1/admin'])).toBeUndefined();
    expect(iconDomain(['http://localhost:3000'])).toBeUndefined();
    expect(iconDomain(['http://app.localhost'])).toBeUndefined();
    expect(iconDomain(['http://[::1]:8080'])).toBeUndefined();
    expect(iconDomain(['intranet'])).toBeUndefined();
    expect(iconDomain(['mailto:me@example.com'])).toBeUndefined();
  });
});

describe('serverIconFetch', () => {
  it('asks the server, sending nothing that identifies the user', async () => {
    const fetchImpl = vi.fn(async () => new Response(PNG, { status: 200, headers: { 'content-type': 'image/png' } }));
    const answer = await serverIconFetch(fetchImpl as typeof fetch)('https://vault.example.org/some/path', 'bank.com');
    expect(answer).toEqual({ kind: 'icon', png: PNG });
    expect(fetchImpl).toHaveBeenCalledWith('https://vault.example.org/v1/icons/bank.com', {
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      headers: { accept: 'image/png' },
    });
  });

  it('reads misses, the server switch, rate limits and failures', async () => {
    const problem = (type: string) => async () => new TextEncoder().encode(JSON.stringify({ type }));
    expect(await iconAnswer(404, 'application/problem+json', null, problem('https://octap.app/problems/not-found'))).toEqual({ kind: 'none' });
    expect(await iconAnswer(404, 'application/problem+json', null, problem('https://octap.app/problems/icons-off'))).toEqual({ kind: 'off' });
    expect(await iconAnswer(400, 'application/problem+json', null, problem('x'))).toEqual({ kind: 'none' });
    expect(await iconAnswer(429, 'application/problem+json', '30', problem('x'))).toEqual({ kind: 'retry', retryAfterMs: 30_000 });
    expect(await iconAnswer(503, 'text/plain', null, problem('x'))).toEqual({ kind: 'retry' });
    const offline = serverIconFetch((async () => Promise.reject(new TypeError('offline'))) as typeof fetch);
    expect(await offline(SERVER, 'bank.com')).toEqual({ kind: 'retry' });
  });
});

describe('SiteIconLoader', () => {
  it('fetches each domain once and keeps it on the device', async () => {
    let now = 1_000;
    const store = memoryIconStore();
    const fetchIcon = vi.fn(async (): Promise<IconAnswer> => ({ kind: 'icon', png: PNG }));
    const loader = new SiteIconLoader(SERVER, { fetchIcon, store, now: () => now });
    const [a, b] = await Promise.all([loader.load('bank.com'), loader.load('bank.com')]);
    expect(a).toEqual(PNG);
    expect(b).toEqual(PNG);
    expect(fetchIcon).toHaveBeenCalledTimes(1);
    expect(fetchIcon).toHaveBeenCalledWith(SERVER, 'bank.com');

    // A new loader (the next visit) reads the device cache.
    const again = new SiteIconLoader(SERVER, { fetchIcon, store, now: () => now });
    expect(await again.load('bank.com')).toEqual(PNG);
    expect(fetchIcon).toHaveBeenCalledTimes(1);

    now += ICON_TTL_MS;
    await again.load('bank.com');
    expect(fetchIcon).toHaveBeenCalledTimes(2);
  });

  it('remembers misses for a day, and keeps nothing on failures', async () => {
    let now = 0;
    const store = memoryIconStore();
    const answers: IconAnswer[] = [{ kind: 'none' }, { kind: 'retry' }, { kind: 'retry' }, { kind: 'icon', png: PNG }];
    const fetchIcon = vi.fn(async () => answers.shift()!);
    const loader = new SiteIconLoader(SERVER, { fetchIcon, store, now: () => now });
    expect(await loader.load('none.com')).toBeNull();
    expect(await loader.load('none.com')).toBeNull();
    expect(fetchIcon).toHaveBeenCalledTimes(1);
    now += ICON_MISS_TTL_MS;
    expect(await loader.load('none.com')).toBeNull();
    expect(await loader.load('none.com')).toBeNull();
    expect(await loader.load('none.com')).toEqual(PNG);
    expect(fetchIcon).toHaveBeenCalledTimes(4);
  });

  it('keeps servers apart', async () => {
    const store = memoryIconStore();
    const fetchIcon = vi.fn(async (): Promise<IconAnswer> => ({ kind: 'icon', png: PNG }));
    await new SiteIconLoader(SERVER, { fetchIcon, store }).load('bank.com');
    await new SiteIconLoader('https://other.example', { fetchIcon, store }).load('bank.com');
    expect(fetchIcon).toHaveBeenCalledTimes(2);
  });

  it('runs at most six requests at once', async () => {
    const gates = new Map<string, ReturnType<typeof deferred<IconAnswer>>>();
    let running = 0;
    let most = 0;
    const fetchIcon = vi.fn(async (_server: string, domain: string) => {
      running++;
      most = Math.max(most, running);
      const gate = deferred<IconAnswer>();
      gates.set(domain, gate);
      const answer = await gate.promise;
      running--;
      return answer;
    });
    const loader = new SiteIconLoader(SERVER, { fetchIcon, store: memoryIconStore() });
    const loads = Array.from({ length: 20 }, (_, i) => loader.load(`site${i}.com`));
    await vi.waitFor(() => expect(fetchIcon).toHaveBeenCalledTimes(6));
    for (let round = 0; round < 20; round++) {
      await vi.waitFor(() => expect(gates.size).toBeGreaterThan(0));
      const [domain, gate] = gates.entries().next().value!;
      gates.delete(domain);
      gate.resolve({ kind: 'none' });
    }
    await Promise.all(loads);
    expect(fetchIcon).toHaveBeenCalledTimes(20);
    expect(most).toBe(6);
  });

  it('stops asking a server that turned icons off, and pauses when rate limited', async () => {
    let now = 0;
    const store = memoryIconStore();
    const fetchIcon = vi.fn(async (): Promise<IconAnswer> => ({ kind: 'off' }));
    const loader = new SiteIconLoader(SERVER, { fetchIcon, store, now: () => now });
    await loader.load('a.com');
    await loader.load('b.com');
    expect(fetchIcon).toHaveBeenCalledTimes(1);
    // Remembered on the device for a day.
    await new SiteIconLoader(SERVER, { fetchIcon, store, now: () => now }).load('c.com');
    expect(fetchIcon).toHaveBeenCalledTimes(1);

    const limited = vi.fn(async (): Promise<IconAnswer> => ({ kind: 'retry', retryAfterMs: 5_000 }));
    const busy = new SiteIconLoader(SERVER, { fetchIcon: limited, store: memoryIconStore(), now: () => now });
    await busy.load('a.com');
    await busy.load('b.com');
    expect(limited).toHaveBeenCalledTimes(1);
    now += 5_000;
    await busy.load('b.com');
    expect(limited).toHaveBeenCalledTimes(2);
  });

  it('keeps icons in IndexedDB under hashed keys', async () => {
    const store = idbIconStore('octapass-icons-test');
    const fetchIcon = vi.fn(async (): Promise<IconAnswer> => ({ kind: 'icon', png: PNG }));
    await new SiteIconLoader(SERVER, { fetchIcon, store }).load('bank.com');
    // IndexedDB hands back a copy, from another realm in the test environment.
    expect(Array.from((await new SiteIconLoader(SERVER, { fetchIcon, store }).load('bank.com'))!)).toEqual(Array.from(PNG));
    expect(fetchIcon).toHaveBeenCalledTimes(1);
    expect(await store.get('bank.com')).toBeUndefined();
    await store.clear();
    await new SiteIconLoader(SERVER, { fetchIcon, store }).load('bank.com');
    expect(fetchIcon).toHaveBeenCalledTimes(2);
  });
});

it('makes data URLs', () => {
  expect(pngDataUrl(PNG)).toBe('data:image/png;base64,iVBORw==');
});
