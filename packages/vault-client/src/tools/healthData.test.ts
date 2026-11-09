import { PASSKEY_DOMAINS } from '../data/passkey-domains';
import { TWO_FACTOR_DOMAINS } from '../data/two-factor-domains';
import { buildHealthReport } from './health';
import {
  BUNDLED_HEALTH_DATA_FILE,
  bundledHealthData,
  createHealthDataStore,
  HEALTH_DATA_CONTEXT,
  HEALTH_DATA_MAX_BYTES,
  HEALTH_DATA_PATH,
  HealthDataRejected,
  healthDataDownload,
  verifyHealthData,
  type HealthDataProblem,
} from './healthData';
import type { Item } from '../types';

const base64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

interface TestKey {
  publicKey: string;
  sign(payload: Uint8Array): Promise<string>;
}

async function testKey(): Promise<TestKey> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return {
    publicKey: base64(raw),
    async sign(payload) {
      const context = new TextEncoder().encode(HEALTH_DATA_CONTEXT);
      const message = new Uint8Array([...context, 0, ...payload]);
      return base64(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, message)));
    },
  };
}

const payloadOf = (fields: Record<string, unknown> = {}) => ({
  format: 1,
  version: 5,
  issuedAt: '2026-11-08T00:00:00.000Z',
  passkeyDomains: ['example.com', 'passkeys.example'],
  twoFactorDomains: ['example.com'],
  ...fields,
});

async function signed(key: TestKey, payload: unknown = payloadOf()): Promise<string> {
  const bytes = new TextEncoder().encode(typeof payload === 'string' ? payload : JSON.stringify(payload));
  return JSON.stringify({ payload: base64(bytes), signature: await key.sign(bytes) });
}

async function problemOf(text: string, after: number, publicKey?: string): Promise<HealthDataProblem | undefined> {
  try {
    await verifyHealthData(text, { after, publicKey });
    return undefined;
  } catch (e) {
    if (e instanceof HealthDataRejected) return e.problem;
    throw e;
  }
}

function memoryStorage() {
  const values = new Map<string, unknown>();
  return {
    values,
    get: async <T>(key: string) => values.get(key) as T | undefined,
    set: async (key: string, value: unknown) => void values.set(key, structuredClone(value)),
  };
}

describe('the bundled health data', () => {
  it('is signed by the pinned key and holds the lists this build was made with', async () => {
    const data = await verifyHealthData(JSON.stringify(BUNDLED_HEALTH_DATA_FILE), { after: 0 });
    expect([...data.passkeyDomains]).toEqual([...PASSKEY_DOMAINS].sort());
    expect([...data.twoFactorDomains]).toEqual([...TWO_FACTOR_DOMAINS].sort());
    expect(bundledHealthData().version).toBe(data.version);
  });

  it('is not accepted again as an update', async () => {
    const { version } = bundledHealthData();
    await expect(verifyHealthData(JSON.stringify(BUNDLED_HEALTH_DATA_FILE), { after: version })).rejects.toThrow(HealthDataRejected);
  });
});

describe('verifyHealthData', () => {
  it('accepts a newer file signed by the key', async () => {
    const key = await testKey();
    const data = await verifyHealthData(await signed(key), { after: 4, publicKey: key.publicKey });
    expect(data.version).toBe(5);
    expect(data.passkeyDomains.has('passkeys.example')).toBe(true);
  });

  it('refuses a bad signature: a changed payload, another key, a changed signature', async () => {
    const key = await testKey();
    const other = await testKey();
    const file = JSON.parse(await signed(key)) as { payload: string; signature: string };

    const changed = new TextEncoder().encode(JSON.stringify(payloadOf({ passkeyDomains: ['evil.example'] })));
    expect(await problemOf(JSON.stringify({ ...file, payload: base64(changed) }), 0, key.publicKey)).toBe('badSignature');
    expect(await problemOf(JSON.stringify(file), 0, other.publicKey)).toBe('badSignature');
    const signature = Uint8Array.from(atob(file.signature), (c) => c.charCodeAt(0));
    signature[0]! ^= 1;
    expect(await problemOf(JSON.stringify({ ...file, signature: base64(signature) }), 0, key.publicKey)).toBe('badSignature');
    // The pinned key refuses a file made with any test key.
    expect(await problemOf(JSON.stringify(file), 0)).toBe('badSignature');
  });

  it('refuses a file signed without the context', async () => {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const publicKey = base64(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
    const bytes = new TextEncoder().encode(JSON.stringify(payloadOf()));
    const signature = base64(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, bytes)));
    expect(await problemOf(JSON.stringify({ payload: base64(bytes), signature }), 0, publicKey)).toBe('badSignature');
  });

  it('refuses rolling back: the same version or an older one', async () => {
    const key = await testKey();
    expect(await problemOf(await signed(key), 5, key.publicKey)).toBe('rollback');
    expect(await problemOf(await signed(key, payloadOf({ version: 3 })), 5, key.publicKey)).toBe('rollback');
  });

  it('refuses malformed files, signed or not', async () => {
    const key = await testKey();
    const cases: [string, string][] = [
      ['not JSON', '{'],
      ['not an object', '"text"'],
      ['no signature', JSON.stringify({ payload: base64(new Uint8Array([1])) })],
      ['a short signature', JSON.stringify({ payload: 'e30=', signature: base64(new Uint8Array(32)) })],
      ['not base64', JSON.stringify({ payload: '%%%%', signature: base64(new Uint8Array(64)) })],
      ['too large', JSON.stringify({ payload: 'A'.repeat(HEALTH_DATA_MAX_BYTES), signature: '' })],
      ['a signed payload that is not JSON', await signed(key, 'not json')],
      ['a signed array', await signed(key, [])],
      ['no version', await signed(key, payloadOf({ version: undefined }))],
      ['a fractional version', await signed(key, payloadOf({ version: 5.5 }))],
      ['a bad date', await signed(key, payloadOf({ issuedAt: 'soon' }))],
      ['a list that is not one', await signed(key, payloadOf({ passkeyDomains: 'example.com' }))],
      ['a name that is not a domain', await signed(key, payloadOf({ passkeyDomains: ['<script>'] }))],
      ['a single label', await signed(key, payloadOf({ twoFactorDomains: ['localhost'] }))],
      ['an upper-case name', await signed(key, payloadOf({ twoFactorDomains: ['Example.com'] }))],
    ];
    for (const [what, text] of cases) expect(await problemOf(text, 0, key.publicKey), what).toBe('malformed');
  });

  it('refuses a format it does not know', async () => {
    const key = await testKey();
    expect(await problemOf(await signed(key, payloadOf({ format: 2 })), 0, key.publicKey)).toBe('unsupported');
  });

  it('ignores fields it does not know, so a later format can add some', async () => {
    const key = await testKey();
    const data = await verifyHealthData(await signed(key, payloadOf({ changePasswordUrls: {} })), { after: 0, publicKey: key.publicKey });
    expect(data.version).toBe(5);
  });
});

describe('createHealthDataStore', () => {
  const now = new Date('2026-11-08T12:00:00Z');
  const later = (hours: number) => new Date(now.getTime() + hours * 3_600_000);

  it('starts from the bundled lists and keeps a newer signed file', async () => {
    const key = await testKey();
    const storage = memoryStorage();
    const store = createHealthDataStore(storage, { publicKey: key.publicKey });
    // The bundled file is signed by the real key, so the store's test key doesn't matter for it.
    expect((await store.current()).version).toBe(bundledHealthData().version);

    const version = bundledHealthData().version + 1;
    expect(await store.update(async () => signed(key, payloadOf({ version })), { now })).toBe('updated');
    expect((await store.current()).version).toBe(version);
    // Kept across restarts, and checked again when read.
    expect((await createHealthDataStore(storage, { publicKey: key.publicKey }).current()).version).toBe(version);
  });

  it('asks once a day, unless forced', async () => {
    const key = await testKey();
    const store = createHealthDataStore(memoryStorage(), { publicKey: key.publicKey });
    let asked = 0;
    const download = async () => {
      asked++;
      return signed(key, payloadOf({ version: bundledHealthData().version + asked }));
    };
    expect(await store.update(download, { now })).toBe('updated');
    expect(await store.update(download, { now: later(23) })).toBe('notDue');
    expect(await store.update(download, { now: later(1), force: true })).toBe('updated');
    expect(await store.update(download, { now: later(48) })).toBe('updated');
    expect(asked).toBe(3);
  });

  it('keeps the newer lists when a server offers an older file', async () => {
    const key = await testKey();
    const store = createHealthDataStore(memoryStorage(), { publicKey: key.publicKey });
    const version = bundledHealthData().version + 5;
    await store.update(async () => signed(key, payloadOf({ version })), { now });
    expect(await store.update(async () => signed(key, payloadOf({ version: version - 1, passkeyDomains: [] })), { now: later(25) })).toBe('current');
    expect(await store.update(async () => signed(key, payloadOf({ version })), { now: later(50) })).toBe('current');
    const data = await store.current();
    expect(data.version).toBe(version);
    expect(data.passkeyDomains.size).toBe(2);
  });

  it('keeps what it has when the file is bad or the server is down', async () => {
    const key = await testKey();
    const other = await testKey();
    const store = createHealthDataStore(memoryStorage(), { publicKey: key.publicKey });
    const version = bundledHealthData().version + 1;
    expect(await store.update(async () => signed(other, payloadOf({ version })), { now })).toBe('rejected');
    expect(await store.update(async () => '{', { now: later(25) })).toBe('rejected');
    expect(
      await store.update(
        async () => {
          throw new Error('offline');
        },
        { now: later(50) },
      ),
    ).toBe('failed');
    expect((await store.current()).version).toBe(bundledHealthData().version);
  });

  it('falls back to the bundled lists when the stored copy was changed on the device', async () => {
    const key = await testKey();
    const storage = memoryStorage();
    await createHealthDataStore(storage, { publicKey: key.publicKey }).update(async () => signed(key, payloadOf({ version: bundledHealthData().version + 1 })), { now });
    const stored = storage.values.get('healthData') as { file: string };
    const file = JSON.parse(stored.file) as { payload: string; signature: string };
    const forged = new TextEncoder().encode(JSON.stringify(payloadOf({ version: 999_999, passkeyDomains: [] })));
    storage.values.set('healthData', { ...stored, file: JSON.stringify({ ...file, payload: base64(forged) }) });
    expect((await createHealthDataStore(storage, { publicKey: key.publicKey }).current()).version).toBe(bundledHealthData().version);
  });
});

describe('healthDataDownload', () => {
  it('asks the server for the one public file, with no cookies or referrer', async () => {
    const calls: [string, RequestInit | undefined][] = [];
    const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([String(input), init]);
      return new Response('{"payload":"","signature":""}');
    }) as typeof fetch;
    expect(await healthDataDownload('https://vault.example/', fetcher)()).toBe('{"payload":"","signature":""}');
    expect(calls[0]![0]).toBe(`https://vault.example${HEALTH_DATA_PATH}`);
    expect(calls[0]![1]).toMatchObject({ credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store' });
  });

  it('fails on an error status', async () => {
    const fetcher = (async () => new Response('nope', { status: 404 })) as unknown as typeof fetch;
    await expect(healthDataDownload('https://vault.example', fetcher)()).rejects.toThrow('404');
  });
});

describe('the health report with updated lists', () => {
  it('uses the lists it is given', async () => {
    const item: Item = {
      id: 'a',
      vaultId: 'v',
      revision: 1,
      createdAt: '2026-11-01T00:00:00Z',
      updatedAt: '2026-11-01T00:00:00Z',
      overview: { schemaVersion: 1, type: 'login', title: 'New site', urls: ['https://login.passkeys.example'] },
      details: { schemaVersion: 1, username: 'me', password: 'correct horse battery staple' },
    } as Item;
    const deps = { estimateStrength: () => ({ score: 4 as const, guessesLog10: 20 }), checkBreached: async () => 0 };
    const before = await buildHealthReport([item], deps);
    expect(before.passkeyAvailable).toHaveLength(0);
    expect(before.missing2fa).toHaveLength(0);
    const data = { version: 9, issuedAt: '', passkeyDomains: new Set(['passkeys.example']), twoFactorDomains: new Set(['passkeys.example']) };
    const after = await buildHealthReport([item], { ...deps, data });
    expect(after.passkeyAvailable.map((e) => e.itemId)).toEqual(['a']);
    expect(after.missing2fa.map((e) => e.itemId)).toEqual(['a']);
  });
});
