// The real service against the real server: WASM core (Node build), octapass-server in dev mode,
// fake-indexeddb for this "browser's" storage. Run with `pnpm --filter @octapass/vault-client test:server`.

import { openKeyValueStore } from '../idb';
import type { ItemDraft, LoginDetails } from '../types';
import { VaultEngine } from './engine';
import { directClient } from './protocol';
import { RemoteVaultService } from './RemoteVaultService';
import { core, device, eventually, expectCode, PASSWORD, signedUp as signUp } from './testing/devices';
import { startServer, type TestServer } from './testing/server';

let server: TestServer;

beforeAll(async () => {
  server = await startServer();
});
afterAll(() => server?.stop());

const signedUp = () => signUp(server.url);

function login(title: string, password: string): ItemDraft {
  return {
    vaultId: '',
    overview: { schemaVersion: 1, title, type: 'login', urls: ['https://example.com'] },
    details: { schemaVersion: 1, username: 'maya', password, notes: 'a note', futureField: { kept: true } } as LoginDetails,
  };
}

async function personalVault(service: RemoteVaultService): Promise<string> {
  const [vault] = await service.listVaults();
  return vault!.id;
}

describe('sign-up and the vault', () => {
  it('signs up, unlocked, with an empty personal vault and a Recovery Kit', async () => {
    const { service, email, secretKey } = await signedUp();
    expect(service.getSession()).toEqual({ status: 'unlocked', email, serverUrl: server.url, confirmed: true });
    expect(secretKey).toMatch(/^OP1-/);
    expect(await service.listVaults()).toEqual([{ id: expect.any(String), name: 'Personal', type: 'personal', role: 'owner' }]);
    expect(await service.listItems()).toEqual([]);
    expect(service.rememberedAccounts()).toEqual([{ email, serverUrl: server.url }]);
    expect(await service.getSecretKey()).toBe(secretKey);
  });

  it('saves, edits, trashes and restores items, keeping unknown fields and password history', async () => {
    const { service } = await signedUp();
    const vaultId = await personalVault(service);
    const created = await service.saveItem({ ...login('GitHub', 'first-pass'), vaultId });
    expect(created.revision).toBeGreaterThan(0);
    expect(Date.parse(created.createdAt)).toBeGreaterThan(Date.now() - 60_000);

    const edited = await service.saveItem({ ...created, details: { ...created.details, password: 'second-pass' } as LoginDetails });
    expect((edited.details as LoginDetails).passwordHistory?.[0]?.password).toBe('first-pass');
    expect((edited.details as unknown as Record<string, unknown>).futureField).toEqual({ kept: true });

    await service.deleteItem(created.id);
    expect(await service.listItems()).toEqual([]);
    expect((await service.listItems({ trash: true })).map((s) => s.id)).toEqual([created.id]);
    await service.restoreItem(created.id);
    expect((await service.listItems()).map((s) => s.title)).toEqual(['GitHub']);
  });

  it('locks, and unlocks with the master password only', async () => {
    const { service } = await signedUp();
    await service.saveItem({ ...login('Bank', 'pw'), vaultId: await personalVault(service) });
    service.lock();
    expect(service.getSession().status).toBe('locked');
    await expectCode(service.listItems(), 'locked');
    await expectCode(service.unlock('wrong password'), 'invalidCredentials');
    await service.unlock(PASSWORD);
    expect((await service.listItems()).map((s) => s.title)).toEqual(['Bank']);
  });

  it('comes back locked after a reload, and opens from the local copy while offline', async () => {
    const first = await signedUp();
    await first.service.saveItem({ ...login('Offline', 'pw'), vaultId: await personalVault(first.service) });
    await first.service.listItems();

    const reloaded = await device(first.storage);
    expect(reloaded.service.getSession().status).toBe('locked');
    await reloaded.service.unlock(PASSWORD);
    expect((await reloaded.service.listItems()).map((s) => s.title)).toEqual(['Offline']);

    const offline = await openKeyValueStore(first.storage);
    const engine = directClient((emit) => new VaultEngine({ loadCore: async () => core, storage: offline, emit, fetch: () => Promise.reject(new TypeError('offline')) }));
    const service = await RemoteVaultService.create(engine, { watch: () => () => undefined });
    await service.unlock(PASSWORD);
    expect((await service.listItems()).map((s) => s.title)).toEqual(['Offline']);
    await expectCode(service.saveItem({ ...login('Not now', 'pw'), vaultId: await personalVault(service) }), 'serverUnreachable');
  });

  it('logs in again with the password when the refresh token no longer works', async () => {
    const first = await signedUp();
    const kv = await openKeyValueStore(first.storage);
    const stored = await kv.get<{ refreshToken: string }>('session');
    await kv.set('session', { ...stored, refreshToken: 'revoked' });
    const reloaded = await device(first.storage);
    await reloaded.service.unlock(PASSWORD);
    expect(reloaded.service.getSession().status).toBe('unlocked');
    expect(await reloaded.service.listItems()).toEqual([]);
  });
});

describe('rate limits', () => {
  it('pauses background sync for as long as Retry-After says', async () => {
    const a = await signedUp();
    let limited = false;
    let syncCalls = 0;
    const kv = await openKeyValueStore(a.storage);
    const fetchThrough: typeof fetch = async (input, init) => {
      if (String(input).includes('/v1/sync')) {
        syncCalls++;
        if (limited) return new Response(JSON.stringify({ type: 'https://octap.app/problems/rate-limited', status: 429 }), { status: 429, headers: { 'Retry-After': '60' } });
      }
      return fetch(input, init);
    };
    let now = Date.now();
    // No WebSocket: its catch-up sync on connecting would land at an unpredictable point in the count.
    const engine = directClient((emit) => new VaultEngine({ loadCore: async () => core, storage: kv, emit, fetch: fetchThrough, now: () => now, WebSocket: false }));
    const service = await RemoteVaultService.create(engine, { watch: () => () => undefined });
    await service.unlock(PASSWORD);
    // Unlocking starts a background sync it doesn't wait for. Let it finish before counting, or under
    // load it lands after `limited` is set and takes the 429 meant for the explicit call.
    for (let quiet = 0, seen = syncCalls; quiet < 3; ) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      quiet = syncCalls === seen ? quiet + 1 : 0;
      seen = syncCalls;
    }

    limited = true;
    const before = syncCalls;
    await expectCode(engine.call('sync', []), 'rateLimited');
    await engine.call('sync', []);
    expect(syncCalls).toBe(before + 1);

    limited = false;
    now += 61_000;
    await engine.call('sync', []);
    expect(syncCalls).toBe(before + 2);
  });
});

describe('paged sync', () => {
  it('a full sync over several pages keeps every item', async () => {
    const a = await signedUp();
    const vaultId = await personalVault(a.service);
    for (const title of ['First', 'Second', 'Third']) await a.service.saveItem({ ...login(title, 'pw'), vaultId });

    // Cut the first full answer after its oldest item; the client must ask again from that revision.
    let pagesServed = 0;
    const paging: typeof fetch = async (input, init) => {
      const response = await fetch(input, init);
      if (!String(input).includes('/v1/sync') || String(input).includes('since=') || pagesServed > 0) return response;
      pagesServed++;
      const body = await response.json();
      const oldest = [...body.items].sort((x: { revision: number }, y: { revision: number }) => x.revision - y.revision)[0];
      const page = {
        vaults: body.vaults.map((v: { id: string }) => (v.id === oldest.vaultId ? { ...v, revision: oldest.revision } : v)),
        items: [oldest],
        deleted: [],
        hasMore: true,
      };
      return new Response(JSON.stringify(page), { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    const kv = await openKeyValueStore(a.storage);
    const engine = directClient((emit) => new VaultEngine({ loadCore: async () => core, storage: kv, emit, fetch: paging }));
    const service = await RemoteVaultService.create(engine, { watch: () => () => undefined });
    await service.unlock(PASSWORD);
    await engine.call('sync', []);

    expect(pagesServed).toBe(1);
    expect((await service.listItems()).map((s) => s.title).sort()).toEqual(['First', 'Second', 'Third']);
  });
});

describe('two devices', () => {
  it('a new device needs the Secret Key, then syncs edits both ways', async () => {
    const a = await signedUp();
    const item = await a.service.saveItem({ ...login('Shared login', 'from-a'), vaultId: await personalVault(a.service) });

    const b = await device();
    await expectCode(b.service.signIn({ serverUrl: server.url, email: a.email, password: PASSWORD }), 'secretKeyRequired');
    await expectCode(b.service.signIn({ serverUrl: server.url, email: a.email, password: PASSWORD, secretKey: 'OP1-nope' }), 'invalidSecretKey');
    await expectCode(b.service.signIn({ serverUrl: server.url, email: a.email, password: 'wrong', secretKey: a.secretKey }), 'invalidCredentials');
    await b.service.signIn({ serverUrl: server.url, email: a.email.toUpperCase(), password: PASSWORD, secretKey: a.secretKey.toLowerCase() });

    const onB = await b.service.getItem(item.id);
    expect((onB.details as LoginDetails).password).toBe('from-a');
    await b.service.saveItem({ ...onB, details: { ...onB.details, password: 'from-b' } as LoginDetails });

    const changed = new Promise<void>((resolve) => a.service.onItemsChange(resolve));
    await a.engine.call('sync', []);
    await changed;
    expect(((await a.service.getItem(item.id)).details as LoginDetails).password).toBe('from-b');
  });

  it('a stale edit is saved as a conflicting copy and nothing is lost', async () => {
    const a = await signedUp();
    const item = await a.service.saveItem({ ...login('Router', 'v1'), vaultId: await personalVault(a.service) });
    const b = await device();
    await b.service.signIn({ serverUrl: server.url, email: a.email, password: PASSWORD, secretKey: a.secretKey });
    const onB = await b.service.getItem(item.id);
    await b.service.saveItem({ ...onB, details: { ...onB.details, password: 'v2-from-b' } as LoginDetails });

    // A hasn't synced, so it writes against the old revision.
    const copy = await a.service.saveItem({ ...item, details: { ...item.details, password: 'v2-from-a' } as LoginDetails });
    expect(copy.overview.title).toBe('Router (conflicting copy)');
    expect(((await a.service.getItem(item.id)).details as LoginDetails).password).toBe('v2-from-b');
    await a.engine.call('sync', []);
    expect((await a.service.listItems()).map((s) => s.title).sort()).toEqual(['Router', 'Router (conflicting copy)']);
  });
});

describe('version history', () => {
  it('keeps past versions, restores one, and can go back', async () => {
    const { service } = await signedUp();
    const vaultId = await personalVault(service);
    const first = await service.saveItem({ ...login('GitHub', 'first-pass'), vaultId });
    expect(await service.itemVersions(first.id)).toEqual([]);
    const second = await service.saveItem({ ...first, details: { ...first.details, password: 'second-pass' } });
    await service.saveItem({ ...second, details: { ...second.details, password: 'third-pass' } });

    const versions = await service.itemVersions(first.id);
    expect(versions.map((v) => (v.details as LoginDetails).password)).toEqual(['second-pass', 'first-pass']);
    const restored = await service.restoreItemVersion(first.id, versions[1]!.revision);
    const details = restored.details as LoginDetails;
    expect(details.password).toBe('first-pass');
    expect(details.passwordHistory?.[0]?.password).toBe('third-pass');
    // The version it replaced is in the list, so restoring can be undone.
    expect(((await service.itemVersions(first.id))[0]!.details as LoginDetails).password).toBe('third-pass');
  });
});

describe('counter-based codes', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  it('gives RFC 4226 codes, saves the counter first, and adds no history', async () => {
    const { service } = await signedUp();
    const vaultId = await personalVault(service);
    const saved = await service.saveItem({ ...login('Bank', 'pass'), vaultId, details: { schemaVersion: 1, totp: `otpauth://hotp/x?secret=${secret}&counter=0` } });
    expect(await service.nextHotpCode(saved.id)).toEqual({ code: '755224', counter: 0 });
    expect(await service.nextHotpCode(saved.id)).toEqual({ code: '287082', counter: 1 });
    expect(((await service.getItem(saved.id)).details as LoginDetails).totp).toContain('counter=2');
    expect(await service.itemVersions(saved.id)).toEqual([]);
    await service.setHotpCounter(saved.id, 7);
    expect((await service.nextHotpCode(saved.id)).code).toBe('162583');
  });

  it('two devices using a code at once never get the same one', async () => {
    const { service, email, secretKey } = await signedUp();
    const vaultId = await personalVault(service);
    const saved = await service.saveItem({ ...login('Bank', 'pass'), vaultId, details: { schemaVersion: 1, totp: `otpauth://hotp/x?secret=${secret}&counter=0` } });
    const other = await device();
    await other.service.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey });
    const [one, two] = await Promise.all([service.nextHotpCode(saved.id), other.service.nextHotpCode(saved.id)]);
    expect(one.counter).not.toBe(two.counter);
    expect(await service.listItems()).toHaveLength(1);
  });

  it('keeps a non-counter login out of it', async () => {
    const { service } = await signedUp();
    const saved = await service.saveItem({ ...login('GitHub', 'pass'), vaultId: await personalVault(service) });
    await expectCode(service.nextHotpCode(saved.id), 'notFound');
  });
});

describe('equivalent domains', () => {
  it('saves cleaned groups in a hidden item, and refuses what is not a site', async () => {
    const { service } = await signedUp();
    const start = await service.equivalentDomains();
    expect(start.groups).toEqual([]);
    expect(start.defaults[0]).toContain('google.com');
    const saved = await service.saveEquivalentDomains({ groups: [['mail.example.com', 'example.org', 'co.uk']], excludedDefaults: ['google.com'] });
    expect(saved).toMatchObject({ groups: [['example.com', 'example.org']], excludedDefaults: ['google.com'], rejected: ['co.uk'] });
    expect(await service.listItems()).toEqual([]);
    expect(await service.listItems({ type: 'equivalentDomains' })).toHaveLength(1);
    await service.saveEquivalentDomains({ groups: [], excludedDefaults: [] });
    expect(await service.listItems({ type: 'equivalentDomains' })).toHaveLength(1);
    expect((await service.equivalentDomains()).groups).toEqual([]);
  });
});

describe('device unlock', () => {
  it('wraps the account key with the PRF output, and a wrong passkey turns it off', async () => {
    const { service, engine } = await signedUp();
    const prf = () => new Uint8Array(32).fill(7);
    await engine.call('enableDeviceUnlock', ['Y3JlZGVudGlhbA', prf()]);
    expect((await engine.call('deviceUnlockStatus', [])).enabled).toBe(true);

    service.lock();
    expect(await engine.call('deviceUnlockCredential', [])).toBe('Y3JlZGVudGlhbA');
    await engine.call('unlockWithDevice', [prf()]);
    expect(service.getSession().status).toBe('unlocked');

    service.lock();
    await expectCode(engine.call('unlockWithDevice', [new Uint8Array(32).fill(8)]), 'deviceUnlockFailed');
    expect((await engine.call('deviceUnlockStatus', [])).enabled).toBe(false);
  });
});

describe('signing out and deleting the account', () => {
  it('signing out forgets the Secret Key on this device', async () => {
    const { service, email, secretKey } = await signedUp();
    await service.signOut();
    expect(service.getSession()).toEqual({ status: 'signedOut' });
    expect(service.rememberedAccounts()).toEqual([]);
    await expectCode(service.signIn({ serverUrl: server.url, email, password: PASSWORD }), 'secretKeyRequired');
    await service.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey });
    expect(service.getSession().status).toBe('unlocked');
  });

  it('deletes everything, signs other devices out, and frees the email', async () => {
    const a = await signedUp();
    await a.service.saveItem({ ...login('Doomed', 'pw'), vaultId: await personalVault(a.service) });
    const b = await device();
    await b.service.signIn({ serverUrl: server.url, email: a.email, password: PASSWORD, secretKey: a.secretKey });

    await expectCode(a.service.deleteAccount({ confirmEmail: 'someone@else.com', password: PASSWORD }), 'emailMismatch');
    await expectCode(a.service.deleteAccount({ confirmEmail: a.email, password: 'wrong' }), 'invalidCredentials');
    expect(a.service.getSession().status).toBe('unlocked');

    await a.service.deleteAccount({ confirmEmail: a.email, password: PASSWORD });
    expect(a.service.getSession()).toEqual({ status: 'signedOut' });
    expect(a.service.rememberedAccounts()).toEqual([]);
    const kv = await openKeyValueStore(a.storage);
    expect(await kv.get('session')).toBeUndefined();

    // Told over the WebSocket, without making a request.
    await eventually(() => expect(b.service.getSession()).toEqual({ status: 'signedOut' }));
    expect(b.service.rememberedAccounts()).toEqual([]);

    const again = await device();
    const { signupId, devVerificationCode } = await again.service.startSignup({ serverUrl: server.url, email: a.email, password: PASSWORD });
    await again.service.finishSignup({ signupId, verificationCode: devVerificationCode! });
    expect(await again.service.listItems()).toEqual([]);
  });
});

describe('tools', () => {
  it('imports with bounded concurrency, exports, and computes TOTP in the core', async () => {
    const { service } = await signedUp();
    const csv = 'name,url,username,password,note\nOne,https://one.example,a,pw-one,\nTwo,https://two.example,b,pw-two,\n';
    const result = await service.importFile('chrome', new File([csv], 'passwords.csv'));
    expect(result).toEqual({ imported: 2, skipped: 0, warnings: [] });
    const exported = JSON.parse(await (await service.exportVault('json')).text()) as { items: { overview: { title: string } }[] };
    expect(exported.items.map((i) => i.overview.title).sort()).toEqual(['One', 'Two']);
    // RFC 6238 test vector, SHA-1, 8 digits.
    const code = await service.totpCode('otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8', 59_000);
    expect(code).toEqual({ code: '94287082', period: 30, remaining: 1 });
  });
});
