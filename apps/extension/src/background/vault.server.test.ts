// The service worker's vault against the real octapass-server and the WASM core (Node build):
// sign-up, surviving a worker restart, locking, and passkeys through the core authenticator.
// Run with `pnpm --filter @octapass/extension test:server`.

import { createHash, createPublicKey, verify } from 'node:crypto';
import type { Item, LoginDetails } from '@octapass/vault-client';
import { RemoteVaultService, type Core, type EngineClient } from '@octapass/vault-client/remote';
import { startPath } from '../popup/startPath';
import { startServer, type TestServer } from '@octapass/vault-client/remote/testing/server';
import { testCore } from '../test/core';
import { memoryStore } from '../test/memoryStore';
import { base64UrlDecode, base64UrlEncode, totpCode, type TotpSetup } from '@octapass/vault-client';
import { appSide } from '../test/desktopApp';
import { withAccountSession } from './accountSession';
import { DesktopLink } from './desktop';
import { SessionKeeper } from './sessionKeeper';
import { Matcher } from './matching';
import { PasskeyAuthenticator } from './passkeys';
import { openKeyValueStore, type KeyValueStore } from './storage';
import { VaultHost } from './vault';

const core = testCore as unknown as Core;
const matcher = new Matcher(testCore);
const PASSWORD = 'Lantern ruby quiet anchor 42';
const b64 = (bytes: Uint8Array | string) => Buffer.from(bytes).toString('base64url');

let server: TestServer;
beforeAll(async () => {
  server = await startServer();
});
afterAll(() => server?.stop());

let profiles = 0;
async function browserProfile() {
  return { disk: await openKeyValueStore(`profile-${profiles++}`), memory: memoryStore() };
}

function start(profile: { disk: KeyValueStore; memory: KeyValueStore }, expired?: () => Promise<boolean>) {
  return VaultHost.start({ loadCore: async () => testCore, ...profile, device: { name: 'Test extension', platform: 'extension' } }, expired);
}

async function until(check: () => Promise<boolean>): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 20));
  }
}

let emails = 0;
async function signedUp(host: VaultHost): Promise<string> {
  const email = `ext${emails++}-${Date.now()}@example.com`;
  const { signupId, devVerificationCode } = (await host.pageCall('startSignup', [{ serverUrl: server.url, email, password: PASSWORD }])) as { signupId: string; devVerificationCode: string };
  await host.pageCall('finishSignup', [{ signupId, verificationCode: devVerificationCode }]);
  await until(async () => Boolean(await host.keeper.read()));
  return email;
}

async function vaultId(host: VaultHost): Promise<string> {
  const [vault] = (await host.pageCall('listVaults', [])) as { id: string }[];
  return vault!.id;
}

describe('the service worker vault', () => {
  it('restores a session as opened by the user only when its wrap says so, and forgets that on a lock', async () => {
    const profile = await browserProfile();
    const first = await start(profile);
    await signedUp(first);
    expect(first.snapshot.session.confirmed).toBe(true);
    expect((await first.keeper.read())?.confirmed).toBe(true);

    // A wrap that doesn't say the user opened it: the restored session keeps asking.
    const wrap = (await first.keeper.read())!;
    await profile.memory.set('session-wrap', { record: wrap.record, key: wrap.key });
    const second = await start(profile);
    expect(second.snapshot.session.status).toBe('unlocked');
    expect(second.snapshot.session.confirmed).toBeUndefined();

    second.lock();
    await until(async () => second.snapshot.session.status === 'locked' && !(await profile.memory.get('session-wrap')));
    expect(second.snapshot.session.confirmed).toBeUndefined();
    await second.pageCall('unlock', [PASSWORD]);
    expect(second.snapshot.session.confirmed).toBe(true);
  });

  it('stays unlocked across a worker restart, and locked after a lock', async () => {
    const profile = await browserProfile();
    const first = await start(profile);
    const email = await signedUp(first);
    await first.pageCall('saveItem', [{ vaultId: await vaultId(first), overview: { schemaVersion: 1, title: 'Example', type: 'login', urls: ['https://example.com'] }, details: { schemaVersion: 1, username: 'maya', password: 'hunter2' } }]);

    // The worker stopped; a new one starts from the same storage. It's the session the user opened,
    // so reveal and copy still don't ask again (plan 03 History, 2026-11-05).
    const second = await start(profile);
    expect(second.snapshot.session).toEqual({ status: 'unlocked', email, serverUrl: server.url, confirmed: true });
    expect((await second.listItems()).map((i) => i.title)).toEqual(['Example']);
    // `init` from a page reports the running session instead of starting over.
    expect(await second.pageCall('init', [])).toEqual(second.snapshot);

    second.lock();
    await until(async () => !(await profile.memory.get('session-wrap')));
    const third = await start(profile);
    expect(third.snapshot.session.status).toBe('locked');

    // The master password still works, and wraps the session again.
    await third.pageCall('unlock', [PASSWORD]);
    await until(async () => Boolean(await third.keeper.read()));
    expect((await start(profile)).snapshot.session.status).toBe('unlocked');
  });

  it('re-authenticates for a reveal, copy or export from a page', async () => {
    const host = await start(await browserProfile());
    await signedUp(host);
    await expect(host.pageCall('confirmMasterPassword', ['wrong password entirely'])).rejects.toMatchObject({ code: 'invalidCredentials' });
    await expect(host.pageCall('confirmMasterPassword', [PASSWORD])).resolves.toBeUndefined();
    expect(await host.pageCall('confirmDeviceCredential', [])).toBeUndefined();
  });

  it('doesn’t come back unlocked after the auto-lock time', async () => {
    const profile = await browserProfile();
    await signedUp(await start(profile));
    const restarted = await start(profile, async () => true);
    expect(restarted.snapshot.session.status).toBe('locked');
    expect(await profile.memory.get('session-wrap')).toBeUndefined();
  });

  it('never writes the session to disk', async () => {
    const profile = await browserProfile();
    const host = await start(profile);
    await signedUp(host);
    const stored = (await host.keeper.read())!;
    const accountId = stored.record.accountId;
    expect(await profile.disk.get(`device-unlock:${accountId}`)).toBeUndefined();
    expect(await profile.disk.get('session-wrap')).toBeUndefined();
    // Device unlock still lands on disk, apart from the session.
    expect(await host.pageCall('deviceUnlockStatus', [])).toEqual({ enabled: false, passwordRequired: false });
  });

  it('creates a passkey into a new login and signs in with it, keeping the key away from pages', async () => {
    const profile = await browserProfile();
    const host = await start(profile);
    await signedUp(host);
    const authenticator = new PasskeyAuthenticator({ host, matcher, keeper: host.keeper, loadCore: async () => core, disk: profile.disk });
    const caller = { origin: 'https://login.example.com' };

    const credential = await authenticator.create(
      {
        rp: { id: 'example.com', name: 'Example' },
        user: { id: b64('user-1'), name: 'maya@example.com', displayName: 'Maya' },
        challenge: b64(new Uint8Array(32).fill(1)),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      },
      caller,
    );
    expect(credential.type).toBe('public-key');

    const [login] = await host.listItems();
    expect(login).toMatchObject({ title: 'Example', hasPasskey: true });
    const full = await host.getItem(login!.id);
    expect((full.details as { passkeys: { privateKey?: string }[] }).passkeys[0]!.privateKey).toBeTruthy();
    const shown = (await host.pageCall('getItem', [login!.id])) as Item;
    expect(JSON.stringify(shown)).not.toContain('privateKey');

    // An edit from the popup keeps the passkey working.
    await host.pageCall('saveItem', [{ ...shown, overview: { ...shown.overview, title: 'Example shop' } }]);
    await until(async () => (await host.listItems())[0]!.title === 'Example shop');

    const options = { challenge: b64(new Uint8Array(32).fill(2)), rpId: 'example.com' };
    const [match] = await authenticator.find(options, caller);
    expect(match).toMatchObject({ rpId: 'example.com', userName: 'maya@example.com', itemId: login!.id });
    const assertion = await authenticator.assert(options, caller, match!);

    // Verify like a relying party, with the public key from registration.
    const publicKey = createPublicKey({ key: Buffer.from(credential.response.publicKey, 'base64url'), format: 'der', type: 'spki' });
    const clientData = Buffer.from(assertion.response.clientDataJSON, 'base64url');
    const signed = Buffer.concat([Buffer.from(assertion.response.authenticatorData, 'base64url'), createHash('sha256').update(clientData).digest()]);
    expect(verify('sha256', signed, publicKey, Buffer.from(assertion.response.signature, 'base64url'))).toBe(true);
    expect(JSON.parse(clientData.toString())).toMatchObject({ type: 'webauthn.get', origin: 'https://login.example.com' });
  });

  it('puts a new passkey into the login with the same account name', async () => {
    const profile = await browserProfile();
    const host = await start(profile);
    await signedUp(host);
    await host.pageCall('saveItem', [{ vaultId: await vaultId(host), overview: { schemaVersion: 1, title: 'Shop', type: 'login', urls: ['https://shop.example.org'] }, details: { schemaVersion: 1, username: 'Maya@Example.com', password: 'pw' } }]);
    const authenticator = new PasskeyAuthenticator({ host, matcher, keeper: host.keeper, loadCore: async () => core, disk: profile.disk });
    await authenticator.create(
      {
        rp: { name: 'Shop' },
        user: { id: b64('u'), name: 'maya@example.com', displayName: 'Maya' },
        challenge: b64(new Uint8Array(32)),
        pubKeyCredParams: [{ type: 'public-key', alg: -8 }],
      },
      { origin: 'https://shop.example.org' },
    );
    const items = await host.listItems();
    expect(items).toHaveLength(1);
    const details = (await host.getItem(items[0]!.id)).details as LoginDetails;
    expect(details.password).toBe('pw');
    expect(details.passkeys).toHaveLength(1);
  });

  it('refuses another site’s rpId and a locked vault', async () => {
    const profile = await browserProfile();
    const host = await start(profile);
    await signedUp(host);
    const authenticator = new PasskeyAuthenticator({ host, matcher, keeper: host.keeper, loadCore: async () => core, disk: profile.disk });
    const options = {
      rp: { id: 'example.com', name: 'Example' },
      user: { id: b64('u'), name: 'm', displayName: 'm' },
      challenge: b64(new Uint8Array(32)),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    };
    await expect(authenticator.create(options, { origin: 'https://example.com.evil.io' })).rejects.toMatchObject({ domName: 'SecurityError' });
    host.lock();
    await expect(authenticator.create(options, { origin: 'https://example.com' })).rejects.toMatchObject({ domName: 'NotAllowedError', message: 'locked' });
  });
});

describe('two-step sign-in', () => {
  it('signs in from the popup with an authenticator code or a recovery code, and stays signed in', async () => {
    const first = await start(await browserProfile());
    const email = await signedUp(first);
    const setup = (await first.pageCall('startTotpSetup', [PASSWORD])) as TotpSetup;
    const { recoveryCodes } = (await first.pageCall('confirmTotpSetup', [(await totpCode(setup.otpauthUri)).code])) as { recoveryCodes: string[] };
    expect(recoveryCodes).toHaveLength(10);
    expect(await first.pageCall('getTwoStepStatus', [])).toMatchObject({ enabled: true, recoveryCodesLeft: 10 });
    // Pages here can't register security keys: they belong to the web vault's site.
    await expect(first.pageCall('securityKeyOptions', [PASSWORD])).rejects.toThrow(/Unknown method/);
    const secretKey = (await first.pageCall('getSecretKey', [])) as string;

    const profile = await browserProfile();
    const second = await start(profile);
    const signIn = [{ serverUrl: server.url, email, password: PASSWORD, secretKey }];
    expect(await second.pageCall('signIn', signIn)).toEqual({ status: 'twoStepRequired', methods: ['totp', 'recoveryCode'] });
    await expect(second.pageCall('finishTwoStep', [{ method: 'totp', code: '000000' }])).rejects.toMatchObject({ code: 'invalidTwoStepCode' });
    // Turning on used the current step; the server takes each step once, so use the next one.
    await second.pageCall('finishTwoStep', [{ method: 'totp', code: (await totpCode(setup.otpauthUri, Date.now() + 30_000)).code }]);
    expect(second.snapshot.session.status).toBe('unlocked');
    await until(async () => Boolean(await second.keeper.read()));
    // A worker restart keeps the session, as after any sign-in.
    expect((await start(profile)).snapshot.session.status).toBe('unlocked');

    const third = await start(await browserProfile());
    await third.pageCall('signIn', signIn);
    await third.pageCall('finishTwoStep', [{ method: 'recoveryCode', code: recoveryCodes[0] }]);
    expect(third.snapshot.session.status).toBe('unlocked');
    expect(await third.pageCall('getTwoStepStatus', [])).toMatchObject({ recoveryCodesLeft: 9 });
  });
});

describe('two-step sign-in in a popup that closes', () => {
  /** A popup opening: the page-side service over the background's page calls. */
  function popup(host: VaultHost): Promise<RemoteVaultService> {
    const engine = { call: (method: string, args: unknown[]) => host.pageCall(method, args), onEvent: (listener: never) => void host.onEvent(listener) } as unknown as EngineClient;
    return RemoteVaultService.create(engine, { watch: () => () => undefined });
  }

  async function waitingSignIn() {
    const first = await start(await browserProfile());
    const email = await signedUp(first);
    const setup = (await first.pageCall('startTotpSetup', [PASSWORD])) as TotpSetup;
    await first.pageCall('confirmTotpSetup', [(await totpCode(setup.otpauthUri)).code]);
    const secretKey = (await first.pageCall('getSecretKey', [])) as string;
    const profile = await browserProfile();
    const host = await start(profile);
    const opened = await popup(host);
    expect(await opened.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey })).toEqual({ status: 'twoStepRequired', methods: ['totp', 'recoveryCode'] });
    return { profile, host, setup };
  }

  it('reopens onto the waiting second step and finishes it there', async () => {
    const { host, setup } = await waitingSignIn();
    // The popup closed while the user read the code, and opens again.
    const reopened = await popup(host);
    expect(await startPath(reopened, null)).toBe('/signin');
    expect(await reopened.pendingTwoStep()).toEqual({ status: 'twoStepRequired', methods: ['totp', 'recoveryCode'] });
    await reopened.finishTwoStep({ method: 'totp', code: (await totpCode(setup.otpauthUri, Date.now() + 30_000)).code });
    expect(host.snapshot.session.status).toBe('unlocked');
    expect(await (await popup(host)).pendingTwoStep()).toBeUndefined();
  });

  it('says the sign-in was lost after a worker restart, and forgets that on start over', async () => {
    const { profile } = await waitingSignIn();
    // The derived keys lived only in the old worker's memory.
    const restarted = await start(profile);
    const reopened = await popup(restarted);
    expect(await startPath(reopened, null)).toBe('/signin');
    expect(await reopened.pendingTwoStep()).toEqual({ status: 'twoStepExpired' });
    await expectTwoStepExpired(reopened.finishTwoStep({ method: 'totp', code: '123456' }));
    expect(await reopened.pendingTwoStep()).toBeUndefined();
    expect(await startPath(reopened, null)).toBe('/');
  });

  it('drops the waiting sign-in on start over', async () => {
    const { host } = await waitingSignIn();
    const reopened = await popup(host);
    await reopened.cancelTwoStep();
    expect(await reopened.pendingTwoStep()).toBeUndefined();
    await expectTwoStepExpired(reopened.finishTwoStep({ method: 'recoveryCode', code: 'AAAAA-AAAAA' }));
  });
});

async function expectTwoStepExpired(promise: Promise<unknown>): Promise<void> {
  await expect(promise).rejects.toMatchObject({ code: 'twoStepExpired' });
}

describe('imports and local mode', () => {
  it('imports into the account with the core importers and /v1/batch', async () => {
    const profile = await browserProfile();
    const host = await start(profile);
    await signedUp(host);
    const rows = Array.from({ length: 30 }, (_, i) => `Site ${i},https://site${i}.example,user${i},pw-${i}-quartz`).join('\n');
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const result = await host.pageCall('importFile', ['chrome', new Blob([`name,url,username,password\n${rows}\n`])]);
    const batches = fetchSpy.mock.calls.filter(([url]) => String(url).endsWith('/v1/batch'));
    fetchSpy.mockRestore();
    expect(result).toEqual({ imported: 30, skipped: 0, warnings: [] });
    expect(batches).toHaveLength(1);
    expect(await host.listItems()).toHaveLength(30);
    // Readable on another device too: the batch carried real ciphertext for this account.
    const other = await start(await browserProfile());
    await other.pageCall('signIn', [{ serverUrl: server.url, email: host.snapshot.session.email, password: PASSWORD, secretKey: await host.pageCall('getSecretKey', []) }]);
    expect((await other.getItem((await other.listItems())[0]!.id)).details).toMatchObject({ username: expect.stringMatching(/^user\d+$/) });
  });

  it('keeps a vault on this device only, then turns on sync without losing an item', async () => {
    const profile = await browserProfile();
    const host = await start(profile);
    await host.createLocal('Lantern ruby quiet anchor 42 tangerine');
    expect(host.local).toBe(true);
    await host.pageCall('saveItem', [{ vaultId: '', overview: { schemaVersion: 1, title: 'Local shop', type: 'login', urls: ['https://shop.example'] }, details: { schemaVersion: 1, username: 'maya', password: 'local-only-pw' } }]);

    // A worker restart finds it locked: there's no session wrap for local vaults.
    const restarted = await start(profile);
    expect(restarted.local).toBe(true);
    expect(restarted.snapshot.session.status).toBe('locked');
    await restarted.pageCall('unlock', ['Lantern ruby quiet anchor 42 tangerine']);

    const email = `local${Date.now()}@example.com`;
    const { signupId, devVerificationCode } = (await restarted.pageCall('startSignup', [{ serverUrl: server.url, email, password: PASSWORD }])) as { signupId: string; devVerificationCode: string };
    const { recoveryKit } = (await restarted.pageCall('finishSignup', [{ signupId, verificationCode: devVerificationCode }])) as { recoveryKit: { secretKey: string } };
    expect(restarted.local).toBe(false);
    expect(restarted.snapshot.session).toEqual({ status: 'unlocked', email, serverUrl: server.url, confirmed: true });
    expect((await restarted.listItems()).map((i) => i.title)).toEqual(['Local shop']);
    expect(await profile.disk.get('local-vault')).toBeUndefined();

    const other = await start(await browserProfile());
    await other.pageCall('signIn', [{ serverUrl: server.url, email, password: PASSWORD, secretKey: recoveryKit.secretKey }]);
    const [item] = await other.listItems();
    expect((await other.getItem(item!.id)).details).toMatchObject({ username: 'maya', password: 'local-only-pw' });
  });
});

describe('unlocking through the desktop app', () => {
  /** A desktop app signed in to the same account: it wraps the account key for the extension's public key. */
  function fakeApp(profile: { disk: KeyValueStore }, email: string, stayUnlocked = false) {
    return new DesktopLink(async (message) => {
      const request = message as { id: number; type: string; publicKey?: string };
      if (request.type === 'unlock-status') return { id: request.id, ok: true, result: { appRunning: true, status: 'unlocked', email, serverUrl: server.url, deviceUnlock: true, label: 'Touch ID', stayUnlocked } };
      const app = appSide(base64UrlDecode(request.publicKey!));
      // The app's own session over the same account (here: opened like the extension's passkeys do).
      const wrapped = await withAccountSession({ keeper: appKeeper, loadCore: async () => core, disk: profile.disk }, async ({ session }) => session.enableDeviceUnlock(app.key));
      return { id: request.id, ok: true, result: { email, serverUrl: server.url, ephemeralPublicKey: base64UrlEncode(app.appPublic), ...wrapped } };
    });
  }
  let appKeeper: SessionKeeper;

  it('unlocks the locked extension with the app’s wrapped key, and refuses another account', async () => {
    const profile = await browserProfile();
    const host = await start(profile);
    const email = await signedUp(host);
    // Keep a copy of the session wrap to stand in for the app's own unlocked session.
    const wrap = (await host.keeper.read())!;
    const appMemory = memoryStore();
    await appMemory.set('session-wrap', wrap);
    appKeeper = new SessionKeeper(profile.disk, appMemory);

    host.lock();
    await until(async () => !(await host.keeper.read()));
    await host.unlockWithDesktop(fakeApp(profile, email));
    expect(host.snapshot.session.status).toBe('unlocked');
    expect(await host.listItems()).toEqual([]);

    host.lock();
    await until(async () => !(await host.keeper.read()));
    await expect(host.unlockWithDesktop(fakeApp(profile, 'someone-else@example.com'))).rejects.toMatchObject({ code: 'deviceUnlockFailed' });
    expect(host.snapshot.session.status).toBe('locked');

    // A browser the app's native host won't vouch for: the error says so, not "app not running".
    const refused = new DesktopLink(async () => ({ ok: false, error: { code: 'browserNotTrusted', message: 'Octa Pass can’t unlock through this browser.' } }));
    await expect(host.unlockWithDesktop(refused)).rejects.toMatchObject({ code: 'deviceUnlockUnsupported', message: 'browserNotTrusted' });
    expect(host.snapshot.session.status).toBe('locked');
  });

  it('opens through an app that stays unlocked, asks once to reveal, and holds after Lock now (plan 18)', async () => {
    const profile = await browserProfile();
    const host = await start(profile);
    const email = await signedUp(host);
    const appMemory = memoryStore();
    await appMemory.set('session-wrap', (await host.keeper.read())!);
    appKeeper = new SessionKeeper(profile.disk, appMemory);
    host.lock();
    await until(async () => !(await host.keeper.read()));

    // An app with the switch off, or signed in to someone else, doesn't open it.
    expect(await host.unlockStayUnlocked(fakeApp(profile, email))).toBe(false);
    expect(await host.unlockStayUnlocked(fakeApp(profile, 'someone-else@example.com', true))).toBe(false);
    expect(host.snapshot.session.status).toBe('locked');

    expect(await host.unlockStayUnlocked(fakeApp(profile, email, true))).toBe(true);
    expect(host.snapshot.session.status).toBe('unlocked');
    // Nobody answered a check: the first reveal asks, and its answer covers the next.
    expect(host.snapshot.session.confirmed).toBeUndefined();
    await host.pageCall('confirmMasterPassword', [PASSWORD]);
    expect(host.snapshot.session.confirmed).toBe(true);
    await until(async () => (await host.keeper.read())?.confirmed === true);
    // The computer locked.
    host.resetConfirmed();
    expect(host.snapshot.session.confirmed).toBeUndefined();
    await until(async () => (await host.keeper.read())?.confirmed === undefined);

    // "Lock now" holds until the user unlocks.
    await host.pageCall('lock', []);
    await until(async () => !(await host.keeper.read()));
    expect(await host.unlockStayUnlocked(fakeApp(profile, email, true))).toBe(false);
    await host.pageCall('unlock', [PASSWORD]);
    expect(host.snapshot.session.confirmed).toBe(true);
    host.lock();
    await until(async () => !(await host.keeper.read()));
    expect(await host.unlockStayUnlocked(fakeApp(profile, email, true))).toBe(true);
  });
});
