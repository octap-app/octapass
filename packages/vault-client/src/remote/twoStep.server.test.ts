// Two-step sign-in against the real server: turning it on with an authenticator app, signing in on
// a new device with a code, a recovery code or a security key, and the trusted-device token that lets
// a device still in the account's device list sign in again without the second step.
// Run with `pnpm --filter @octapass/vault-client test:server`.

import { openKeyValueStore } from '../idb';
import { totpCode } from '../tools/totp';
import type { TotpSetup } from '../types';
import type { DeviceAccount } from './store';
import { device, expectCode, PASSWORD, signedUp as signUp } from './testing/devices';
import { installSoftwareSecurityKey } from './testing/securityKey';
import { startServer, type TestServer } from './testing/server';

const WEB_ORIGIN = 'http://localhost:5174';
let server: TestServer;

beforeAll(async () => {
  server = await startServer({ webOrigins: [WEB_ORIGIN] });
});
afterAll(() => server?.stop());
afterEach(() => vi.unstubAllGlobals());

/**
 * The server takes each authenticator step once, and allows the steps either side of now. Turning on
 * uses the current one, so the next sign-in uses the one after.
 */
const code = async (setup: TotpSetup, stepsAhead = 0) => (await totpCode(setup.otpauthUri, Date.now() + stepsAhead * 30_000)).code;

async function turnedOn() {
  const account = await signUp(server.url);
  const setup = await account.service.twoStep.startTotpSetup(PASSWORD);
  const { recoveryCodes } = await account.service.twoStep.confirmTotpSetup(await code(setup));
  return { ...account, setup, recoveryCodes: recoveryCodes! };
}

async function storedAccount(storage: string): Promise<DeviceAccount> {
  const kv = await openKeyValueStore(storage);
  return (await kv.get<DeviceAccount[]>('device-accounts'))![0]!;
}

describe('two-step sign-in on the real server', () => {
  it('turns on with an authenticator app, after the master password', async () => {
    const { service } = await signUp(server.url);
    expect(await service.twoStep.getTwoStepStatus()).toEqual({ enabled: false, securityKeys: [], recoveryCodesLeft: 0, securityKeysSupported: false });
    await expectCode(service.twoStep.startTotpSetup('wrong password'), 'invalidCredentials');
    await expectCode(service.twoStep.confirmTotpSetup('123456'), 'twoStepExpired');

    const setup = await service.twoStep.startTotpSetup(PASSWORD);
    expect(setup.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
    expect(setup.otpauthUri).toContain(setup.secret);
    const wrong = String((Number(await code(setup)) + 1) % 1_000_000).padStart(6, '0');
    await expectCode(service.twoStep.confirmTotpSetup(wrong), 'invalidTwoStepCode');
    const { recoveryCodes } = await service.twoStep.confirmTotpSetup(await code(setup));
    expect(recoveryCodes).toHaveLength(10);
    expect(await service.twoStep.getTwoStepStatus()).toMatchObject({ enabled: true, recoveryCodesLeft: 10 });
    expect((await service.getSecurityLog()).map((e) => e.type)).toContain('two-step-enabled');
  });

  it('asks a new device for a code, refuses a wrong one, and then trusts the device', async () => {
    const { email, secretKey, setup } = await turnedOn();
    const other = await device();
    const result = await other.service.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey });
    expect(result).toEqual({ status: 'twoStepRequired', methods: ['totp', 'recoveryCode'] });
    expect(other.service.getSession().status).toBe('signedOut');

    await expectCode(other.service.finishTwoStep({ method: 'totp', code: '000000' }), 'invalidTwoStepCode');
    await other.service.finishTwoStep({ method: 'totp', code: await code(setup, 1) });
    expect(other.service.getSession()).toEqual({ status: 'unlocked', email, serverUrl: server.url, confirmed: true });
    expect((await storedAccount(other.storage)).trustedDeviceToken).toEqual(expect.any(String));

    // Its refresh token stops working: the password unlock signs in again, with no second step.
    const kv = await openKeyValueStore(other.storage);
    other.service.lock();
    await kv.set('session', { ...(await kv.get<object>('session')), refreshToken: 'revoked' });
    await other.service.unlock(PASSWORD);
    expect(other.service.getSession().status).toBe('unlocked');

    // Locked, the same device signs in again without a second step too.
    other.service.lock();
    expect(await other.service.signIn({ serverUrl: server.url, email, password: PASSWORD })).toEqual({ status: 'signedIn' });
  });

  it('signs in with a recovery code, once', async () => {
    const { email, secretKey, recoveryCodes, service } = await turnedOn();
    const other = await device();
    await other.service.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey });
    await other.service.finishTwoStep({ method: 'recoveryCode', code: recoveryCodes[0]!.toLowerCase() });
    expect(other.service.getSession().status).toBe('unlocked');
    expect((await service.twoStep.getTwoStepStatus()).recoveryCodesLeft).toBe(9);

    const third = await device();
    await third.service.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey });
    await expectCode(third.service.finishTwoStep({ method: 'recoveryCode', code: recoveryCodes[0]! }), 'invalidTwoStepCode');
    await third.service.finishTwoStep({ method: 'recoveryCode', code: recoveryCodes[1]! });
    expect((await service.getSecurityLog()).filter((e) => e.type === 'recovery-code-used')).toHaveLength(2);
  });

  it('keeps the waiting sign-in for a screen that opens again, until it’s cancelled', async () => {
    const { email, secretKey } = await turnedOn();
    const other = await device();
    expect(await other.service.pendingTwoStep()).toBeUndefined();
    await other.service.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey });
    expect(await other.service.pendingTwoStep()).toEqual({ status: 'twoStepRequired', methods: ['totp', 'recoveryCode'] });
    await other.service.cancelTwoStep();
    expect(await other.service.pendingTwoStep()).toBeUndefined();
    await expectCode(other.service.finishTwoStep({ method: 'totp', code: '000000' }), 'twoStepExpired');
  });

  it('ends the sign-in after 5 wrong codes, so it starts over', async () => {
    const { email, secretKey } = await turnedOn();
    const other = await device();
    await other.service.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey });
    for (let i = 0; i < 5; i++) await expectCode(other.service.finishTwoStep({ method: 'totp', code: '000000' }), 'invalidTwoStepCode');
    await expectCode(other.service.finishTwoStep({ method: 'totp', code: '000000' }), 'twoStepExpired');
    await expectCode(other.service.finishTwoStep({ method: 'recoveryCode', code: 'AAAAA-AAAAA' }), 'twoStepExpired');
  });

  it('sends a device whose trust is gone back to sign-in when its session expires', async () => {
    const { email, storage, service } = await turnedOn();
    const kv = await openKeyValueStore(storage);
    const accounts = await kv.get<DeviceAccount[]>('device-accounts');
    await kv.set('device-accounts', accounts!.map((a) => ({ ...a, trustedDeviceToken: 'forgotten' })));
    service.lock();
    await kv.set('session', { ...(await kv.get<object>('session')), refreshToken: 'revoked' });

    const reloaded = await device(storage);
    await expectCode(reloaded.service.unlock(PASSWORD), 'sessionExpired');
    expect(reloaded.service.getSession()).toEqual({ status: 'signedOut' });
    // The Secret Key stays, so signing in again needs only the password and the second step.
    expect(reloaded.service.rememberedAccounts()).toEqual([{ email, serverUrl: server.url }]);
    expect(await reloaded.service.signIn({ serverUrl: server.url, email, password: PASSWORD })).toMatchObject({ status: 'twoStepRequired' });
  });

  it('asks every other device for the second step again, keeping this one trusted', async () => {
    const { email, secretKey, setup, service } = await turnedOn();
    const other = await device();
    await other.service.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey });
    await other.service.finishTwoStep({ method: 'totp', code: await code(setup, 1) });

    await service.twoStep.forgetTrustedDevices!();
    expect((await service.getSecurityLog()).map((e) => e.type)).toContain('trusted-devices-forgotten');
    // The other device stays signed in, but its next sign-in needs a code.
    expect(other.service.getSession().status).toBe('unlocked');
    other.service.lock();
    expect(await other.service.signIn({ serverUrl: server.url, email, password: PASSWORD })).toMatchObject({ status: 'twoStepRequired' });
    // This one still skips it.
    service.lock();
    expect(await service.signIn({ serverUrl: server.url, email, password: PASSWORD })).toEqual({ status: 'signedIn' });
  });

  it('forgets the trusted-device token on sign-out', async () => {
    const { email, secretKey, setup, service } = await turnedOn();
    await service.signOut();
    expect(await service.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey })).toMatchObject({ status: 'twoStepRequired' });
    await service.finishTwoStep({ method: 'totp', code: await code(setup, 1) });
    expect(service.getSession().status).toBe('unlocked');
  });

  it('renews recovery codes, replaces the authenticator and turns off, each after the master password', async () => {
    const { service, recoveryCodes, email, secretKey } = await turnedOn();
    await expectCode(service.twoStep.renewRecoveryCodes('wrong'), 'invalidCredentials');
    const renewed = await service.twoStep.renewRecoveryCodes(PASSWORD);
    expect(renewed).toHaveLength(10);
    expect(renewed).not.toContain(recoveryCodes[0]);

    const next = await service.twoStep.startTotpSetup(PASSWORD);
    expect(await service.twoStep.confirmTotpSetup(await code(next))).toEqual({});

    await service.twoStep.disableTwoStep(PASSWORD);
    expect((await service.twoStep.getTwoStepStatus()).enabled).toBe(false);
    const other = await device();
    expect(await other.service.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey })).toEqual({ status: 'signedIn' });
    expect((await service.getSecurityLog()).map((e) => e.type)).toEqual(expect.arrayContaining(['recovery-codes-renewed', 'authenticator-changed', 'two-step-disabled']));
  });

  it('adds a security key on the web vault’s site, signs in with it, and removes it', async () => {
    const key = installSoftwareSecurityKey(WEB_ORIGIN);
    const { service, email, secretKey } = await turnedOn();
    expect((await service.twoStep.getTwoStepStatus()).securityKeysSupported).toBe(true);
    const added = await service.twoStep.addSecurityKey({ password: PASSWORD, name: 'Blue key' });
    expect(added).toMatchObject({ name: 'Blue key', id: expect.any(String), createdAt: expect.any(String) });

    const other = await device();
    expect(await other.service.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey })).toEqual({ status: 'twoStepRequired', methods: ['totp', 'securityKey', 'recoveryCode'] });
    await other.service.finishTwoStep({ method: 'securityKey' });
    expect(other.service.getSession().status).toBe('unlocked');
    expect(key.uses).toBe(1);

    // Somewhere else (another host, the extension), the key isn't offered but can still be removed.
    vi.stubGlobal('location', { hostname: 'elsewhere.example' });
    const third = await device();
    expect(await third.service.signIn({ serverUrl: server.url, email, password: PASSWORD, secretKey })).toEqual({ status: 'twoStepRequired', methods: ['totp', 'recoveryCode'] });
    const status = await service.twoStep.getTwoStepStatus();
    expect(status).toMatchObject({ securityKeysSupported: false, securityKeys: [{ id: added.id, name: 'Blue key', lastUsedAt: expect.any(String) }] });
    await service.twoStep.removeSecurityKey({ id: added.id, password: PASSWORD });
    expect((await service.twoStep.getTwoStepStatus()).securityKeys).toEqual([]);
  });
});
