import { isVaultError } from '../errors';
import { totpCode } from '../tools/totp';
import type { TotpSetup } from '../types';
import { DEFAULT_SERVER_URL, MockVaultService } from './MockVaultService';

let db = 0;
const serverUrl = DEFAULT_SERVER_URL;
const email = 'maya@example.com';
const password = 'Lantern ruby quiet anchor';

async function signedUp() {
  const service = await MockVaultService.create({ dbName: `two-step-${db++}`, latency: [0, 0], fetch: async () => new Response(''), seed: false });
  const { signupId, devVerificationCode } = await service.startSignup({ serverUrl, email, password });
  const { recoveryKit } = await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
  return { service, secretKey: recoveryKit.secretKey };
}

async function expectCode(promise: Promise<unknown>, code: Parameters<typeof isVaultError>[1]) {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(isVaultError(error) ? error.code : error).toBe(code);
}

const code = async (setup: TotpSetup) => (await totpCode(setup.otpauthUri)).code;
const wrong = async (setup: TotpSetup) => String((Number(await code(setup)) + 1) % 1_000_000).padStart(6, '0');

async function turnedOn() {
  const signed = await signedUp();
  const setup = await signed.service.twoStep.startTotpSetup(password);
  const { recoveryCodes } = await signed.service.twoStep.confirmTotpSetup(await code(setup));
  return { ...signed, setup, recoveryCodes: recoveryCodes! };
}

/** A security key in software: enough WebAuthn for the mock, which checks only the credential id. */
function installSecurityKey() {
  const ids: Uint8Array[] = [];
  const bytes = (n: number) => crypto.getRandomValues(new Uint8Array(n)).buffer;
  const create = vi.fn(async () => {
    const id = crypto.getRandomValues(new Uint8Array(16));
    ids.push(id);
    return { rawId: id.buffer, response: { clientDataJSON: bytes(8), attestationObject: bytes(8) } };
  });
  const get = vi.fn(async (options: CredentialRequestOptions) => {
    const allowed = options.publicKey!.allowCredentials!.map((c) => new Uint8Array(c.id as ArrayBuffer).join());
    const id = ids.find((i) => allowed.includes(i.join()));
    if (!id) throw new DOMException('No key', 'NotAllowedError');
    return { rawId: id.buffer, response: { clientDataJSON: bytes(8), authenticatorData: bytes(8), signature: bytes(8) } };
  });
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create, get } });
  vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
  return { create, get };
}

afterEach(() => vi.unstubAllGlobals());

describe('MockVaultService two-step sign-in', () => {
  it('turns on with an authenticator app and shows 10 recovery codes once', async () => {
    const { service } = await signedUp();
    expect(await service.twoStep.getTwoStepStatus()).toEqual({ enabled: false, securityKeys: [], recoveryCodesLeft: 0, securityKeysSupported: false });

    await expectCode(service.twoStep.startTotpSetup('wrong'), 'invalidCredentials');
    const setup = await service.twoStep.startTotpSetup(password);
    expect(setup.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(setup.otpauthUri).toContain(`secret=${setup.secret}`);
    await expectCode(service.twoStep.confirmTotpSetup(await wrong(setup)), 'invalidTwoStepCode');
    expect((await service.twoStep.getTwoStepStatus()).enabled).toBe(false);

    const { recoveryCodes } = await service.twoStep.confirmTotpSetup(await code(setup));
    expect(recoveryCodes).toHaveLength(10);
    for (const c of recoveryCodes!) expect(c).toMatch(/^[0-9A-Z]{5}-[0-9A-Z]{5}$/);
    expect(await service.twoStep.getTwoStepStatus()).toMatchObject({ enabled: true, recoveryCodesLeft: 10 });
    // The setup is used up.
    await expectCode(service.twoStep.confirmTotpSetup(await code(setup)), 'twoStepExpired');
    expect((await service.sharing.getSecurityLog()).map((e) => e.type)).toEqual(['two-step-enabled']);
  });

  it('asks a new sign-in for the second step, and accepts the current code', async () => {
    const { service, secretKey, setup } = await turnedOn();
    await service.signOut();

    const result = await service.signIn({ serverUrl, email, password, secretKey });
    expect(result).toEqual({ status: 'twoStepRequired', methods: ['totp', 'recoveryCode'] });
    expect(service.getSession().status).toBe('signedOut');
    await expectCode(service.finishTwoStep({ method: 'totp', code: await wrong(setup) }), 'invalidTwoStepCode');
    await service.finishTwoStep({ method: 'totp', code: await code(setup) });
    expect(service.getSession().status).toBe('unlocked');
    expect(service.rememberedAccounts()).toEqual([{ email, serverUrl }]);
  });

  it('takes each recovery code once, ignoring case and dashes', async () => {
    const { service, secretKey, recoveryCodes } = await turnedOn();
    await service.signOut();
    await service.signIn({ serverUrl, email, password, secretKey });
    await service.finishTwoStep({ method: 'recoveryCode', code: recoveryCodes[0]!.toLowerCase().replace('-', ' ') });
    expect(await service.twoStep.getTwoStepStatus()).toMatchObject({ recoveryCodesLeft: 9 });
    expect((await service.sharing.getSecurityLog()).map((e) => e.type)).toContain('recovery-code-used');

    await service.signOut();
    await service.signIn({ serverUrl, email, password, secretKey });
    await expectCode(service.finishTwoStep({ method: 'recoveryCode', code: recoveryCodes[0]! }), 'invalidTwoStepCode');
  });

  it('keeps the waiting sign-in until it’s cancelled or finished', async () => {
    const { service, secretKey, setup } = await turnedOn();
    await service.signOut();
    await service.signIn({ serverUrl, email, password, secretKey });
    expect(await service.pendingTwoStep()).toEqual({ status: 'twoStepRequired', methods: ['totp', 'recoveryCode'] });
    await service.cancelTwoStep();
    expect(await service.pendingTwoStep()).toBeUndefined();
    await service.signIn({ serverUrl, email, password, secretKey });
    await service.finishTwoStep({ method: 'totp', code: await code(setup) });
    expect(await service.pendingTwoStep()).toBeUndefined();
  });

  it('gives up after 5 wrong tries, and when there’s no sign-in waiting', async () => {
    const { service, secretKey, setup } = await turnedOn();
    await expectCode(service.finishTwoStep({ method: 'totp', code: '123456' }), 'twoStepExpired');
    await service.signOut();
    await service.signIn({ serverUrl, email, password, secretKey });
    for (let i = 0; i < 5; i++) await expectCode(service.finishTwoStep({ method: 'totp', code: await wrong(setup) }), 'invalidTwoStepCode');
    await expectCode(service.finishTwoStep({ method: 'totp', code: await code(setup) }), 'twoStepExpired');
  });

  it('doesn’t ask a device that already signed in, until it signs out', async () => {
    const { service } = await turnedOn();
    service.lock();
    expect(await service.signIn({ serverUrl, email, password })).toEqual({ status: 'signedIn' });
  });

  it('replaces the authenticator without new recovery codes, renews codes, and turns off', async () => {
    const { service, recoveryCodes } = await turnedOn();
    const next = await service.twoStep.startTotpSetup(password);
    expect(await service.twoStep.confirmTotpSetup(await code(next))).toEqual({});

    await expectCode(service.twoStep.renewRecoveryCodes('wrong'), 'invalidCredentials');
    const renewed = await service.twoStep.renewRecoveryCodes(password);
    expect(renewed).toHaveLength(10);
    expect(renewed).not.toContain(recoveryCodes[0]);

    await service.twoStep.disableTwoStep(password);
    expect(await service.twoStep.getTwoStepStatus()).toMatchObject({ enabled: false, recoveryCodesLeft: 0 });
    expect((await service.sharing.getSecurityLog()).map((e) => e.type).sort()).toEqual(['authenticator-changed', 'recovery-codes-renewed', 'two-step-disabled', 'two-step-enabled']);
  });

  it('adds a security key, signs in with it, and removes it', async () => {
    const authenticator = installSecurityKey();
    const { service, secretKey } = await turnedOn();
    expect((await service.twoStep.getTwoStepStatus()).securityKeysSupported).toBe(true);
    const key = await service.twoStep.addSecurityKey({ password, name: ' Blue key ' });
    expect(key).toMatchObject({ name: 'Blue key', id: expect.any(String) });
    expect(authenticator.create).toHaveBeenCalledOnce();

    await service.signOut();
    expect(await service.signIn({ serverUrl, email, password, secretKey })).toEqual({ status: 'twoStepRequired', methods: ['totp', 'securityKey', 'recoveryCode'] });
    await service.finishTwoStep({ method: 'securityKey' });
    expect(service.getSession().status).toBe('unlocked');
    expect((await service.twoStep.getTwoStepStatus()).securityKeys).toEqual([{ ...key, lastUsedAt: expect.any(String) }]);

    await expectCode(service.twoStep.removeSecurityKey({ id: key.id, password: 'wrong' }), 'invalidCredentials');
    await service.twoStep.removeSecurityKey({ id: key.id, password });
    expect((await service.twoStep.getTwoStepStatus()).securityKeys).toEqual([]);
  });

  it('needs two-step sign-in on before a security key', async () => {
    installSecurityKey();
    const { service } = await signedUp();
    await expectCode(service.twoStep.addSecurityKey({ password, name: 'Key' }), 'serverError');
  });
});
