// The page side of two-step sign-in: which methods the page offers, and the WebAuthn prompts it runs
// for the engine. The engine is a stub here; the server-backed tests cover the rest.

import { isVaultError } from '../errors';
import { base64UrlEncode } from '../tools/encoding';
import type { EngineClient } from './protocol';
import { RemoteVaultService } from './RemoteVaultService';

const b64 = (...bytes: number[]) => base64UrlEncode(new Uint8Array(bytes));
const buffer = (...bytes: number[]) => new Uint8Array(bytes).buffer;

function stubEngine(answers: Record<string, unknown>) {
  const call = vi.fn(async (method: string, _args: unknown[]) => {
    if (method === 'init') return { session: { status: 'signedOut' }, remembered: [] };
    return answers[method];
  });
  const engine = { call, onEvent: () => undefined } as unknown as EngineClient;
  return { engine, call };
}

const webauthn = (rpId: string) => ({ challenge: b64(1, 2, 3), rpId, allowCredentials: [b64(9, 9)], timeout: 60_000, userVerification: 'discouraged' });
const twoStepRequired = (rpId: string) => ({ status: 'twoStepRequired', methods: ['totp', 'securityKey', 'recoveryCode'], webauthn: webauthn(rpId) });
const input = { serverUrl: 'https://vault.example', email: 'maya@example.com', password: 'pw' };

function installWebAuthn() {
  const get = vi.fn(async () => ({ rawId: buffer(9, 9), response: { clientDataJSON: buffer(1), authenticatorData: buffer(2), signature: buffer(3) } }));
  const create = vi.fn(async () => ({ rawId: buffer(7, 7), response: { clientDataJSON: buffer(4), attestationObject: buffer(5) } }));
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get, create } });
  vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
  return { get, create };
}

afterEach(() => vi.unstubAllGlobals());

describe('RemoteVaultService two-step sign-in', () => {
  it('offers security keys only where WebAuthn runs for the server’s relying party', async () => {
    installWebAuthn();
    // jsdom's page is on localhost.
    for (const [rpId, offered] of [
      ['localhost', true],
      ['vault.example.com', false],
      ['host', false],
    ] as const) {
      const { engine } = stubEngine({ signIn: twoStepRequired(rpId) });
      const service = await RemoteVaultService.create(engine, { watch: () => () => undefined });
      const result = await service.signIn(input);
      expect(result).toEqual({ status: 'twoStepRequired', methods: offered ? ['totp', 'securityKey', 'recoveryCode'] : ['totp', 'recoveryCode'] });
    }
    vi.unstubAllGlobals();
    const { engine } = stubEngine({ signIn: twoStepRequired('localhost') });
    const service = await RemoteVaultService.create(engine, { watch: () => () => undefined });
    expect(await service.signIn(input)).toEqual({ status: 'twoStepRequired', methods: ['totp', 'recoveryCode'] });
    const error = await service.finishTwoStep({ method: 'securityKey' }).catch((e: unknown) => e);
    expect(isVaultError(error, 'securityKeyUnsupported')).toBe(true);
  });

  it('runs the security key prompt on the page and hands only the assertion to the engine', async () => {
    const { get } = installWebAuthn();
    const { engine, call } = stubEngine({ signIn: twoStepRequired('localhost') });
    const service = await RemoteVaultService.create(engine, { watch: () => () => undefined });
    await service.signIn(input);
    await service.finishTwoStep({ method: 'securityKey' });

    const { publicKey } = (get.mock.calls[0] as unknown as [CredentialRequestOptions])[0];
    expect(new Uint8Array(publicKey!.challenge as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]));
    expect(publicKey).toMatchObject({ rpId: 'localhost', userVerification: 'discouraged', timeout: 60_000 });
    expect(call).toHaveBeenLastCalledWith('finishTwoStep', [
      { method: 'securityKey', assertion: { credentialId: b64(9, 9), clientDataJson: b64(1), authenticatorData: b64(2), signature: b64(3) } },
    ]);
  });

  it('turns a dismissed prompt into securityKeyCancelled', async () => {
    const { get } = installWebAuthn();
    get.mockRejectedValueOnce(new DOMException('dismissed', 'NotAllowedError'));
    const { engine } = stubEngine({ signIn: twoStepRequired('localhost') });
    const service = await RemoteVaultService.create(engine, { watch: () => () => undefined });
    await service.signIn(input);
    const error = await service.finishTwoStep({ method: 'securityKey' }).catch((e: unknown) => e);
    expect(isVaultError(error, 'securityKeyCancelled')).toBe(true);
  });

  it('picks up a waiting sign-in with the same filtering, and can answer its security key', async () => {
    installWebAuthn();
    const elsewhere = stubEngine({ pendingTwoStep: twoStepRequired('vault.example.com') });
    expect(await (await RemoteVaultService.create(elsewhere.engine)).pendingTwoStep()).toEqual({ status: 'twoStepRequired', methods: ['totp', 'recoveryCode'] });
    const here = stubEngine({ pendingTwoStep: twoStepRequired('localhost') });
    const service = await RemoteVaultService.create(here.engine);
    expect(await service.pendingTwoStep()).toEqual({ status: 'twoStepRequired', methods: ['totp', 'securityKey', 'recoveryCode'] });
    await service.finishTwoStep({ method: 'securityKey' });
    expect(here.call).toHaveBeenLastCalledWith('finishTwoStep', [expect.objectContaining({ method: 'securityKey' })]);
    const lost = stubEngine({ pendingTwoStep: { status: 'twoStepExpired' } });
    expect(await (await RemoteVaultService.create(lost.engine)).pendingTwoStep()).toEqual({ status: 'twoStepExpired' });
  });

  it('passes codes straight to the engine', async () => {
    const { engine, call } = stubEngine({ signIn: { status: 'twoStepRequired', methods: ['totp', 'recoveryCode'] } });
    const service = await RemoteVaultService.create(engine, { watch: () => () => undefined });
    await service.signIn(input);
    await service.finishTwoStep({ method: 'totp', code: '123456' });
    expect(call).toHaveBeenLastCalledWith('finishTwoStep', [{ method: 'totp', code: '123456' }]);
  });
});

describe('RemoteVaultService two-step settings', () => {
  it('works out security key support from the relying party id', async () => {
    installWebAuthn();
    const status = { enabled: true, securityKeys: [], recoveryCodesLeft: 10 };
    const here = stubEngine({ getTwoStepStatus: { ...status, rpId: 'localhost' } });
    expect(await (await RemoteVaultService.create(here.engine)).twoStep.getTwoStepStatus()).toEqual({ ...status, securityKeysSupported: true });
    const elsewhere = stubEngine({ getTwoStepStatus: { ...status, rpId: 'vault.example.com' } });
    expect(await (await RemoteVaultService.create(elsewhere.engine)).twoStep.getTwoStepStatus()).toEqual({ ...status, securityKeysSupported: false });
  });

  it('registers a security key with the server’s options', async () => {
    const { create } = installWebAuthn();
    const publicKey = { challenge: b64(1), rp: { id: 'localhost', name: 'Octa Pass' }, user: { id: b64(2), name: 'maya', displayName: 'maya' }, algorithms: [-7, -8], excludeCredentials: [b64(6)], timeout: 60_000 };
    const key = { id: 'k1', name: 'Blue key', createdAt: '2026-01-01T00:00:00Z' };
    const { engine, call } = stubEngine({ securityKeyOptions: { setupId: 's1', publicKey }, addSecurityKey: key });
    const service = await RemoteVaultService.create(engine);
    expect(await service.twoStep.addSecurityKey({ password: 'pw', name: 'Blue key' })).toEqual(key);

    expect(call).toHaveBeenCalledWith('securityKeyOptions', ['pw']);
    const options = (create.mock.calls[0] as unknown as [CredentialCreationOptions])[0].publicKey!;
    expect(options.pubKeyCredParams).toEqual([
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -8 },
    ]);
    expect(options).toMatchObject({ rp: publicKey.rp, attestation: 'none' });
    expect(call).toHaveBeenLastCalledWith('addSecurityKey', [{ setupId: 's1', name: 'Blue key', credentialId: b64(7, 7), clientDataJson: b64(4), attestationObject: b64(5) }]);
  });
});

describe('RemoteVaultService session', () => {
  it('keeps what the engine says about the unlock, and drops it the moment the page locks', async () => {
    let emit: (event: unknown) => void = () => undefined;
    const call = vi.fn(async (method: string) => (method === 'init' ? { session: { status: 'unlocked', email: 'maya@example.com', serverUrl: 'https://vault.example', confirmed: true }, remembered: [] } : undefined));
    const engine = { call, onEvent: (listener: (event: unknown) => void) => void (emit = listener) } as unknown as EngineClient;
    const service = await RemoteVaultService.create(engine, { watch: () => () => undefined });
    expect(service.getSession().confirmed).toBe(true);

    service.lock();
    expect(service.getSession()).toEqual({ status: 'locked', email: 'maya@example.com', serverUrl: 'https://vault.example' });

    // A session that's the same in every way but this one is still news.
    const seen = vi.fn();
    service.onSessionChange(seen);
    emit({ type: 'session', snapshot: { session: { status: 'unlocked', email: 'maya@example.com', serverUrl: 'https://vault.example' }, remembered: [] } });
    emit({ type: 'session', snapshot: { session: { status: 'unlocked', email: 'maya@example.com', serverUrl: 'https://vault.example', confirmed: true }, remembered: [] } });
    expect(seen).toHaveBeenCalledTimes(2);
    expect(service.getSession().confirmed).toBe(true);
  });
});
