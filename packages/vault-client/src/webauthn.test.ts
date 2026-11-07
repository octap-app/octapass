import { isVaultError } from './errors';
import { installFakeAuthenticator } from './mock/fakeAuthenticator';
import { canMakeDevicePasskey, createDeviceCredential, DEVICE_UNLOCK_SALT, detectPlatform, evaluatePrf, isPlatformAuthenticatorAvailable, setUpDeviceCredential } from './webauthn';

afterEach(() => vi.unstubAllGlobals());

describe('detectPlatform', () => {
  it('names the device lock people know', () => {
    expect(detectPlatform('Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)', 0)).toBe('mac');
    expect(detectPlatform('Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)', 5)).toBe('ios');
    expect(detectPlatform('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)', 5)).toBe('ios');
    expect(detectPlatform('Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 0)).toBe('windows');
    expect(detectPlatform('Mozilla/5.0 (Linux; Android 15)', 5)).toBe('android');
    expect(detectPlatform('Mozilla/5.0 (X11; Linux x86_64)', 0)).toBe('other');
  });
});

describe('device credentials', () => {
  it('asks for a platform passkey with user verification and PRF', async () => {
    const auth = installFakeAuthenticator();
    await createDeviceCredential('maya@example.com');
    const { publicKey } = auth.create.mock.calls[0]![0] as CredentialCreationOptions;
    expect(publicKey!.rp).toEqual({ id: location.hostname, name: 'Octa Pass' });
    expect(publicKey!.user.name).toBe('maya@example.com');
    expect((publicKey!.user.id as Uint8Array).byteLength).toBe(16);
    expect(publicKey!.pubKeyCredParams.map((p) => p.alg)).toEqual([-7, -257]);
    expect(publicKey!.authenticatorSelection).toEqual({ authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'discouraged' });
    // The salt goes in at creation too, so browsers that can answer then need only one prompt.
    expect(publicKey!.extensions).toEqual({ prf: { eval: { first: DEVICE_UNLOCK_SALT } } });
  });

  it('uses SHA-256("octapass/v1/device-unlock") as the salt', async () => {
    const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('octapass/v1/device-unlock')));
    expect(DEVICE_UNLOCK_SALT).toEqual(expected);
  });

  it('gets the same 32-byte PRF output every time for one credential', async () => {
    installFakeAuthenticator();
    const { id } = await createDeviceCredential('maya@example.com');
    const first = await evaluatePrf(id);
    expect(first).toHaveLength(32);
    expect(await evaluatePrf(id)).toEqual(first);
  });

  it('evaluates PRF with SHA-256("octapass/v1/device-unlock") and the stored credential only', async () => {
    const auth = installFakeAuthenticator();
    const { id } = await createDeviceCredential('maya@example.com');
    await evaluatePrf(id);
    const { publicKey } = auth.get.mock.calls[0]![0] as CredentialRequestOptions;
    const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('octapass/v1/device-unlock')));
    expect(new Uint8Array((publicKey!.extensions as { prf: { eval: { first: Uint8Array } } }).prf.eval.first)).toEqual(expected);
    expect(publicKey!.userVerification).toBe('required');
    expect(new Uint8Array(publicKey!.allowCredentials![0]!.id as Uint8Array)).toEqual(id);
  });

  it('reports a browser without PRF as unsupported', async () => {
    installFakeAuthenticator({ prf: false });
    const error = await createDeviceCredential('maya@example.com').catch((e: unknown) => e);
    expect(isVaultError(error, 'deviceUnlockUnsupported')).toBe(true);
  });

  it('treats a dismissed prompt as cancelled', async () => {
    const auth = installFakeAuthenticator();
    const { id } = await createDeviceCredential('maya@example.com');
    auth.cancelNext();
    const error = await evaluatePrf(id).catch((e: unknown) => e);
    expect(isVaultError(error, 'deviceUnlockCancelled')).toBe(true);
  });

  it('keeps the browser’s own reason on the error', async () => {
    const auth = installFakeAuthenticator();
    auth.failNext(new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError'), 'create');
    const cancelled = await createDeviceCredential('maya@example.com').catch((e: unknown) => e);
    expect(cancelled).toMatchObject({ code: 'deviceUnlockCancelled', message: 'NotAllowedError: The operation either timed out or was not allowed.' });

    auth.failNext(new DOMException('The authenticator failed.', 'ConstraintError'), 'create');
    expect(await createDeviceCredential('maya@example.com').catch((e: unknown) => e)).toMatchObject({ code: 'deviceUnlockFailed', message: 'ConstraintError: The authenticator failed.' });

    auth.failNext(new DOMException('No PRF here.', 'NotSupportedError'), 'create');
    expect(await createDeviceCredential('maya@example.com').catch((e: unknown) => e)).toMatchObject({ code: 'deviceUnlockUnsupported' });

    auth.failNext(new TypeError('Bad options'), 'create');
    expect(await createDeviceCredential('maya@example.com').catch((e: unknown) => e)).toMatchObject({ code: 'deviceUnlockFailed', message: 'TypeError: Bad options' });
  });

  it('reads a page whose origin can’t have a passkey as unsupported, not broken', async () => {
    // Firefox's answer on a moz-extension: page, where rp.id is the extension's own host.
    const auth = installFakeAuthenticator();
    auth.failNext(new DOMException('The operation is insecure.', 'SecurityError'), 'create');
    expect(await setUpDeviceCredential('maya@example.com').catch((e: unknown) => e)).toMatchObject({ code: 'deviceUnlockUnsupported', message: 'SecurityError: The operation is insecure.' });

    const { id } = await createDeviceCredential('maya@example.com');
    auth.failNext(new DOMException('The operation is insecure.', 'SecurityError'), 'get');
    expect(await evaluatePrf(id).catch((e: unknown) => e)).toMatchObject({ code: 'deviceUnlockUnsupported' });
  });

  it('is unavailable without a platform authenticator', async () => {
    installFakeAuthenticator({ available: false });
    expect(await isPlatformAuthenticatorAvailable()).toBe(false);
  });

  it('is unavailable on a Firefox extension page, which can’t make a passkey for itself', async () => {
    installFakeAuthenticator();
    expect(canMakeDevicePasskey('moz-extension:')).toBe(false);
    expect(await isPlatformAuthenticatorAvailable('moz-extension:')).toBe(false);
    // Chrome accepts the extension's ID as the RP ID, and websites their own host.
    expect(canMakeDevicePasskey('chrome-extension:')).toBe(true);
    expect(await isPlatformAuthenticatorAvailable('chrome-extension:')).toBe(true);
    expect(await isPlatformAuthenticatorAvailable()).toBe(true);
  });
});

describe('setting up device unlock', () => {
  it('needs one prompt where the browser gives the PRF output at creation', async () => {
    const auth = installFakeAuthenticator({ prfAtCreate: true });
    const { id, prf } = await setUpDeviceCredential('maya@example.com');
    expect(auth.get).not.toHaveBeenCalled();
    // The same output a later unlock gets.
    expect(await evaluatePrf(id)).toEqual(prf);
  });

  it('reads the PRF output with a second prompt where the browser only gives it then', async () => {
    const auth = installFakeAuthenticator();
    const { id, prf } = await setUpDeviceCredential('maya@example.com');
    expect(auth.get).toHaveBeenCalledTimes(1);
    expect(await evaluatePrf(id)).toEqual(prf);
  });

  it('asks for one more click when the second prompt is refused, and reuses the passkey', async () => {
    const auth = installFakeAuthenticator();
    auth.cancelNext();
    const error = await setUpDeviceCredential('maya@example.com').catch((e: unknown) => e);
    expect(error).toMatchObject({ code: 'deviceUnlockConfirm', message: 'NotAllowedError: The operation either timed out or was not allowed.' });

    const { id } = await setUpDeviceCredential('maya@example.com');
    expect(auth.create).toHaveBeenCalledTimes(1);
    expect(new Uint8Array((auth.get.mock.calls[1]![0] as CredentialRequestOptions).publicKey!.allowCredentials![0]!.id as Uint8Array)).toEqual(id);

    // A different account starts over.
    await setUpDeviceCredential('sam@example.com');
    expect(auth.create).toHaveBeenCalledTimes(2);
  });

  it('says setting up failed, not that it stopped working', async () => {
    const auth = installFakeAuthenticator();
    auth.failNext(new DOMException('The authenticator failed.', 'UnknownError'), 'create');
    expect(await setUpDeviceCredential('maya@example.com').catch((e: unknown) => e)).toMatchObject({ code: 'deviceUnlockSetupFailed', message: 'UnknownError: The authenticator failed.' });
  });

  it('treats a dismissed first prompt as cancelled', async () => {
    const auth = installFakeAuthenticator();
    auth.failNext(new DOMException('Cancelled.', 'NotAllowedError'), 'create');
    expect(await setUpDeviceCredential('maya@example.com').catch((e: unknown) => e)).toMatchObject({ code: 'deviceUnlockCancelled' });
  });
});
