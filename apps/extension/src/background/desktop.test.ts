import { base64UrlDecode, base64UrlEncode, isVaultError } from '@octapass/vault-client';
import { appSide } from '../test/desktopApp';
import { DesktopLink, deriveWrapKey, isBrowserNotTrusted } from './desktop';

describe('desktop app unlock', () => {
  it('derives the same wrap key as the desktop app', async () => {
    const ours = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
    const ourPublic = new Uint8Array(await crypto.subtle.exportKey('raw', ours.publicKey));
    const app = appSide(ourPublic);
    expect(await deriveWrapKey(ours, app.appPublic)).toEqual(app.key);
  });

  it('sends the protocol’s requests and maps the app’s errors', async () => {
    const sent: Record<string, unknown>[] = [];
    let key: Uint8Array | undefined;
    const link = new DesktopLink(async (message) => {
      const request = message as Record<string, unknown>;
      sent.push(request);
      if (request.type === 'unlock-status') return { id: request.id, ok: true, result: { appRunning: true, status: 'unlocked', email: 'maya@example.com', deviceUnlock: true, label: 'Touch ID' } };
      const app = appSide(base64UrlDecode(request.publicKey as string));
      key = app.key;
      return { id: request.id, ok: true, result: { email: 'maya@example.com', serverUrl: 'https://s.example', ephemeralPublicKey: base64UrlEncode(app.appPublic), deviceSalt: 'salt', wrappedAsk: 'wrapped' } };
    });
    expect(await link.status()).toMatchObject({ appRunning: true, label: 'Touch ID' });
    const wrap = await link.sessionKey();
    expect(wrap.key).toEqual(key);
    expect(sent.map((m) => m.type)).toEqual(['unlock-status', 'get-session-key-wrap']);
    expect(new Set(sent.map((m) => m.id)).size).toBe(2);

    const cancelled = new DesktopLink(async () => ({ ok: false, error: { code: 'deviceUnlockCancelled' } }));
    await expect(cancelled.sessionKey()).rejects.toSatisfy((e: unknown) => isVaultError(e, 'deviceUnlockCancelled'));
    const missing = new DesktopLink(async () => {
      throw new Error('Specified native messaging host not found.');
    });
    expect(await missing.status()).toEqual({ appRunning: false });
  });

  it('asks for the chip’s secret under a key of its own', async () => {
    const sent: Record<string, unknown>[] = [];
    let plainKey: Uint8Array | undefined;
    const link = new DesktopLink(async (message) => {
      const request = message as Record<string, unknown>;
      sent.push(request);
      const app = appSide(base64UrlDecode(request.publicKey as string));
      plainKey = app.key;
      return { id: request.id, ok: true, result: { context: 'ctx', ephemeralPublicKey: base64UrlEncode(app.appPublic), sealedSecret: 'sealed' } };
    });
    const first = await link.chipSecret('vault-1');
    expect(first).toMatchObject({ context: 'ctx', sealedSecret: 'sealed' });
    expect(first!.key).not.toEqual(plainKey);
    await link.chipSecret('vault-1', 'ctx');
    expect(sent[0]).toMatchObject({ type: 'local-chip-secret', vaultId: 'vault-1' });
    expect(sent[0]).not.toHaveProperty('context');
    expect(sent[1]).toMatchObject({ context: 'ctx' });

    const none = new DesktopLink(async (message) => ({ id: (message as { id: number }).id, ok: true, result: null }));
    expect(await none.chipSecret('vault-1')).toBeUndefined();
    const missing = new DesktopLink(async () => {
      throw new Error('Specified native messaging host not found.');
    });
    await expect(missing.chipSecret('vault-1', 'ctx')).rejects.toSatisfy((e: unknown) => isVaultError(e, 'deviceUnlockUnsupported'));
  });

  it('tells a browser the app refused apart from an app that isn’t running', async () => {
    // The native host (or the app) answers every request this way when it doesn't trust the browser.
    const refused = new DesktopLink(async (message) => ({
      id: (message as { id: number }).id,
      ok: false,
      error: { code: 'browserNotTrusted', message: 'Octa Pass can’t unlock through this browser: Chromium isn’t signed by its vendor.' },
    }));
    expect(await refused.status()).toEqual({ appRunning: false, browserNotTrusted: true });
    await expect(refused.sessionKey()).rejects.toSatisfy(isBrowserNotTrusted);

    const notRunning = new DesktopLink(async () => ({ ok: false, error: { code: 'appNotRunning' } }));
    await expect(notRunning.unlockApp()).rejects.toSatisfy((e: unknown) => !isBrowserNotTrusted(e));
    expect(await notRunning.status()).toEqual({ appRunning: false });
  });
});
