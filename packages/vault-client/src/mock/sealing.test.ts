import { deriveDeviceKey, derivePasswordKey, importAsk, openBytes, openJson, randomBytes, sealBytes, sealJson, toBase64 } from './sealing';

describe('sealing', () => {
  it('wraps the ASK so only the same password and Secret Key open it', async () => {
    const salt = toBase64(randomBytes(16));
    const key = await derivePasswordKey('pw', 'OP1-KEY', salt);
    const ask = randomBytes(32);
    const wrapped = await sealBytes(key, ask, 'ask');

    await expect(openBytes(key, wrapped, 'ask')).resolves.toEqual(ask);
    await expect(openBytes(await derivePasswordKey('other', 'OP1-KEY', salt), wrapped, 'ask')).rejects.toThrow();
    await expect(openBytes(await derivePasswordKey('pw', 'OP1-OTHER', salt), wrapped, 'ask')).rejects.toThrow();
  });

  it('binds ciphertext to its context', async () => {
    const vaultKey = await importAsk(randomBytes(32));
    const sealed = await sealJson(vaultKey, { hello: 'vault' }, 'vault');
    expect(sealed.data).not.toContain('vault');
    await expect(openJson(vaultKey, sealed, 'vault')).resolves.toEqual({ hello: 'vault' });
    await expect(openJson(vaultKey, sealed, 'ask')).rejects.toThrow();
  });

  it('derives the same device key from the same PRF output and salt', async () => {
    const prf = randomBytes(32);
    const salt = randomBytes(16);
    const wrapped = await sealBytes(await deriveDeviceKey(prf, salt), new Uint8Array([1, 2, 3]), 'device-unlock');
    await expect(openBytes(await deriveDeviceKey(prf, salt), wrapped, 'device-unlock')).resolves.toEqual(new Uint8Array([1, 2, 3]));
    await expect(openBytes(await deriveDeviceKey(randomBytes(32), salt), wrapped, 'device-unlock')).rejects.toThrow();
  });
});
