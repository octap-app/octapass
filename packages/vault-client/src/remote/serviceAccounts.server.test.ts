// Service accounts from the web client: the real service against the real server, with the WASM
// core. `pnpm --filter @octapass/vault-client test:server`.

import { signedUp as signUp } from './testing/devices';
import { startServer, type TestServer } from './testing/server';

let server: TestServer;

beforeAll(async () => {
  server = await startServer();
});
afterAll(() => server?.stop());
afterEach(({ task }) => {
  if (task.result?.state === 'fail') console.error(server.output().split('\n').filter((line) => !line.includes('dev mode')).join('\n'));
});

const signedUp = () => signUp(server.url);

describe('service accounts', () => {
  it('makes one, shows its name only to its creator, and revoking rotates the key', async () => {
    const device = await signedUp();
    const sharing = device.service.sharing!;
    const vault = await sharing.createVault('CI');

    const { account, token } = await sharing.createServiceAccount(vault.id, { name: 'Deploy job', role: 'read' });
    expect(token).toMatch(/^opsa1_/);
    expect(account).toMatchObject({ name: 'Deploy job', role: 'read', needsNewToken: false });

    const [listed] = await sharing.listServiceAccounts(vault.id);
    expect(listed).toEqual(account);
    expect(JSON.stringify(listed)).not.toContain(token);

    const logged = await sharing.getSecurityLog();
    expect(logged.map((e) => e.type)).toContain('service-account-created');
    expect(logged.find((e) => e.type === 'service-account-created')?.serviceAccountId).toBe(account.id);

    await sharing.revokeServiceAccount(vault.id, account.id);
    const [revoked] = await sharing.listServiceAccounts(vault.id);
    expect(revoked?.revokedAt).toBeDefined();
    expect((await sharing.getSecurityLog()).map((e) => e.type)).toContain('service-account-revoked');

    // The vault still works for its people after the rotation.
    const item = await device.service.saveItem({
      vaultId: vault.id,
      overview: { schemaVersion: 1, title: 'After rotation', type: 'login' },
      details: { schemaVersion: 1, password: 'still works' },
    } as Parameters<typeof device.service.saveItem>[0]);
    expect((await device.service.getItem(item.id)).overview.title).toBe('After rotation');
  });

  it('refuses a personal vault', async () => {
    const device = await signedUp();
    const personal = (await device.service.listVaults())[0]!;
    await expect(device.service.sharing!.createServiceAccount(personal.id, { name: 'x', role: 'read' })).rejects.toThrow();
  });

  it('a rotation for another reason keeps active service accounts on the new key', async () => {
    const device = await signedUp();
    const sharing = device.service.sharing!;
    const vault = await sharing.createVault('CI');
    const { account } = await sharing.createServiceAccount(vault.id, { name: 'keeps working', role: 'read' });
    const { account: other } = await sharing.createServiceAccount(vault.id, { name: 'goes', role: 'read' });
    await sharing.revokeServiceAccount(vault.id, other.id);
    const kept = (await sharing.listServiceAccounts(vault.id)).find((s) => s.id === account.id);
    expect(kept).toMatchObject({ needsNewToken: false });
    expect(kept?.revokedAt).toBeUndefined();
  });
});
