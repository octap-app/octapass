import { isVaultError, VaultError, type HealthReport, type Item, type ItemSummary, type LoginDetails } from '@octapass/vault-client';
import { testCore } from '../test/core';
import { memoryStore } from '../test/memoryStore';
import { LOCAL_SERVER, LocalEngine } from './local';
import type { EngineEvent } from './vault';

const PASSWORD = 'Lantern ruby quiet anchor 42 tangerine';

function engine(disk = memoryStore()) {
  const events: EngineEvent[] = [];
  const local = new LocalEngine({ loadCore: async () => testCore, disk, emit: (e) => events.push(e), memoryKib: [65_536] });
  return { local, disk, events };
}

const draft = (title: string, password: string) => ({
  vaultId: '',
  overview: { schemaVersion: 1 as const, title, type: 'login' as const, urls: ['https://example.com'], subtitle: 'maya' },
  details: { schemaVersion: 1 as const, username: 'maya', password, futureField: { kept: true } } as LoginDetails,
});

// Every vault runs Argon2id (and restoring a backup runs it at 256 MiB), which takes seconds.
describe('LocalEngine', { timeout: 60_000 }, () => {
  it('creates a vault on this device, keeps items encrypted on disk, and reopens it with the password', async () => {
    const { local, disk, events } = engine();
    expect((await local.init()).session.status).toBe('signedOut');
    const code = await local.create(PASSWORD);
    expect(code.split('-')).toHaveLength(11);
    expect(local.snapshot().session).toEqual({ status: 'unlocked', email: 'This device', serverUrl: LOCAL_SERVER, confirmed: true });

    const saved = (await local.call('saveItem', [draft('Example', 'hunter2-orchid')])) as Item;
    await local.call('saveItem', [{ ...saved, details: { ...saved.details, password: 'changed-quartz' } }]);
    const item = local.getItem(saved.id);
    expect((item.details as LoginDetails).passwordHistory?.[0]?.password).toBe('hunter2-orchid');
    expect((item.details as unknown as Record<string, unknown>).futureField).toEqual({ kept: true });
    expect(events.some((e) => e.type === 'items')).toBe(true);
    expect(Buffer.from(disk.data.get('local-vault') as Uint8Array).toString('latin1')).not.toContain('changed-quartz');

    local.lock();
    await expect(local.call('listItems', [])).rejects.toSatisfy((e: unknown) => isVaultError(e, 'locked'));
    await expect(local.unlock('wrong password entirely')).rejects.toSatisfy((e: unknown) => isVaultError(e, 'invalidCredentials'));

    const reopened = engine(disk).local;
    expect((await reopened.init()).session.status).toBe('locked');
    await reopened.unlock(PASSWORD);
    expect(((await reopened.call('listItems', [])) as ItemSummary[]).map((s) => s.title)).toEqual(['Example']);
    // Reveal/copy/export on a local vault: the master password is the gate (no device lock exists).
    await expect(reopened.call('confirmMasterPassword', ['wrong password entirely'])).rejects.toSatisfy((e: unknown) => isVaultError(e, 'invalidCredentials'));
    await expect(reopened.call('confirmMasterPassword', [PASSWORD])).resolves.toBeUndefined();
  });

  it('trashes, restores, imports, reports health and says what needs sync', async () => {
    const { local } = engine();
    await local.init();
    await local.create(PASSWORD);
    const saved = (await local.call('saveItem', [draft('Example', 'password')])) as Item;
    await local.call('deleteItem', [saved.id]);
    expect(local.listItems({ trash: true }).map((s) => s.id)).toEqual([saved.id]);
    await local.call('restoreItem', [saved.id]);
    expect(local.listItems().map((s) => s.id)).toEqual([saved.id]);

    const csv = 'name,url,username,password\nShop,https://shop.example,maya,Xq7!plover-quartz\n';
    expect(await local.call('importFile', ['chrome', new Blob([csv])])).toMatchObject({ imported: 1, skipped: 0 });
    expect(local.listItems().map((s) => s.title).sort()).toEqual(['Example', 'Shop']);

    const report = (await local.call('getHealthReport', [])) as HealthReport;
    expect(report.checked).toBe(2);
    await expect(local.call('getSecretKey', [])).rejects.toThrow(/needs sync/);
  });

  it('exports encrypted or as CXF, and imports an Octa Pass export with its links, leaving files out', async () => {
    const { local } = engine();
    await local.init();
    await local.create(PASSWORD);
    const me = (await local.call('saveItem', [{ vaultId: '', overview: { schemaVersion: 1, title: 'Me', type: 'identity' }, details: { schemaVersion: 1, email: 'maya@example.com' } }])) as Item;
    const login = draft('Example', 'hunter2-orchid');
    (login.details as LoginDetails).recovery = { email: 'maya@example.com', emailSource: { kind: 'identity', itemId: me.id } };
    await local.call('saveItem', [login]);

    await expect(local.call('exportVault', ['encrypted', { password: 'export pw 12', masterPassword: 'wrong' }])).rejects.toSatisfy((e: unknown) =>
      isVaultError(e, 'invalidCredentials'),
    );
    const encrypted = (await local.call('exportVault', ['encrypted', { password: 'export pw 12', masterPassword: PASSWORD }])) as Blob;
    expect(Buffer.from(await encrypted.arrayBuffer()).subarray(0, 4).toString()).toBe('OPEX');
    const cxf = JSON.parse(await ((await local.call('exportVault', ['cxf'])) as Blob).text());
    expect(cxf.accounts[0].items.map((i: { title: string }) => i.title).sort()).toEqual(['Example', 'Me']);

    const other = engine().local;
    await other.init();
    await other.create(PASSWORD);
    expect(await other.call('importFile', ['octapass', encrypted, { password: 'export pw 12' }])).toEqual({ imported: 2, skipped: 0, warnings: [] });
    const items = other.listItems();
    const copy = other.getItem(items.find((s) => s.title === 'Example')!.id);
    expect((copy.details as LoginDetails).recovery?.emailSource).toEqual({ kind: 'identity', itemId: items.find((s) => s.title === 'Me')!.id });

    // An export from an account, with a file: the items come in, the file can't.
    const json = JSON.stringify({
      format: 'octapass-export',
      version: 1,
      exportedAt: '2026-10-24T00:00:00.000Z',
      vaults: [],
      items: [{ id: 'old', vaultId: 'v', createdAt: '', updatedAt: '', overview: { schemaVersion: 1, title: 'Lease', type: 'document' }, details: { schemaVersion: 1, attachments: [{ id: 'f1', name: 'lease.pdf', type: 'application/pdf', size: 3 }] } }],
    });
    const writer = new testCore.ExportWriter('export pw 12', { algorithm: 'argon2id', memoryKib: 65_536, iterations: 3, parallelism: 1 });
    const archive = new Blob([writer.addItems(json) as Uint8Array<ArrayBuffer>, writer.addFile('f1', new Uint8Array([1, 2, 3])) as Uint8Array<ArrayBuffer>, writer.finish() as Uint8Array<ArrayBuffer>]);
    writer.free();
    expect(await other.call('importFile', ['octapass', archive, { password: 'export pw 12' }])).toEqual({
      imported: 1,
      skipped: 0,
      warnings: ['1 attached file wasn’t imported: a vault on this device only can’t hold files.'],
    });
  });

  it('backs up and restores the vault on another browser with the recovery code', async () => {
    const { local } = engine();
    await local.init();
    const code = await local.create(PASSWORD);
    await local.call('saveItem', [draft('Example', 'hunter2-orchid')]);
    const backup = new Uint8Array(await (await local.backup()).arrayBuffer());

    const other = engine().local;
    await other.init();
    await other.restore(backup, { recoveryCode: code }, 'A brand new master password for this laptop 77');
    expect(other.listItems().map((s) => s.title)).toEqual(['Example']);
    await expect(engine().local.restore(backup, { recoveryCode: 'WRONG-CODE' }, PASSWORD)).rejects.toSatisfy((e: unknown) => isVaultError(e, 'invalidImportFile'));
  });

  it('refuses a weak master password', async () => {
    const { local } = engine();
    await local.init();
    await expect(local.create('password1')).rejects.toThrow('weak_master_password');
  });

  it('binds a new vault to the desktop app’s chip when the app is there, and needs it to open', async () => {
    const secret = new Uint8Array(32).fill(7);
    const core = new Proxy(testCore, { get: (target, key) => (key === 'openChipSecret' ? () => secret : Reflect.get(target, key)) });
    const asked: (string | undefined)[] = [];
    let running = true;
    const chip = async (vaultId: string, context?: string) => {
      asked.push(context);
      if (!running) throw new VaultError('deviceUnlockUnsupported', 'appNotRunning');
      return { context: `context-of-${vaultId}`, sealedSecret: 'sealed', key: new Uint8Array(32) };
    };
    const disk = memoryStore();
    const local = new LocalEngine({ loadCore: async () => core, disk, emit: () => undefined, memoryKib: [65_536], chip });
    await local.create(PASSWORD);
    const meta = await local.meta();
    expect(meta?.chip?.context).toBe(`context-of-${meta?.chip?.vaultId}`);
    expect(asked).toEqual([undefined]);

    local.lock();
    await local.unlock(PASSWORD);
    expect(asked.at(-1)).toBe(meta?.chip?.context);
    await local.backup();
    expect((await local.meta())?.chip).toEqual(meta?.chip);

    // Without the app there's no secret, and the password alone opens nothing.
    local.lock();
    running = false;
    await expect(local.unlock(PASSWORD)).rejects.toSatisfy((e: unknown) => isVaultError(e, 'deviceUnlockUnsupported'));
  });

  it('goes without a chip when the app isn’t there', async () => {
    const chip = async () => {
      throw new VaultError('deviceUnlockUnsupported', 'appNotRunning');
    };
    const local = new LocalEngine({ loadCore: async () => testCore, disk: memoryStore(), emit: () => undefined, memoryKib: [65_536], chip });
    await local.create(PASSWORD);
    expect((await local.meta())?.chip).toBeUndefined();
    local.lock();
    await local.unlock(PASSWORD);
  });
});
