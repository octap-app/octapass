// Exports and imports: the real service against the real server, with the WASM core. An encrypted
// export moves every item and every attached file into a fresh account; CXF and the plaintext
// JSON move what they hold. `pnpm --filter @octapass/vault-client test:server`.

import type { DocumentDetails, ItemDraft, LoginDetails } from '../types';
import { expectCode, PASSWORD, signedUp as signUp } from './testing/devices';
import { startServer, type TestServer } from './testing/server';

let server: TestServer;

beforeAll(async () => {
  server = await startServer();
});
afterAll(() => server?.stop());
afterEach(({ task }) => {
  if (task.result?.state === 'fail') console.error(server.output().split('\n').filter((line) => !line.includes('dev mode')).join('\n'));
});

// Cheap Argon2id, so the test doesn't spend its time on the 256 MiB default.
const exportKdf = { algorithm: 'argon2id', memoryKib: 65_536, iterations: 3, parallelism: 1 } as const;
const signedUp = () => signUp(server.url, { exportKdf });

function bytes(length: number, seed = 1): Uint8Array<ArrayBuffer> {
  return new Uint8Array(length).map((_, i) => (i * 31 + seed) % 251);
}

async function file(blob: Blob, name: string): Promise<File> {
  return new File([await blob.arrayBuffer()], name);
}

async function filled() {
  const device = await signedUp();
  const vaultId = (await device.service.listVaults())[0]!.id;
  const identity = await device.service.saveItem({
    vaultId,
    overview: { schemaVersion: 1, title: 'Me', type: 'identity' },
    details: { schemaVersion: 1, firstName: 'ليلى', email: 'layla@example.com' },
  } as ItemDraft);
  const login = await device.service.saveItem({
    vaultId,
    overview: { schemaVersion: 1, title: 'Bank', type: 'login', urls: ['https://bank.example'] },
    details: {
      schemaVersion: 1,
      username: 'layla',
      password: 'p,"w"',
      totp: 'otpauth://totp/Bank:layla?secret=JBSWY3DPEHPK3PXP&issuer=Bank',
      recovery: { email: 'layla@example.com', emailSource: { kind: 'identity', itemId: identity.id } },
    } as LoginDetails,
  });
  // Several chunks of both the attachment and the export.
  const big = bytes(300_000);
  await device.service.addAttachment(login.id, new Blob([big], { type: 'application/pdf' }), 'statement.pdf');
  const lease = await device.service.saveItem({ vaultId, overview: { schemaVersion: 1, title: 'Lease', type: 'document' }, details: { schemaVersion: 1, notes: 'Signed' } });
  await device.service.addAttachment(lease.id, new Blob([bytes(10, 7)], { type: 'text/plain' }), 'عقد.txt');
  return { device, big };
}

describe('the encrypted export', () => {
  it('moves every item and file into a fresh account', async () => {
    const { device, big } = await filled();
    await expectCode(device.service.exportVault('encrypted', { password: 'export pw', masterPassword: 'wrong' }), 'invalidCredentials');
    const exported = await device.service.exportVault('encrypted', { password: 'export pw', masterPassword: PASSWORD });
    const head = new TextDecoder().decode(new Uint8Array(await exported.slice(0, 4).arrayBuffer()));
    expect(head).toBe('OPEX');

    const fresh = await signedUp();
    const upload = await file(exported, 'backup.octapass');
    await expectCode(fresh.service.importFile('octapass', upload), 'importPasswordRequired');
    await expectCode(fresh.service.importFile('octapass', upload, { password: 'nope' }), 'wrongImportPassword');
    const result = await fresh.service.importFile('octapass', upload, { password: 'export pw' });
    expect(result).toEqual({ imported: 3, skipped: 0, warnings: [], files: 2 });

    const items = await fresh.service.listItems();
    const byTitle = (title: string) => fresh.service.getItem(items.find((i) => i.title === title)!.id);
    const bank = await byTitle('Bank');
    const me = await byTitle('Me');
    const details = bank.details as LoginDetails;
    expect(details.password).toBe('p,"w"');
    expect(details.recovery?.emailSource).toEqual({ kind: 'identity', itemId: me.id });
    const [statement] = bank.details.attachments!;
    expect(statement).toMatchObject({ name: 'statement.pdf', type: 'application/pdf', size: big.length });
    expect(new Uint8Array(await (await fresh.service.getAttachment(bank.id, statement!.id)).arrayBuffer())).toEqual(big);
    const lease = await byTitle('Lease');
    expect((lease.details as DocumentDetails).notes).toBe('Signed');
    expect(lease.details.attachments!.map((a) => a.name)).toEqual(['عقد.txt']);
  });

  it('imported again into the same account, adds only what the vaults no longer have', async () => {
    const { device } = await filled();
    const backup = await file(await device.service.exportVault('encrypted', { password: 'export pw' }), 'backup.octapass');
    const before = await device.service.listItems();
    expect(await device.service.importFile('octapass', backup, { password: 'export pw' })).toEqual({ imported: 0, skipped: 0, warnings: [], unchanged: 3 });
    expect(await device.service.listItems()).toHaveLength(before.length);

    // The identity goes to the trash, and the lease changes after the export: the identity comes
    // back, the lease's newer version stays.
    const byTitle = (title: string) => before.find((i) => i.title === title)!.id;
    await device.service.deleteItem(byTitle('Me'));
    const lease = await device.service.getItem(byTitle('Lease'));
    await device.service.saveItem({ ...lease, details: { ...lease.details, notes: 'Signed again' } as DocumentDetails });
    const again = await device.service.importFile('octapass', backup, { password: 'export pw' });
    expect(again).toEqual({ imported: 1, skipped: 0, unchanged: 2, warnings: ["1 item changed in the vault after this export was made, so the vault's version was kept."] });
    const after = await device.service.listItems();
    expect(after.map((i) => i.title).sort()).toEqual(['Bank', 'Lease', 'Me']);
    expect(((await device.service.getItem(byTitle('Lease'))).details as DocumentDetails).notes).toBe('Signed again');
  });

  it('into another account, recognises its items the second time and brings files to items that lack them', async () => {
    const other = await signedUp();
    const vaultId = (await other.service.listVaults())[0]!.id;
    // The same lease, saved here without its file before the export was made.
    const lease = await other.service.saveItem({ vaultId, overview: { schemaVersion: 1, title: 'Lease', type: 'document' }, details: { schemaVersion: 1, notes: 'Signed' } });
    const { device } = await filled();
    const backup = await file(await device.service.exportVault('encrypted', { password: 'export pw' }), 'backup.octapass');
    expect(await other.service.importFile('octapass', backup, { password: 'export pw' })).toEqual({ imported: 2, skipped: 0, warnings: [], unchanged: 1, files: 2 });
    expect((await other.service.getItem(lease.id)).details.attachments!.map((a) => a.name)).toEqual(['عقد.txt']);
    expect(await other.service.listItems()).toHaveLength(3);

    expect(await other.service.importFile('octapass', backup, { password: 'export pw' })).toEqual({ imported: 0, skipped: 0, warnings: [], unchanged: 3 });
    expect(await other.service.listItems()).toHaveLength(3);
  });

  it('is refused without a password, and damage is caught', async () => {
    const { device } = await filled();
    await expect(device.service.exportVault('encrypted', { password: '' })).rejects.toBeDefined();
    const exported = new Uint8Array(await (await device.service.exportVault('encrypted', { password: 'export pw' })).arrayBuffer());
    exported[exported.length - 5]! ^= 1;
    const fresh = await signedUp();
    await expectCode(fresh.service.importFile('octapass', new File([exported], 'x.octapass'), { password: 'export pw' }), 'invalidImportFile');
  });
});

describe('plaintext and CXF exports', () => {
  it('bring items, but not files, into another account', async () => {
    const { device } = await filled();
    const fresh = await signedUp();
    const json = await fresh.service.importFile('octapass', await file(await device.service.exportVault('json'), 'export.json'));
    expect(json.imported).toBe(3);
    expect(json.warnings).toEqual(["2 attached files aren't in this export: only the encrypted export includes them."]);

    const cxf = await device.service.exportVault('cxf');
    const header = JSON.parse(await cxf.text());
    expect(header).toMatchObject({ version: { major: 1, minor: 0 }, exporterDisplayName: 'Octa Pass', exporterRpId: new URL(server.url).hostname });
    const other = await signedUp();
    const result = await other.service.importFile('cxf', await file(cxf, 'export.json'));
    expect(result.imported).toBe(3);
    const bank = (await other.service.listItems()).find((i) => i.title === 'Bank')!;
    expect(((await other.service.getItem(bank.id)).details as LoginDetails).totp).toContain('secret=JBSWY3DPEHPK3PXP');
  });

  it('adds each export to the security log, naming the device and nothing from the vault', async () => {
    const { device } = await filled();
    await device.service.exportVault('csv');
    await device.service.exportVault('encrypted', { password: 'export pw' });
    await vi.waitFor(async () => expect((await device.service.sharing!.getSecurityLog()).filter((e) => e.type === 'vault-exported')).toHaveLength(2));
    const [encrypted, csv] = (await device.service.sharing!.getSecurityLog()).filter((e) => e.type === 'vault-exported');
    expect(encrypted).toMatchObject({ exportFormat: 'encrypted', exportAttachments: true, deviceName: expect.any(String) });
    expect(csv).toMatchObject({ exportFormat: 'csv', exportAttachments: false });
    expect(JSON.stringify(csv)).not.toContain('Bank');
  });

  it('imports other apps through the core, joining one-time codes to existing logins', async () => {
    const { device } = await filled();
    const before = (await device.service.listItems()).length;
    const codes = 'otpauth://totp/Bank:layla?secret=GEZDGNBVGY3TQOJQ&issuer=Bank\notpauth://totp/New:me?secret=GEZDGNBVGY3TQOJQ&issuer=New\n';
    // Bank already has a code, so both become new logins; the core decides.
    const result = await device.service.importFile('otpauth', new File([codes], 'codes.txt'));
    expect(result.imported).toBe(2);
    expect((await device.service.listItems()).length).toBe(before + 2);
  });

  it('updates what an earlier import of the same file brought, keeping its dates', async () => {
    const device = await signedUp();
    const header = '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\n';
    const row = (password: string, changed: number) =>
      `"https://www.example.org","alice","${password}",,"https://www.example.org","{6a7e1f4e-0000-4000-8000-000000000001}","1600000000000","1700000500000","${changed}"\n`;
    const router = '"http://192.168.0.1","admin","admin","Router Admin",,"{6a7e1f4e-0000-4000-8000-000000000002}","1600000000000","1600000000000","1600000000000"\n';
    const first = await device.service.importFile('firefox', new File([header + row('one', 1650000000000) + router], 'passwords.csv'));
    expect(first).toEqual({ imported: 2, skipped: 0, warnings: [] });

    const again = await device.service.importFile('firefox', new File([header + row('one', 1650000000000) + router], 'passwords.csv'));
    expect(again).toEqual({ imported: 0, unchanged: 2, skipped: 0, warnings: [] });

    const changed = await device.service.importFile('firefox', new File([header + row('two', 1700000000000) + router], 'passwords.csv'));
    expect(changed).toEqual({ imported: 0, updated: 1, unchanged: 1, skipped: 0, warnings: [] });
    const items = await device.service.listItems();
    expect(items).toHaveLength(2);
    const login = await device.service.getItem(items.find((i) => i.title === 'example.org')!.id);
    expect(login.overview).toMatchObject({ createdAt: '2020-09-13T12:26:40Z', updatedAt: '2023-11-14T22:13:20Z', lastUsedAt: '2023-11-14T22:21:40Z' });
    const details = login.details as LoginDetails;
    expect(details.password).toBe('two');
    expect(details.passwordHistory).toEqual([{ password: 'one', changedAt: '2023-11-14T22:13:20Z' }]);
    const realm = await device.service.getItem(items.find((i) => i.title === '192.168.0.1')!.id);
    expect((realm.details as LoginDetails).httpRealm).toBe('Router Admin');
  });
});
