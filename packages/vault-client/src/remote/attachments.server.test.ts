// Attachments and Document items: the real service against the real server, with files encrypted
// and decrypted by the WASM core. `pnpm --filter @octapass/vault-client test:server`.

import type { DocumentDetails, ItemDraft, LoginDetails } from '../types';
import { device, eventually, expectCode, PASSWORD, signedUp as signUp } from './testing/devices';
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

function bytes(length: number, seed = 1): Uint8Array<ArrayBuffer> {
  return new Uint8Array(length).map((_, i) => (i * 31 + seed) % 251);
}

async function contents(blob: Blob): Promise<Uint8Array> {
  return new Uint8Array(await blob.arrayBuffer());
}

function login(vaultId: string, title: string): ItemDraft {
  return { vaultId, overview: { schemaVersion: 1, title, type: 'login' }, details: { schemaVersion: 1, username: 'maya', password: 'pw' } as LoginDetails };
}

function document(vaultId: string, title: string): ItemDraft {
  return { vaultId, overview: { schemaVersion: 1, title, type: 'document' }, details: { schemaVersion: 1, notes: 'Signed in March' } };
}

describe('attachments', () => {
  it('adds, downloads and removes a file, and counts it in the usage', async () => {
    const { service } = await signedUp();
    const vaultId = (await service.listVaults())[0]!.id;
    const item = await service.saveItem(login(vaultId, 'Bank'));
    // Several chunks and slices, so the streaming paths run.
    const file = bytes(2_500_000);
    const withFile = await service.addAttachment(item.id, new Blob([file], { type: 'application/pdf' }), 'statement.pdf');
    const [attachment] = withFile.details.attachments!;
    expect(attachment).toMatchObject({ name: 'statement.pdf', type: 'application/pdf', size: file.length });

    const downloaded = await service.getAttachment(item.id, attachment!.id);
    expect(downloaded.type).toBe('application/pdf');
    expect(await contents(downloaded)).toEqual(file);
    const usage = await service.getStorageUsage();
    expect(usage.attachmentBytes).toBeGreaterThan(file.length);
    expect(usage.maxAttachmentBytes).toBe(1024 ** 3);
    expect(usage.maxFileBytes).toBe(100 * 1024 ** 2);

    // An edit from a form that never saw the file keeps it.
    const edited = await service.saveItem({ ...withFile, overview: { ...item.overview, title: 'Bank (old)' }, details: item.details });
    expect(edited.details.attachments?.map((a) => a.id)).toEqual([attachment!.id]);

    const removed = await service.removeAttachment(item.id, attachment!.id);
    expect(removed.details.attachments).toBeUndefined();
    await expectCode(service.getAttachment(item.id, attachment!.id), 'notFound');
    expect((await service.getStorageUsage()).attachmentBytes).toBe(0);
  });

  it('opens a Document on another device, and copies its file into another vault', async () => {
    const first = await signedUp();
    const vaultId = (await first.service.listVaults())[0]!.id;
    const created = await first.service.saveItem(document(vaultId, 'Lease'));
    const empty = new Blob([]);
    await first.service.addAttachment(created.id, new Blob([bytes(70_000)], { type: 'text/plain' }), 'lease.txt');
    await first.service.addAttachment(created.id, empty, 'empty.txt');

    const second = await device();
    await second.service.signIn({ serverUrl: server.url, email: first.email, password: PASSWORD, secretKey: first.secretKey });
    const synced = await second.service.getItem(created.id);
    expect(synced.overview.type).toBe('document');
    expect((synced.details as DocumentDetails).notes).toBe('Signed in March');
    const [lease, blank] = synced.details.attachments!;
    expect(await contents(await second.service.getAttachment(created.id, lease!.id))).toEqual(bytes(70_000));
    expect((await second.service.getAttachment(created.id, blank!.id)).size).toBe(0);

    // A copy has its own item key, so its files are encrypted again for it.
    const work = await first.service.createVault('Work');
    const copy = await first.service.copyItem(created.id, work.id);
    expect(copy.details.attachments?.map((a) => a.name)).toEqual(['lease.txt', 'empty.txt']);
    expect(copy.details.attachments![0]!.id).not.toBe(lease!.id);
    expect(await contents(await first.service.getAttachment(copy.id, copy.details.attachments![0]!.id))).toEqual(bytes(70_000));
  });

  it('lets members read a shared vault’s files, and counts them against the owner', async () => {
    const owner = await signedUp();
    const writer = await signedUp();
    const reader = await signedUp();
    const vault = await owner.service.createVault('Household');
    for (const [member, role] of [[writer, 'write'], [reader, 'read']] as const) {
      await owner.service.addMember(vault.id, await owner.service.lookupAccount(member.email), role);
      await member.service.listVaults();
    }
    const item = await writer.service.saveItem(document(vault.id, 'Boiler warranty'));
    const added = await writer.service.addAttachment(item.id, new Blob([bytes(1000)]), 'warranty.pdf');
    const id = added.details.attachments![0]!.id;

    expect((await owner.service.getStorageUsage()).attachmentBytes).toBeGreaterThan(1000);
    expect((await writer.service.getStorageUsage()).attachmentBytes).toBe(0);

    // The reader learns about the item and its file through live sync.
    await eventually(async () => expect((await reader.service.getItem(item.id)).details.attachments).toHaveLength(1));
    expect(await contents(await reader.service.getAttachment(item.id, id))).toEqual(bytes(1000));
    await expectCode(reader.service.addAttachment(item.id, new Blob([bytes(10)]), 'x'), 'readOnlyVault');
    await expectCode(reader.service.removeAttachment(item.id, id), 'readOnlyVault');
  });
});

describe('limits', () => {
  let small: TestServer;
  beforeAll(async () => {
    small = await startServer({ env: { OCTAPASS_MAX_FILE_BYTES: '5000', OCTAPASS_MAX_ATTACHMENT_BYTES: '8000' } });
  });
  afterAll(() => small?.stop());

  it('refuses files over the size limit and the quota before uploading', async () => {
    const { service } = await signUp(small.url);
    const vaultId = (await service.listVaults())[0]!.id;
    const item = await service.saveItem(document(vaultId, 'Scans'));
    await expectCode(service.addAttachment(item.id, new Blob([bytes(5000)]), 'big.png'), 'fileTooLarge');
    await service.addAttachment(item.id, new Blob([bytes(4000)]), 'one.png');
    await expectCode(service.addAttachment(item.id, new Blob([bytes(4000)]), 'two.png'), 'quotaExceeded');
    expect((await service.getItem(item.id)).details.attachments?.map((a) => a.name)).toEqual(['one.png']);
  });
});
