// The key log (plan 03) through the real service on real accounts against the real server:
// publishing, hybrid grants, and what a device does when the server lies about someone's keys.
// `pnpm --filter @octapass/vault-client test:server`.

import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { eventually, expectCode, signedUp as signUp } from './testing/devices';
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

/** Reads or changes the server's database, as a malicious operator could. */
function withDb<T>(run: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(join(server.dataDir, 'octapass.db'));
  try {
    return run(db);
  } finally {
    db.close();
  }
}

function sealedVersion(vaultId: string, email: string): number {
  const row = withDb(
    (db) =>
      db
        .prepare('SELECT m.wrapped_vault_key AS key FROM vault_members m JOIN accounts a ON a.id = m.account_id WHERE m.vault_id = ? AND a.email = ?')
        .get(vaultId, email) as { key: string },
  );
  return Buffer.from(row.key, 'base64url')[0]!;
}

describe('the key log', () => {
  it('publishes every account, and shares with hybrid grants that open', async () => {
    const [maya, sam] = await Promise.all([signedUp(), signedUp()]);
    await eventually(async () => expect(await maya.service.getKeyLogState()).toMatchObject({ published: true }));
    await eventually(async () => expect((await sam.service.getKeyLogState()).published).toBe(true));

    const account = await maya.service.lookupAccount(sam.email);
    expect(account.keyLog).toBe('verified');
    const vault = await maya.service.createVault('Household');
    const item = await maya.service.saveItem({
      vaultId: vault.id,
      overview: { schemaVersion: 1, title: 'Wi-Fi', type: 'login', urls: ['https://example.com'] },
      details: { schemaVersion: 1, username: 'maya', password: 'ochre-lantern' },
    });
    await maya.service.addMember(vault.id, account, 'write');
    expect(sealedVersion(vault.id, sam.email)).toBe(2);
    expect(sealedVersion(vault.id, maya.email)).toBe(2);

    await eventually(async () => expect((await sam.service.getItem(item.id)).id).toBe(item.id));
    const members = await maya.service.listMembers(vault.id);
    expect(members.find((m) => m.email === sam.email)?.keyLog).toBe('verified');
    expect(members.find((m) => m.isYou)?.keyLog).toBeUndefined();

    // A rotation reseals everyone, and the vault keeps working.
    await maya.service.removeMember(vault.id, (await maya.service.lookupAccount(sam.email)).accountId);
    expect(sealedVersion(vault.id, maya.email)).toBe(2);
    expect((await maya.service.getItem(item.id)).id).toBe(item.id);
  });

  it('refuses to share when the server swaps someone’s keys', async () => {
    const [maya, sam, carol] = await Promise.all([signedUp(), signedUp(), signedUp()]);
    await eventually(async () => expect((await sam.service.getKeyLogState()).published).toBe(true));
    await eventually(async () => expect((await carol.service.getKeyLogState()).published).toBe(true));
    expect((await maya.service.lookupAccount(sam.email)).keyLog).toBe('verified');

    // The server answers for Sam with Carol's keys.
    withDb((db) => {
      const carolKeys = db.prepare('SELECT public_enc_key AS enc, public_sign_key AS sign, key_record AS record FROM accounts WHERE email = ?').get(carol.email) as { enc: string; sign: string; record: string };
      db.prepare('UPDATE accounts SET public_enc_key = ?, public_sign_key = ?, key_record = ? WHERE email = ?').run(carolKeys.enc, carolKeys.sign, carolKeys.record, sam.email);
    });
    const swapped = await maya.service.lookupAccount(sam.email);
    expect(swapped.keyLog).toBe('failed');
    const vault = await maya.service.createVault('Household');
    await expectCode(maya.service.addMember(vault.id, swapped, 'read'), 'keyLogMismatch');
  });

  it('marks accounts that have nothing in the log, and seals to them with the older box', async () => {
    const [maya, sam] = await Promise.all([signedUp(), signedUp()]);
    await eventually(async () => expect((await sam.service.getKeyLogState()).published).toBe(true));
    // As an account whose client hasn't published yet.
    withDb((db) => {
      db.prepare('UPDATE accounts SET key_record = NULL, wrapped_pq_private_key = NULL WHERE email = ?').run(sam.email);
      db.prepare('UPDATE key_log_leaves SET record = NULL WHERE account_id = (SELECT id FROM accounts WHERE email = ?)').run(sam.email);
    });
    const account = await maya.service.lookupAccount(sam.email);
    expect(account.keyLog).toBe('notLogged');
    const vault = await maya.service.createVault('Household');
    await maya.service.addMember(vault.id, account, 'read');
    expect(sealedVersion(vault.id, sam.email)).toBe(1);
  });

  it('raises an alert when the log holds a record this account didn’t make', async () => {
    const maya = await signedUp();
    await eventually(async () => expect((await maya.service.getKeyLogState()).checkedAt).toBeDefined());
    expect((await maya.service.getKeyLogState()).alert).toBeUndefined();

    // The server serves a different record under Maya's label.
    withDb((db) => {
      const { record } = db.prepare('SELECT record FROM key_log_leaves WHERE account_id = (SELECT id FROM accounts WHERE email = ?)').get(maya.email) as { record: string };
      const forged = JSON.stringify({ ...(JSON.parse(record) as object), createdAt: 1 });
      db.prepare('UPDATE key_log_leaves SET record = ? WHERE account_id = (SELECT id FROM accounts WHERE email = ?)').run(forged, maya.email);
    });
    // Reading the log is hourly; dismissing reads it at once.
    await maya.service.dismissKeyLogAlert();
    await eventually(async () => expect((await maya.service.getKeyLogState()).alert?.kind).toBe('foreignRecord'));
  });
});
