// Local mode through WASM: create, store, unlock, back up, restore, and turn on sync.
// Run `pnpm --filter @octapass/core build` first.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { describe, test } from 'node:test';

const core = createRequire(import.meta.url)('../dist/node/octapass_core.js');
const { DerivedKeys, LocalVault, TestOpaqueServer } = core;

const PASSWORD = 'vexed-kiwi-trumpet-galaxy-oboe';
const CHIP = new Uint8Array(32).fill(5);
const item = {
  overview: { schemaVersion: 1, title: 'Example', type: 'login', urls: ['https://example.com'] },
  details: { schemaVersion: 1, username: 'alice', password: 'hunter2', fieldFromTheFuture: [1, 2] },
};

describe('local vault', () => {
  const vault = LocalVault.create(PASSWORD);
  const itemId = vault.addItem(item);

  test('create, add, store and unlock', () => {
    assert.match(vault.backupRecoveryCode, /^[0-9A-Z]{5}(-[0-9A-Z]{5}){10}$/);
    assert.equal(vault.hardwareBound, false);
    const blob = vault.toBytes();
    const file = JSON.parse(new TextDecoder().decode(blob));
    assert.equal(file.format, 'octapass-local-vault');
    assert.deepEqual(file.kdf, { algorithm: 'argon2id', memoryKib: 262144, iterations: 3, parallelism: 1 });
    assert.ok(!new TextDecoder().decode(blob).includes('hunter2'));

    const again = LocalVault.unlock(blob, PASSWORD);
    assert.deepEqual(again.getItem(itemId), item);
    const [listed] = again.list();
    assert.equal(listed.overview.title, 'Example');
    assert.equal(typeof listed.updatedAt, 'number');
    again.free();
    assert.throws(() => LocalVault.unlock(blob, 'wrong'), { code: 'login_failed' });
  });

  test('edit, trash, restore and purge', () => {
    const id = vault.addItem(item);
    vault.updateItem(id, { ...item, overview: { ...item.overview, title: 'Renamed' } });
    assert.equal(vault.getItem(id).overview.title, 'Renamed');
    vault.deleteItem(id);
    assert.equal(typeof vault.list().find((i) => i.id === id).deletedAt, 'number');
    vault.restoreItem(id);
    assert.equal(vault.list().find((i) => i.id === id).deletedAt, undefined);
    vault.purgeItem(id);
    assert.throws(() => vault.getItem(id), { code: 'item_not_found' });
  });

  test('weak passwords need the device chip', () => {
    assert.throws(() => LocalVault.create('password123', { memoryKib: 65536 }), { code: 'weak_master_password' });
    const bound = LocalVault.create('password123', { memoryKib: 65536, hardwareSecret: CHIP });
    const blob = bound.toBytes();
    assert.throws(() => LocalVault.unlock(blob, 'password123'), { code: 'hardware_secret_required' });
    assert.ok(LocalVault.unlock(blob, 'password123', CHIP).hardwareBound);
    bound.free();
  });

  test('backups restore with the password or the recovery code', () => {
    const backup = vault.createBackup();
    assert.deepEqual([...backup.subarray(0, 5)], [...new TextEncoder().encode('OPBK'), 1]);
    const restored = LocalVault.restoreBackup(backup, { password: PASSWORD }, PASSWORD, { memoryKib: 65536, hardwareSecret: CHIP });
    assert.deepEqual(restored.getItem(itemId), item);
    restored.free();

    const newPassword = 'quartz-meadow-lantern-fjord-pixel';
    const recovered = LocalVault.restoreBackup(backup, { recoveryCode: vault.backupRecoveryCode }, newPassword, { memoryKib: 65536 });
    assert.deepEqual(LocalVault.unlock(recovered.toBytes(), newPassword).getItem(itemId), item);
    recovered.free();
    assert.throws(() => LocalVault.restoreBackup(backup, { password: 'wrong' }, PASSWORD), { code: 'login_failed' });
  });

  test('turn on sync keeps the keys and uploads items unchanged', () => {
    const opaque = new TestOpaqueServer();
    const signup = vault.upgradeToAccount('Alice@Example.com', 'account password');
    const body = signup.finish(opaque.registrationStart(signup.email, signup.registrationRequest));
    const passwordFile = opaque.registrationFinish(body.registrationUpload);
    assert.equal(body.personalVault.id, vault.vaultId);
    const uploaded = vault.items();
    assert.deepEqual(Object.keys(uploaded[0]).sort(), ['createdAt', 'details', 'encryptedItemKey', 'id', 'overview', 'updatedAt']);

    // A new device signs in to the account and reads the uploaded ciphertext.
    const keys = DerivedKeys.derive('alice@example.com', 'account password', signup.secretKey, { kdf: body.account.kdf, accountSalt: body.account.accountSalt });
    const flow = keys.startLogin();
    const login = opaque.loginStart(signup.email, passwordFile, flow.credentialRequest);
    login.finish(flow.finish(login.credentialResponse));
    const session = keys.unlock(body.account);
    session.openVault(body.personalVault.id, body.personalVault.wrappedVaultKey);
    assert.deepEqual(session.decryptItem(vault.vaultId, uploaded[0].id, uploaded[0]), item);
    session.free();
    keys.free();
    signup.free();
  });
});
