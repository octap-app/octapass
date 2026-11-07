// Attachments through WASM: a file encrypted in pieces opens in other pieces, and only in its item.
// Run `pnpm --filter @octapass/core build` first.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { before, describe, test } from 'node:test';

const core = createRequire(import.meta.url)('../dist/node/octapass_core.js');
const { Signup, attachmentEncryptedSize, newId } = core;

const CHUNK = 64 * 1024;

function pieces(bytes, size) {
  const out = [];
  for (let i = 0; i < bytes.length; i += size) out.push(bytes.subarray(i, i + size));
  return out;
}

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

describe('attachments', () => {
  let session;
  let vaultId;
  const itemId = newId();
  let item;

  before(() => {
    const signup = Signup.create('files@example.com', 'correct horse battery staple');
    const body = signup.finish(new core.TestOpaqueServer().registrationStart(signup.email, signup.registrationRequest));
    session = signup.derivedKeys().unlock({ accountId: newId(), ...body.account });
    vaultId = body.personalVault.id;
    session.openVault(vaultId, body.personalVault.wrappedVaultKey);
    item = session.encryptItem(vaultId, itemId, { overview: { title: 'Lease', type: 'document' }, details: { notes: 'signed' } });
  });

  test('a file encrypted in pieces decrypts in other pieces', () => {
    const file = new Uint8Array(2 * CHUNK + 123).map((_, i) => i % 251);
    const attachmentId = newId();
    const encryptor = session.newAttachment(vaultId, itemId, item.encryptedItemKey, attachmentId);
    assert.match(encryptor.wrappedKey, /^[A-Za-z0-9_-]+$/);
    const encrypted = concat([...pieces(file, 50_000).map((p) => encryptor.push(p)), encryptor.finish()]);
    assert.equal(encrypted.length, attachmentEncryptedSize(file.length));
    assert.throws(() => encryptor.push(file), { code: 'flow_finished' });

    const decryptor = session.openAttachment(vaultId, itemId, item.encryptedItemKey, attachmentId, encryptor.wrappedKey);
    const plain = concat([...pieces(encrypted, 70_001).map((p) => decryptor.push(p)), decryptor.finish()]);
    assert.deepEqual(plain, file);
  });

  test('a cut-short or moved file is refused', () => {
    const attachmentId = newId();
    const encryptor = session.newAttachment(vaultId, itemId, item.encryptedItemKey, attachmentId);
    const encrypted = concat([encryptor.push(new Uint8Array(CHUNK + 1)), encryptor.finish()]);

    const cut = session.openAttachment(vaultId, itemId, item.encryptedItemKey, attachmentId, encryptor.wrappedKey);
    cut.push(encrypted.subarray(0, encrypted.length - 1));
    assert.throws(() => cut.finish(), { code: 'decryption_failed' });

    assert.throws(
      () => session.openAttachment(vaultId, itemId, item.encryptedItemKey, newId(), encryptor.wrappedKey),
      { code: 'decryption_failed' },
    );
    const other = session.encryptItem(vaultId, itemId, { overview: { title: 'x', type: 'document' }, details: {} });
    assert.throws(
      () => session.openAttachment(vaultId, itemId, other.encryptedItemKey, attachmentId, encryptor.wrappedKey),
      { code: 'wrong_key' },
    );
  });

  test('sizes', () => {
    assert.equal(attachmentEncryptedSize(0), 52);
    assert.equal(attachmentEncryptedSize(CHUNK + 1), 36 + CHUNK + 1 + 32);
    assert.throws(() => attachmentEncryptedSize(-1), { code: 'invalid_argument' });
    assert.throws(() => attachmentEncryptedSize(1.5), { code: 'invalid_argument' });
  });
});
