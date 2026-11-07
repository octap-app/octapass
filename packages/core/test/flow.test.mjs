// The whole client lifecycle through WASM, against the in-WASM OPAQUE test server:
// sign-up → login on a new device → encrypt → decrypt → reauth → recovery.
// Run `pnpm --filter @octapass/core build` first.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { before, describe, test } from 'node:test';

const core = createRequire(import.meta.url)('../dist/node/octapass_core.js');
const { DerivedKeys, Session, Signup, TestOpaqueServer, newId } = core;

const EMAIL = 'Alice@Example.com';
const PASSWORD = 'correct horse battery staple';
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** Stands in for the sync server: OPAQUE plus what it stores. */
class FakeServer {
  opaque = new TestOpaqueServer();
  accounts = new Map();

  register(signup) {
    const registrationResponse = this.opaque.registrationStart(signup.email, signup.registrationRequest);
    const body = signup.finish(registrationResponse);
    this.accounts.set(signup.email, {
      passwordFile: this.opaque.registrationFinish(body.registrationUpload),
      account: { accountId: newId(), ...body.account },
      vault: body.personalVault,
    });
    return body;
  }

  prelogin(email) {
    const { account } = this.accounts.get(email.trim().toLowerCase());
    return { kdf: account.kdf, accountSalt: account.accountSalt };
  }

  /** login/start + login/finish (also used for reauth). Returns the bundle on success. */
  login(email, flow) {
    const stored = this.accounts.get(email.trim().toLowerCase());
    const serverLogin = this.opaque.loginStart(email, stored?.passwordFile, flow.credentialRequest);
    const credentialFinalization = flow.finish(serverLogin.credentialResponse);
    serverLogin.finish(credentialFinalization);
    return stored.account;
  }
}

const item = {
  overview: { schemaVersion: 1, title: 'GitHub', type: 'login', urls: ['https://github.com'], favorite: true },
  details: {
    schemaVersion: 1,
    username: 'alice',
    password: 'hunter2',
    totp: 'otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP',
    customFields: [{ label: 'PIN', value: '1234', hidden: true }],
    fieldFromTheFuture: { kept: true },
  },
};

describe('sign-up, login, encrypt, decrypt, reauth, recovery', () => {
  const server = new FakeServer();
  let signup;
  let registered;

  before(() => {
    signup = Signup.create(EMAIL, PASSWORD);
    registered = server.register(signup);
  });

  test('sign-up produces display secrets and the register/finish body', () => {
    assert.equal(signup.email, 'alice@example.com');
    assert.match(signup.secretKey, /^OP1-[0-9A-Z]{6}-[0-9A-Z]{6}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{4}$/);
    assert.match(signup.recoveryCode, /^[0-9A-Z]{5}(-[0-9A-Z]{5}){10}$/);
    assert.match(registered.registrationUpload, BASE64URL);
    assert.equal(registered.account.email, 'alice@example.com');
    assert.deepEqual(registered.account.kdf, { algorithm: 'argon2id', memoryKib: 65536, iterations: 3, parallelism: 1 });
    for (const field of ['accountSalt', 'wrappedAsk', 'publicEncKey', 'publicSignKey', 'wrappedPrivateKeys', 'recoveryWrappedAsk']) {
      assert.match(registered.account[field], BASE64URL, field);
    }
    assert.match(registered.personalVault.id, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-/);
    assert.match(registered.personalVault.wrappedVaultKey, BASE64URL);
    assert.throws(() => signup.finish('AAAA'), { name: 'OctaPassError', code: 'flow_finished' });
  });

  test('logs in right after sign-up without deriving again', () => {
    const keys = signup.derivedKeys();
    const account = server.login(EMAIL, keys.startLogin());
    const session = keys.unlock(account);
    assert.equal(session.account.accountId, account.accountId);
    session.free();
    keys.free();
  });

  test('new device: derive, login, unlock, encrypt and decrypt', () => {
    const keys = DerivedKeys.derive(EMAIL, PASSWORD, signup.secretKey.toLowerCase(), server.prelogin(EMAIL));
    const account = server.login(EMAIL, keys.startLogin());
    const session = keys.unlock(account);
    const { id: vaultId, wrappedVaultKey } = registered.personalVault;
    const itemId = newId();

    assert.throws(() => session.encryptItem(vaultId, itemId, item), { code: 'vault_not_open' });
    session.openVault(vaultId, wrappedVaultKey);
    assert.ok(session.isVaultOpen(vaultId));

    const encrypted = session.encryptItem(vaultId, itemId, item);
    assert.deepEqual(Object.keys(encrypted).sort(), ['details', 'encryptedItemKey', 'overview']);
    for (const value of Object.values(encrypted)) assert.match(value, BASE64URL);
    assert.ok(!JSON.stringify(encrypted).includes('hunter2'));

    assert.deepEqual(session.decryptItem(vaultId, itemId, encrypted), item);
    assert.equal(session.decryptOverview(vaultId, itemId, encrypted).title, 'GitHub');

    // An update keeps the item key; ciphertext can't be moved to another item.
    const updated = session.encryptItem(vaultId, itemId, { ...item, overview: { ...item.overview, title: 'GitHub (work)' } }, encrypted.encryptedItemKey);
    assert.equal(session.decryptOverview(vaultId, itemId, updated).title, 'GitHub (work)');
    assert.throws(() => session.decryptItem(vaultId, newId(), updated), { name: 'OctaPassError' });
    assert.throws(() => session.encryptItem(vaultId, itemId, { overview: { type: 'login' }, details: {} }), { code: 'invalid_item' });

    session.free();
    keys.free();
  });

  test('a wrong password fails locally and at the server', () => {
    const keys = DerivedKeys.derive(EMAIL, 'Correct horse battery staple', signup.secretKey, server.prelogin(EMAIL));
    assert.throws(() => server.login(EMAIL, keys.startLogin()), { code: 'login_failed' });
    assert.throws(() => keys.unlock(server.accounts.get('alice@example.com').account), { code: 'login_failed' });
    keys.free();
  });

  test('reauth runs a fresh OPAQUE login and leaves the session alone', () => {
    const keys = signup.derivedKeys();
    const session = keys.unlock(server.login(EMAIL, keys.startLogin()));
    const { id: vaultId, wrappedVaultKey } = registered.personalVault;
    session.openVault(vaultId, wrappedVaultKey);
    const itemId = newId();
    const encrypted = session.encryptItem(vaultId, itemId, item);

    const reauth = session.startReauth(PASSWORD, signup.secretKey);
    server.login(EMAIL, reauth);
    assert.throws(() => reauth.finish('AAAA'), { code: 'flow_finished' });
    assert.deepEqual(session.decryptItem(vaultId, itemId, encrypted), item);

    assert.throws(() => session.startReauth('wrong password', signup.secretKey), { code: 'login_failed' });
    session.free();
    keys.free();
  });

  test('device unlock wraps the account key with the passkey PRF output', () => {
    const keys = signup.derivedKeys();
    const session = keys.unlock(server.login(EMAIL, keys.startLogin()));
    const prfOutput = new Uint8Array(32).fill(7);
    const stored = session.enableDeviceUnlock(prfOutput);
    assert.match(stored.deviceSalt, BASE64URL);
    assert.match(stored.wrappedAsk, BASE64URL);
    session.free();

    const { account, vault } = server.accounts.get('alice@example.com');
    const unlocked = Session.unlockWithDeviceKey(prfOutput, stored.deviceSalt, stored.wrappedAsk, account);
    unlocked.openVault(vault.id, vault.wrappedVaultKey);
    const itemId = newId();
    assert.deepEqual(unlocked.decryptItem(vault.id, itemId, unlocked.encryptItem(vault.id, itemId, item)), item);
    unlocked.free();

    const otherDevice = new Uint8Array(32).fill(8);
    assert.throws(() => Session.unlockWithDeviceKey(otherDevice, stored.deviceSalt, stored.wrappedAsk, account), { code: 'device_unlock_failed' });
    assert.throws(() => session.enableDeviceUnlock(prfOutput), /null pointer|freed|moved/i, 'a freed session is locked');
    keys.free();
  });

  test('the recovery code unlocks everything', () => {
    const stored = server.accounts.get('alice@example.com');
    const session = Session.recover(signup.recoveryCode.toLowerCase().replaceAll('-', ' '), stored.account);
    session.openVault(stored.vault.id, stored.vault.wrappedVaultKey);
    const itemId = newId();
    assert.deepEqual(session.decryptItem(stored.vault.id, itemId, session.encryptItem(stored.vault.id, itemId, item)), item);
    session.free();
    assert.throws(() => Session.recover('AAAAA-'.repeat(10) + 'AAAAA', stored.account), { code: 'invalid_recovery_code' });
  });

  test('weak KDF parameters from the server are refused', () => {
    const prelogin = { ...server.prelogin(EMAIL), kdf: { algorithm: 'argon2id', memoryKib: 1024, iterations: 1, parallelism: 1 } };
    assert.throws(() => DerivedKeys.derive(EMAIL, PASSWORD, signup.secretKey, prelogin), { code: 'unsupported_kdf' });
    assert.throws(() => DerivedKeys.derive(EMAIL, PASSWORD, signup.secretKey, { nope: true }), { code: 'invalid_argument' });
  });
});
