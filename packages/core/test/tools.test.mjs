import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { test } from 'node:test';

const core = createRequire(import.meta.url)('../dist/node/octapass_core.js');

test('generatePassword', () => {
  const password = core.generatePassword({ type: 'random', length: 24, symbols: false });
  assert.match(password, /^[A-Za-z0-9]{24}$/);
  assert.match(core.generatePassword({ type: 'passphrase', words: 4, separator: '.' }), /^[a-z-]+(\.[a-z-]+){3}$/);
  assert.throws(() => core.generatePassword({ type: 'random', length: 2 }), { code: 'invalid_generator_options' });
});

test('estimateStrength', () => {
  const weak = core.estimateStrength('password1');
  assert.equal(weak.score, 0);
  assert.equal(typeof weak.feedback, 'string');
  assert.equal(core.estimateStrength('vexed-kiwi-trumpet-galaxy-oboe').score, 4);
  assert.ok(core.estimateStrength('alice2026!', ['alice']).guessesLog10 < core.estimateStrength('alice2026!').guessesLog10);
});

test('totpCode matches RFC 6238', () => {
  // base32 of "12345678901234567890"
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.deepEqual(core.totpCode(`otpauth://totp/x?secret=${secret}&digits=8`, 59), { code: '94287082', period: 30, remaining: 1 });
  assert.equal(core.totpCode(secret).code.length, 6);
  assert.throws(() => core.totpCode('not a secret!'), { code: 'invalid_totp' });
});

test('breach check helpers keep the full hash inside WASM', () => {
  assert.equal(core.breachPrefix('password'), '5BAA6');
  const body = '1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0';
  assert.equal(core.breachCount('password', body), 9545824);
  assert.equal(core.breachCount('something else', body), 0);
});

test('normalizeSecretKey and newId', () => {
  assert.equal(core.normalizeSecretKey('op1 000g40 r40m30 e2091 85gr3 8e1w'), 'OP1-000G40-R40M30-E2091-85GR3-8E1W');
  assert.throws(() => core.normalizeSecretKey('OP1-nope'), { name: 'OctaPassError', code: 'invalid_secret_key' });
  const [a, b] = [core.newId(), core.newId()];
  assert.match(a, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.notEqual(a, b);
});

test('parseOtpMigration rejects non-migration URIs', () => {
  assert.throws(() => core.parseOtpMigration('otpauth://totp/x?secret=A'), { code: 'invalid_totp' });
});

test('deviceUnlockPrfInput is SHA-256("openpass/v1/device-unlock")', async () => {
  const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('openpass/v1/device-unlock')));
  assert.deepEqual(core.deviceUnlockPrfInput(), expected);
});

test('SSH keys: generate, read, write', () => {
  const key = core.generateSshKey('ed25519', 'me@laptop');
  assert.equal(key.keyType, 'ssh-ed25519');
  assert.equal(key.bits, 256);
  assert.match(key.fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/);
  assert.match(key.publicKey, /^ssh-ed25519 AAAA\S+$/);
  assert.equal(key.comment, 'me@laptop');
  assert.ok(key.usable);
  assert.ok(key.privateKey.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----'));

  const locked = core.writeSshKey(key.privateKey, 'work', 'correct horse');
  assert.throws(() => core.readSshKey(locked), { code: 'ssh_passphrase_required' });
  assert.throws(() => core.readSshKey(locked, 'nope'), { code: 'wrong_passphrase' });
  const read = core.readSshKey(locked, 'correct horse');
  assert.equal(read.fingerprint, key.fingerprint);
  assert.equal(read.comment, 'work');
  assert.equal(core.readSshPublicKey(`${key.publicKey} me`).fingerprint, key.fingerprint);
  assert.throws(() => core.readSshKey(key.publicKey), { code: 'ssh_public_key_only' });
  assert.throws(() => core.readSshKey('hello'), { code: 'invalid_ssh_key' });
  assert.throws(() => core.generateSshKey('dsa', ''), { code: 'invalid_argument' });
});

test('the developer toolkit runs through one JSON entry point', () => {
  const run = (op, input) => JSON.parse(core.toolRun(op, JSON.stringify(input)));
  assert.equal(run('encoding.encode', { format: 'base64', text: 'hello' }).value, 'aGVsbG8=');
  const sha256 = run('hash.digest', { text: 'abc', algorithms: ['sha256'] }).hashes[0];
  assert.equal(sha256.hex, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

  // Keys, certificates and tokens: the random and clock sources work in WebAssembly.
  const ca = run('cert.caCreate', {});
  const leaf = run('cert.issue', { sans: ['localhost'], keyType: 'ed25519', caCertificate: ca.certificate, caKey: ca.privateKey });
  assert.equal(leaf.info.commonName, 'localhost');
  const report = run('cert.read', { text: leaf.certificate + leaf.chain, host: 'localhost' });
  assert.deepEqual(report.problems, []);
  const key = run('jwt.generateKey', { algorithm: 'ES256' });
  const { token } = run('jwt.sign', { payload: { sub: 'ada' }, algorithm: 'ES256', key: key.privateKey, issuedNow: true, expiresInSeconds: 60 });
  assert.equal(run('jwt.verify', { token, key: key.jwks }).valid, true);
  assert.match(run('random.uuid', { version: 7 }).values[0], /^[0-9a-f-]{36}$/);
  assert.match(run('key.age', {}).recipient, /^age1/);
  assert.match(run('key.gpg', { userId: 'Ada <ada@example.test>' }).privateKey, /BEGIN PGP PRIVATE KEY/);

  assert.throws(() => core.toolRun('nope', '{}'), { code: 'unknown_tool' });
  assert.throws(() => core.toolRun('cert.read', '{"text":"x"}'), { code: 'invalid_certificate' });
});

test('StreamHasher hashes in chunks', () => {
  const hasher = new core.StreamHasher(['sha256']);
  hasher.update(new TextEncoder().encode('a'));
  hasher.update(new TextEncoder().encode('bc'));
  assert.equal(JSON.parse(hasher.finish())[0].hex, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
