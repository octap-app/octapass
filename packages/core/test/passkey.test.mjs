// The passkey authenticator through WASM, checked with Node's own crypto (OpenSSL) as the relying
// party. Run `pnpm --filter @octapass/core build` first.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { before, describe, test } from 'node:test';

const core = createRequire(import.meta.url)('../dist/node/octapass_core.js');
const { Signup, TestOpaqueServer, newId } = core;

const AAGUID = Buffer.from('c9a077341d0b4c728ff545e0daa2064f', 'hex');
const ORIGIN = 'https://login.example.com';
const caller = { origin: ORIGIN };
const b64 = (bytes) => Buffer.from(bytes).toString('base64url');
const bytes = (text) => Buffer.from(text, 'base64url');
const sha256 = (data) => createHash('sha256').update(data).digest();

function creationOptions(alg = -7, extra = {}) {
  return {
    rp: { id: 'example.com', name: 'Example' },
    user: { id: b64('user-123'), name: 'alice@example.com', displayName: 'Alice' },
    challenge: b64(Buffer.alloc(32, 1)),
    pubKeyCredParams: [{ type: 'public-key', alg }],
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    attestation: 'none',
    ...extra,
  };
}

function requestOptions(extra = {}) {
  return { challenge: b64(Buffer.alloc(32, 2)), rpId: 'example.com', userVerification: 'required', ...extra };
}

/** Just enough CBOR (RFC 8949) to read an attestation object and a COSE key. */
function decodeCbor(buffer) {
  let offset = 0;
  const readLength = (info) => {
    if (info < 24) return info;
    const size = { 24: 1, 25: 2, 26: 4 }[info];
    if (!size) throw new Error(`unsupported CBOR length ${info}`);
    const value = buffer.readUIntBE(offset, size);
    offset += size;
    return value;
  };
  const read = () => {
    const initial = buffer[offset++];
    const major = initial >> 5;
    const length = readLength(initial & 31);
    switch (major) {
      case 0: return length;
      case 1: return -1 - length;
      case 2: return buffer.subarray(offset, (offset += length));
      case 3: return buffer.subarray(offset, (offset += length)).toString('utf8');
      case 5: return new Map(Array.from({ length }, () => [read(), read()]));
      default: throw new Error(`unsupported CBOR major type ${major}`);
    }
  };
  const value = read();
  assert.equal(offset, buffer.length, 'no trailing bytes');
  return value;
}

/** WebAuthn §7.1 for attestation `none`. Returns the stored credential public key. */
function verifyRegistration(credential, challenge) {
  assert.equal(credential.type, 'public-key');
  assert.equal(credential.id, credential.rawId);
  const { response } = credential;
  const clientData = JSON.parse(bytes(response.clientDataJSON));
  assert.deepEqual(clientData, { type: 'webauthn.create', challenge, origin: ORIGIN, crossOrigin: false });

  const attestation = decodeCbor(bytes(response.attestationObject));
  assert.deepEqual([...attestation.keys()], ['fmt', 'attStmt', 'authData']);
  assert.equal(attestation.get('fmt'), 'none');
  assert.equal(attestation.get('attStmt').size, 0);
  const authData = attestation.get('authData');
  assert.deepEqual(authData, bytes(response.authenticatorData));
  assert.deepEqual(authData.subarray(0, 32), sha256('example.com'));
  assert.equal(authData[32], 0x5d, 'UP | UV | BE | BS | AT');
  assert.equal(authData.readUInt32BE(33), 0, 'signCount');
  assert.deepEqual(authData.subarray(37, 53), AAGUID);
  const idLength = authData.readUInt16BE(53);
  assert.equal(idLength, 16);
  assert.equal(b64(authData.subarray(55, 55 + idLength)), credential.rawId);

  const cose = decodeCbor(authData.subarray(55 + idLength));
  const publicKey = createPublicKey({ key: bytes(response.publicKey), format: 'der', type: 'spki' });
  const jwk = publicKey.export({ format: 'jwk' });
  assert.equal(cose.get(3), response.publicKeyAlgorithm);
  if (response.publicKeyAlgorithm === -7) {
    assert.deepEqual([cose.get(1), cose.get(-1)], [2, 1], 'EC2, P-256');
    assert.deepEqual([b64(cose.get(-2)), b64(cose.get(-3))], [jwk.x, jwk.y]);
  } else {
    assert.deepEqual([cose.get(1), cose.get(-1)], [1, 6], 'OKP, Ed25519');
    assert.equal(b64(cose.get(-2)), jwk.x);
  }
  return publicKey;
}

/** WebAuthn §7.2. */
function verifyAssertion(assertion, publicKey, challenge, credentialId) {
  assert.equal(assertion.id, credentialId);
  const { response } = assertion;
  const clientDataJSON = bytes(response.clientDataJSON);
  assert.deepEqual(JSON.parse(clientDataJSON), { type: 'webauthn.get', challenge, origin: ORIGIN, crossOrigin: false });
  const authData = bytes(response.authenticatorData);
  assert.equal(authData.length, 37);
  assert.deepEqual(authData.subarray(0, 32), sha256('example.com'));
  assert.equal(authData[32], 0x1d, 'UP | UV | BE | BS');
  const signed = Buffer.concat([authData, sha256(clientDataJSON)]);
  const algorithm = publicKey.asymmetricKeyType === 'ec' ? 'sha256' : null;
  assert.ok(verify(algorithm, signed, { key: publicKey, dsaEncoding: 'der' }, bytes(response.signature)), 'signature');
}

describe('passkeys in the vault', () => {
  let session;
  let vaultId;

  before(() => {
    const opaque = new TestOpaqueServer();
    const signup = Signup.create('alice@example.com', 'correct horse battery staple');
    const { account, personalVault } = signup.finish(opaque.registrationStart(signup.email, signup.registrationRequest));
    session = signup.derivedKeys().unlock(account);
    session.openVault(personalVault.id, personalVault.wrappedVaultKey);
    vaultId = personalVault.id;
  });

  for (const alg of [-7, -8]) {
    test(`create and sign in (alg ${alg})`, () => {
      const options = creationOptions(alg);
      const itemId = newId();
      const { credential, item } = session.createPasskey(options, caller, { vaultId, itemId }, []);
      const publicKey = verifyRegistration(credential, options.challenge);
      assert.equal(credential.response.publicKeyAlgorithm, alg);
      assert.equal(credential.authenticatorAttachment, 'platform');

      const login = session.decryptItem(vaultId, itemId, item);
      assert.deepEqual(login.overview, { schemaVersion: 1, title: 'Example', type: 'login', urls: [ORIGIN] });
      const [record] = login.details.passkeys;
      assert.equal(record.credentialId, credential.id);
      assert.equal(record.userHandle, options.user.id);
      // The stored PKCS#8 key is the credential's private key.
      const privateKey = createPrivateKey({ key: bytes(record.privateKey), format: 'der', type: 'pkcs8' });
      assert.deepEqual(createPublicKey(privateKey).export({ format: 'jwk' }), publicKey.export({ format: 'jwk' }));

      const candidates = [{ vaultId, itemId, item }];
      const request = requestOptions();
      const [match] = session.findPasskeys(request, caller, candidates);
      assert.deepEqual(match, {
        vaultId, itemId, credentialId: credential.id, rpId: 'example.com',
        userName: 'alice@example.com', userDisplayName: 'Alice', createdAt: record.createdAt,
      });
      const assertion = session.getAssertion(request, caller, candidates[0], match.credentialId);
      verifyAssertion(assertion, publicKey, request.challenge, credential.id);
      assert.equal(assertion.response.userHandle, options.user.id);
    });
  }

  test('refuses other sites, frames, duplicates and bad requests', () => {
    const itemId = newId();
    const { credential, item } = session.createPasskey(creationOptions(), caller, { vaultId, itemId }, []);
    const candidates = [{ vaultId, itemId, item }];
    const target = { vaultId, itemId: newId() };

    const phishing = { origin: 'https://example.com.evil.net' };
    assert.throws(() => session.createPasskey(creationOptions(), phishing, target, []), { name: 'OctaPassError', code: 'passkey_rp_mismatch' });
    assert.throws(() => session.findPasskeys(requestOptions(), phishing, candidates), { code: 'passkey_rp_mismatch' });
    assert.deepEqual(session.findPasskeys(requestOptions({ rpId: undefined }), phishing, candidates), []);
    assert.throws(() => session.getAssertion(requestOptions({ rpId: undefined }), phishing, candidates[0], credential.id), { code: 'passkey_not_found' });
    assert.throws(() => session.createPasskey(creationOptions(), { origin: 'http://example.com' }, target, []), { code: 'passkey_rp_mismatch' });

    const frame = { origin: ORIGIN, topOrigin: 'https://shop.example' };
    assert.throws(() => session.findPasskeys(requestOptions(), frame, candidates), { code: 'passkey_frame_not_allowed' });
    assert.equal(session.findPasskeys(requestOptions(), { ...frame, frameAllowed: true }, candidates).length, 1);

    const exclude = { excludeCredentials: [{ type: 'public-key', id: credential.id }] };
    assert.throws(() => session.createPasskey(creationOptions(-7, exclude), caller, target, candidates), { code: 'passkey_excluded' });

    const unknown = requestOptions({ allowCredentials: [{ type: 'public-key', id: b64(Buffer.alloc(16)) }] });
    assert.deepEqual(session.findPasskeys(unknown, caller, candidates), []);
    assert.throws(() => session.getAssertion(unknown, caller, candidates[0], credential.id), { code: 'passkey_not_found' });

    assert.throws(() => session.createPasskey(creationOptions(-257), caller, target, []), { code: 'passkey_unsupported_algorithm' });
    assert.throws(() => session.createPasskey({ challenge: 'AAAA' }, caller, target, []), { code: 'invalid_passkey_request' });
    assert.throws(() => session.createPasskey(creationOptions(), {}, target, []), { code: 'invalid_argument' });
  });

  test('credProps reports a discoverable credential', () => {
    const options = creationOptions(-7, { extensions: { credProps: true } });
    const { credential } = session.createPasskey(options, caller, { vaultId, itemId: newId() }, []);
    assert.deepEqual(credential.clientExtensionResults, { credProps: { rk: true } });
  });
});

test('the committed test vectors verify with OpenSSL', () => {
  const vectors = JSON.parse(readFileSync(new URL('../../../crates/octapass-core/tests/vectors/passkey.json', import.meta.url)));
  assert.equal(vectors.cases.length, 2);
  for (const { registration, record, assertion, assertionRequest } of vectors.cases) {
    const publicKey = verifyRegistration(registration, JSON.parse(bytes(registration.response.clientDataJSON)).challenge);
    const privateKey = createPrivateKey({ key: bytes(record.privateKey), format: 'der', type: 'pkcs8' });
    assert.deepEqual(createPublicKey(privateKey).export({ format: 'jwk' }), publicKey.export({ format: 'jwk' }));
    verifyAssertion(assertion, publicKey, assertionRequest.challenge, record.credentialId);
  }
});
