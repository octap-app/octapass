// A software security key for the server-backed tests: `navigator.credentials` with a P-256 key,
// "none" attestation and real signatures, as a browser and a USB key would make them. Node only.

import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';

const sha256 = (data: Uint8Array | string) => new Uint8Array(createHash('sha256').update(data).digest());

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

// Just enough CBOR (RFC 8949) for an attestation object and a COSE key.
type Cbor = number | string | Uint8Array | Map<Cbor, Cbor>;
function head(major: number, length: number): Uint8Array {
  if (length < 24) return Uint8Array.of((major << 5) | length);
  if (length < 256) return Uint8Array.of((major << 5) | 24, length);
  return Uint8Array.of((major << 5) | 25, length >> 8, length & 255);
}
function cbor(value: Cbor): Uint8Array {
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') {
    const text = new TextEncoder().encode(value);
    return concat(head(3, text.length), text);
  }
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  return concat(head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)]));
}

const u32 = (n: number) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);

export interface SoftwareSecurityKey {
  /** How many assertions it made. */
  uses: number;
}

/**
 * Installs `navigator.credentials`, `PublicKeyCredential` and `location` for a page at `origin`.
 * Each `create` makes a new key; `get` answers with the first allowed one it has.
 */
export function installSoftwareSecurityKey(origin: string): SoftwareSecurityKey {
  const keys = new Map<string, { id: Uint8Array<ArrayBuffer>; privateKey: KeyObject; signCount: number }>();
  const state: SoftwareSecurityKey = { uses: 0 };
  const clientData = (type: string, challenge: BufferSource) =>
    new TextEncoder().encode(JSON.stringify({ type, challenge: Buffer.from(challenge as ArrayBuffer).toString('base64url'), origin, crossOrigin: false }));

  const create = async ({ publicKey }: CredentialCreationOptions) => {
    const options = publicKey!;
    const id = crypto.getRandomValues(new Uint8Array(16));
    const { privateKey, publicKey: pub } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = pub.export({ format: 'jwk' });
    const cose = cbor(
      new Map<Cbor, Cbor>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, new Uint8Array(Buffer.from(jwk.x!, 'base64url'))],
        [-3, new Uint8Array(Buffer.from(jwk.y!, 'base64url'))],
      ]),
    );
    // Flags: user present, attested credential data included.
    const authData = concat(sha256(options.rp.id!), Uint8Array.of(0x41), u32(0), new Uint8Array(16), Uint8Array.of(0, id.length), id, cose);
    keys.set(Buffer.from(id).toString('base64url'), { id, privateKey, signCount: 0 });
    const attestationObject = cbor(
      new Map<Cbor, Cbor>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', authData],
      ]),
    );
    return { rawId: id.buffer, response: { clientDataJSON: clientData('webauthn.create', options.challenge).buffer, attestationObject: concat(attestationObject).buffer } };
  };

  const get = async ({ publicKey }: CredentialRequestOptions) => {
    const options = publicKey!;
    const key = options.allowCredentials?.map((c) => keys.get(Buffer.from(c.id as ArrayBuffer).toString('base64url'))).find(Boolean);
    if (!key) throw new DOMException('No credential', 'NotAllowedError');
    key.signCount++;
    state.uses++;
    const authData = concat(sha256(options.rpId!), Uint8Array.of(0x01), u32(key.signCount));
    const data = clientData('webauthn.get', options.challenge);
    const signature = new Uint8Array(sign('sha256', concat(authData, sha256(data)), { key: key.privateKey, dsaEncoding: 'der' }));
    return { rawId: key.id.buffer, response: { clientDataJSON: data.buffer, authenticatorData: authData.buffer, signature: concat(signature).buffer } };
  };

  Object.defineProperty(globalThis.navigator, 'credentials', { configurable: true, value: { create, get } });
  vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
  vi.stubGlobal('location', { hostname: new URL(origin).hostname });
  return state;
}
