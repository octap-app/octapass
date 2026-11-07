import { createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync } from 'node:crypto';

/** The desktop app's half of the key exchange (apps/desktop/crates/vault/src/bridge.rs), with Node's crypto. */
export function appSide(extensionPublic: Uint8Array): { appPublic: Uint8Array; key: Uint8Array } {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  const appPublic = new Uint8Array(Buffer.from(publicKey.export({ format: 'jwk' }).x!, 'base64url'));
  const peer = createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: Buffer.from(extensionPublic).toString('base64url') }, format: 'jwk' });
  const shared = diffieHellman({ privateKey, publicKey: peer });
  const key = new Uint8Array(hkdfSync('sha256', shared, Buffer.concat([appPublic, extensionPublic]), 'octapass/v1/native-messaging', 32));
  return { appPublic, key };
}
