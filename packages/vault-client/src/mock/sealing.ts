// Stand-in for the real key hierarchy (Argon2id + Secret Key + XChaCha20-Poly1305 in @octapass/core),
// built from WebCrypto with the same shape: a random account key (ASK) seals the vault, and the ASK is
// wrapped separately by the password key and, optionally, by a device key from a passkey's PRF output.
// The mock never keeps a demo vault in IndexedDB as plaintext, and locking really forgets the keys.

const ITERATIONS = 210_000;
const encoder = new TextEncoder();

export interface Sealed {
  iv: string;
  data: string;
}

export function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(n));
}

function aad(context: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(`openpass/v1|${context}`);
}

/** The key that wraps the ASK, from the master password and this account's Secret Key. */
export async function derivePasswordKey(password: string, secretKey: string, salt: string): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', encoder.encode(`${password}\u0000${secretKey}`), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromBase64(salt), iterations: ITERATIONS },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** device_key = HKDF(ikm = prf_output, salt = device_salt, info = "openpass/v1/device-unlock") (plan 11). */
export async function deriveDeviceKey(prfOutput: Uint8Array<ArrayBuffer>, deviceSalt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: deviceSalt, info: encoder.encode('openpass/v1/device-unlock') },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export function importAsk(ask: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', ask, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function sealBytes(key: CryptoKey, bytes: Uint8Array<ArrayBuffer>, context: string): Promise<Sealed> {
  const iv = randomBytes(12);
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(context) }, key, bytes);
  return { iv: toBase64(iv), data: toBase64(new Uint8Array(data)) };
}

/** Rejects when the key or context is wrong, because AES-GCM authentication fails. */
export async function openBytes(key: CryptoKey, sealed: Sealed, context: string): Promise<Uint8Array<ArrayBuffer>> {
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(sealed.iv), additionalData: aad(context) }, key, fromBase64(sealed.data));
  return new Uint8Array(plain);
}

export function sealJson(key: CryptoKey, value: unknown, context: string): Promise<Sealed> {
  return sealBytes(key, encoder.encode(JSON.stringify(value)), context);
}

export async function openJson<T>(key: CryptoKey, sealed: Sealed, context: string): Promise<T> {
  return JSON.parse(new TextDecoder().decode(await openBytes(key, sealed, context))) as T;
}
