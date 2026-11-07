const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const RFC4648 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function encode32(bytes: Uint8Array, alphabet: string): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = ((buffer << 8) | byte) & 0xfff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(buffer >> bits) & 31];
    }
  }
  if (bits > 0) out += alphabet[(buffer << (5 - bits)) & 31];
  return out;
}

/** Leftover bits that don't fill a byte are padding and dropped. */
function decode32(text: string, valueOf: (char: string) => number | undefined): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(Math.floor((text.length * 5) / 8));
  let buffer = 0;
  let bits = 0;
  let at = 0;
  for (const char of text) {
    const value = valueOf(char);
    if (value === undefined) throw new Error(`Invalid base32 character: ${JSON.stringify(char)}`);
    buffer = ((buffer << 5) | value) & 0xfff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[at++] = (buffer >> bits) & 0xff;
    }
  }
  return out;
}

const CROCKFORD_ALIASES: Record<string, string> = { O: '0', I: '1', L: '1' };

export function crockfordEncode(bytes: Uint8Array): string {
  return encode32(bytes, CROCKFORD);
}

export function crockfordDecode(text: string): Uint8Array<ArrayBuffer> {
  const compact = text.replace(/[\s-]/g, '').toUpperCase();
  return decode32(compact, (char) => {
    const index = CROCKFORD.indexOf(CROCKFORD_ALIASES[char] ?? char);
    return index < 0 ? undefined : index;
  });
}

/** RFC 4648 base32 without padding, as authenticator apps take secrets. */
export function base32Encode(bytes: Uint8Array): string {
  return encode32(bytes, RFC4648);
}

export function base32Decode(text: string): Uint8Array<ArrayBuffer> {
  const compact = text.replace(/[\s=]/g, '').toUpperCase();
  return decode32(compact, (char) => {
    const index = RFC4648.indexOf(char);
    return index < 0 ? undefined : index;
  });
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

/** base64url without padding, the API's encoding for binary values. */
export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(text: string): Uint8Array<ArrayBuffer> {
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
