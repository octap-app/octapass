import { crockfordDecode, crockfordEncode } from './tools/encoding';
import { randomBytes } from './tools/random';

const SECRET_KEY_PREFIX = 'OP1';
const SECRET_KEY_GROUPS = [6, 6, 5, 5, 4];

function group(text: string, sizes: number[]): string[] {
  const parts: string[] = [];
  let at = 0;
  for (const size of sizes) {
    parts.push(text.slice(at, at + size));
    at += size;
  }
  return parts;
}

/** `OP1-` + Crockford base32 of 16 random bytes, grouped 6-6-5-5-4 (plan 11). */
export function formatSecretKey(bytes: Uint8Array): string {
  return [SECRET_KEY_PREFIX, ...group(crockfordEncode(bytes), SECRET_KEY_GROUPS)].join('-');
}

export function generateSecretKey(): string {
  return formatSecretKey(randomBytes(16));
}

/** Ignores case, spaces and dashes. Returns undefined for anything that isn't a version 1 Secret Key. */
export function parseSecretKey(input: string): Uint8Array | undefined {
  const compact = input.replace(/[\s-]/g, '').toUpperCase();
  if (!compact.startsWith(SECRET_KEY_PREFIX) || compact.length !== SECRET_KEY_PREFIX.length + 26) return undefined;
  try {
    const bytes = crockfordDecode(compact.slice(SECRET_KEY_PREFIX.length));
    return bytes.length === 16 ? bytes : undefined;
  } catch {
    return undefined;
  }
}

/** The canonical text form, so a typed key compares equal to the stored one. */
export function normalizeSecretKey(input: string): string | undefined {
  const bytes = parseSecretKey(input);
  return bytes && formatSecretKey(bytes);
}

/**
 * 32 random bytes as 52 Crockford characters in groups of four. The crypto core owns the final
 * format (crates/octapass-core/README.md); the integration step switches to it.
 */
export function generateRecoveryCode(): string {
  return crockfordEncode(randomBytes(32)).match(/.{1,4}/g)!.join('-');
}
