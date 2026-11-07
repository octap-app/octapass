// getRandomValues refuses more than 65536 bytes per call.
const MAX_CHUNK = 65536;

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(n);
  for (let at = 0; at < n; at += MAX_CHUNK) {
    crypto.getRandomValues(bytes.subarray(at, Math.min(n, at + MAX_CHUNK)));
  }
  return bytes;
}

const RANGE = 2 ** 32;

/** Uniform integer in [0, maxExclusive). */
export function randomInt(maxExclusive: number): number {
  if (!Number.isInteger(maxExclusive) || maxExclusive < 1 || maxExclusive > RANGE) {
    throw new RangeError(`randomInt: maxExclusive must be an integer in 1..2^32, got ${maxExclusive}`);
  }
  // Drop the top values that would make `value % maxExclusive` favour small results.
  const limit = RANGE - (RANGE % maxExclusive);
  const buffer = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buffer);
    const value = buffer[0]!;
    if (value < limit) return value % maxExclusive;
  }
}
