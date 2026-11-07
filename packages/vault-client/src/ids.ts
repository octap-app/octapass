import { bytesToHex } from './tools/encoding';
import { randomBytes } from './tools/random';

/** UUIDv7 (RFC 9562): 48-bit Unix milliseconds, then random bits. Sorts by creation time. */
export function uuidv7(now: number = Date.now()): string {
  const bytes = randomBytes(16);
  let ms = now;
  for (let i = 5; i >= 0; i--) {
    bytes[i] = ms % 256;
    ms = Math.floor(ms / 256);
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytesToHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** The creation time inside a UUIDv7, in Unix milliseconds. */
export function uuidv7Time(id: string): number {
  return Number.parseInt(id.replace(/-/g, '').slice(0, 12), 16);
}
