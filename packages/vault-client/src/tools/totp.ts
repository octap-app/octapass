import type { HotpCode, TotpCode } from '../types';
import { base32Decode } from './encoding';

export interface TotpParams {
  secret: Uint8Array;
  algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512';
  digits: number;
  period: number;
  /** Counter-based (HOTP) setups only: the counter of the next code. */
  counter?: number;
  issuer?: string;
  account?: string;
}

const ALGORITHMS: Record<string, TotpParams['algorithm']> = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
// 80 bits: the shortest secret services issue in practice. RFC 4226 asks for 128 or more.
const MIN_SECRET_BYTES = 10;
const MAX_PERIOD = 300;

function invalid(): never {
  throw new Error('Invalid one-time code secret');
}

function decodeSecret(text: string): Uint8Array {
  let secret: Uint8Array;
  try {
    secret = base32Decode(text);
  } catch {
    invalid();
  }
  return secret.length >= MIN_SECRET_BYTES ? secret : invalid();
}

function integerParam(value: string | null, fallback: number, min: number, max: number): number {
  if (value === null) return fallback;
  const n = Number(value);
  return Number.isInteger(n) && n >= min && n <= max ? n : invalid();
}

function parseUri(input: string): TotpParams {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    invalid();
  }
  // otpauth is not a special scheme, so the type lands in `host` and the label in `pathname`.
  const type = url.host.toLowerCase();
  if (type !== 'totp' && type !== 'hotp') invalid();
  const secretParam = url.searchParams.get('secret');
  if (!secretParam) invalid();
  const algorithmParam = url.searchParams.get('algorithm');
  const algorithm = algorithmParam === null ? 'SHA-1' : ALGORITHMS[algorithmParam.toUpperCase().replace('-', '')];
  if (!algorithm) invalid();

  let label: string;
  try {
    label = decodeURIComponent(url.pathname.replace(/^\//, ''));
  } catch {
    invalid();
  }
  const colon = label.indexOf(':');
  const labelIssuer = colon >= 0 ? label.slice(0, colon).trim() : '';
  const account = (colon >= 0 ? label.slice(colon + 1) : label).trim();
  const issuer = url.searchParams.get('issuer')?.trim() || labelIssuer;

  return {
    secret: decodeSecret(secretParam),
    algorithm,
    digits: integerParam(url.searchParams.get('digits'), 6, 6, 8),
    period: integerParam(url.searchParams.get('period'), 30, 1, MAX_PERIOD),
    ...(type === 'hotp' && { counter: integerParam(url.searchParams.get('counter'), 0, 0, Number.MAX_SAFE_INTEGER) }),
    ...(issuer && { issuer }),
    ...(account && { account }),
  };
}

/** An otpauth://totp/ or otpauth://hotp/ URI, or a bare base32 secret (spaces allowed). */
export function parseTotp(input: string): TotpParams {
  const text = input.trim();
  if (/^otpauth:/i.test(text)) return parseUri(text);
  return { secret: decodeSecret(text), algorithm: 'SHA-1', digits: 6, period: 30 };
}

export function isValidTotp(input: string): boolean {
  try {
    parseTotp(input);
    return true;
  } catch {
    return false;
  }
}

/** Whether an item's `totp` field is a counter-based (HOTP) setup. */
export function isHotp(input: string | undefined): boolean {
  try {
    return input !== undefined && parseTotp(input).counter !== undefined;
  } catch {
    return false;
  }
}

/** The counter of the next code. Throws for anything but an `otpauth://hotp/` URI. */
export function hotpCounter(input: string): number {
  return parseTotp(input).counter ?? invalid();
}

/** The `totp` field with its counter set: bringing a token back in step with the site. */
export function withHotpCounter(input: string, counter: number): string {
  hotpCounter(input);
  if (!Number.isSafeInteger(counter) || counter < 0) invalid();
  const text = input.trim();
  const updated = text.replace(/([?&]counter=)[^&]*/i, `$1${counter}`);
  return updated !== text || /[?&]counter=/i.test(text) ? updated : `${text}&counter=${counter}`;
}

/** RFC 4226: dynamic truncation of `HMAC(secret, counter)`. */
async function hmacCode({ secret, algorithm, digits }: Pick<TotpParams, 'secret' | 'algorithm' | 'digits'>, moving: number): Promise<string> {
  const counter = new DataView(new ArrayBuffer(8));
  counter.setBigUint64(0, BigInt(moving));
  const key = await crypto.subtle.importKey('raw', new Uint8Array(secret), { name: 'HMAC', hash: algorithm }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter.buffer));
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary =
    ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/** RFC 6238: HOTP (RFC 4226) over the number of periods since the Unix epoch. */
export async function totpCode(input: string, at: number = Date.now()): Promise<TotpCode> {
  const params = parseTotp(input);
  if (params.counter !== undefined) invalid();
  const seconds = Math.floor(at / 1000);
  return {
    code: await hmacCode(params, Math.floor(seconds / params.period)),
    period: params.period,
    remaining: params.period - (seconds % params.period),
  };
}

/** The next counter-based code, and the `totp` field to save before showing it (the mock's; the apps use the core's). */
export async function nextHotp(input: string): Promise<{ code: HotpCode; totp: string }> {
  const params = parseTotp(input);
  const counter = params.counter ?? invalid();
  return { code: { code: await hmacCode(params, counter), counter }, totp: withHotpCounter(input, counter + 1) };
}
