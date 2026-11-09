// The health report's site lists (plan 06): which sites accept passkeys and which offer two-step
// sign-in. Each release bundles a copy, and a newer one can come later as a signed file from the
// account's own server (`GET /v1/health/data`), which serves its bundled copy or one it fetched
// from the project's site. Nobody in between is trusted: a file counts only when it's signed by
// the pinned key and newer than the one in use, so a server can hold an update back, never forge
// one or roll the lists back. The same file is the same for everyone, so asking for it says
// nothing about the vault.

import bundledFile from '../data/health-data.json';
import type { KeyValueStore } from '../idb';

/** The project's Ed25519 key for the lists, raw and base64. The private half never enters the repository. */
export const HEALTH_DATA_PUBLIC_KEY = 'N7Z3UT7ZfowEy2zn0I0PaHMOaENZECw9OSyZCaRSB1E=';
/** Signed as `context ‖ 0x00 ‖ payload`, so the signature means nothing anywhere else. */
export const HEALTH_DATA_CONTEXT = 'openpass/v1/health-data';
export const HEALTH_DATA_FORMAT = 1;
export const HEALTH_DATA_PATH = '/v1/health/data';
/** The most a file may be. Today's is about 20 KB. */
export const HEALTH_DATA_MAX_BYTES = 1 << 20;
/** How often a device asks for a newer file. */
export const HEALTH_DATA_CHECK_HOURS = 24;
const MAX_DOMAINS = 50_000;
const DOMAIN = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;
const TIMEOUT_MS = 10_000;

export interface HealthData {
  /** Goes up with every signed file. */
  version: number;
  issuedAt: string;
  /** Registrable domains of sites that accept passkeys. */
  passkeyDomains: ReadonlySet<string>;
  /** Registrable domains of sites that offer an authenticator app or passkeys for two-step sign-in. */
  twoFactorDomains: ReadonlySet<string>;
}

export type HealthDataProblem = 'malformed' | 'badSignature' | 'unsupported' | 'rollback';

export class HealthDataRejected extends Error {
  constructor(readonly problem: HealthDataProblem) {
    super(`health data rejected: ${problem}`);
    this.name = 'HealthDataRejected';
  }
}

function base64Decode(text: string): Uint8Array<ArrayBuffer> | undefined {
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return undefined;
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function domains(value: unknown): Set<string> {
  if (!Array.isArray(value) || value.length > MAX_DOMAINS) throw new HealthDataRejected('malformed');
  for (const name of value) if (typeof name !== 'string' || name.length > 253 || !DOMAIN.test(name)) throw new HealthDataRejected('malformed');
  return new Set(value as string[]);
}

/** Reads a payload the caller already trusts: a verified one, or the copy bundled with this build. */
function parsePayload(bytes: Uint8Array): HealthData {
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new HealthDataRejected('malformed');
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new HealthDataRejected('malformed');
  const { format, version, issuedAt, passkeyDomains, twoFactorDomains } = payload as Record<string, unknown>;
  if (typeof format !== 'number' || !Number.isSafeInteger(format)) throw new HealthDataRejected('malformed');
  if (format !== HEALTH_DATA_FORMAT) throw new HealthDataRejected('unsupported');
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) throw new HealthDataRejected('malformed');
  if (typeof issuedAt !== 'string' || Number.isNaN(Date.parse(issuedAt))) throw new HealthDataRejected('malformed');
  return { version, issuedAt, passkeyDomains: domains(passkeyDomains), twoFactorDomains: domains(twoFactorDomains) };
}

function envelope(text: string): { payload: Uint8Array<ArrayBuffer>; signature: Uint8Array<ArrayBuffer> } {
  if (text.length > HEALTH_DATA_MAX_BYTES) throw new HealthDataRejected('malformed');
  let file: unknown;
  try {
    file = JSON.parse(text);
  } catch {
    throw new HealthDataRejected('malformed');
  }
  const { payload, signature } = (typeof file === 'object' && file !== null ? file : {}) as Record<string, unknown>;
  const payloadBytes = typeof payload === 'string' ? base64Decode(payload) : undefined;
  const signatureBytes = typeof signature === 'string' ? base64Decode(signature) : undefined;
  if (!payloadBytes || signatureBytes?.length !== 64) throw new HealthDataRejected('malformed');
  return { payload: payloadBytes, signature: signatureBytes };
}

/**
 * Checks a downloaded file: the signature first (nothing unsigned is parsed), then the payload,
 * then that it's newer than `after`, the version in use. Throws `HealthDataRejected`.
 */
export async function verifyHealthData(text: string, options: { after: number; publicKey?: string }): Promise<HealthData> {
  const { payload, signature } = envelope(text);
  const raw = base64Decode(options.publicKey ?? HEALTH_DATA_PUBLIC_KEY);
  if (raw?.length !== 32) throw new Error('health data key is not 32 bytes');
  const context = new TextEncoder().encode(HEALTH_DATA_CONTEXT);
  const message = new Uint8Array(context.length + 1 + payload.length);
  message.set(context, 0);
  message.set(payload, context.length + 1);
  let valid = false;
  try {
    const key = await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
    valid = await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, message);
  } catch {
    // A browser without Ed25519 can't check, so it keeps what it has.
    valid = false;
  }
  if (!valid) throw new HealthDataRejected('badSignature');
  const data = parsePayload(payload);
  if (data.version <= options.after) throw new HealthDataRejected('rollback');
  return data;
}

let bundled: HealthData | undefined;

/** The lists this build shipped with. Signed like any update; trusted as part of the code. */
export function bundledHealthData(): HealthData {
  bundled ??= parsePayload(envelope(JSON.stringify(bundledFile)).payload);
  return bundled;
}

/** The bundled file as published, for the signing tool's checks and the server. */
export const BUNDLED_HEALTH_DATA_FILE: { payload: string; signature: string } = bundledFile;

export type HealthDataUpdate = 'notDue' | 'current' | 'updated' | 'rejected' | 'failed';

export interface HealthDataStore {
  /** The newest data on this device: an update kept from before, or the bundled lists. */
  current(): Promise<HealthData>;
  /**
   * Asks `download` for the file when a day has passed since the last ask (or `force`) and keeps
   * it if it's valid and newer. Never throws; what happened is the answer.
   */
  update(download: () => Promise<string>, options?: { force?: boolean; now?: Date }): Promise<HealthDataUpdate>;
}

const KEY = 'healthData';

interface Stored {
  /** The newest file accepted, as downloaded, checked again whenever it's read. */
  file?: string;
  checkedAt?: string;
}

/** Keeps the newest verified file in `storage`. It's public data, the same for everyone, so it isn't encrypted. */
export function createHealthDataStore(storage: Pick<KeyValueStore, 'get' | 'set'>, options: { publicKey?: string } = {}): HealthDataStore {
  let active: Promise<HealthData> | undefined;
  const key = options.publicKey ? { publicKey: options.publicKey } : {};

  const read = async (): Promise<Stored> => (await storage.get<Stored>(KEY).catch(() => undefined)) ?? {};
  const load = async (): Promise<HealthData> => {
    const base = bundledHealthData();
    const { file } = await read();
    if (!file) return base;
    // Checked again on every read: a stored copy is no more trusted than a download.
    return verifyHealthData(file, { after: base.version, ...key }).catch(() => base);
  };

  return {
    current() {
      active ??= load();
      return active;
    },

    async update(download, { force = false, now = new Date() } = {}) {
      const stored = await read();
      const checkedAt = stored.checkedAt ? Date.parse(stored.checkedAt) : 0;
      if (!force && now.getTime() - checkedAt < HEALTH_DATA_CHECK_HOURS * 3_600_000) return 'notDue';
      const remember = (next: Stored) => storage.set(KEY, next).catch(() => undefined);
      let text: string;
      try {
        text = await download();
      } catch {
        return 'failed';
      }
      const inUse = await this.current();
      try {
        await verifyHealthData(text, { after: inUse.version, ...key });
      } catch (e) {
        await remember({ ...stored, checkedAt: now.toISOString() });
        return e instanceof HealthDataRejected && e.problem === 'rollback' ? 'current' : 'rejected';
      }
      await remember({ file: text, checkedAt: now.toISOString() });
      active = undefined;
      return 'updated';
    },
  };
}

/** Fetches the file from a server: no cookies, no referrer, nothing but the path. */
export function healthDataDownload(serverOrigin: string, fetcher: typeof fetch = (input, init) => fetch(input, init)): () => Promise<string> {
  return async () => {
    const response = await fetcher(`${serverOrigin.replace(/\/+$/, '')}${HEALTH_DATA_PATH}`, {
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok) throw new Error(`health data: ${response.status}`);
    const text = await response.text();
    if (text.length > HEALTH_DATA_MAX_BYTES) throw new Error('health data: too large');
    return text;
  };
}
