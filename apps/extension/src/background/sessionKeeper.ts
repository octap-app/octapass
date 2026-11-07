// Keeps the unlocked vault across service worker restarts (plan 05: MV3 workers stop when idle).
//
// The account key never leaves the WASM core, but the core can wrap it under any 32-byte secret:
// that's how device unlock works with a passkey's PRF output. The keeper uses the same mechanism
// with a random per-session key instead of a PRF output, and keeps the wrapped key and the
// session key in `chrome.storage.session`, which lives in memory only and is cleared when the
// browser closes. On restart it unwraps through the engine's own device-unlock path.
//
// The engine stores device-unlock records under `device-unlock:<accountId>`. The keeper's storage
// adapter sends a record marked with SESSION_CREDENTIAL to memory, and while restoring, reads (and
// deletes) that key from memory instead of disk. Real device unlock records are untouched. The same
// trick serves a one-off record (`unlockWith`), for the desktop app's key over native messaging.

import { base64UrlDecode, base64UrlEncode } from '@octapass/vault-client';
import type { KeyValueStore } from './storage';

/** Stands in for a passkey credential ID in the engine's device-unlock record. */
export const SESSION_CREDENTIAL = 'octapass-extension-session';

const DEVICE_UNLOCK = 'device-unlock:';
const WRAP = 'session-wrap';

/** The engine's device-unlock record (`@octapass/vault-client` `DeviceUnlockRecord`). */
export interface UnlockRecord {
  accountId: string;
  credentialId: string;
  deviceSalt: string;
  wrappedAsk: string;
  enabledAt: string;
  lastPasswordUnlockAt: string;
}

export interface SessionWrap {
  record: UnlockRecord;
  /** The per-session key, base64url. */
  key: string;
  /**
   * The user opened this session themselves (the master password, device unlock or the desktop
   * app's device lock), so reveal and copy don't ask again (plan 03 History, 2026-11-05). Kept in
   * the wrap so it goes with it: a lock, a sign-out or the browser closing ends both.
   */
  confirmed?: boolean;
}

/** What the keeper needs from the engine. */
export interface Unlocker {
  /** `enableDeviceUnlock(credentialId, key)`: wraps the account key and stores the record. */
  wrap(credentialId: string, key: Uint8Array): Promise<void>;
  /** `unlockWithDevice(key)`: reads the record and unlocks with it. */
  unwrap(key: Uint8Array): Promise<void>;
}

const isUnlockKey = (key: string) => key.startsWith(DEVICE_UNLOCK);

export class SessionKeeper {
  /** Give this to the engine as its storage. */
  readonly storage: KeyValueStore;
  /** While unwrapping: the session wrap from memory, or a one-off record. */
  private override: 'wrap' | Omit<UnlockRecord, 'accountId'> | undefined;
  private pendingKey: Uint8Array | undefined;
  private pendingConfirmed = false;
  // Saves, restores and clears run one at a time, so a lock right after an unlock always wins.
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    disk: KeyValueStore,
    private readonly memory: KeyValueStore,
  ) {
    this.storage = {
      get: <T>(key: string) => (this.override && isUnlockKey(key) ? this.overrideRecord<T>(key) : disk.get<T>(key)),
      set: (key, value) => (isUnlockKey(key) && (value as Partial<UnlockRecord>).credentialId === SESSION_CREDENTIAL ? this.store(value as UnlockRecord) : disk.set(key, value)),
      // A failed unwrap makes the engine delete the record it read: the session wrap, or nothing stored.
      delete: async (key) => {
        if (!this.override || !isUnlockKey(key)) return disk.delete(key);
        if (this.override === 'wrap') await memory.delete(WRAP);
      },
      clear: () => disk.clear(),
    };
  }

  /** After an unlock: wraps the session with a fresh key, remembering whether the user opened it. */
  save(unlocker: Unlocker, confirmed = false): Promise<void> {
    return this.enqueue(async () => {
      const key = crypto.getRandomValues(new Uint8Array(32));
      this.pendingKey = key;
      this.pendingConfirmed = confirmed;
      try {
        // The engine zeroes what it's given, so it gets a copy.
        await unlocker.wrap(SESSION_CREDENTIAL, key.slice());
      } finally {
        this.pendingKey = undefined;
      }
    });
  }

  /** At start-up: unlocks the engine again if this browser session had it unlocked. */
  restore(unlocker: Unlocker): Promise<boolean> {
    return this.enqueue(async () => {
      const wrap = await this.read();
      if (!wrap) return false;
      this.override = 'wrap';
      try {
        await unlocker.unwrap(base64UrlDecode(wrap.key));
        return true;
      } catch {
        await this.memory.delete(WRAP);
        return false;
      } finally {
        this.override = undefined;
      }
    });
  }

  /** Unlocks the engine with a wrapped account key from elsewhere (the desktop app) and its key. */
  unlockWith(record: Omit<UnlockRecord, 'accountId'>, key: Uint8Array, unlocker: Unlocker): Promise<void> {
    return this.enqueue(async () => {
      this.override = record;
      try {
        await unlocker.unwrap(key);
      } finally {
        this.override = undefined;
      }
    });
  }

  /**
   * The user answered a check since the unlock (or, staying unlocked, the computer locked): the
   * wrap remembers it, so a worker restart keeps "revealing asked once" as it was (plan 18).
   */
  setConfirmed(confirmed: boolean): Promise<void> {
    return this.enqueue(async () => {
      const wrap = await this.read();
      if (!wrap) return;
      const { confirmed: _was, ...rest } = wrap;
      await this.memory.set(WRAP, { ...rest, ...(confirmed ? { confirmed: true } : {}) } satisfies SessionWrap);
    });
  }

  /** After a lock or sign-out. */
  clear(): Promise<void> {
    return this.enqueue(() => this.memory.delete(WRAP));
  }

  read(): Promise<SessionWrap | undefined> {
    return this.memory.get<SessionWrap>(WRAP);
  }

  private async store(record: UnlockRecord): Promise<void> {
    if (!this.pendingKey) return;
    await this.memory.set(WRAP, { record, key: base64UrlEncode(this.pendingKey), ...(this.pendingConfirmed ? { confirmed: true } : {}) } satisfies SessionWrap);
  }

  private async overrideRecord<T>(key: string): Promise<T | undefined> {
    if (this.override !== 'wrap') return { ...this.override, accountId: key.slice(DEVICE_UNLOCK.length) } as T;
    const wrap = await this.read();
    return wrap && `${DEVICE_UNLOCK}${wrap.record.accountId}` === key ? (wrap.record as T) : undefined;
  }

  private enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = this.queue.then(task, task);
    this.queue = run.catch(() => undefined);
    return run;
  }
}
