// Locks the vault after a stretch without use, and when the computer locks. The service worker can
// stop at any time, so the last activity lives in `chrome.storage.session` and the timer is a
// `chrome.alarms` alarm, which wakes the worker up again.
//
// Plan 18, "Stay unlocked while you're logged in to this device": while it's on there is no timer
// and no lock when the computer locks; a computer lock only resets "revealing asked once"
// (`onDeviceLock`). The vault stays in `chrome.storage.session` until the browser closes.

import type { KeyValueStore } from './storage';

export interface LockSettings {
  /** 0 = only when the browser closes. */
  autoLockMinutes: number;
  lockOnSystemLock: boolean;
  /** Plan 18. Per browser, never synced. */
  stayUnlocked: boolean;
}

export const DEFAULT_LOCK_SETTINGS: LockSettings = { autoLockMinutes: 15, lockOnSystemLock: true, stayUnlocked: true };
export const LOCK_SETTINGS_KEY = 'lock-settings';

/**
 * The lock settings as stored, with plan 18's migration: they're written only when the user changes
 * one, so none stored means none picked, and the new default (stay unlocked) applies. Settings stored
 * before plan 18 were picked by the user and keep their lock.
 */
export function readLockSettings(stored: Partial<LockSettings> | undefined): LockSettings {
  if (!stored) return DEFAULT_LOCK_SETTINGS;
  return { ...DEFAULT_LOCK_SETTINGS, ...stored, stayUnlocked: stored.stayUnlocked ?? false };
}
export const AUTO_LOCK_ALARM = 'octapass-auto-lock';

const LAST_ACTIVE = 'last-active';
/** Activity is written at most this often. */
const TOUCH_INTERVAL_MS = 10_000;

export interface Alarms {
  create(name: string, info: { when: number }): unknown;
  clear(name: string): unknown;
}

export interface AutoLockOptions {
  memory: KeyValueStore;
  alarms: Alarms;
  lock: () => void;
  /** Staying unlocked, the computer locked or slept: revealing and copying ask again. */
  onDeviceLock?: () => void;
  now?: () => number;
}

export class AutoLock {
  private settings = DEFAULT_LOCK_SETTINGS;
  private lastWrite = 0;

  constructor(private readonly options: AutoLockOptions) {}

  private now(): number {
    return this.options.now?.() ?? Date.now();
  }

  private get limitMs(): number {
    return this.settings.stayUnlocked ? 0 : this.settings.autoLockMinutes * 60_000;
  }

  /** Plan 18's switch, as configured. */
  get stayUnlocked(): boolean {
    return this.settings.stayUnlocked;
  }

  /** `settings`: as stored (see `readLockSettings`). */
  async configure(settings: Partial<LockSettings> | undefined): Promise<void> {
    this.settings = readLockSettings(settings);
    await this.schedule((await this.options.memory.get<number>(LAST_ACTIVE)) ?? this.now());
  }

  /** The user did something with the vault. */
  async touch(): Promise<void> {
    const now = this.now();
    if (now - this.lastWrite < TOUCH_INTERVAL_MS) return;
    this.lastWrite = now;
    await this.options.memory.set(LAST_ACTIVE, now);
    await this.schedule(now);
  }

  /** Whether the vault should already be locked, e.g. when the worker starts again. */
  async expired(): Promise<boolean> {
    const last = await this.options.memory.get<number>(LAST_ACTIVE);
    return this.limitMs > 0 && last !== undefined && this.now() - last >= this.limitMs;
  }

  async onAlarm(name: string): Promise<void> {
    if (name !== AUTO_LOCK_ALARM) return;
    if (await this.expired()) this.options.lock();
    else await this.schedule((await this.options.memory.get<number>(LAST_ACTIVE)) ?? this.now());
  }

  onIdleState(state: string): void {
    if (state !== 'locked') return;
    if (this.settings.stayUnlocked) this.options.onDeviceLock?.();
    else if (this.settings.lockOnSystemLock) this.options.lock();
  }

  /** After a lock: nothing to time any more. */
  async stop(): Promise<void> {
    this.lastWrite = 0;
    await this.options.memory.delete(LAST_ACTIVE);
    await this.options.alarms.clear(AUTO_LOCK_ALARM);
  }

  private async schedule(lastActive: number): Promise<void> {
    if (this.limitMs > 0) await this.options.alarms.create(AUTO_LOCK_ALARM, { when: lastActive + this.limitMs });
    else await this.options.alarms.clear(AUTO_LOCK_ALARM);
  }
}
