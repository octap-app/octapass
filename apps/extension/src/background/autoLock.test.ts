import { memoryStore } from '../test/memoryStore';
import { AUTO_LOCK_ALARM, AutoLock, DEFAULT_LOCK_SETTINGS, readLockSettings } from './autoLock';

function setup(minutes = 5) {
  let now = 1_000_000;
  const alarms = new Map<string, number>();
  const lock = vi.fn();
  const memory = memoryStore();
  const autoLock = new AutoLock({
    memory,
    lock,
    now: () => now,
    alarms: { create: (name, { when }) => alarms.set(name, when), clear: (name) => alarms.delete(name) },
  });
  return {
    autoLock,
    alarms,
    lock,
    memory,
    advance: (ms: number) => (now += ms),
    ready: () => autoLock.configure({ autoLockMinutes: minutes }),
  };
}

describe('AutoLock', () => {
  it('locks when the alarm fires after the timeout', async () => {
    const t = setup(5);
    await t.ready();
    await t.autoLock.touch();
    expect(t.alarms.get(AUTO_LOCK_ALARM)).toBe(1_000_000 + 5 * 60_000);
    t.advance(5 * 60_000);
    await t.autoLock.onAlarm(AUTO_LOCK_ALARM);
    expect(t.lock).toHaveBeenCalledOnce();
  });

  it('moves the alarm on with activity instead of locking', async () => {
    const t = setup(5);
    await t.ready();
    await t.autoLock.touch();
    t.advance(4 * 60_000);
    await t.autoLock.touch();
    t.advance(60_000);
    await t.autoLock.onAlarm(AUTO_LOCK_ALARM);
    expect(t.lock).not.toHaveBeenCalled();
    expect(t.alarms.get(AUTO_LOCK_ALARM)).toBe(1_000_000 + 9 * 60_000);
  });

  it('remembers the last activity across worker restarts', async () => {
    const t = setup(5);
    await t.ready();
    await t.autoLock.touch();
    t.advance(6 * 60_000);
    const restarted = new AutoLock({ memory: t.memory, lock: t.lock, now: () => 1_000_000 + 6 * 60_000, alarms: { create: () => undefined, clear: () => undefined } });
    await restarted.configure({ autoLockMinutes: 5 });
    expect(await restarted.expired()).toBe(true);
  });

  it('never times out at 0 minutes, and locks with the computer when asked', async () => {
    const t = setup(0);
    await t.ready();
    await t.autoLock.touch();
    t.advance(24 * 3_600_000);
    expect(await t.autoLock.expired()).toBe(false);
    expect(t.alarms.has(AUTO_LOCK_ALARM)).toBe(false);
    t.autoLock.onIdleState('idle');
    expect(t.lock).not.toHaveBeenCalled();
    t.autoLock.onIdleState('locked');
    expect(t.lock).toHaveBeenCalledOnce();
  });

  describe('staying unlocked (plan 18)', () => {
    it('has no timer and only resets the reveal state when the computer locks', async () => {
      const t = setup(5);
      const onDeviceLock = vi.fn();
      const autoLock = new AutoLock({ memory: t.memory, lock: t.lock, onDeviceLock, now: () => 1_000_000, alarms: { create: (name, { when }) => t.alarms.set(name, when), clear: (name) => t.alarms.delete(name) } });
      await autoLock.configure({ autoLockMinutes: 5, lockOnSystemLock: true, stayUnlocked: true });
      await autoLock.touch();
      expect(t.alarms.has(AUTO_LOCK_ALARM)).toBe(false);
      expect(await autoLock.expired()).toBe(false);
      autoLock.onIdleState('locked');
      expect(t.lock).not.toHaveBeenCalled();
      expect(onDeviceLock).toHaveBeenCalledOnce();

      // Off: the timer and the lock with the computer come back.
      await autoLock.configure({ autoLockMinutes: 5, lockOnSystemLock: true, stayUnlocked: false });
      expect(t.alarms.has(AUTO_LOCK_ALARM)).toBe(true);
      autoLock.onIdleState('locked');
      expect(t.lock).toHaveBeenCalledOnce();
      expect(onDeviceLock).toHaveBeenCalledOnce();
    });

    it('reaches new installs and keeps a lock the user picked', () => {
      // Nothing stored: nothing was picked.
      expect(readLockSettings(undefined)).toEqual({ ...DEFAULT_LOCK_SETTINGS, stayUnlocked: true });
      // Stored only when changed, so anything stored before plan 18 was the user's choice.
      expect(readLockSettings({ autoLockMinutes: 15, lockOnSystemLock: true })).toEqual({ autoLockMinutes: 15, lockOnSystemLock: true, stayUnlocked: false });
      expect(readLockSettings({ autoLockMinutes: 1, lockOnSystemLock: true }).stayUnlocked).toBe(false);
      expect(readLockSettings({ autoLockMinutes: 15, lockOnSystemLock: true, stayUnlocked: true }).stayUnlocked).toBe(true);
    });
  });
});
