import { useEffect } from 'react';

const ACTIVITY = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const;

/**
 * Locks after `minutes` without input. Uses wall-clock time rather than one long timer, because
 * browsers throttle timers in background tabs and a sleeping laptop doesn't fire them at all.
 */
export function useAutoLock(lock: () => void, minutes: number, lockOnHide: boolean): void {
  useEffect(() => {
    let last = Date.now();
    const limit = minutes * 60_000;
    const touch = () => (last = Date.now());
    const check = () => {
      if (limit > 0 && Date.now() - last >= limit) lock();
    };
    const onVisibility = () => {
      if (document.visibilityState === 'hidden' && lockOnHide) lock();
      else check();
    };

    for (const event of ACTIVITY) window.addEventListener(event, touch, { passive: true });
    document.addEventListener('visibilitychange', onVisibility);
    const interval = setInterval(check, 5_000);
    return () => {
      for (const event of ACTIVITY) window.removeEventListener(event, touch);
      document.removeEventListener('visibilitychange', onVisibility);
      clearInterval(interval);
    };
  }, [lock, minutes, lockOnHide]);
}
