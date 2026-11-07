import { renderHook } from '@testing-library/react';
import { useAutoLock } from './useAutoLock';

describe('useAutoLock', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('locks after the idle limit, and activity resets it', () => {
    const lock = vi.fn();
    renderHook(() => useAutoLock(lock, 1, false));
    vi.advanceTimersByTime(45_000);
    window.dispatchEvent(new Event('keydown'));
    vi.advanceTimersByTime(45_000);
    expect(lock).not.toHaveBeenCalled();
    vi.advanceTimersByTime(20_000);
    expect(lock).toHaveBeenCalled();
  });

  it('never locks on a timer when set to 0', () => {
    const lock = vi.fn();
    renderHook(() => useAutoLock(lock, 0, false));
    vi.advanceTimersByTime(24 * 3_600_000);
    expect(lock).not.toHaveBeenCalled();
  });
});
