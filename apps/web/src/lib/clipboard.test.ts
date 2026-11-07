import { copyWithAutoClear } from './clipboard';

describe('copyWithAutoClear', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    const writes: string[] = [];
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn(async (text: string) => void writes.push(text)) } });
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
  });

  afterEach(() => vi.useRealTimers());

  it('clears the clipboard after 30 seconds', async () => {
    await copyWithAutoClear('hunter2');
    expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith('hunter2');
    await vi.advanceTimersByTimeAsync(29_000);
    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith('');
  });

  it('restarts the timer on each copy', async () => {
    await copyWithAutoClear('one');
    await vi.advanceTimersByTimeAsync(20_000);
    await copyWithAutoClear('two');
    await vi.advanceTimersByTimeAsync(20_000);
    expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith('two');
    await vi.advanceTimersByTimeAsync(10_000);
    expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith('');
  });
});
