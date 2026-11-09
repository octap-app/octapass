import { describe, expect, it, vi } from 'vitest';
import { desktopBrowserExtension } from './browserExtension';
import type { Transport } from './transport';

describe('desktopBrowserExtension', () => {
  it('calls the app’s commands with their arguments', async () => {
    const invoke = vi.fn((_command: string, _args?: unknown) => Promise.resolve(undefined));
    const extension = desktopBrowserExtension({ invoke } as unknown as Transport);
    await extension.status();
    expect(invoke).toHaveBeenLastCalledWith('browser_extension_status');
    await extension.connect();
    expect(invoke).toHaveBeenLastCalledWith('browser_extension_connect');
    await extension.disconnect();
    expect(invoke).toHaveBeenLastCalledWith('browser_extension_disconnect');
    await extension.get('Firefox');
    expect(invoke).toHaveBeenLastCalledWith('browser_extension_get', { browser: 'Firefox' });
  });
});
