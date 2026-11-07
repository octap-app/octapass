import { describe, expect, it, vi } from 'vitest';
import { desktopBackground } from './background';
import type { Transport } from './transport';

describe('desktopBackground', () => {
  it('calls the app’s commands with their arguments', async () => {
    const invoke = vi.fn((_command: string, _args?: unknown) => Promise.resolve(undefined));
    const background = desktopBackground({ invoke } as unknown as Transport);
    await background.status();
    expect(invoke).toHaveBeenLastCalledWith('background_status');
    await background.setTray(false);
    expect(invoke).toHaveBeenLastCalledWith('background_set_tray', { visible: false });
    await background.setOpenAtLogin(true);
    expect(invoke).toHaveBeenLastCalledWith('background_set_open_at_login', { enabled: true });
  });
});
