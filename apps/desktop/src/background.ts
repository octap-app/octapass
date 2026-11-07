import type { BackgroundService, BackgroundStatus } from '@octapass/vault-client';
import type { Transport } from './transport';

/** The tray icon and opening at login over the app's commands (`src-tauri/src/background.rs`). */
export function desktopBackground(transport: Transport): BackgroundService {
  return {
    status: () => transport.invoke<BackgroundStatus>('background_status'),
    setTray: (visible) => transport.invoke<BackgroundStatus>('background_set_tray', { visible }),
    setOpenAtLogin: (enabled) => transport.invoke<BackgroundStatus>('background_set_open_at_login', { enabled }),
  };
}
