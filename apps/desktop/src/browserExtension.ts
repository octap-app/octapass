import type { BrowserExtensionService, BrowserExtensionStatus } from '@octapass/vault-client';
import type { Transport } from './transport';

/** Settings → Browser extension and the offer of it, over the app's commands (`src-tauri/src/browser_extension.rs`). */
export function desktopBrowserExtension(transport: Transport): BrowserExtensionService {
  return {
    status: () => transport.invoke<BrowserExtensionStatus>('browser_extension_status'),
    connect: () => transport.invoke<BrowserExtensionStatus>('browser_extension_connect'),
    disconnect: () => transport.invoke<BrowserExtensionStatus>('browser_extension_disconnect'),
    get: (browser) => transport.invoke<void>('browser_extension_get', { browser }),
  };
}
