import { cloneElement, type ReactElement } from 'react';
import type { routes } from '@octapass/web/src/app/routes';
import type { Transport } from './transport';

/** `ProviderStatus` in `src-tauri/src/windows_passkey.rs`. */
export interface ProviderStatus {
  /** This Windows has the plugin API and the app runs from its package. */
  available: boolean;
  /** On here: Windows knows Octa Pass as a provider. */
  registered: boolean;
  /** Also on in Windows Settings, which only Windows can ask for. */
  enabled: boolean;
}

export interface PasskeyProvider {
  status(): Promise<ProviderStatus>;
  set(enabled: boolean): Promise<ProviderStatus>;
  openSettings(): Promise<void>;
}

/** The Windows passkey provider over the app's commands. Missing wherever it isn't available. */
export async function desktopPasskeyProvider(transport: Transport): Promise<PasskeyProvider | undefined> {
  const status = await transport.invoke<ProviderStatus>('windows_passkey_status').catch(() => undefined);
  if (!status?.available) return undefined;
  return {
    status: () => transport.invoke<ProviderStatus>('windows_passkey_status'),
    set: (enabled) => transport.invoke<ProviderStatus>('windows_passkey_set', { enabled }),
    openSettings: () => transport.invoke<void>('windows_passkey_open_settings'),
  };
}

type Routes = typeof routes;

/** The web vault's routes, with `section` in Settings as the app's own (`platformSection`). */
export function withPasskeyProvider(appRoutes: Routes, section: ReactElement): Routes {
  return appRoutes.map((route) => {
    const copy = { ...route } as Routes[number];
    if (route.path === 'settings' && route.element) {
      copy.element = cloneElement(route.element as ReactElement<{ platformSection?: unknown }>, { platformSection: section });
    }
    if (route.children) copy.children = withPasskeyProvider(route.children, section);
    return copy;
  });
}
