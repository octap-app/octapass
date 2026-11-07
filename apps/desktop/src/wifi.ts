import type { DeviceWifiNetwork, WifiFeatures, WifiPermission, WifiService, WifiSighting } from '@octapass/vault-client';
import type { Transport } from './transport';

/** The platform names `WifiService` uses, from the web view's own platform string. */
export function desktopPlatform(platform: string): 'mac' | 'windows' | 'linux' {
  return /^Mac/.test(platform) ? 'mac' : /^Win/.test(platform) ? 'windows' : 'linux';
}

/**
 * The computer's Wi-Fi over the app's commands (`src-tauri/src/wifi.rs`). Missing when the
 * computer has no Wi-Fi Octa Pass can read.
 */
export async function desktopWifi(transport: Transport, platform = navigator.platform): Promise<WifiService | undefined> {
  const features = await transport.invoke<WifiFeatures>('wifi_features').catch(() => undefined);
  if (!features || !Object.values(features).some(Boolean)) return undefined;
  const joins = new Set<(ssid: string) => void>();
  await transport.listen<string>('wifi://joined', (ssid) => {
    for (const cb of joins) cb(ssid);
  });
  return {
    platform: desktopPlatform(platform),
    features,
    permission: () => transport.invoke<WifiPermission>('wifi_permission'),
    requestPermission: () => transport.invoke<WifiPermission>('wifi_request_permission'),
    currentNetwork: async () => (await transport.invoke<string | null>('wifi_current')) ?? undefined,
    nearbyNetworks: (rescan = false) => transport.invoke<WifiSighting[]>('wifi_nearby', { rescan }),
    savedNetworks: () => transport.invoke<DeviceWifiNetwork[]>('wifi_saved'),
    readSavedPasswords: (ssids) => transport.invoke<DeviceWifiNetwork[]>('wifi_read_passwords', { ssids }),
    onJoin: (cb) => {
      joins.add(cb);
      return () => joins.delete(cb);
    },
  };
}
