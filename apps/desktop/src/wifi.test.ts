import { describe, expect, it, vi } from 'vitest';
import { FakeTransport } from './test/fakeTransport';
import { desktopPlatform, desktopWifi } from './wifi';

const all = { current: true, nearby: true, savedNetworks: true, joins: true };

describe('desktop Wi-Fi', () => {
  it('goes through the app’s commands', async () => {
    const transport = new FakeTransport()
      .on('wifi_features', () => all)
      .on('wifi_permission', () => 'granted')
      .on('wifi_current', () => null)
      .on('wifi_nearby', (args) => (args?.rescan ? [{ ssid: 'Home', signal: 80 }] : []))
      .on('wifi_saved', () => [{ ssid: 'Home', security: 'wpa2' }])
      .on('wifi_read_passwords', (args) => (args?.ssids as string[]).map((ssid) => ({ ssid, password: 'pw' })));
    const wifi = (await desktopWifi(transport, 'MacIntel'))!;
    expect(wifi.platform).toBe('mac');
    expect(await wifi.permission()).toBe('granted');
    expect(await wifi.currentNetwork()).toBeUndefined();
    expect(await wifi.nearbyNetworks()).toEqual([]);
    expect(await wifi.nearbyNetworks(true)).toEqual([{ ssid: 'Home', signal: 80 }]);
    expect(await wifi.savedNetworks!()).toEqual([{ ssid: 'Home', security: 'wpa2' }]);
    expect(await wifi.readSavedPasswords!(['Home'])).toEqual([{ ssid: 'Home', password: 'pw' }]);
  });

  it('tells the page when the computer joins a network', async () => {
    const transport = new FakeTransport().on('wifi_features', () => all);
    const wifi = (await desktopWifi(transport, 'Win32'))!;
    const joined = vi.fn();
    const stop = wifi.onJoin!(joined);
    transport.emit('wifi://joined', 'Cafe');
    stop();
    transport.emit('wifi://joined', 'Later');
    expect(joined.mock.calls).toEqual([['Cafe']]);
  });

  it('is missing where the computer has no Wi-Fi Octa Pass can read', async () => {
    expect(await desktopWifi(new FakeTransport().on('wifi_features', () => ({ current: false, nearby: false, savedNetworks: false, joins: false })))).toBeUndefined();
    expect(await desktopWifi(new FakeTransport())).toBeUndefined();
  });

  it('names the platform', () => {
    expect([desktopPlatform('MacIntel'), desktopPlatform('Win32'), desktopPlatform('Linux x86_64')]).toEqual(['mac', 'windows', 'linux']);
  });
});
