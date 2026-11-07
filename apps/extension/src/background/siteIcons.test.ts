import { memoryIconStore, type IconAnswer } from '@octapass/vault-client';
import { SiteIcons, siteIconsEnabled, SITE_ICONS_KEY } from './siteIcons';

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47]);

function icons(options: { serverUrl?: string; enabled?: boolean } = {}) {
  const fetchIcon = vi.fn(async (): Promise<IconAnswer> => ({ kind: 'icon', png: PNG }));
  const siteIcons = new SiteIcons({
    serverUrl: () => options.serverUrl,
    defaultServer: 'https://vault.octap.app',
    enabled: async () => options.enabled ?? true,
    fetchIcon,
    store: memoryIconStore(),
  });
  return { siteIcons, fetchIcon };
}

describe('SiteIcons', () => {
  it('loads through the account’s server, once per domain', async () => {
    const { siteIcons, fetchIcon } = icons({ serverUrl: 'https://vault.example.org' });
    expect(await siteIcons.forUrls(['https://login.bank.com/'])).toBe('iVBORw==');
    expect(await siteIcons.forUrls(['https://www.bank.com/help'])).toBe('iVBORw==');
    expect(fetchIcon).toHaveBeenCalledTimes(1);
    expect(fetchIcon).toHaveBeenCalledWith('https://vault.example.org', 'bank.com');
  });

  it('uses the default server for a vault on this device only', async () => {
    const { siteIcons, fetchIcon } = icons({ serverUrl: 'local:this-device' });
    await siteIcons.forUrls(['https://bank.com']);
    expect(fetchIcon).toHaveBeenCalledWith('https://vault.octap.app', 'bank.com');
  });

  it('asks for nothing while the setting is off, or for addresses without a public icon', async () => {
    const off = icons({ serverUrl: 'https://vault.example.org', enabled: false });
    expect(await off.siteIcons.forUrls(['https://bank.com'])).toBeNull();
    expect(off.fetchIcon).not.toHaveBeenCalled();
    const on = icons({ serverUrl: 'https://vault.example.org' });
    expect(await on.siteIcons.forUrls(['http://192.168.1.1'])).toBeNull();
    expect(await on.siteIcons.forUrls(undefined)).toBeNull();
    expect(on.fetchIcon).not.toHaveBeenCalled();
  });

  it('reads the setting the popup mirrors, on unless turned off', async () => {
    const stored: Record<string, unknown> = {};
    const local = {
      get: async (key: string) => (key in stored ? { [key]: stored[key] } : {}),
      set: async (items: Record<string, unknown>) => void Object.assign(stored, items),
    };
    vi.stubGlobal('chrome', { ...chrome, storage: { local } });
    expect(await siteIconsEnabled()).toBe(true);
    await chrome.storage.local.set({ [SITE_ICONS_KEY]: false });
    expect(await siteIconsEnabled()).toBe(false);
    await chrome.storage.local.set({ [SITE_ICONS_KEY]: true });
    expect(await siteIconsEnabled()).toBe(true);
    vi.unstubAllGlobals();
  });
});
