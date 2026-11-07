// Website icons for the in-page menu. The service worker loads them (from the device cache the
// popup shares, else through the Octa Pass server) and hands the content script the bytes, which
// it draws as pixels: the page never sees a request, a URL or which items exist.

import { iconDomain, idbIconStore, serverIconFetch, SiteIconLoader, type IconFetch, type IconStore } from '@octapass/vault-client';

/** "Show website icons", mirrored from the popup's settings into `chrome.storage.local`. On unless set to false. */
export const SITE_ICONS_KEY = 'octapass:siteIcons';

export interface SiteIconOptions {
  /** The account's server, or undefined for a vault on this device only. */
  serverUrl: () => string | undefined;
  /** Used without an account, and only while the setting is on. */
  defaultServer: string;
  enabled: () => Promise<boolean>;
  fetchIcon?: IconFetch;
  store?: IconStore;
}

export class SiteIcons {
  private loader?: SiteIconLoader;

  constructor(private readonly options: SiteIconOptions) {}

  /** The icon for an item's URLs as base64 PNG, or null. Nothing is fetched while the setting is off. */
  async forUrls(urls: readonly string[] | undefined): Promise<string | null> {
    const domain = iconDomain(urls);
    if (!domain || !(await this.options.enabled())) return null;
    const png = await this.loaderFor(this.server()).load(domain);
    if (!png) return null;
    let binary = '';
    for (const byte of png) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  private server(): string {
    const url = this.options.serverUrl();
    return url && /^https?:\/\//i.test(url) ? url : this.options.defaultServer;
  }

  private loaderFor(server: string): SiteIconLoader {
    if (this.loader?.serverUrl !== server) {
      this.loader = new SiteIconLoader(server, {
        fetchIcon: this.options.fetchIcon ?? serverIconFetch(),
        store: this.options.store ?? idbIconStore(),
      });
    }
    return this.loader;
  }
}

export async function siteIconsEnabled(): Promise<boolean> {
  try {
    return (await chrome.storage.local.get(SITE_ICONS_KEY))[SITE_ICONS_KEY] !== false;
  } catch {
    return false;
  }
}
