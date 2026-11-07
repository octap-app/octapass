import { Avatar, type AvatarProps } from '@octapass/ui';
import { iconDomain, idbIconStore, pngDataUrl, serverIconFetch, SiteIconLoader, type IconFetch, type IconStore } from '@octapass/vault-client';
import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useService, useSession } from '../app/ServiceContext';
import { DEFAULT_SERVER_URL } from '../app/service';
import { useSettings } from '../app/settings';

interface SiteIcons {
  /** A data URL for an icon already loaded in this session. */
  cached(domain: string): string | undefined;
  /** Loads the icon; undefined when there is none (yet). */
  load(domain: string): Promise<string | undefined>;
}

const SiteIconsContext = createContext<SiteIcons | null>(null);

/**
 * The server icons come from: the account's, or for a vault without an account (the extension's
 * local mode), the default Octa Pass server. Only while "Show website icons" is on.
 */
export function iconServer(serverUrl: string | undefined): string {
  return serverUrl && /^https?:\/\//i.test(serverUrl) ? serverUrl : DEFAULT_SERVER_URL;
}

let deviceStore: IconStore | undefined;
const defaultStore = () => (deviceStore ??= idbIconStore());

/**
 * Website icons for item lists and pages. Off ("Show website icons", or locked) means no loader at
 * all, so nothing is requested and every item shows its initial. Turning it off or signing out
 * also clears the icons this device kept.
 */
export function SiteIconsProvider({ children, store, fetchIcon }: { children: ReactNode; store?: IconStore; fetchIcon?: IconFetch }) {
  const { settings } = useSettings();
  const service = useService();
  const session = useSession();
  const on = settings.showSiteIcons && session.status === 'unlocked';
  const server = iconServer(session.serverUrl);
  const iconStore = store ?? defaultStore();

  const value = useMemo<SiteIcons | null>(() => {
    if (!on) return null;
    const loader = new SiteIconLoader(server, {
      fetchIcon: fetchIcon ?? (service.fetchSiteIcon ? (url, domain) => service.fetchSiteIcon!(url, domain) : serverIconFetch()),
      store: iconStore,
    });
    const urls = new Map<string, string>();
    return {
      cached: (domain) => urls.get(domain),
      load: async (domain) => {
        const png = await loader.load(domain);
        if (!png) return undefined;
        const url = urls.get(domain) ?? pngDataUrl(png);
        urls.set(domain, url);
        return url;
      },
    };
  }, [on, server, service, fetchIcon, iconStore]);

  const status = useRef(session.status);
  useEffect(() => {
    const signedOut = session.status === 'signedOut' && status.current !== 'signedOut';
    status.current = session.status;
    if (!settings.showSiteIcons || signedOut) void iconStore.clear();
  }, [settings.showSiteIcons, session.status, iconStore]);

  return <SiteIconsContext.Provider value={value}>{children}</SiteIconsContext.Provider>;
}

/**
 * An item's avatar: its website's icon when it has a URL and icons are on, the coloured initial
 * otherwise, while loading and when the site has none. Rows ask only once they scroll into view.
 */
export function ItemAvatar({ urls, ...props }: { urls?: readonly string[] } & Omit<AvatarProps, 'src' | 'ref'>) {
  const icons = useContext(SiteIconsContext);
  const domain = icons ? iconDomain(urls) : undefined;
  const [loaded, setLoaded] = useState<{ domain: string; url?: string }>();
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (!icons || !domain || icons.cached(domain)) return;
    let cancelled = false;
    const start = () => void icons.load(domain).then((url) => !cancelled && setLoaded({ domain, url }));
    const element = ref.current;
    if (!element || typeof IntersectionObserver === 'undefined') {
      start();
      return () => void (cancelled = true);
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (!entries.some((entry) => entry.isIntersecting)) return;
        observer.disconnect();
        start();
      },
      { rootMargin: '200px' },
    );
    observer.observe(element);
    return () => {
      cancelled = true;
      observer.disconnect();
    };
  }, [icons, domain]);

  const src = icons && domain ? (icons.cached(domain) ?? (loaded?.domain === domain ? loaded.url : undefined)) : undefined;
  return <Avatar ref={ref} {...props} src={src} />;
}
