// The toolbar button has no popup: it opens the app page in a tab, or brings back the one that's
// already open. The page then follows the user's other tabs for "This site" (popup/useCurrentTab.ts).

export const APP_PAGE = 'app.html';

export interface OpenAppOptions {
  /** The tab the user was on: "This site" starts with its page, and the app tab opens next to it. */
  from?: number;
  /** Where to open, such as `/scan`; an open app tab goes there too. */
  path?: string;
  /** Go back to `from` once the vault is unlocked (the inline menu's "Unlock"). */
  back?: boolean;
}

interface TabInfo {
  id?: number;
  index: number;
  windowId: number;
}

export interface AppTabApis {
  getURL(path: string): string;
  tabs: {
    get(tabId: number): Promise<TabInfo>;
    create(properties: { url: string; active: boolean; windowId?: number; index?: number; openerTabId?: number }): Promise<unknown>;
    update(tabId: number, properties: { active: boolean; url?: string }): Promise<unknown>;
  };
  focusWindow(windowId: number): Promise<unknown>;
  /** The app page's open tabs, not the prompt windows (`view=window`). */
  appTabs(): Promise<{ tabId: number; windowId: number }[]>;
}

export function appUrl(getURL: (path: string) => string, { from, path, back }: OpenAppOptions = {}): string {
  const params = new URLSearchParams();
  if (from !== undefined) params.set('tab', String(from));
  if (path) params.set('path', path);
  if (back && from !== undefined) params.set('back', '1');
  const query = params.toString();
  return getURL(query ? `${APP_PAGE}?${query}` : APP_PAGE);
}

/** Whether a URL is the app page in a tab (prompt windows load the same page with `view=window`). */
export function isAppTabUrl(getURL: (path: string) => string, url: string | undefined): boolean {
  if (!url?.startsWith(getURL(APP_PAGE))) return false;
  return new URL(url).searchParams.get('view') !== 'window';
}

export async function openApp(apis: AppTabApis, options: OpenAppOptions = {}): Promise<void> {
  const source = options.from !== undefined ? await apis.tabs.get(options.from).catch(() => undefined) : undefined;
  const open = await apis.appTabs().catch(() => []);
  // The button clicked on the app tab itself.
  if (source?.id !== undefined && open.some((tab) => tab.tabId === source.id)) return;
  // One in the window the user is in, else any.
  const existing = open.find((tab) => tab.windowId === source?.windowId) ?? open[0];
  if (existing) {
    // A plain click keeps the tab where it is; a path (a scan, an unlock to go back from) reloads it there.
    await apis.tabs.update(existing.tabId, { active: true, ...(options.path || options.back ? { url: appUrl(apis.getURL, options) } : {}) });
    await apis.focusWindow(existing.windowId).catch(() => undefined);
    return;
  }
  await apis.tabs.create({
    url: appUrl(apis.getURL, options),
    active: true,
    ...(source?.id !== undefined ? { windowId: source.windowId, index: source.index + 1, openerTabId: source.id } : {}),
  });
}

type GetContexts = (filter: { contextTypes: string[] }) => Promise<{ tabId: number; windowId: number; documentUrl?: string }[]>;

/** The browser's APIs. `runtime.getContexts` where there is one; else the tabs whose URL is ours. */
export function chromeAppTabApis(): AppTabApis {
  const getURL = (path: string) => chrome.runtime.getURL(path);
  const getContexts = (chrome.runtime as unknown as { getContexts?: GetContexts }).getContexts;
  return {
    getURL,
    tabs: {
      get: (tabId) => chrome.tabs.get(tabId),
      create: (properties) => chrome.tabs.create(properties),
      update: (tabId, properties) => chrome.tabs.update(tabId, properties),
    },
    focusWindow: (windowId) => chrome.windows?.update(windowId, { focused: true }) ?? Promise.resolve(),
    appTabs: async () => {
      if (getContexts) {
        const contexts = await getContexts({ contextTypes: ['TAB'] });
        return contexts.filter((c) => c.tabId >= 0 && isAppTabUrl(getURL, c.documentUrl)).map(({ tabId, windowId }) => ({ tabId, windowId }));
      }
      const tabs = await chrome.tabs.query({ url: `${getURL(APP_PAGE)}*` });
      return tabs.filter((tab) => tab.id !== undefined && isAppTabUrl(getURL, tab.url)).map((tab) => ({ tabId: tab.id!, windowId: tab.windowId }));
    },
  };
}
