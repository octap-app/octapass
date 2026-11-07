import type { VaultService } from '@octapass/vault-client';
import { useEffect, useState } from 'react';
import { useExtension } from './ExtensionContext';

export interface CurrentTab {
  id: number;
  /** Undefined for pages the extension may not read (browser pages, the web store). */
  url?: string;
}

interface TabLike {
  id?: number;
  url?: string;
  windowId: number;
  lastAccessed?: number;
}

/** The tab used most recently in the window other than the app's own. */
async function lastUsed(windowId: number, own: number | undefined): Promise<TabLike | undefined> {
  const tabs = (await chrome.tabs.query({ windowId })) as TabLike[];
  return tabs.filter((tab) => tab.id !== undefined && tab.id !== own).sort((a, b) => (b.lastAccessed ?? 0) - (a.lastAccessed ?? 0))[0];
}

/**
 * The page "This site" is for: the tab the app was opened from, then whichever tab the user goes to
 * in this window before coming back. The app tab itself is never it.
 */
export function useCurrentTab(): CurrentTab | undefined {
  const { tabId } = useExtension();
  const [tab, setTab] = useState<CurrentTab>();

  useEffect(() => {
    let live = true;
    let tracked: number | undefined;
    let own: { id?: number; windowId: number } | undefined;
    const show = (found: TabLike | undefined) => {
      if (!live || found?.id === undefined) return;
      tracked = found.id;
      setTab({ id: found.id, ...(found.url ? { url: found.url } : {}) });
    };
    const follow = async (id: number) => show(await chrome.tabs.get(id).catch(() => undefined));
    const start = async () => {
      own = await chrome.tabs.getCurrent?.().catch(() => undefined);
      if (tabId !== undefined && tabId !== own?.id && (await chrome.tabs.get(tabId).catch(() => undefined))) return follow(tabId);
      if (own) return show(await lastUsed(own.windowId, own.id));
      // Not in a tab (a test page): the active tab, as before.
      show((await chrome.tabs.query({ active: true, currentWindow: true }))[0]);
    };
    void start();

    const onActivated = ({ tabId: id, windowId }: { tabId: number; windowId: number }) => {
      if (id === own?.id || (own && windowId !== own.windowId)) return;
      void follow(id);
    };
    const onUpdated = (id: number, change: { url?: string }) => {
      if (id === tracked && change.url) void follow(id);
    };
    const onRemoved = (id: number) => {
      if (id === tracked && own) void lastUsed(own.windowId, own.id).then(show);
    };
    chrome.tabs.onActivated?.addListener(onActivated);
    chrome.tabs.onUpdated?.addListener(onUpdated);
    chrome.tabs.onRemoved?.addListener(onRemoved);
    return () => {
      live = false;
      chrome.tabs.onActivated?.removeListener(onActivated);
      chrome.tabs.onUpdated?.removeListener(onUpdated);
      chrome.tabs.onRemoved?.removeListener(onRemoved);
    };
  }, [tabId]);

  return tab;
}

/** Brings a tab (and its window) to the front: after a fill, the user goes back to the page. */
export async function showTab(id: number): Promise<void> {
  const tab = await chrome.tabs.update(id, { active: true });
  if (tab?.windowId !== undefined) await chrome.windows?.update(tab.windowId, { focused: true }).catch(() => undefined);
}

/**
 * Reads the QR codes on the page the user was on. The browser only captures the visible tab, so
 * that page comes to the front for the screenshot and the app tab comes back after it.
 */
export async function captureFromPage(scan: (tabId: number) => Promise<string[]>): Promise<string[]> {
  const own = await chrome.tabs.getCurrent().catch(() => undefined);
  const page = own ? await lastUsed(own.windowId, own.id) : undefined;
  if (!own?.id || page?.id === undefined) return [];
  await chrome.tabs.update(page.id, { active: true });
  try {
    // Long enough for the browser to draw it.
    await new Promise((resolve) => setTimeout(resolve, 250));
    return await scan(page.id).catch(() => []);
  } finally {
    await chrome.tabs.update(own.id, { active: true }).catch(() => undefined);
  }
}

/** The inline menu's "Unlock" opened the app: once the vault is open, back to that page. */
export function returnAfterUnlock(service: Pick<VaultService, 'getSession' | 'onSessionChange'>, tabId: number): void {
  if (service.getSession().status === 'unlocked') return;
  const stop = service.onSessionChange((session) => {
    if (session.status !== 'unlocked') return;
    stop();
    void showTab(tabId).catch(() => undefined);
  });
}
