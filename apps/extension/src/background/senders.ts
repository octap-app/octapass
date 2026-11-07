// Who is talking to the service worker. The browser fills in `sender`, so these checks hold even
// against a compromised page: web pages can't message us at all (no `externally_connectable`), and
// a content script always reports the page it runs in, never the extension's origin.

/** The extension's own pages: popup, side panel, tabs and the passkey prompt framed by a website. */
export function isExtensionPage(sender: chrome.runtime.MessageSender, runtimeId = chrome.runtime.id): boolean {
  if (sender.id !== runtimeId || !sender.url) return false;
  const base = chrome.runtime.getURL('/');
  return sender.url.startsWith(base) && (sender.origin === undefined || `${sender.origin}/` === base);
}

/** A content script in a web page, with the frame it runs in. */
export interface PageSender {
  tabId: number;
  frameId: number;
  /** The frame's URL. */
  url: string;
  origin: string;
  /** The top-level page's origin, which differs from `origin` in a cross-origin frame. */
  topOrigin: string | undefined;
}

export function pageSender(sender: chrome.runtime.MessageSender, runtimeId = chrome.runtime.id): PageSender | undefined {
  if (sender.id !== runtimeId || !sender.tab?.id || sender.frameId === undefined || !sender.url) return undefined;
  let url: URL;
  try {
    url = new URL(sender.url);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return undefined;
  const origin = url.origin;
  // Chrome also reports the origin on its own; a frame whose URL and origin disagree gets nothing.
  if (sender.origin !== undefined && sender.origin !== origin) return undefined;
  let topOrigin: string | undefined;
  try {
    topOrigin = sender.tab.url ? new URL(sender.tab.url).origin : undefined;
  } catch {
    topOrigin = undefined;
  }
  return { tabId: sender.tab.id, frameId: sender.frameId, url: sender.url, origin, topOrigin };
}
