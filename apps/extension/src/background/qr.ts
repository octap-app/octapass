// QR codes for one-time codes, read here in the worker with the core: a screenshot of the page in a
// tab (the popup's "Scan QR code on this page"), and an image on a page (its context menu). Nothing
// is sent or downloaded. Capturing a tab needs `activeTab` (granted by the toolbar click or the menu
// click) or host access to the page, which the extension has for http and https pages.

/** The core's reader. */
export type QrReader = (image: Uint8Array) => string[];

export interface TabCapture {
  captureVisibleTab(windowId: number, options: { format: 'png' }): Promise<string>;
  get(tabId: number): Promise<{ windowId: number; active: boolean }>;
}

/** The QR codes in what a tab shows right now. The tab must be the active one in its window. */
export async function scanTab(tabs: TabCapture, read: QrReader, tabId: number): Promise<string[]> {
  const tab = await tabs.get(tabId);
  if (!tab.active) return [];
  return read(dataUrlBytes(await tabs.captureVisibleTab(tab.windowId, { format: 'png' })));
}

export function dataUrlBytes(dataUrl: string): Uint8Array {
  const base64 = dataUrl.slice(dataUrl.indexOf(',') + 1);
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

/**
 * The QR codes in an image from a page's context menu. A `data:` image is read as it is; any other
 * is read from a screenshot of the tab (the image is on screen, since the user just clicked it), so
 * nothing is downloaded again: some sites put the setup secret in the image's address.
 */
export async function scanImage(tabs: TabCapture, read: QrReader, srcUrl: string | undefined, tabId: number | undefined): Promise<string[]> {
  if (srcUrl?.startsWith('data:image/')) {
    try {
      const found = read(dataUrlBytes(srcUrl));
      if (found.length > 0) return found;
    } catch {
      // An image format the core doesn't read (SVG): try the screenshot.
    }
  }
  return tabId === undefined ? [] : scanTab(tabs, read, tabId);
}

/**
 * The latest image scan from the context menu, until the popup takes it. Kept in memory: the popup
 * opens right after the click, while the worker is surely still running.
 */
export class PendingScans {
  private latest: Promise<string[]> | undefined;

  start(scan: Promise<string[]>): void {
    this.latest = scan.catch(() => []);
  }

  has(): boolean {
    return this.latest !== undefined;
  }

  async take(): Promise<string[] | undefined> {
    const latest = this.latest;
    this.latest = undefined;
    return latest;
  }
}
