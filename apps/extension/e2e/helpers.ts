import { chromium, expect, type BrowserContext, type CDPSession, type Frame, type Locator, type Page, type Worker } from '@playwright/test';
import { PASSWORD } from './data';

const DIST = new URL('../dist/chrome', import.meta.url).pathname;
export const SCREENSHOTS = new URL('../screenshots/', import.meta.url).pathname;
export const pagesPort = () => process.env.E2E_PAGES_PORT!;

export interface Extension {
  context: BrowserContext;
  worker: Worker;
  url: string;
}

/** A fresh browser profile with the unpacked build loaded; *.test hosts point at the test pages. */
export async function launchExtension({ dist = DIST } = {}): Promise<Extension> {
  const context = await chromium.launchPersistentContext('', {
    channel: 'chromium',
    headless: process.env.HEADED !== '1',
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`, '--host-resolver-rules=MAP *.test 127.0.0.1'],
  });
  const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'));
  return { context, worker, url: new URL('/', worker.url()).href };
}

/** The app tab; with `tabOf`, "This site" is for that tab, as when opened from the toolbar there. */
export async function openApp({ context, worker, url }: Extension, options: { tabOf?: Page; query?: string } = {}): Promise<Page> {
  const app = await context.newPage();
  // Wide enough for the sidebar, which is a drawer on small screens.
  await app.setViewportSize({ width: 1280, height: 800 });
  const tabId = options.tabOf ? await worker.evaluate(async (pageUrl) => (await chrome.tabs.query({ url: pageUrl }))[0]?.id, options.tabOf.url()) : undefined;
  await app.goto(`${url}app.html${options.query ?? (tabId ? `?tab=${tabId}` : '')}`);
  return app;
}

/** A spec's own test account (global-setup.ts): `main`, `corpus`, `masked` or `icons`. */
export function testAccount(name: 'main' | 'corpus' | 'masked' | 'icons' = 'main'): { email: string; secretKey: string } {
  const prefix = name === 'main' ? 'E2E' : `E2E_${name.toUpperCase()}`;
  return { email: process.env[`${prefix}_EMAIL`]!, secretKey: process.env[`${prefix}_SECRET_KEY`]! };
}

/** Signs in to a test account from the app tab, as on a new device. */
export async function signIn(extension: Extension, account = testAccount()): Promise<void> {
  const app = await openApp(extension);
  await app.getByRole('button', { name: 'Sign in' }).click();
  await app.getByRole('textbox', { name: 'Email' }).fill(account.email);
  await app.getByRole('textbox', { name: 'Master password' }).fill(PASSWORD);
  await app.getByRole('textbox', { name: 'Secret Key' }).fill(account.secretKey);
  await app.getByRole('button', { name: 'Sign in' }).click();
  await expect(app.getByText(account.email)).toBeVisible();
  // The one-time suggestion to replace the browser's password manager.
  await app.getByRole('button', { name: 'Not now' }).click();
  await app.close();
}

/**
 * An item's row in the app tab's lists (the web vault's): a link with the item's id, named by its
 * title first. "This site" has buttons instead, with Fill beside them.
 */
export function itemLink(app: Page, title: string | RegExp): Locator {
  const name = typeof title === 'string' ? new RegExp(`^${title.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`) : title;
  return app.getByRole('link', { name }).and(app.locator('a[data-item-id]'));
}

/**
 * Makes the worker's tab screenshot return what `page` shows. Playwright can't give the extension
 * `activeTab` (that takes a click on the toolbar button or a context menu), which the real capture
 * needs; the screenshot itself is the page as Chromium drew it, read by the core in the worker.
 */
export async function shareScreenshot({ worker }: Extension, page: Page): Promise<void> {
  const dataUrl = `data:image/png;base64,${(await page.screenshot()).toString('base64')}`;
  await worker.evaluate((url) => {
    chrome.tabs.captureVisibleTab = (async () => url) as unknown as typeof chrome.tabs.captureVisibleTab;
  }, dataUrl);
  await page.bringToFront();
}

interface DomNode {
  backendNodeId: number;
  localName?: string;
  nodeValue?: string;
  children?: DomNode[];
  shadowRoots?: DomNode[];
}

function* walk(node: DomNode): Generator<DomNode> {
  yield node;
  for (const child of [...(node.shadowRoots ?? []), ...(node.children ?? [])]) yield* walk(child);
}

/** The text people see: everything but the notice's stylesheet. */
function textOf(node: DomNode): string {
  if (node.localName === 'style') return '';
  return [node.nodeValue ?? '', ...[...(node.shadowRoots ?? []), ...(node.children ?? [])].map(textOf)].join('').trim();
}

/** Octa Pass's in-page notices (save prompts), read through the DevTools protocol: their shadow root is closed. */
async function notices(cdp: CDPSession): Promise<DomNode[]> {
  const { root } = (await cdp.send('DOM.getDocument', { depth: -1, pierce: true })) as { root: DomNode };
  return [...walk(root)].filter((n) => n.localName === 'octapass-notice');
}

/** The text of the notice showing in the page, or '' when there's none. */
export async function noticeText(page: Page): Promise<string> {
  const cdp = await page.context().newCDPSession(page);
  try {
    return (await notices(cdp)).map(textOf).join(' ');
  } finally {
    await cdp.detach();
  }
}

/** Clicks a button (or a checkbox's label) in the notice, as a real click at its position. */
export async function clickInNotice(page: Page, label: string): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  try {
    let target: DomNode | undefined;
    await expect
      .poll(async () => {
        target = (await notices(cdp)).flatMap((n) => [...walk(n)]).find((n) => (n.localName === 'button' || n.localName === 'label') && textOf(n) === label);
        return target !== undefined;
      }, { timeout: WORKER_WAIT })
      .toBe(true);
    const { model } = (await cdp.send('DOM.getBoxModel', { backendNodeId: target!.backendNodeId })) as { model: { border: number[] } };
    const [x1, y1, , , x3, y3] = model.border as [number, number, number, number, number, number];
    await page.mouse.click((x1 + x3) / 2, (y1 + y3) / 2);
  } finally {
    await cdp.detach();
  }
}

/**
 * How long a step waits for the service worker's answer to a page (a menu, a fill, a save prompt).
 * On a busy machine, while none of the extension's pages is in front, an answer has taken 20 s.
 */
export const WORKER_WAIT = 45_000;

/** Whether one of Octa Pass's elements (`octapass-menu`, `octapass-icon`) shows up in `target` within `timeout` ms. */
export function shows(target: Page | Frame, tag: string, timeout = WORKER_WAIT): Promise<boolean> {
  return target.waitForFunction((tag) => document.querySelector(tag) !== null, tag, { timeout }).then(
    () => true,
    () => false,
  );
}

/**
 * Clicks a field and waits for the inline menu (its host element is in the field's document while
 * it's open; its shadow root is closed). Says whether it opened within `timeout` ms.
 */
export async function openMenu(page: Page, field: string, { frame, timeout = WORKER_WAIT }: { frame?: Frame; timeout?: number } = {}): Promise<boolean> {
  const target = frame ?? page;
  await target.locator(field).click();
  // The field's icon shows once the content script's engine runs and has the field.
  await shows(target, 'octapass-icon, octapass-menu', timeout);
  if (await shows(target, 'octapass-menu', Math.min(timeout, 5000))) return true;
  // A click before the engine started opens nothing: the user clicks again. One while the first
  // click's answer is on its way waits for that same answer.
  await target.locator(field).click();
  return shows(target, 'octapass-menu', timeout);
}

/**
 * Picks the open menu's first entry from the keyboard: ArrowDown moves into the menu, unless a key
 * press opened it (`focused`), which focuses its first entry already.
 */
export async function pickFirst(page: Page, { focused = false } = {}): Promise<void> {
  if (!focused) await page.keyboard.press('ArrowDown');
  // The engine ignores picks in the first 250 ms after the menu appears.
  await page.waitForTimeout(400);
  await page.keyboard.press('Enter');
}

/**
 * Opens the inline menu on a field and picks its first entry. Where no menu should open (a
 * look-alike site), pass a short `timeout`: the keys then press on nothing.
 */
export async function pickFirstSuggestion(page: Page, field: string, options: { timeout?: number } = {}): Promise<void> {
  await openMenu(page, field, options);
  await pickFirst(page);
}
