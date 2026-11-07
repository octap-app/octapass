// Website icons end to end: the app tab asks the local octapass-server, which fetches from a test
// site (its names reach the test pages through OCTAPASS_DEV_ICON_HOSTS), keeps them on the device,
// and asks nothing once "Show website icons" is off. Its own profile and account.

import { expect, test, type Page } from '@playwright/test';
import { itemLink, launchExtension, openApp as open, SCREENSHOTS, signIn, testAccount, type Extension } from './helpers';

let extension: Extension;

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  extension = await launchExtension();
  await signIn(extension, testAccount('icons'));
});

test.afterAll(() => extension?.context.close());

/** The app tab's All items, counting the icon requests it makes to the server. */
async function allItems(): Promise<{ app: Page; requests: string[] }> {
  const app = await open(extension);
  const requests: string[] = [];
  app.on('request', (request) => {
    if (request.url().includes('/v1/icons/')) requests.push(new URL(request.url()).pathname);
  });
  await app.getByRole('link', { name: 'All items' }).click();
  await expect(app.getByRole('heading', { name: 'Logins 3 items', level: 2 })).toBeVisible();
  return { app, requests };
}

/** An item's row in All items, with its icon or initial. */
const row = (app: Page, title: string) => app.locator('li').filter({ has: itemLink(app, title) });

test('shows the site’s icon from the server, and the initial for the others', async () => {
  const { app, requests } = await allItems();
  await expect(row(app, 'Icon shop').locator('img')).toBeVisible();
  expect(await row(app, 'Icon shop').locator('img').getAttribute('src')).toMatch(/^data:image\/png;base64,/);
  // Re-encoded by the server, at the size it was linked with.
  expect(await row(app, 'Icon shop').locator('img').evaluate((img: HTMLImageElement) => img.naturalWidth)).toBe(64);
  await expect.poll(() => requests.length).toBe(2);
  expect(requests.sort()).toEqual(['/v1/icons/octapass-e2e.com', '/v1/icons/octapass-e2e.net']);
  await expect(row(app, 'Plain site').locator('img')).toHaveCount(0);
  await expect(row(app, 'Plain site')).toContainText('P');
  await expect(row(app, 'Home router').locator('img')).toHaveCount(0);
  await app.evaluate(() => document.fonts.ready);
  for (const scheme of ['light', 'dark'] as const) {
    await app.emulateMedia({ colorScheme: scheme });
    await app.screenshot({ path: `${SCREENSHOTS}app-site-icons-${scheme}.png` });
  }
  await app.close();
});

test('keeps icons on the device', async () => {
  const { app, requests } = await allItems();
  await expect(row(app, 'Icon shop').locator('img')).toBeVisible();
  await app.waitForTimeout(500);
  expect(requests).toEqual([]);
  await app.close();
});

test('asks for nothing with Show website icons off, and shows initials', async () => {
  const settings = await open(extension);
  await settings.getByRole('link', { name: 'Settings' }).click();
  const toggle = settings.getByRole('switch', { name: 'Show website icons' });
  await expect(toggle).toBeChecked();
  await expect(settings.getByText('Icons come through your Octa Pass server')).toBeVisible();
  await toggle.click();
  await expect(toggle).not.toBeChecked();
  await settings.close();

  const { app, requests } = await allItems();
  await expect(row(app, 'Icon shop')).toContainText('I');
  await app.waitForTimeout(800);
  await expect(row(app, 'Icon shop').locator('img')).toHaveCount(0);
  expect(requests).toEqual([]);
  // The service worker reads the same switch for the menu in web pages.
  expect(await extension.worker.evaluate(async () => (await chrome.storage.local.get('octapass:siteIcons'))['octapass:siteIcons'])).toBe(false);
  await app.close();
});
