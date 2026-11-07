// Local mode end to end: a vault on this device only, filled and backed up, then moved into a new
// account with Turn on sync. Its own browser profile, steps in order.

import { expect, test, type Page } from '@playwright/test';
import { itemLink, launchExtension, openApp as open, pagesPort as port, pickFirstSuggestion, SCREENSHOTS, shareScreenshot, WORKER_WAIT, type Extension } from './helpers';

const LOCAL_PASSWORD = 'Marble kettle orchid lantern 1987 quietly';
const ACCOUNT_PASSWORD = 'Lantern ruby quiet anchor 42';

let extension: Extension;

// Steps that go through the inline menu or a save prompt wait for the service worker (helpers.ts).
test.describe.configure({ mode: 'serial', timeout: 240_000 });

test.beforeAll(async () => {
  extension = await launchExtension();
});

test.afterAll(() => extension?.context.close());

const openApp = (query = ''): Promise<Page> => open(extension, { query });

test('keeps a vault on this device only', async () => {
  const app = await openApp();
  await expect(app.getByRole('heading', { name: 'Welcome to Octa Pass' })).toBeVisible();
  await app.screenshot({ path: `${SCREENSHOTS}welcome-light.png` });
  await app.getByRole('button', { name: 'Use on this device only' }).click();
  await app.getByLabel('Master password', { exact: true }).fill(LOCAL_PASSWORD);
  await app.getByLabel('Confirm master password').fill(LOCAL_PASSWORD);
  await app.getByRole('button', { name: 'Create vault' }).click();
  await expect(app.getByRole('heading', { name: 'Write down your backup recovery code' })).toBeVisible({ timeout: 30_000 });
  await app.getByRole('checkbox', { name: /written it down/ }).check();
  await app.getByRole('button', { name: 'Open my vault' }).click();
  await expect(app.getByText('This device')).toBeVisible();
  await app.close();
});

test('saves a sign-up with a suggested password into the local vault', async () => {
  const page = await extension.context.newPage();
  await page.goto(`http://join.localsite.test:${port()}/signup.html`);
  await page.locator('#email').fill('maya@localsite.test');
  await pickFirstSuggestion(page, '#new');
  await expect(page.locator('#confirm')).not.toHaveValue('', { timeout: WORKER_WAIT });
  const app = await openApp();
  await app.getByRole('link', { name: 'All items' }).click();
  await expect(itemLink(app, 'join.localsite.test')).toBeVisible();
  await app.close();
  await page.close();
});

test('adds a one-time code from a page’s QR code, then moves it into a login', async () => {
  const page = await extension.context.newPage();
  await page.goto(`http://join.localsite.test:${port()}/two-step.html`);
  const tabId = await extension.worker.evaluate(async (url) => (await chrome.tabs.query({ url }))[0]?.id, page.url());
  const app = await openApp(`?tab=${tabId}`);
  await shareScreenshot(extension, page);
  await app.getByRole('button', { name: 'Scan QR code on this page' }).click();
  const scan = app.getByRole('dialog', { name: 'Add one-time codes from a QR code' });
  // The scan opens on a screenshot of the page, taken right away (the page comes to the front for a
  // moment) and read by the core in the service worker: on a busy machine, that has taken a minute.
  await expect(scan.getByText('GitHub (octo)')).toBeVisible({ timeout: 90_000 });
  await scan.getByRole('button', { name: 'Continue' }).click();
  const review = app.getByRole('dialog', { name: 'Choose where each code goes' });
  await expect(review.getByText('Keep as a separate item')).toBeVisible();
  await review.getByRole('button', { name: 'Save 1 item' }).click();
  await expect(review).toBeHidden();

  // The code is an item of its own: Link to a login moves it into the sign-up's login.
  await app.getByRole('link', { name: 'All items' }).click();
  await itemLink(app, 'GitHub').click();
  await app.getByRole('button', { name: 'Link to a login' }).click();
  const link = app.getByRole('dialog', { name: 'Move this code to a login' });
  await link.getByRole('searchbox').fill('localsite');
  await link.getByRole('radio', { name: /^join\.localsite\.test/ }).check();
  await link.getByRole('button', { name: 'Link to a login' }).click();
  await expect(app.getByRole('heading', { name: 'join.localsite.test' })).toBeVisible();
  await expect(app.getByText('One-time code', { exact: true })).toBeVisible();
  await app.close();
  await page.close();
});

test('backs up, locks and unlocks with the local master password', async () => {
  const app = await openApp();
  await app.getByRole('link', { name: 'Settings' }).click();
  const download = app.waitForEvent('download');
  await app.getByRole('button', { name: 'Back up now' }).click();
  // A backup is an export: it asks for the master password every time (plan 03).
  const gate = app.getByRole('dialog', { name: 'Confirm it’s you' });
  await gate.getByLabel('Master password').fill(LOCAL_PASSWORD);
  await gate.getByRole('button', { name: 'Confirm' }).click();
  expect((await download).suggestedFilename()).toMatch(/\.octapass-backup$/);
  await expect(app.getByText(/Last backup/)).toBeVisible();

  await app.getByRole('navigation', { name: 'Vault' }).getByRole('button', { name: 'Lock now' }).click();
  await expect(app.getByText('On this device only')).toBeVisible();
  await app.getByLabel('Master password').fill(LOCAL_PASSWORD);
  await app.getByRole('button', { name: 'Unlock' }).click();
  await expect(app.getByText('This device')).toBeVisible({ timeout: 30_000 });
  await app.close();
});

test('turns on sync, keeping every item', async () => {
  const tab = await openApp('?view=tab&path=/local/sync');
  await tab.getByRole('textbox', { name: 'Email' }).fill(`local-${Date.now()}@example.com`);
  await tab.getByLabel('Master password', { exact: true }).fill(ACCOUNT_PASSWORD);
  await tab.getByLabel('Confirm master password').fill(ACCOUNT_PASSWORD);
  await tab.getByRole('button', { name: 'Continue' }).click();
  const devCode = (await tab.locator('strong.mono').textContent({ timeout: 30_000 }))!;
  await tab.getByRole('textbox', { name: 'Verification code' }).fill(devCode);
  await tab.getByRole('button', { name: 'Verify email' }).click();
  await expect(tab.getByRole('heading', { name: 'Sync is on' })).toBeVisible({ timeout: 30_000 });
  await tab.getByRole('checkbox').check();
  await tab.getByRole('button', { name: 'Continue' }).click();
  await tab.close();

  const app = await openApp();
  await app.getByRole('link', { name: 'All items' }).click();
  await expect(itemLink(app, 'join.localsite.test')).toBeVisible();
  await app.getByRole('link', { name: 'Settings' }).click();
  await expect(app.getByRole('button', { name: 'Sign out' })).toBeVisible();
  await app.close();
});
