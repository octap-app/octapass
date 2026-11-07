// HTTP sign-in prompts end to end: router.test answers 401 with `WWW-Authenticate: Basic` (see
// global-setup.ts). A login saved with its realm in the editor fills the prompt after the user
// picks it in Octa Pass's window, never for the site framed by another one, and never for another
// realm. A vault on this device only, so no account is needed. Its own browser profile, in order.

import { expect, test, type Page } from '@playwright/test';
import { ROUTER } from './data';
import { launchExtension, openApp as open, pagesPort as port, type Extension } from './helpers';

const LOCAL_PASSWORD = 'Copper willow banjo meadow 2031 softly';

let extension: Extension;

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  extension = await launchExtension();
});

test.afterAll(() => extension?.context.close());

const openApp = (query = ''): Promise<Page> => open(extension, { query });
const router = (path = '') => `http://router.test:${port()}/${path}`;
const promptWindows = () => extension.context.pages().filter((page) => page.url().includes('http-auth'));
/**
 * Loads a page whose sign-in prompt Octa Pass must leave alone. The browser's own dialog blocks the
 * frame, so DevTools cancels the challenge (as a user pressing Escape does) and records the status.
 */
async function loadUnanswered(page: Page, url: string, watch = url): Promise<number[]> {
  const cdp = await page.context().newCDPSession(page);
  const statuses: number[] = [];
  await cdp.send('Network.enable');
  cdp.on('Network.responseReceived', ({ response }) => {
    if (response.url === watch) statuses.push(response.status);
  });
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: `http://router.test:${port()}/*` }], handleAuthRequests: true });
  cdp.on('Fetch.requestPaused', (event) => void cdp.send('Fetch.continueRequest', { requestId: event.requestId }).catch(() => {}));
  cdp.on('Fetch.authRequired', (event) => void cdp.send('Fetch.continueWithAuth', { requestId: event.requestId, authChallengeResponse: { response: 'CancelAuth' } }).catch(() => {}));
  await page.goto(url).catch(() => {});
  return statuses;
}

test('saves a login with its HTTP realm', async () => {
  const app = await openApp();
  await app.getByRole('button', { name: 'Use on this device only' }).click();
  await app.getByLabel('Master password', { exact: true }).fill(LOCAL_PASSWORD);
  await app.getByLabel('Confirm master password').fill(LOCAL_PASSWORD);
  await app.getByRole('button', { name: 'Create vault' }).click();
  await expect(app.getByRole('heading', { name: 'Write down your backup recovery code' })).toBeVisible({ timeout: 30_000 });
  await app.getByRole('checkbox', { name: /written it down/ }).check();
  await app.getByRole('button', { name: 'Open my vault' }).click();
  await expect(app.getByText('This device')).toBeVisible();
  await app.close();

  const editor = await openApp(`?path=${encodeURIComponent('/items/all/new?type=login')}`);
  await editor.getByRole('textbox', { name: 'Title' }).fill('Home router');
  await editor.getByRole('textbox', { name: 'Username' }).fill(ROUTER.username);
  await editor.getByRole('textbox', { name: 'Password', exact: true }).fill(ROUTER.password);
  await editor.getByRole('textbox', { name: 'HTTP realm' }).fill(ROUTER.realm);
  await editor.getByRole('textbox', { name: 'Website' }).first().fill(router());
  await editor.getByRole('button', { name: 'Save' }).click();
  await expect(editor.getByRole('heading', { name: 'Home router' })).toBeVisible();
  await expect(editor.getByText(ROUTER.realm)).toBeVisible();
  await editor.close();
});

test('never answers the site inside another site’s page', async () => {
  const page = await extension.context.newPage();
  const statuses = await loadUnanswered(page, `http://elsewhere.test:${port()}/frames-router.html`, router('framed'));
  await expect(page.frameLocator('#router').getByRole('heading', { name: 'Locked' })).toBeVisible();
  expect(promptWindows()).toHaveLength(0);
  expect(statuses).toContain(401);
  expect(statuses).not.toContain(200);
  await page.close();
});

test('asks once, then fills the sign-in prompt with the login picked', async () => {
  const page = await extension.context.newPage();
  const prompt = extension.context.waitForEvent('page', (opened) => opened.url().includes('http-auth'));
  const loading = page.goto(router('admin'));
  const window = await prompt;
  await expect(window.getByRole('heading', { name: `Sign in to router.test:${port()}?` })).toBeVisible();
  await expect(window.getByText(`for “${ROUTER.realm}”`, { exact: false })).toBeVisible();
  // Plain http: the window says so.
  await expect(window.getByText(/isn’t encrypted/)).toBeVisible();
  const closed = window.waitForEvent('close');
  await window.getByRole('button', { name: /Home router/ }).click();
  await closed;
  await loading;
  await expect(page.getByRole('heading', { name: 'Signed in to the router' })).toBeVisible();
  await page.close();

  const settings = await openApp(`?path=${encodeURIComponent('/settings')}`);
  const section = settings.getByRole('region', { name: 'HTTP sign-in prompts' });
  await expect(section.getByText(`router.test:${port()}`)).toBeVisible();
  await settings.close();
});

test('leaves a prompt for another realm to the browser', async () => {
  const page = await extension.context.newPage();
  const statuses = await loadUnanswered(page, router('other-realm'));
  await expect(page.getByRole('heading', { name: 'Locked' })).toBeVisible();
  expect(promptWindows()).toHaveLength(0);
  expect(statuses).toContain(401);
  expect(statuses).not.toContain(200);
  await page.close();
});
