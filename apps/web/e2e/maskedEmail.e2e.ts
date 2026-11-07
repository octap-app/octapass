// Masked email and the recovery map in Chrome, on the real WASM core and the real server. The
// provider is a Playwright route standing in for SimpleLogin, so nothing reaches the real service;
// it answers CORS as SimpleLogin does. The token must reach the provider and never the server.
//
//   pnpm --filter @octapass/web e2e          (HEADED=1 to watch)

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { BrowserContext, Page, Request } from 'playwright-core';
import { startStack, type Stack } from './stack';

const PASSWORD = 'Lantern ruby quiet anchor 42';
const EMAIL = `masked-${Date.now()}@example.com`;
const TOKEN = 'sl-token-pumpkin-lighthouse-2290';
const ALIAS = 'quokka.w7r3@simplelogin.com';

let stack: Stack;
let context: BrowserContext;
let page: Page;
const pageErrors: string[] = [];
const providerCalls: Request[] = [];

const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authentication, content-type, accept', 'access-control-allow-methods': 'POST' };

beforeAll(async () => {
  stack = await startStack();
  context = await stack.browser.newContext({ viewport: { width: 1440, height: 900 } });
  context.on('weberror', (error) => pageErrors.push(error.error().message));
  await context.route('https://app.simplelogin.io/**', async (route) => {
    if (route.request().method() === 'OPTIONS') return route.fulfill({ status: 204, headers: CORS });
    providerCalls.push(route.request());
    const ok = route.request().headers().authentication === TOKEN;
    await route.fulfill({ status: ok ? 201 : 401, headers: { ...CORS, 'content-type': 'application/json' }, body: JSON.stringify(ok ? { alias: ALIAS, id: 77 } : { error: 'Wrong api key' }) });
  });
  // Firefox Relay doesn't answer CORS; the web vault must not even try.
  await context.route('https://relay.firefox.com/**', (route) => {
    providerCalls.push(route.request());
    return route.abort();
  });
  page = await context.newPage();
});

afterAll(async () => {
  await stack?.stop();
});

afterEach(() => {
  expect(pageErrors, 'uncaught errors in the page').toEqual([]);
});

function serverFiles(): Buffer {
  const files = readdirSync(stack.server.dataDir, { recursive: true, withFileTypes: true }).filter((entry) => entry.isFile());
  return Buffer.concat(files.map((entry) => readFileSync(join(entry.parentPath, entry.name))));
}

describe('masked email on the real server', () => {
  it('signs up', async () => {
    await page.goto(`${stack.webUrl}/signup`);
    await page.getByRole('textbox', { name: 'Email' }).fill(EMAIL);
    await page.getByRole('textbox', { name: 'Master password', exact: true }).fill(PASSWORD);
    await page.getByRole('textbox', { name: 'Confirm master password' }).fill(PASSWORD);
    await page.getByRole('button', { name: 'Continue' }).click();
    const code = (await page.getByRole('status').filter({ hasText: 'Development server' }).locator('strong').innerText()).trim();
    await page.getByRole('textbox', { name: 'Verification code' }).fill(code);
    await page.getByRole('button', { name: 'Verify email' }).click();
    await page.getByRole('checkbox', { name: /saved my Recovery Kit/ }).check();
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByRole('button', { name: 'Open my vault' }).click();
    await page.getByRole('heading', { name: 'Nothing here yet' }).waitFor();
  });

  it('explains that Firefox Relay only works in the extension and apps', async () => {
    await page.getByRole('link', { name: 'Masked email' }).click();
    const form = page.getByRole('form', { name: 'Connect a provider' });
    await form.getByLabel('Provider').selectOption('firefoxRelay');
    await form.getByText('Firefox Relay doesn’t allow calls from web pages', { exact: false }).waitFor();
  });

  it('connects SimpleLogin; the server only ever holds the token encrypted', async () => {
    const form = page.getByRole('form', { name: 'Connect a provider' });
    await form.getByLabel('Provider').selectOption('simplelogin');
    await form.getByLabel('API token').fill(TOKEN);
    await form.getByRole('button', { name: 'Connect' }).click();
    await page.getByRole('region', { name: 'Providers' }).getByRole('button', { name: 'Disconnect' }).waitFor();
    // Synced: wait for the item to reach the server, then look at every byte it keeps.
    await expect.poll(() => serverFiles().length).toBeGreaterThan(0);
    await page.waitForTimeout(1000);
    expect(serverFiles().includes(TOKEN)).toBe(false);
    expect(providerCalls).toEqual([]);
  });

  it('uses a masked email for a new login, straight from the browser to the provider', async () => {
    await page.getByRole('link', { name: 'All items' }).click();
    await page.getByRole('button', { name: 'New item' }).click();
    await page.getByRole('menuitem', { name: 'Login' }).click();
    await page.getByRole('textbox', { name: 'Title' }).fill('Quokka Shop');
    await page.getByRole('textbox', { name: 'Website' }).fill('https://www.quokka-shop.example/join');
    await page.getByRole('button', { name: 'Use a masked email' }).first().click();
    await expect.poll(() => page.getByRole('textbox', { name: 'Username' }).inputValue()).toBe(ALIAS);
    expect(await page.getByRole('textbox', { name: 'Recovery email' }).inputValue()).toBe(ALIAS);

    expect(providerCalls.map((r) => r.url())).toEqual(['https://app.simplelogin.io/api/alias/random/new?hostname=quokka-shop.example']);
    const headers = providerCalls[0]!.headers();
    expect(headers.authentication).toBe(TOKEN);
    expect(headers.cookie).toBeUndefined();
    expect(headers.referer).toBeUndefined();

    await page.getByRole('button', { name: 'Save' }).click();
    await page.getByRole('heading', { name: 'Quokka Shop' }).waitFor();
    await page.getByText('Masked email from SimpleLogin').waitFor();
    expect(serverFiles().includes(ALIAS)).toBe(false);
  });

  it('lists the alias with its login, and maps what it can reset', async () => {
    await page.getByRole('link', { name: 'Masked email' }).click();
    const aliases = page.getByRole('region', { name: 'Aliases in use' });
    await aliases.getByText(ALIAS).waitFor();
    await aliases.getByRole('link', { name: 'Quokka Shop' }).waitFor();

    // Reloading would lock the vault, so this goes through the app: Health, then the map.
    await page.getByRole('link', { name: /Health/ }).click();
    await page.getByRole('link', { name: /^Recovery map/ }).click();
    const contact = page.getByRole('region', { name: ALIAS });
    await contact.getByRole('heading', { name: `1 account can be reset through ${ALIAS}` }).waitFor();
    await contact.getByText('Masked email from SimpleLogin').waitFor();
  });
});
