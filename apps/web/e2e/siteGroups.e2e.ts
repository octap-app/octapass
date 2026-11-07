// Logins for the same website as one row, on the real server in Chrome: three accounts on one host
// share a row inside Logins, other subdomains stay apart, the row opens in place from the mouse and
// the keyboard, search lists every login, and the same in Arabic on a phone-sized screen.
// Screenshots with a site row open go to screenshots/.
//
//   pnpm --filter @octapass/web e2e siteGroups          (HEADED=1 to watch)

import { mkdirSync } from 'node:fs';
import type { BrowserContext, Page } from 'playwright-core';
import { startStack, type Stack } from './stack';

const SCREENSHOTS = new URL('../screenshots/', import.meta.url).pathname;
const PASSWORD = 'Lantern ruby quiet anchor 42';
const EMAIL = `sites-${Date.now()}@example.com`;

const login = (name: string, username: string, uri: string) => ({ type: 1, name, login: { username, password: 'x', uris: [{ uri }] } });
const BITWARDEN = JSON.stringify({
  encrypted: false,
  items: [
    login('Work', 'maya@work.example', 'https://a.xxx.com/login'),
    login('Personal', 'maya.orchid', 'https://www.a.xxx.com'),
    login('Shared inbox', 'team@work.example', 'a.xxx.com'),
    login('Billing', 'maya', 'https://b.xxx.com'),
    login('GitHub', 'maya-orchid', 'https://github.com'),
    login('GitHub (bot)', 'orchid-bot', 'https://github.com/login'),
    login('Netflix', 'maya', 'https://netflix.com'),
    login('Zoom', 'maya', 'https://zoom.us'),
    login('بنك الخليج', 'maya', 'https://gulf-bank.example'),
    { type: 3, name: 'Visa Platinum', card: { cardholderName: 'Maya Orchid', number: '4111111111111111', brand: 'Visa' } },
    { type: 2, name: 'Wi-Fi at home', notes: 'tangerine', secureNote: { type: 0 } },
  ],
});

let stack: Stack;
const contexts: BrowserContext[] = [];
let page: Page;
let secretKey: string;
const pageErrors: string[] = [];

beforeAll(async () => {
  stack = await startStack();
  mkdirSync(SCREENSHOTS, { recursive: true });
  page = await newPage({ viewport: { width: 1280, height: 800 } });
});

afterAll(async () => {
  for (const context of contexts) await context.close();
  await stack?.stop();
});

afterEach(() => {
  expect(pageErrors, 'uncaught errors in the page').toEqual([]);
});

async function newPage(options: Parameters<Stack['browser']['newContext']>[0]): Promise<Page> {
  const context = await stack.browser.newContext(options);
  context.on('weberror', (error) => pageErrors.push(error.error().message));
  contexts.push(context);
  return context.newPage();
}

async function shoot(target: Page, name: string): Promise<void> {
  await target.evaluate(() => document.fonts.ready);
  await target.screenshot({ path: `${SCREENSHOTS}${name}.png`, animations: 'disabled' });
}

/** The rows of the Logins section as shown: titles, and hosts for website rows. */
function loginRows(target: Page): Promise<string[]> {
  return target
    .locator('section[data-section="login"]')
    .locator('a[data-item-id], button[data-site]')
    .evaluateAll((rows) => rows.map((row) => (row as HTMLElement).dataset.site ?? row.querySelector('bdi')!.textContent!));
}

describe('logins for the same website', () => {
  it('signs up and imports several accounts on a few websites', async () => {
    await page.goto(`${stack.webUrl}/signup`);
    await page.getByRole('textbox', { name: 'Email' }).fill(EMAIL);
    await page.getByRole('textbox', { name: 'Master password', exact: true }).fill(PASSWORD);
    await page.getByRole('textbox', { name: 'Confirm master password' }).fill(PASSWORD);
    await page.getByRole('button', { name: 'Continue' }).click();
    const code = (await page.getByRole('status').filter({ hasText: 'Development server' }).locator('strong').innerText()).trim();
    await page.getByRole('textbox', { name: 'Verification code' }).fill(code);
    await page.getByRole('button', { name: 'Verify email' }).click();
    const kit = page.getByRole('article', { name: 'Octa Pass Recovery Kit' });
    secretKey = (await kit.getByRole('definition').nth(2).innerText()).trim();
    await page.getByRole('checkbox', { name: /saved my Recovery Kit/ }).check();
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByRole('button', { name: 'Open my vault' }).click();
    await page.getByRole('heading', { name: 'Nothing here yet' }).waitFor();

    await page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: 'Settings' }).click();
    await page.getByLabel('Import from').selectOption('bitwarden-json');
    await page.getByLabel('File', { exact: true }).setInputFiles({ name: 'bitwarden.json', mimeType: 'application/json', buffer: Buffer.from(BITWARDEN) });
    await page.getByRole('button', { name: 'Import', exact: true }).click();
    await page.getByText('Imported 11 items.').waitFor({ timeout: 30_000 });
  });

  it('shows one row per website with two or more logins, by host, inside Logins', async () => {
    await page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: 'All items' }).click();
    await page.getByRole('heading', { name: 'Logins 9 items', level: 2 }).waitFor();
    expect(await loginRows(page)).toEqual(['a.xxx.com', 'Billing', 'github.com', 'Netflix', 'Zoom', 'بنك الخليج']);
    await expect.poll(() => page.locator('button[data-site="a.xxx.com"]').innerText()).toMatch(/a\.xxx\.com\s+3 accounts/);
  });

  it('opens a website row in place and closes it again', async () => {
    const site = page.locator('button[data-site="a.xxx.com"]');
    await site.click();
    await expect.poll(() => site.getAttribute('aria-expanded')).toBe('true');
    expect(await loginRows(page)).toEqual(['a.xxx.com', 'Personal', 'Shared inbox', 'Work', 'Billing', 'github.com', 'Netflix', 'Zoom', 'بنك الخليج']);
    // The logins are indented under the website row.
    const logins = page.getByRole('list', { name: 'a.xxx.com' });
    const [row, first] = await Promise.all([site.boundingBox(), logins.getByRole('link', { name: /^Personal/ }).boundingBox()]);
    expect(first!.x).toBeGreaterThan(row!.x + 20);
    expect(first!.y).toBeGreaterThan(row!.y);
    await logins.getByRole('link', { name: /^Work/ }).click();
    await page.waitForURL(/\/items\/all\/[^/]+$/);
    await expect.poll(() => logins.getByRole('link', { name: /^Work/ }).getAttribute('aria-current')).toBe('page');
    await shoot(page, 'list-site-group');

    await site.click();
    await expect.poll(() => site.getAttribute('aria-expanded')).toBe('false');
    expect(await loginRows(page)).toEqual(['a.xxx.com', 'Billing', 'github.com', 'Netflix', 'Zoom', 'بنك الخليج']);
  });

  it('works from the keyboard', async () => {
    await page.getByRole('searchbox', { name: 'Search' }).focus();
    await page.keyboard.press('ArrowDown');
    await expect.poll(() => page.evaluate(() => (document.activeElement as HTMLElement | null)?.dataset.site)).toBe('a.xxx.com');
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('ArrowDown');
    await expect.poll(() => page.evaluate(() => (document.activeElement as HTMLElement | null)?.dataset.site)).toBe('github.com');
    await page.keyboard.press('Enter');
    await expect.poll(() => page.locator('button[data-site="github.com"]').getAttribute('aria-expanded')).toBe('true');
    await page.keyboard.press('ArrowDown');
    await expect.poll(() => page.evaluate(() => document.activeElement?.querySelector('bdi')?.textContent)).toBe('GitHub');
  });

  it('lists every login on its own in search results', async () => {
    await page.getByRole('searchbox', { name: 'Search' }).fill('xxx');
    await page.getByText('Search results are in name order, without groups.').waitFor();
    await expect.poll(() => page.locator('a[data-item-id]').count()).toBe(4);
    expect(await page.locator('button[data-site]').count()).toBe(0);
    await page.getByRole('searchbox', { name: 'Search' }).fill('');
    await page.getByRole('heading', { name: 'Logins 9 items', level: 2 }).waitFor();
  });

  it('can be turned off from the Sort and group menu', async () => {
    await page.getByRole('button', { name: 'Sort and group' }).click();
    await page.getByRole('menuitemcheckbox', { name: 'Combine accounts for the same website' }).click();
    await expect.poll(() => page.locator('button[data-site]').count()).toBe(0);
    expect(await loginRows(page)).toHaveLength(9);
    await page.getByRole('button', { name: 'Sort and group' }).click();
    await page.getByRole('menuitemcheckbox', { name: 'Combine accounts for the same website' }).click();
    await expect.poll(() => page.locator('button[data-site]').count()).toBe(2);
  });

  it('shows website rows in Arabic, and opens them in place on a phone', async () => {
    const arabic = await newPage({ viewport: { width: 1280, height: 800 }, locale: 'ar-EG' });
    await signIn(arabic);
    const site = arabic.locator('button[data-site="a.xxx.com"]');
    await expect.poll(() => site.innerText()).toMatch(/a\.xxx\.com\s+3 حسابات/);
    await site.click();
    await arabic.getByRole('list', { name: 'a.xxx.com' }).waitFor();
    await shoot(arabic, 'ar-list-site-group');

    for (const [locale, prefix] of [
      ['en-GB', ''],
      ['ar-EG', 'ar-'],
    ] as const) {
      const phone = await newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, locale });
      await signIn(phone);
      const row = phone.locator('button[data-site="a.xxx.com"]');
      await row.tap();
      await phone.getByRole('list', { name: 'a.xxx.com' }).waitFor();
      // Still the list, with the logins under the row: no sheet, no other screen.
      expect(await phone.getByRole('menu').count()).toBe(0);
      expect(await phone.getByRole('list', { name: 'a.xxx.com' }).getByRole('link').count()).toBe(3);
      await shoot(phone, `${prefix}list-site-group-phone`);
    }
  });
});

async function signIn(target: Page): Promise<void> {
  const arabic = (await target.evaluate(() => navigator.language)).startsWith('ar');
  await target.goto(`${stack.webUrl}/welcome`);
  await target.getByRole('textbox', { name: arabic ? 'البريد الإلكتروني' : 'Email' }).fill(EMAIL);
  await target.getByRole('textbox', { name: arabic ? 'كلمة المرور الرئيسية' : 'Master password' }).fill(PASSWORD);
  await target.getByRole('textbox', { name: arabic ? 'المفتاح السري' : 'Secret Key' }).fill(secretKey);
  await target.getByRole('button', { name: arabic ? 'تسجيل الدخول' : 'Sign in' }).click();
  await target.getByRole('heading', { name: arabic ? 'كل العناصر' : 'All items', level: 1 }).waitFor({ timeout: 30_000 });
}
