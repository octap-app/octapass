// The One-time codes list on the real server in Chrome: the category next to Passkeys with its count,
// each row's live code that copies, and the same in Arabic on a phone-sized screen. Screenshots go to
// screenshots/.
//
//   pnpm --filter @octapass/web e2e codesList          (HEADED=1 to watch)

import { mkdirSync } from 'node:fs';
import type { BrowserContext, Page } from 'playwright-core';
import { startStack, type Stack } from './stack';

const SCREENSHOTS = new URL('../screenshots/', import.meta.url).pathname;
const PASSWORD = 'Lantern ruby quiet anchor 42';
const EMAIL = `codes-${Date.now()}@example.com`;

const login = (name: string, uri: string, totp?: string) => ({ type: 1, name, login: { username: 'maya', password: 'x', uris: [{ uri }], ...(totp ? { totp } : {}) } });
const BITWARDEN = JSON.stringify({
  encrypted: false,
  items: [
    login('GitHub', 'https://github.com', 'JBSWY3DPEHPK3PXP'),
    login('Dropbox', 'https://dropbox.com', 'otpauth://totp/Dropbox:maya?secret=GEZDGNBVGY3TQOJQ&issuer=Dropbox'),
    login('Gulf Bank', 'https://gulf-bank.example', 'otpauth://totp/Gulf%20Bank:maya?secret=KRSXG5CTMVRXEZLU&digits=8'),
    login('Netflix', 'https://netflix.com'),
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
  page = await newPage({ viewport: { width: 1280, height: 800 }, permissions: ['clipboard-read', 'clipboard-write'] });
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

const codeButtons = (target: Page) => target.locator('button[aria-label^="Copy the one-time code"], button[aria-label^="نسخ الرمز"]');

describe('the one-time codes list', () => {
  it('signs up and imports logins, some with codes', async () => {
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
    await page.getByText('Imported 5 items.').waitFor({ timeout: 30_000 });
  });

  it('is a category next to Passkeys with a count, and lists only the items with a code', async () => {
    const nav = page.getByRole('navigation', { name: 'Vault' });
    const category = nav.getByRole('link', { name: /^One-time codes/ });
    await expect.poll(() => category.innerText()).toMatch(/One-time codes\s+3/);
    const names = await category.locator('xpath=ancestor::ul[1]').getByRole('link').allInnerTexts();
    expect(names.map((name) => name.split('\n')[0]).slice(0, 3)).toEqual(['Logins', 'Passkeys', 'One-time codes']);

    await category.click();
    await page.getByRole('heading', { name: 'One-time codes', level: 1 }).waitFor();
    await expect.poll(() => page.locator('a[data-item-id]').evaluateAll((rows) => rows.map((row) => row.querySelector('bdi')!.textContent))).toEqual(['Dropbox', 'GitHub', 'Gulf Bank']);
    await expect.poll(() => codeButtons(page).allInnerTexts()).toEqual([expect.stringMatching(/^\d{3} \d{3}$/), expect.stringMatching(/^\d{3} \d{3}$/), expect.stringMatching(/^\d{4} \d{4}$/)]);
    await shoot(page, 'codes-list');
  });

  it('copies a code from its row', async () => {
    const button = page.getByRole('button', { name: 'Copy the one-time code for GitHub' });
    await button.click();
    const shown = (await button.innerText()).replace(' ', '');
    await page.getByText('One-time code copied. Clears in 30 seconds').first().waitFor();
    // The code can roll over between the click and reading it back.
    expect([shown, (await button.innerText()).replace(' ', '')]).toContain(await page.evaluate(() => navigator.clipboard.readText()));
  });

  it('shows the list in Arabic, on a computer and a phone', async () => {
    for (const [viewport, name] of [
      [{ width: 1280, height: 800 }, 'ar-codes-list'],
      [{ width: 390, height: 844 }, 'ar-codes-list-phone'],
    ] as const) {
      const arabic = await newPage({ viewport, locale: 'ar-EG', ...(viewport.width < 700 ? { deviceScaleFactor: 2, isMobile: true, hasTouch: true } : {}) });
      await signIn(arabic);
      // In the app, not a page load, which would lock the vault again.
      await arabic.evaluate(() => {
        history.pushState(null, '', '/items/codes');
        dispatchEvent(new PopStateEvent('popstate'));
      });
      await arabic.getByRole('heading', { name: 'الرموز لمرة واحدة', level: 1 }).waitFor();
      await expect.poll(() => codeButtons(arabic).count()).toBe(3);
      await expect.poll(() => codeButtons(arabic).first().innerText()).toMatch(/^\d{3} \d{3}$/);
      expect(await arabic.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), 'nothing sticks out sideways').toBe(0);
      await shoot(arabic, name);
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
