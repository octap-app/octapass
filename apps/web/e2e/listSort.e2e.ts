// Item lists sorted and grouped, on the real server in Chrome: All items in sections by type with
// headers that stay in view, the Sort and group menu from the keyboard, the choice remembered per
// list, search without groups, and the same in Arabic on a phone-sized screen. Screenshots of the
// grouped list go to screenshots/.
//
//   pnpm --filter @octapass/web e2e listSort          (HEADED=1 to watch)

import { mkdirSync } from 'node:fs';
import type { BrowserContext, Page } from 'playwright-core';
import { startStack, type Stack } from './stack';

const SCREENSHOTS = new URL('../screenshots/', import.meta.url).pathname;
const PASSWORD = 'Lantern ruby quiet anchor 42';
const EMAIL = `lists-${Date.now()}@example.com`;

const login = (name: string, host: string) => ({ type: 1, name, login: { username: 'maya', password: 'x', uris: [{ uri: `https://${host}` }] } });
const BITWARDEN = JSON.stringify({
  encrypted: false,
  items: [
    login('Zoom', 'zoom.us'),
    login('amazon', 'amazon.com'),
    login('Apple ID', 'apple.com'),
    login('GitHub', 'github.com'),
    login('Gmail', 'mail.google.com'),
    login('Netflix', 'netflix.com'),
    login('PayPal', 'paypal.com'),
    login('Slack', 'slack.com'),
    login('Dropbox', 'dropbox.com'),
    login('Éclair Bakery', 'eclair.example'),
    login('1Password (old)', 'old.example'),
    login('بنك الخليج', 'gulf-bank.example'),
    login('أمازون مصر', 'amazon.eg'),
    login('تويتر', 'twitter.com'),
    { type: 3, name: 'Visa Platinum', card: { cardholderName: 'Maya Orchid', number: '4111111111111111', brand: 'Visa' } },
    { type: 3, name: 'Mastercard', card: { cardholderName: 'Maya Orchid', number: '5555555555554444', brand: 'Mastercard' } },
    { type: 4, name: 'Passport', identity: { firstName: 'Maya', lastName: 'Orchid' } },
    { type: 4, name: 'هوية العمل', identity: { firstName: 'مايا' } },
    { type: 2, name: 'Wi-Fi at home', notes: 'tangerine', secureNote: { type: 0 } },
    { type: 2, name: 'ملاحظات السفر', notes: 'جواز', secureNote: { type: 0 } },
    { type: 2, name: '2026 tax notes', notes: 'receipts', secureNote: { type: 0 } },
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

/** Each section header's name, in order. */
function headers(target: Page): Promise<string[]> {
  return target.locator('section[data-section] > h2 > bdi').allInnerTexts();
}

/** The row titles in one section, in order. */
function titlesIn(target: Page, section: string): Promise<string[]> {
  return target.locator(`section[data-section="${section}"] a[data-item-id]`).evaluateAll((rows) => rows.map((row) => row.querySelector('bdi')!.textContent));
}

async function choose(target: Page, menuLabel: string, option: string): Promise<void> {
  await target.getByRole('button', { name: menuLabel }).click();
  await target.getByRole('menuitemradio', { name: option }).click();
  await target.getByRole('menu').waitFor({ state: 'detached' });
}

describe('sorted and grouped item lists', () => {
  it('signs up and imports a mixed vault', async () => {
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
    await page.getByText('Imported 21 items.').waitFor({ timeout: 30_000 });
  });

  it('groups All items by type, with counts, in name order inside each section', async () => {
    await page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: 'All items' }).click();
    await page.getByRole('heading', { name: 'Logins 14 items', level: 2 }).waitFor();
    expect(await headers(page)).toEqual(['Logins', 'Cards', 'Identities', 'Secure notes']);
    expect(await titlesIn(page, 'login')).toEqual([
      '1Password (old)',
      'amazon',
      'Apple ID',
      'Dropbox',
      'Éclair Bakery',
      'GitHub',
      'Gmail',
      'Netflix',
      'PayPal',
      'Slack',
      'Zoom',
      'أمازون مصر',
      'بنك الخليج',
      'تويتر',
    ]);
    expect(await titlesIn(page, 'secureNote')).toEqual(['2026 tax notes', 'Wi-Fi at home', 'ملاحظات السفر']);
    await shoot(page, 'list-grouped');
  });

  it('keeps the current section’s header at the top while scrolling', async () => {
    const stuck = await page.evaluate(() => {
      const first = document.querySelector('section[data-section]')!;
      const scroller = first.parentElement!.parentElement!;
      scroller.scrollTop = 420;
      const top = scroller.getBoundingClientRect().top;
      return Array.from(document.querySelectorAll('section[data-section] > h2'))
        .filter((h2) => Math.abs(h2.getBoundingClientRect().top - top) < 1.5)
        .map((h2) => h2.closest('section')!.getAttribute('data-section'));
    });
    expect(stuck).toHaveLength(1);
    await page.evaluate(() => (document.querySelector('section[data-section]')!.parentElement!.parentElement!.scrollTop = 0));
  });

  it('sorts and groups from the keyboard, and remembers the choice for that list', async () => {
    const button = page.getByRole('button', { name: 'Sort and group' });
    await button.focus();
    await page.keyboard.press('Enter');
    await expect.poll(() => page.evaluate(() => document.activeElement?.textContent)).toBe('Name, A to Z');
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');
    await page.getByRole('menu').waitFor({ state: 'detached' });
    await expect.poll(() => page.evaluate(() => document.activeElement?.getAttribute('aria-label'))).toBe('Sort and group');
    expect((await titlesIn(page, 'login')).slice(0, 3)).toEqual(['تويتر', 'بنك الخليج', 'أمازون مصر']);

    await choose(page, 'Sort and group', 'First letter');
    // Z to A: backwards through English name order (Latin, then Arabic), with # still last. أ is filed under ا.
    expect(await headers(page)).toEqual(['ه', 'م', 'ت', 'ب', 'ا', 'Z', 'W', 'V', 'S', 'P', 'N', 'M', 'G', 'E', 'D', 'A', '#']);
    expect(await titlesIn(page, 'E')).toEqual(['Éclair Bakery']);
    expect(await titlesIn(page, '#')).toEqual(['2026 tax notes', '1Password (old)']);

    // Logins is a list of its own: it starts by first letter, A to Z.
    await page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: /^Logins/ }).click();
    await page.getByRole('heading', { name: 'Logins', level: 1 }).waitFor();
    expect((await headers(page)).slice(0, 3)).toEqual(['A', 'D', 'E']);

    await page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: /^All items/ }).click();
    await page.getByRole('heading', { name: 'All items', level: 1 }).waitFor();
    expect((await headers(page)).slice(0, 2)).toEqual(['ه', 'م']);
    await choose(page, 'Sort and group', 'Type');
    await choose(page, 'Sort and group', 'Name, A to Z');
  });

  it('lists search results without groups, with a note', async () => {
    await page.getByRole('searchbox', { name: 'Search' }).fill('a');
    await page.getByText('Search results are in name order, without groups.').waitFor();
    expect(await page.locator('section[data-section]').count()).toBe(0);
    await page.getByRole('searchbox', { name: 'Search' }).fill('');
    await page.getByRole('heading', { name: 'Logins 14 items', level: 2 }).waitFor();
  });

  it('shows the grouped list and the menu in Arabic, right to left', async () => {
    const arabic = await newPage({ viewport: { width: 1280, height: 800 }, locale: 'ar-EG' });
    await signIn(arabic);
    await arabic.getByRole('heading', { name: /^بيانات الدخول/, level: 2 }).waitFor();
    expect(await headers(arabic)).toEqual(['بيانات الدخول', 'البطاقات', 'الهويات', 'الملاحظات الآمنة']);
    // In Arabic, Arabic titles come before Latin ones (digits first, as in every language).
    expect((await titlesIn(arabic, 'login')).slice(0, 5)).toEqual(['1Password (old)', 'أمازون مصر', 'بنك الخليج', 'تويتر', 'amazon']);
    await shoot(arabic, 'ar-list-grouped');
  });

  it('opens the menu as a sheet on a phone, in English and Arabic', async () => {
    for (const [locale, name, menu, prefix] of [
      ['en-GB', /^Logins/, 'Sort and group', ''],
      ['ar-EG', /^بيانات الدخول/, 'الترتيب والتجميع', 'ar-'],
    ] as const) {
      const phone = await newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, locale });
      await signIn(phone);
      await phone.getByRole('heading', { name, level: 2 }).waitFor();
      await shoot(phone, `${prefix}list-grouped-phone`);
      await phone.getByRole('button', { name: menu }).click();
      // Measured once the sheet has slid up.
      await phone.getByRole('menu').evaluate((sheet) => Promise.all(sheet.getAnimations().map((animation) => animation.finished)));
      const sheet = await phone.getByRole('menu').boundingBox();
      expect(sheet!.y + sheet!.height).toBeCloseTo(844, -1);
      expect(sheet!.width).toBe(390);
      await shoot(phone, `${prefix}sort-menu-phone`);
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
