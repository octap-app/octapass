// The web vault in Arabic, right to left, on the real server in Chrome. The browser's language is
// Arabic, so nothing is chosen: the vault follows it. Each main screen is checked for direction and
// layout, and saved as a screenshot in screenshots/ for the record.
//
//   pnpm --filter @octapass/web e2e rtl          (HEADED=1 to watch)

import { mkdirSync } from 'node:fs';
import { totpCode } from '@octapass/vault-client';
import type { BrowserContext, Page } from 'playwright-core';
import { startStack, type Stack } from './stack';

const SCREENSHOTS = new URL('../screenshots/', import.meta.url).pathname;
const PASSWORD = 'Lantern ruby quiet anchor 42';
const EMAIL = `rania-${Date.now()}@example.com`;
const ITEM = { title: 'بنك الخليج', url: 'https://bank.example', username: 'rania.k', password: 'Xq7!plover-quartz-ochre-91', note: 'رقم الفرع 2041' };

let stack: Stack;
let context: BrowserContext;
let page: Page;
let secretKey: string;
let setupKey: string;
const pageErrors: string[] = [];
const outsideRequests: string[] = [];

beforeAll(async () => {
  stack = await startStack();
  mkdirSync(SCREENSHOTS, { recursive: true });
  context = await stack.browser.newContext({ viewport: { width: 1280, height: 800 }, locale: 'ar-EG' });
  context.on('weberror', (error) => pageErrors.push(error.error().message));
  // Fonts and everything else come from the vault itself: no font CDN. The one other host is the
  // breach check (Have I Been Pwned's range API), which only ever sees a hash prefix.
  context.on('request', (request) => {
    const { hostname } = new URL(request.url());
    if (!['localhost', '127.0.0.1', 'api.pwnedpasswords.com'].includes(hostname) && !request.url().startsWith('data:')) outsideRequests.push(request.url());
  });
  page = await context.newPage();
});

afterAll(async () => {
  await stack?.stop();
});

afterEach(() => {
  expect(pageErrors, 'uncaught errors in the page').toEqual([]);
  expect(outsideRequests, 'requests to other hosts').toEqual([]);
});

async function shoot(target: Page, name: string): Promise<void> {
  await target.evaluate(() => document.fonts.ready);
  await target.screenshot({ path: `${SCREENSHOTS}${name}.png`, animations: 'disabled' });
}

/** Text with a value inserted, which carries bidi isolation marks around the value in Arabic. */
const withValue = (before: string, value: string) => new RegExp(`${before}\\W*${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`);

/** The page is right to left in Arabic and nothing sticks out sideways (a scrollbar along the bottom). */
async function expectRtl(target: Page): Promise<void> {
  const root = await target.evaluate(() => ({
    lang: document.documentElement.lang,
    dir: document.documentElement.dir,
    overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
  }));
  expect(root).toEqual({ lang: 'ar', dir: 'rtl', overflow: 0 });
}

describe('the web vault in Arabic', () => {
  it('signs up in Arabic, with data fields left to right', async () => {
    await page.goto(`${stack.webUrl}/signup`);
    await page.getByRole('heading', { name: 'أنشئ حسابك' }).waitFor();
    await expectRtl(page);
    for (const name of ['البريد الإلكتروني', 'كلمة المرور الرئيسية', 'تأكيد كلمة المرور الرئيسية']) {
      expect(await page.getByRole('textbox', { name, exact: true }).getAttribute('dir')).toBe('ltr');
    }
    await page.getByRole('textbox', { name: 'البريد الإلكتروني' }).fill(EMAIL);
    await page.getByRole('textbox', { name: 'كلمة المرور الرئيسية', exact: true }).fill(PASSWORD);
    await page.getByRole('textbox', { name: 'تأكيد كلمة المرور الرئيسية' }).fill(PASSWORD);
    await shoot(page, 'ar-signup');
    await page.getByRole('button', { name: 'متابعة' }).click();

    const devCode = page.getByRole('status').filter({ hasText: 'خادم التطوير' }).locator('strong');
    const code = (await devCode.innerText()).trim();
    await page.getByRole('textbox', { name: 'رمز التحقق' }).fill(code);
    await page.getByRole('button', { name: 'تحقّق من البريد' }).click();

    const kit = page.getByRole('article', { name: 'مجموعة استرداد Octa Pass' });
    await kit.waitFor();
    secretKey = (await kit.getByRole('definition').nth(2).innerText()).trim();
    expect(secretKey).toMatch(/^OP1-[0-9A-Z]{6}-[0-9A-Z]{6}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{4}$/);
    // The Secret Key reads left to right even in the Arabic sheet.
    expect(await kit.getByRole('definition').nth(2).evaluate((el) => getComputedStyle(el).direction)).toBe('ltr');
    await shoot(page, 'ar-recovery-kit');
    await page.getByRole('checkbox', { name: /حفظت مجموعة الاسترداد/ }).check();
    await page.getByRole('button', { name: 'متابعة' }).click();
    await page.getByRole('button', { name: 'افتح خزنتي' }).click();
    await page.getByRole('heading', { name: 'لا شيء هنا بعد' }).waitFor();
  });

  it('draws the Arabic text in the bundled Arabic font', async () => {
    const loaded = await page.evaluate(async () => {
      await document.fonts.ready;
      return [...document.fonts].filter((font) => font.status === 'loaded').map((font) => font.family.replaceAll('"', ''));
    });
    expect(loaded).toContain('Noto Sans Arabic Variable');
  });

  it('puts the sidebar on the right and the content on the left', async () => {
    const nav = await page.getByRole('navigation', { name: 'الخزنة' }).boundingBox();
    expect(nav!.x).toBeGreaterThan(1280 / 2);
    await expectRtl(page);
  });

  it('edits a login, with the password, code and website left to right', async () => {
    await page.getByRole('button', { name: 'عنصر جديد' }).click();
    await page.getByRole('menuitem', { name: 'بيانات دخول' }).click();
    await page.getByRole('textbox', { name: 'العنوان' }).fill(ITEM.title);
    await page.getByRole('textbox', { name: 'اسم المستخدم' }).fill(ITEM.username);
    const password = page.getByRole('textbox', { name: 'كلمة المرور', exact: true });
    await password.fill(ITEM.password);
    await page.getByRole('textbox', { name: 'الموقع الإلكتروني' }).first().fill(ITEM.url);
    await page.getByRole('textbox', { name: 'ملاحظات' }).fill(ITEM.note);
    await page.getByRole('textbox', { name: 'العنوان' }).scrollIntoViewIfNeeded();
    for (const field of [password, page.getByRole('textbox', { name: 'الموقع الإلكتروني' }).first(), page.getByRole('textbox', { name: 'رمز لمرة واحدة' })]) {
      expect(await field.getAttribute('dir')).toBe('ltr');
      // Left-to-right text still lines up with the right-to-left labels.
      expect(await field.evaluate((el) => getComputedStyle(el).textAlign)).toBe('right');
    }
    await expectRtl(page);
    await shoot(page, 'ar-editor');
    await page.getByRole('button', { name: 'حفظ' }).click();
    await page.getByRole('heading', { name: ITEM.title }).waitFor();
  });

  it('shows the item and the list', async () => {
    await expectRtl(page);
    // Arrows that point somewhere are mirrored; the lock and the check marks aren't.
    const mirrored = await page.locator('svg[data-mirror]').first().evaluate((el) => getComputedStyle(el).scale);
    expect(mirrored).toBe('-1 1');
    expect(await page.getByText(ITEM.username).first().isVisible()).toBe(true);
    await page.getByRole('button', { name: withValue('إظهار', 'كلمة المرور') }).first().click();
    const revealed = page.getByText(ITEM.password);
    expect(await revealed.evaluate((el) => getComputedStyle(el).direction)).toBe('ltr');
    await page.getByRole('button', { name: withValue('إخفاء', 'كلمة المرور') }).first().click();
    await shoot(page, 'ar-item');
  });

  it('shows the generator', async () => {
    await page.getByRole('link', { name: 'المولّد' }).click();
    await page.getByRole('heading', { name: 'مولّد كلمات المرور', level: 1 }).waitFor();
    await expectRtl(page);
    expect(await page.getByLabel('كلمة المرور المُنشأة').evaluate((el) => getComputedStyle(el).direction)).toBe('ltr');
    await shoot(page, 'ar-generator');
  });

  it('shows the settings, with the language choice', async () => {
    await page.getByRole('link', { name: 'الإعدادات' }).click();
    await page.getByRole('heading', { name: 'الإعدادات', level: 1 }).waitFor();
    await expectRtl(page);
    expect(await page.getByRole('radiogroup', { name: 'اللغة' }).getByRole('radio', { name: 'النظام' }).isChecked()).toBe(true);
    await shoot(page, 'ar-settings');
  });

  it('locks, and unlocks in Arabic', async () => {
    await page.getByRole('button', { name: 'اقفل الآن' }).first().click();
    await page.getByRole('heading', { name: 'الخزنة مقفلة' }).waitFor();
    await expectRtl(page);
    await shoot(page, 'ar-lock');
    await page.getByRole('textbox', { name: 'كلمة المرور الرئيسية' }).fill(PASSWORD);
    await page.getByRole('button', { name: 'فتح القفل', exact: true }).click();
    await page.getByRole('heading', { name: 'الإعدادات', level: 1 }).waitFor();
  });

  it('signs in on a phone, and shows the list there', async () => {
    const device = await stack.browser.newContext({ viewport: { width: 390, height: 844 }, locale: 'ar' });
    const phone = await device.newPage();
    await phone.goto(`${stack.webUrl}/welcome`);
    await phone.getByRole('heading', { name: 'مرحبًا بعودتك' }).waitFor();
    await expectRtl(phone);
    expect(await phone.getByRole('textbox', { name: 'المفتاح السري' }).getAttribute('dir')).toBe('ltr');
    await shoot(phone, 'ar-signin-phone');
    await phone.getByRole('textbox', { name: 'البريد الإلكتروني' }).fill(EMAIL);
    await phone.getByRole('textbox', { name: 'كلمة المرور الرئيسية' }).fill(PASSWORD);
    await phone.getByRole('textbox', { name: 'المفتاح السري' }).fill(secretKey);
    await phone.getByRole('button', { name: 'تسجيل الدخول' }).click();
    await phone.getByRole('heading', { name: 'كل العناصر', level: 1 }).waitFor();
    await expectRtl(phone);
    await phone.getByRole('link', { name: new RegExp(ITEM.title) }).first().waitFor();
    await shoot(phone, 'ar-list-phone');
    await device.close();
  });

  it('turns on two-step sign-in in Arabic, with the codes left to right', async () => {
    const section = page.getByRole('region', { name: 'تسجيل الدخول بخطوتين' });
    await section.getByRole('button', { name: 'تفعيل' }).click();
    const dialog = page.getByRole('dialog', { name: 'تفعيل تسجيل الدخول بخطوتين' });
    await dialog.getByRole('textbox', { name: 'كلمة المرور الرئيسية' }).fill(PASSWORD);
    await dialog.getByRole('button', { name: 'متابعة' }).click();

    await dialog.getByRole('img', { name: 'رمز QR لتطبيق المصادقة' }).waitFor();
    const key = dialog.getByLabel('مفتاح الإعداد', { exact: true });
    expect(await key.evaluate((el) => getComputedStyle(el).direction)).toBe('ltr');
    setupKey = (await key.innerText()).replace(/\s/g, '');
    const field = dialog.getByRole('textbox', { name: 'رمز تطبيق المصادقة' });
    expect(await field.getAttribute('dir')).toBe('ltr');
    await field.fill((await totpCode(setupKey)).code);
    await dialog.getByRole('button', { name: 'تفعيل' }).click();

    const codes = dialog.getByRole('list', { name: 'رموز الاسترداد' });
    await codes.waitFor();
    expect(await codes.getByRole('listitem').first().evaluate((el) => getComputedStyle(el).direction)).toBe('ltr');
    await expectRtl(page);
    await dialog.getByRole('checkbox', { name: 'حفظت هذه الرموز' }).check();
    await dialog.getByRole('button', { name: 'تم' }).click();
    await section.getByText(withValue('بقيت', '10')).waitFor();
    // The "it's on" notice closes by itself; the screenshot shows the section without it.
    await page.locator('[aria-hidden="true"]').getByText('تسجيل الدخول بخطوتين مُفعّل', { exact: true }).waitFor({ state: 'detached' });
    await section.evaluate((el) => el.scrollIntoView({ block: 'start' }));
    await shoot(page, 'ar-two-step-settings');
  });

  it('asks a new browser for the second step in Arabic', async () => {
    const device = await stack.browser.newContext({ viewport: { width: 1280, height: 800 }, locale: 'ar' });
    device.on('weberror', (error) => pageErrors.push(error.error().message));
    const fresh = await device.newPage();
    await fresh.goto(`${stack.webUrl}/welcome`);
    await fresh.getByRole('textbox', { name: 'البريد الإلكتروني' }).fill(EMAIL);
    await fresh.getByRole('textbox', { name: 'كلمة المرور الرئيسية' }).fill(PASSWORD);
    await fresh.getByRole('textbox', { name: 'المفتاح السري' }).fill(secretKey);
    await fresh.getByRole('button', { name: 'تسجيل الدخول' }).click();
    await fresh.getByRole('heading', { name: 'تسجيل الدخول بخطوتين' }).waitFor();
    await expectRtl(fresh);
    const field = fresh.getByRole('textbox', { name: 'رمز تطبيق المصادقة' });
    expect(await field.getAttribute('dir')).toBe('ltr');
    await shoot(fresh, 'ar-two-step-signin');

    await field.fill('000000');
    await fresh.getByRole('button', { name: 'تحقّق' }).click();
    await fresh.getByText(/هذا الرمز غير صحيح/).waitFor();
    // Turning on used the current step, so the next one finishes the sign-in.
    await field.fill((await totpCode(setupKey, Date.now() + 30_000)).code);
    await fresh.getByRole('button', { name: 'تحقّق' }).click();
    await fresh.getByRole('heading', { name: 'كل العناصر', level: 1 }).waitFor();
    await device.close();
  });

  it('switches to English from Settings, and back', async () => {
    await page.getByRole('radiogroup', { name: 'اللغة' }).getByText('English').click();
    await page.getByRole('heading', { name: 'Settings', level: 1 }).waitFor();
    expect(await page.evaluate(() => [document.documentElement.lang, document.documentElement.dir])).toEqual(['en', 'ltr']);
    await page.reload();
    await page.getByRole('heading', { name: 'Vault locked' }).waitFor();
    await page.getByRole('textbox', { name: 'Master password' }).fill(PASSWORD);
    await page.getByRole('button', { name: 'Unlock', exact: true }).click();
    await page.getByRole('heading', { name: 'Settings', level: 1 }).waitFor();
    await page.getByRole('radiogroup', { name: 'Language' }).getByText('System').click();
    await page.getByRole('heading', { name: 'الإعدادات', level: 1 }).waitFor();
  });
});
