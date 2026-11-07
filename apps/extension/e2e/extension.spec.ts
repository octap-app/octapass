// The extension end to end: the unpacked Chrome build in Playwright's Chromium, the real WASM core
// in its service worker, a local octapass-server and local pages. One profile, steps in order.
//
//   pnpm --filter @octapass/extension e2e          (HEADED=1 to watch)

import { mkdirSync } from 'node:fs';
import { expect, test, type Frame, type Page } from '@playwright/test';
import { FRAME_LOGIN, LOGIN, TEAM_LOGINS } from './data';
import { itemLink, launchExtension, openApp as open, openMenu, pagesPort as port, pickFirst, pickFirstSuggestion, SCREENSHOTS, shareScreenshot, signIn, WORKER_WAIT, type Extension } from './helpers';

const shopUrl = () => `http://shop.example.test:${port()}/login.html`;
/** shop.example.test's two-step setup page, with a QR code for GitHub:octo. */
const twoStepUrl = () => `http://shop.example.test:${port()}/two-step.html`;
const lookalikeUrl = () => `http://shop.example.test.evil.test:${port()}/login.html`;
const passkeyUrl = () => `http://localhost:${port()}/passkey.html`;
/** shop.example.test with a sign-in form framed from `frame`. */
const framedUrl = (frame: string) => `http://shop.example.test:${port()}/framed.html?frame=${encodeURIComponent(frame)}`;
const idpFrameUrl = () => `http://accounts.idp.test:${port()}/login.html`;
const sameSiteFrameUrl = () => `http://login.shop.example.test:${port()}/login.html`;

let extension: Extension;
const pageErrors: string[] = [];
const context = () => extension.context;

// Steps that go through the inline menu wait for the service worker several times (helpers.ts).
test.describe.configure({ mode: 'serial', timeout: 300_000 });

test.beforeAll(async () => {
  extension = await launchExtension();
  extension.context.on('weberror', (error) => pageErrors.push(error.error().message));
});

test.afterAll(() => extension?.context.close());

test.afterEach(() => {
  expect(pageErrors, 'uncaught errors in a page').toEqual([]);
});

const openApp = (tabOf?: Page) => open(extension, tabOf ? { tabOf } : {});

async function promptFrame(page: Page): Promise<Frame> {
  await expect.poll(() => page.frames().some((f) => f.url().includes('/passkey.html#')), { timeout: WORKER_WAIT }).toBe(true);
  return page.frames().find((f) => f.url().includes('/passkey.html#'))!;
}

async function frameAt(page: Page, url: string): Promise<Frame> {
  await expect.poll(() => page.frames().some((f) => f.url() === url)).toBe(true);
  const frame = page.frames().find((f) => f.url() === url)!;
  await frame.locator('#username').waitFor();
  return frame;
}

/** The inline menu's options in a frame from another site, from its accessibility tree (the menu's shadow root is closed). */
async function menuOptions(frame: Frame): Promise<string[]> {
  const cdp = await context().newCDPSession(frame);
  try {
    const { nodes } = await cdp.send('Accessibility.getFullAXTree');
    return nodes.filter((n) => n.role?.value === 'option').map((n) => String(n.name?.value ?? ''));
  } finally {
    await cdp.detach();
  }
}

/** Polls the frame's menu options for as long as the service worker may take to answer. */
const optionsIn = (frame: Frame) => expect.poll(() => menuOptions(frame), { timeout: WORKER_WAIT });

test('signs in from the app tab with the Secret Key on a new device', async () => {
  await signIn(extension);
  const app = await openApp();
  await app.getByRole('link', { name: 'All items' }).click();
  await expect(itemLink(app, LOGIN.title)).toBeVisible();
  await app.close();
});

/** Each section header's name in the app tab's All items, in order, and the titles in one section. */
const headers = (app: Page) => app.locator('section[data-section] > h2 > bdi').allInnerTexts();
const titlesIn = (app: Page, section: string) => app.locator(`section[data-section="${section}"] li`).evaluateAll((rows) => rows.map((row) => row.querySelector('bdi')!.textContent));

test('groups All items by type with headers, and remembers a new order', async () => {
  const app = await openApp();
  await app.getByRole('link', { name: 'All items' }).click();
  await expect(app.getByRole('heading', { name: 'Logins 5 items', level: 2 })).toBeVisible();
  expect(await headers(app)).toEqual(['Logins', 'Cards', 'Identities']);
  expect(await titlesIn(app, 'login')).toEqual(['Corpus login', FRAME_LOGIN.title, LOGIN.title, 'team.example.test']);
  await app.evaluate(() => document.fonts.ready);
  await app.screenshot({ path: `${SCREENSHOTS}app-all-items.png` });

  await app.getByRole('button', { name: 'Sort and group' }).click();
  await app.getByRole('menuitemradio', { name: 'Name, Z to A' }).click();
  expect(await titlesIn(app, 'login')).toEqual(['team.example.test', LOGIN.title, FRAME_LOGIN.title, 'Corpus login']);
  await app.close();

  // Closing the app tab keeps the choice for next time.
  const again = await openApp();
  await again.getByRole('link', { name: 'All items' }).click();
  await expect(again.getByRole('heading', { name: 'Logins 5 items', level: 2 })).toBeVisible();
  expect(await titlesIn(again, 'login')).toEqual(['team.example.test', LOGIN.title, FRAME_LOGIN.title, 'Corpus login']);
  await again.getByRole('button', { name: 'Sort and group' }).click();
  await again.getByRole('menuitemradio', { name: 'None' }).click();
  await expect(again.locator('section[data-section]')).toHaveCount(0);
  await again.getByRole('button', { name: 'Sort and group' }).click();
  await again.getByRole('menuitemradio', { name: 'Type' }).click();
  await again.getByRole('button', { name: 'Sort and group' }).click();
  await again.getByRole('menuitemradio', { name: 'Name, A to Z' }).click();
  await expect(again.getByRole('heading', { name: 'Logins 5 items', level: 2 })).toBeVisible();
  await again.close();
});

test('shows the logins for one website as one row that opens in place', async () => {
  const app = await openApp();
  await app.getByRole('link', { name: 'All items' }).click();
  const site = app.locator('button[data-site="team.example.test"]');
  await expect(site).toContainText('2 accounts');
  await site.click();
  await expect(site).toHaveAttribute('aria-expanded', 'true');
  await expect
    .poll(() => app.getByRole('list', { name: 'team.example.test' }).locator('li').evaluateAll((rows) => rows.map((row) => row.querySelector('bdi')!.textContent)))
    .toEqual(TEAM_LOGINS.map((login) => login.title));
  expect(await app.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), 'nothing sticks out sideways').toBe(0);
  await app.evaluate(() => document.fonts.ready);
  await app.screenshot({ path: `${SCREENSHOTS}app-site-group.png` });

  // Search lists each login on its own.
  await app.getByRole('searchbox', { name: 'Search' }).fill('team');
  await expect(app.locator('button[data-site]')).toHaveCount(0);
  await expect(itemLink(app, /^Team /)).toHaveCount(2);
  await app.close();
});

test('lists every one-time code under One-time codes, with the live code', async () => {
  const app = await openApp();
  await app.getByRole('link', { name: 'One-time codes' }).click();
  await expect(app.getByRole('heading', { name: 'One-time codes', level: 1 })).toBeVisible();
  const code = app.getByRole('button', { name: 'Copy the one-time code for Corpus login' });
  await expect(code).toHaveText(/^\d{3} \d{3}$/);
  await expect(app.locator('a[data-item-id]')).toHaveCount(1);
  expect(await app.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), 'nothing sticks out sideways').toBe(0);
  await app.evaluate(() => document.fonts.ready);
  await app.screenshot({ path: `${SCREENSHOTS}app-codes.png` });
  await app.close();
});

test('fills a login from the inline menu on its own site', async () => {
  const page = await context().newPage();
  await page.goto(shopUrl());
  await pickFirstSuggestion(page, '#username');
  await expect(page.locator('#username')).toHaveValue(LOGIN.username, { timeout: WORKER_WAIT });
  await expect(page.locator('#password')).toHaveValue(LOGIN.password);
  await page.close();
});

test('offers nothing on a look-alike domain', async () => {
  const page = await context().newPage();
  await page.goto(lookalikeUrl());
  await pickFirstSuggestion(page, '#username', { timeout: 3000 });
  await page.waitForTimeout(500);
  await expect(page.locator('#username')).toHaveValue('');
  await expect(page.locator('#password')).toHaveValue('');

  // "This site" in the app tab has no logins for it either.
  const app = await openApp(page);
  await expect(app.getByText('No logins for shop.example.test.evil.test')).toBeVisible();
  await app.close();
  await page.close();
});

test('fills from the Fill button in the app tab’s This site, and screenshots it', async () => {
  const page = await context().newPage();
  await page.goto(shopUrl());
  const app = await openApp(page);
  await expect(app.getByRole('button', { name: `Fill ${LOGIN.title}` })).toBeVisible();
  mkdirSync(SCREENSHOTS, { recursive: true });
  for (const scheme of ['light', 'dark'] as const) {
    await app.emulateMedia({ colorScheme: scheme });
    await app.screenshot({ path: `${SCREENSHOTS}app-${scheme}.png` });
  }
  await app.getByRole('button', { name: `Fill ${LOGIN.title}` }).click();
  await expect(page.locator('#username')).toHaveValue(LOGIN.username, { timeout: WORKER_WAIT });
  await expect(page.locator('#password')).toHaveValue(LOGIN.password);
  await page.close();
});

test('fills in a frame from the page’s own site without asking', async () => {
  const page = await context().newPage();
  await page.goto(framedUrl(sameSiteFrameUrl()));
  const frame = await frameAt(page, sameSiteFrameUrl());
  await openMenu(page, '#username', { frame });
  await pickFirst(page);
  await expect(frame.locator('#username')).toHaveValue(LOGIN.username, { timeout: WORKER_WAIT });
  await expect(frame.locator('#password')).toHaveValue(LOGIN.password);
  await page.close();
});

test('asks before filling in a frame from another site, remembers the answer, and forgets it from settings', async () => {
  const page = await context().newPage();
  await page.goto(framedUrl(idpFrameUrl()));
  let frame = await frameAt(page, idpFrameUrl());
  const notice = `This form is from accounts.idp.test:${port()}, inside example.test.`;

  // The menu asks first, naming the frame's real host and the page's site.
  await openMenu(page, '#username', { frame });
  await optionsIn(frame).toEqual([expect.stringContaining(notice)]);
  await pickFirst(page);
  // Allowed: the menu comes back with the logins for the frame's own site (its first entry
  // focused, as the pick was a key press), and nothing was filled yet.
  await optionsIn(frame).toEqual([expect.stringContaining(FRAME_LOGIN.title)]);
  await expect(frame.locator('#username')).toHaveValue('');
  await pickFirst(page, { focused: true });
  await expect(frame.locator('#username')).toHaveValue(FRAME_LOGIN.username, { timeout: WORKER_WAIT });
  await expect(frame.locator('#password')).toHaveValue(FRAME_LOGIN.password);

  // Next time it fills straight away.
  await page.reload();
  frame = await frameAt(page, idpFrameUrl());
  await openMenu(page, '#username', { frame });
  await optionsIn(frame).toEqual([expect.stringContaining(FRAME_LOGIN.title)]);
  await pickFirst(page);
  await expect(frame.locator('#password')).toHaveValue(FRAME_LOGIN.password, { timeout: WORKER_WAIT });

  // The settings list the approval; removing it makes the menu ask again.
  const app = await openApp();
  await app.getByRole('link', { name: 'Settings' }).click();
  const section = app.getByRole('region', { name: 'Frames from other sites' });
  await expect(section.getByText(`accounts.idp.test:${port()}`)).toBeVisible();
  await expect(section.getByText('Inside example.test')).toBeVisible();
  await section.getByRole('button', { name: `Remove accounts.idp.test:${port()} inside example.test` }).click();
  await expect(section.getByText('None yet. Octa Pass asks the first time you use one.')).toBeVisible();
  await app.close();

  await page.reload();
  frame = await frameAt(page, idpFrameUrl());
  await openMenu(page, '#username', { frame });
  await optionsIn(frame).toEqual([expect.stringContaining(notice)]);
  await page.close();
});

test('saves a new login from a sign-up page with a suggested password', async () => {
  const page = await context().newPage();
  await page.goto(`http://join.newsite.test:${port()}/signup.html`);
  await page.locator('#email').fill('maya@newsite.test');
  await pickFirstSuggestion(page, '#new');
  await expect(page.locator('#new')).not.toHaveValue('', { timeout: WORKER_WAIT });
  const password = await page.locator('#new').inputValue();
  expect(password.length).toBeGreaterThanOrEqual(20);
  await expect(page.locator('#confirm')).toHaveValue(password);

  // Saved as a draft straight away, before the form is even sent.
  const app = await openApp(page);
  await app.getByRole('button', { name: /^join\.newsite\.test/ }).click();
  await expect(app.getByRole('list', { name: 'Tags' })).toContainText('Unconfirmed');

  // Signing up for real confirms it.
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.locator('#done')).toBeVisible();
  await expect(app.getByRole('list', { name: 'Tags' })).toHaveCount(0, { timeout: WORKER_WAIT });
  await app.close();
  await page.close();
});

test('creates a passkey in Octa Pass and signs in with it', async () => {
  const page = await context().newPage();
  await page.goto(passkeyUrl());
  const result = page.locator('#result');

  await page.getByRole('button', { name: 'Register' }).click();
  const create = await promptFrame(page);
  await expect(create.getByRole('heading', { name: 'Save a passkey for localhost?' })).toBeVisible();
  await create.getByRole('button', { name: 'Save in Octa Pass' }).click();
  await expect(result).toContainText('"step":"registered"', { timeout: WORKER_WAIT });
  const registered = JSON.parse((await result.textContent())!) as Record<string, unknown>;
  expect(registered).toMatchObject({ isCredential: true, type: 'webauthn.create', origin: `http://localhost:${port()}`, algorithm: -7 });

  await page.getByRole('button', { name: 'Sign in' }).click();
  const get = await promptFrame(page);
  await get.getByRole('button', { name: /maya@example\.test/ }).first().click();
  await expect(result).toContainText('"step":"signed-in"', { timeout: WORKER_WAIT });
  expect(JSON.parse((await result.textContent())!)).toMatchObject({ sameCredential: true, type: 'webauthn.get', signature: true });

  // It's an ordinary login in the vault now.
  const app = await openApp();
  await app.getByRole('link', { name: 'All items' }).click();
  await expect(itemLink(app, /Passkey test/)).toBeVisible();
  await app.close();
  await page.close();
});

test('hands the request back to the browser when the user picks another device', async () => {
  const page = await context().newPage();
  // A virtual security key stands in for the browser's own passkey flow.
  const cdp = await context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
  });
  await page.goto(passkeyUrl());
  await page.getByRole('button', { name: 'Register' }).click();
  const prompt = await promptFrame(page);
  await prompt.getByRole('button', { name: 'Use another device or security key' }).click();
  await expect(page.locator('#result')).toContainText('"step":"registered"', { timeout: WORKER_WAIT });
  await expect.poll(() => page.frames().some((f) => f.url().includes('/passkey.html#'))).toBe(false);
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  expect(credentials).toHaveLength(1);
  await page.close();
});

test('reads the QR code a page shows, and the review adds it to a login found by search', async () => {
  const page = await context().newPage();
  await page.goto(twoStepUrl());
  const app = await openApp(page);
  await shareScreenshot(extension, page);
  await app.getByRole('button', { name: 'Scan QR code on this page' }).click();
  const scan = app.getByRole('dialog', { name: 'Add one-time codes from a QR code' });
  // The scan opens on a screenshot of the page, taken right away (the page comes to the front for a
  // moment) and read by the core in the service worker: on a busy machine, that has taken a minute.
  await expect(scan.getByText('Found 1 one-time code:')).toBeVisible({ timeout: 90_000 });
  await expect(scan.getByText('GitHub (octo)')).toBeVisible();
  await scan.getByRole('button', { name: 'Continue' }).click();

  const review = app.getByRole('dialog', { name: 'Choose where each code goes' });
  await expect(review.getByText('Keep as a separate item')).toBeVisible();
  await review.getByRole('button', { name: 'Change' }).click();
  await review.getByRole('searchbox').fill('shop.example');
  await review.getByRole('radio', { name: new RegExp(LOGIN.title) }).check();
  await expect(review.getByText(`Joins ${LOGIN.title}`)).toBeVisible();
  await review.getByRole('button', { name: 'Save 1 item' }).click();
  await expect(review).toBeHidden();

  await app.getByRole('button', { name: new RegExp(`^${LOGIN.title}`) }).click();
  await expect(app.getByText('One-time code', { exact: true })).toBeVisible();
  await expect(app.getByRole('button', { name: 'Add one-time code' })).toBeHidden();
  await app.close();
  await page.close();
});

test('imports authenticator links, and the review links one to a login with the picker', async () => {
  const tab = await open(extension, { query: '?view=tab&path=/settings' });
  await tab.getByLabel('Import from').selectOption('otpauth');
  await tab.getByLabel('File', { exact: true }).setInputFiles({
    name: 'codes.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('otpauth://totp/Identity%20provider:maya?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Identity%20provider\n'),
  });
  await tab.getByRole('button', { name: 'Import' }).click();
  const review = tab.getByRole('list', { name: 'Choose where each code goes' });
  await expect(review.getByText('Identity provider (maya)')).toBeVisible();
  await review.getByRole('button', { name: 'Change' }).click();
  // The shop login has a code now: it can't take a second one.
  await review.getByRole('searchbox').fill('example');
  await expect(review.getByRole('radio', { name: new RegExp(LOGIN.title) })).toBeDisabled();
  await review.getByRole('radio', { name: new RegExp(FRAME_LOGIN.title) }).check();
  await tab.getByRole('button', { name: 'Save 1 item' }).click();
  await expect(tab.getByText('Imported 1 item.')).toBeVisible();
  await tab.close();

  const app = await openApp();
  await app.getByRole('link', { name: 'All items' }).click();
  await itemLink(app, FRAME_LOGIN.title).click();
  await expect(app.getByText('One-time code', { exact: true })).toBeVisible();
  await app.close();
});

test('shows the app tab, its settings and the page’s menu in Arabic, right to left', async () => {
  const settings = await openApp();
  await settings.getByRole('link', { name: 'Settings' }).click();
  await settings.getByRole('radiogroup', { name: 'Language' }).getByText('العربية').click();
  await expect(settings.locator('html')).toHaveAttribute('dir', 'rtl');
  await expect(settings.getByRole('radiogroup', { name: 'اللغة' })).toBeVisible();
  await settings.evaluate(() => document.fonts.ready);
  await settings.screenshot({ path: `${SCREENSHOTS}app-settings-ar.png` });
  await settings.close();

  const page = await context().newPage();
  await page.goto(shopUrl());
  const app = await openApp(page);
  await expect(app.locator('html')).toHaveAttribute('lang', 'ar');
  await expect(app.getByRole('button', { name: new RegExp(`تعبئة\\W*${LOGIN.title}`) })).toBeVisible();
  expect(await app.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), 'nothing sticks out sideways').toBe(0);
  await app.evaluate(() => document.fonts.ready);
  await app.screenshot({ path: `${SCREENSHOTS}app-ar.png` });
  await app.getByRole('link', { name: 'كل العناصر' }).click();
  await expect(app.getByRole('heading', { name: /^بيانات الدخول/, level: 2 })).toBeVisible();
  expect((await headers(app)).slice(0, 3)).toEqual(['بيانات الدخول', 'البطاقات', 'الهويات']);
  expect(await app.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), 'nothing sticks out sideways').toBe(0);
  await app.evaluate(() => document.fonts.ready);
  await app.screenshot({ path: `${SCREENSHOTS}app-all-items-ar.png` });
  await app.locator('button[data-site="team.example.test"]').click();
  await expect(app.locator('button[data-site="team.example.test"]')).toContainText('حسابان');
  await expect(app.getByRole('list', { name: 'team.example.test' })).toBeVisible();
  await app.evaluate(() => document.fonts.ready);
  await app.screenshot({ path: `${SCREENSHOTS}app-site-group-ar.png` });
  await app.getByRole('link', { name: 'الرموز لمرة واحدة' }).click();
  // Earlier steps added codes to several logins (the QR code scans): each row shows its code.
  await expect(app.getByRole('button', { name: /^نسخ الرمز لمرة واحدة لـ/ }).first()).toHaveText(/^\d{3} \d{3}$/);
  await app.evaluate(() => document.fonts.ready);
  await app.screenshot({ path: `${SCREENSHOTS}app-codes-ar.png` });
  await app.close();
  await page.close();

  // Pages opened from now on get the inline menu in Arabic, from the language the app tab saved.
  const framed = await context().newPage();
  await framed.goto(framedUrl(idpFrameUrl()));
  const frame = await frameAt(framed, idpFrameUrl());
  await openMenu(framed, '#username', { frame });
  await optionsIn(frame).toEqual([expect.stringContaining(`هذا النموذج من accounts.idp.test:${port()}، داخل example.test.`)]);
  await framed.close();

  // Back to English for the steps after this one.
  const back = await openApp();
  await back.getByRole('link', { name: 'الإعدادات' }).click();
  await back.getByRole('radiogroup', { name: 'اللغة' }).getByText('English').click();
  await expect(back.locator('html')).toHaveAttribute('dir', 'ltr');
  await back.close();
});

test('locks from the app tab, and stays locked for the content script', async () => {
  const app = await openApp();
  await app.getByRole('navigation', { name: 'Vault' }).getByRole('button', { name: 'Lock now' }).click();
  await expect(app.getByRole('heading', { name: 'Vault locked' })).toBeVisible();
  const page = await context().newPage();
  await page.goto(shopUrl());
  await pickFirstSuggestion(page, '#username');
  await page.waitForTimeout(500);
  await expect(page.locator('#password')).toHaveValue('');
  await page.close();
  await app.close();
});
