// Taking over from the browser's password manager, and saving addresses and cards, with a vault on this
// device only. Its own browser profile, steps in order.
//
// Playwright can't answer Chrome's permission prompt, so this profile loads a copy of the build whose
// manifest also lists `privacy` as granted: the real `chrome.privacy` settings change, only the prompt
// is skipped. Prompts in pages live in a closed shadow root and are clicked through the DevTools protocol.

import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, test, type Page } from '@playwright/test';
import { clickInNotice, itemLink, launchExtension, noticeText, openApp as open, pagesPort as port, WORKER_WAIT, type Extension } from './helpers';

const LOCAL_PASSWORD = 'Marble kettle orchid lantern 1987 quietly';
const SWITCH = 'Use Octa Pass instead of Chrome’s password manager';

let extension: Extension;

// Steps that go through the inline menu or a save prompt wait for the service worker (helpers.ts).
test.describe.configure({ mode: 'serial', timeout: 240_000 });

test.beforeAll(async () => {
  const dist = join(mkdtempSync(join(tmpdir(), 'octapass-e2e-')), 'chrome');
  cpSync(new URL('../dist/chrome', import.meta.url).pathname, dist, { recursive: true });
  const manifest = JSON.parse(readFileSync(join(dist, 'manifest.json'), 'utf8')) as { permissions: string[] };
  manifest.permissions.push('privacy');
  writeFileSync(join(dist, 'manifest.json'), JSON.stringify(manifest));
  extension = await launchExtension({ dist });
});

test.afterAll(() => extension?.context.close());

const openApp = (query = ''): Promise<Page> => open(extension, { query });
// http://localhost counts as a secure page; other plain-http pages never get address or card prompts.
const checkoutUrl = () => `http://localhost:${port()}/checkout.html`;

/** Waits for the content script's engine: the field icon appears once it runs (slow on a busy machine). */
async function engineReady(page: Page, field: string): Promise<void> {
  await page.locator(field).click();
  await expect(page.locator('octapass-icon')).toBeAttached({ timeout: 30_000 });
}

/** The browser's own settings, as the service worker sees them. */
function privacy() {
  return extension.worker.evaluate(async () => {
    const services = chrome.privacy.services;
    const read = async (s: chrome.types.ChromeSetting<boolean>) => {
      const { value, levelOfControl } = await s.get({});
      return `${value} ${levelOfControl}`;
    };
    return {
      passwords: await read(services.passwordSavingEnabled),
      addresses: await read(services.autofillAddressEnabled),
      cards: await read(services.autofillCreditCardEnabled),
    };
  });
}

test('suggests replacing the browser’s password manager after the vault is made, and turns it off', async () => {
  const app = await openApp();
  await app.getByRole('button', { name: 'Use on this device only' }).click();
  await app.getByLabel('Master password', { exact: true }).fill(LOCAL_PASSWORD);
  await app.getByLabel('Confirm master password').fill(LOCAL_PASSWORD);
  await app.getByRole('button', { name: 'Create vault' }).click();
  await app.getByRole('checkbox', { name: /written it down/ }).check({ timeout: 30_000 });
  await app.getByRole('button', { name: 'Open my vault' }).click();

  await expect(app.getByText('Use Octa Pass instead of Chrome’s password manager?')).toBeVisible();
  await app.getByRole('button', { name: 'Turn on' }).click();
  await expect(app.getByRole('button', { name: 'Turn on' })).toBeHidden();
  await expect.poll(privacy).toEqual({
    passwords: 'false controlled_by_this_extension',
    addresses: 'false controlled_by_this_extension',
    cards: 'false controlled_by_this_extension',
  });

  // Addresses back to the browser, then everything.
  await app.getByRole('link', { name: 'Settings' }).click();
  await expect(app.getByRole('switch', { name: SWITCH })).toHaveAttribute('aria-checked', 'true');
  await app.getByRole('switch', { name: 'Addresses' }).click();
  await expect.poll(async () => (await privacy()).addresses).toBe('true controllable_by_this_extension');
  expect((await privacy()).cards).toBe('false controlled_by_this_extension');
  await app.getByRole('switch', { name: SWITCH }).click();
  await expect.poll(privacy).toEqual({
    passwords: 'true controllable_by_this_extension',
    addresses: 'true controllable_by_this_extension',
    cards: 'true controllable_by_this_extension',
  });
  await app.close();
});

test('saves an address from a checkout into the vault', async () => {
  const page = await extension.context.newPage();
  await page.goto(checkoutUrl());
  await engineReady(page, '#name');
  await page.locator('#name').fill('Maya Haddad');
  await page.locator('#email').fill('maya@example.test');
  await page.locator('#line1').fill('1 High Street');
  await page.locator('#city').fill('London');
  await page.locator('#zip').fill('N1 9GU');
  await page.locator('#country').selectOption('GB');
  await page.locator('#notes').fill('Leave with the neighbour');
  await page.getByRole('button', { name: 'Continue' }).click();

  await expect.poll(() => noticeText(page), { timeout: WORKER_WAIT }).toContain('Save this address in Octa Pass?');
  expect(await noticeText(page)).toContain('Maya Haddad, 1 High Street, London');
  await clickInNotice(page, 'Save');
  await expect.poll(() => noticeText(page), { timeout: WORKER_WAIT }).toBe('');

  const app = await openApp();
  await app.getByRole('link', { name: 'All items' }).click();
  await itemLink(app, '1 High Street, London').click();
  await expect(app.getByText('N1 9GU')).toBeVisible();
  await expect(app.getByText('United Kingdom')).toBeVisible();
  await expect(app.getByText('Leave with the neighbour')).toBeHidden();
  await app.close();
  await page.close();
});

test('saves a card without its security code, then updates its expiry', async () => {
  const page = await extension.context.newPage();
  const payWith = async (expiry: string) => {
    await page.goto(checkoutUrl());
    await page.evaluate(() => {
      document.getElementById('address')!.hidden = true;
      document.getElementById('card')!.hidden = false;
    });
    await engineReady(page, '#holder');
    await page.locator('#holder').fill('Maya Haddad');
    await page.locator('#number').fill('4242 4242 4242 4242');
    await page.locator('#exp').fill(expiry);
    await page.locator('#cvc').fill('123');
    await page.getByRole('button', { name: 'Pay' }).click();
  };

  await payWith('08/27');
  await expect.poll(() => noticeText(page), { timeout: WORKER_WAIT }).toContain('Save this card in Octa Pass?');
  const prompt = await noticeText(page);
  expect(prompt).toContain('Visa ending 4242');
  expect(prompt).toContain('Also save the security code');
  expect(prompt).not.toContain('4242 4242');
  await clickInNotice(page, 'Save');

  const app = await openApp();
  await app.getByRole('link', { name: 'All items' }).click();
  await itemLink(app, 'Visa ending 4242').click();
  await expect(app.getByText('08/27').first()).toBeVisible();
  await expect(app.getByText('Security code')).toBeHidden();
  await app.close();

  await payWith('09/28');
  await expect.poll(() => noticeText(page), { timeout: WORKER_WAIT }).toContain('Update your saved card?');
  await clickInNotice(page, 'Also save the security code');
  await clickInNotice(page, 'Update');

  const after = await openApp();
  await after.getByRole('link', { name: 'All items' }).click();
  await expect(itemLink(after, 'Visa ending 4242')).toHaveCount(1);
  await itemLink(after, 'Visa ending 4242').click();
  await expect(after.getByText('09/28').first()).toBeVisible();
  await expect(after.getByText('Security code')).toBeVisible();
  await after.close();

  // Nothing new to save: no prompt.
  await payWith('09/28');
  await page.waitForTimeout(1000);
  expect(await noticeText(page)).toBe('');
  await page.close();
});

test('never asks again on a site after “Never for this site”', async () => {
  const page = await extension.context.newPage();
  await page.goto(checkoutUrl());
  await engineReady(page, '#line1');
  await page.locator('#line1').fill('2 Low Road');
  await page.locator('#zip').fill('E1 6AN');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect.poll(() => noticeText(page), { timeout: WORKER_WAIT }).toContain('Save this address in Octa Pass?');
  await clickInNotice(page, 'Never for this site');

  await page.goto(checkoutUrl());
  await engineReady(page, '#line1');
  await page.locator('#line1').fill('3 Side Street');
  await page.locator('#zip').fill('E2 7AA');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.waitForTimeout(1000);
  expect(await noticeText(page)).toBe('');

  const app = await openApp();
  await app.getByRole('link', { name: 'Settings' }).click();
  const section = app.getByRole('region', { name: 'Never offered to save' });
  await expect(section.getByText(`localhost:${port()}`)).toBeVisible();
  await section.getByRole('button', { name: `Remove localhost:${port()} (Addresses)` }).click();
  await expect(section.getByText('None.')).toBeVisible();
  await app.close();
  await page.close();
});
