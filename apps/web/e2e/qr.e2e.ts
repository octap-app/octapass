// One-time codes from QR images in Chrome, on the real WASM core and server. The web vault's core
// has no image decoders: the browser decodes the image in the worker and the core reads the pixels.
//
//   pnpm --filter @octapass/web e2e          (HEADED=1 to watch)

import { readFileSync } from 'node:fs';
import type { BrowserContext, Page } from 'playwright-core';
import { startStack, type Stack } from './stack';

const PASSWORD = 'Lantern ruby quiet anchor 42';
const qr = (name: string) => ({
  name,
  mimeType: 'image/png',
  buffer: readFileSync(new URL(`../../../crates/octapass-core/tests/qr-fixtures/${name}`, import.meta.url)),
});

let stack: Stack;
const contexts: BrowserContext[] = [];
const pageErrors: string[] = [];

beforeAll(async () => {
  stack = await startStack();
});

afterAll(async () => {
  await stack?.stop();
});

afterEach(() => {
  expect(pageErrors, 'uncaught errors in the page').toEqual([]);
});

async function newPage(): Promise<Page> {
  const context = await stack.browser.newContext({ viewport: { width: 1440, height: 900 } });
  context.on('weberror', (error) => pageErrors.push(error.error().message));
  contexts.push(context);
  return context.newPage();
}

async function signUp(page: Page, email: string): Promise<void> {
  await page.goto(`${stack.webUrl}/signup`);
  await page.getByRole('textbox', { name: 'Email' }).fill(email);
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
}

describe('one-time codes from QR images', () => {
  it('adds the code in a screenshot to a login, then every account of a two-part Google Authenticator export', async () => {
    const page = await newPage();
    await signUp(page, `qr-${Date.now()}@example.com`);
    await page.getByRole('button', { name: 'New item' }).click();
    await page.getByRole('menuitem', { name: 'Login' }).click();
    await page.getByRole('textbox', { name: 'Title' }).fill('GitHub');
    await page.getByRole('textbox', { name: 'Username' }).fill('octo');
    await page.getByRole('button', { name: 'Save' }).click();
    await page.getByRole('heading', { name: 'GitHub' }).waitFor();

    await page.getByRole('button', { name: 'Add one-time code' }).click();
    const add = page.getByRole('dialog', { name: 'Add one-time code' });
    await add.locator('input[type="file"]').setInputFiles(qr('not-a-code.png'));
    await add.getByText('That QR code isn’t a one-time code.').waitFor();
    await add.locator('input[type="file"]').setInputFiles(qr('github.png'));
    await add.getByText('Found this one-time code:').waitFor();
    await add.getByRole('button', { name: 'Add code' }).click();
    await add.waitFor({ state: 'hidden' });
    await page.getByText('One-time code', { exact: true }).waitFor();

    await page.getByRole('button', { name: 'New item' }).click();
    await page.getByRole('menuitem', { name: 'One-time codes from a QR code' }).click();
    const scan = page.getByRole('dialog', { name: 'Add one-time codes from a QR code' });
    await scan.locator('input[type="file"]').setInputFiles(qr('google-authenticator-1-of-2.png'));
    await scan.getByText('Google Authenticator export: 1 of 2 QR codes scanned. Scan the next one, or continue with these.').waitFor();
    await scan.locator('input[type="file"]').setInputFiles(qr('google-authenticator-2-of-2.png'));
    await scan.getByText('Found 3 one-time codes:').waitFor();
    expect(await scan.getByText(/QR codes scanned/).count()).toBe(0);
    await scan.getByRole('button', { name: 'Continue' }).click();

    // GitHub already has its code, so GitHub:octo from the export becomes an item of its own.
    const review = page.getByRole('dialog', { name: 'Choose where each code goes' });
    await review.getByText('Keep as a separate item').first().waitFor();
    expect(await review.getByText('Keep as a separate item').count()).toBe(3);
    await review.getByRole('button', { name: 'Save 3 items' }).click();
    await review.waitFor({ state: 'hidden' });
    for (const title of ['ACME', 'Example']) await page.getByRole('link', { name: new RegExp(`^${title}`) }).first().waitFor();
  });
});
