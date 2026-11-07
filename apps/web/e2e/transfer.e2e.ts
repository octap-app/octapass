// Moving a vault between accounts in Chrome, on the real WASM core (in the worker) and the real
// server: the encrypted export, with its files, imported into a fresh account.
//
//   pnpm --filter @octapass/web e2e          (HEADED=1 to watch)

import { readFileSync } from 'node:fs';
import type { BrowserContext, Page } from 'playwright-core';
import { startStack, type Stack } from './stack';

const PASSWORD = 'Lantern ruby quiet anchor 42';
const EXPORT_PASSWORD = 'otter harbour velvet 9';
const LOGIN = { title: 'Gooseberry bank', username: 'maya', password: 'p,"w" lantern-7731' };
const DOCUMENT = { title: 'عقد الإيجار', name: 'lease.txt', text: 'Tenant: Maya Orchid.\n'.repeat(5000) };

let stack: Stack;
const contexts: BrowserContext[] = [];
const pageErrors: string[] = [];
let exported: Buffer;

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
  const context = await stack.browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
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

async function settings(page: Page): Promise<void> {
  await page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: 'Settings' }).click();
}

describe('moving a vault to another account', () => {
  it('exports everything, files included, encrypted', async () => {
    const page = await newPage();
    await signUp(page, `export-${Date.now()}@example.com`);
    await page.getByRole('button', { name: 'New item' }).click();
    await page.getByRole('menuitem', { name: 'Login' }).click();
    await page.getByRole('textbox', { name: 'Title' }).fill(LOGIN.title);
    await page.getByRole('textbox', { name: 'Username' }).fill(LOGIN.username);
    await page.getByRole('textbox', { name: 'Password', exact: true }).fill(LOGIN.password);
    await page.getByRole('button', { name: 'Save' }).click();
    await page.getByRole('heading', { name: LOGIN.title }).waitFor();
    await page.getByRole('button', { name: 'New item' }).click();
    await page.getByRole('menuitem', { name: 'Document' }).click();
    await page.getByRole('textbox', { name: 'Title' }).fill(DOCUMENT.title);
    await page.getByTestId('file-input').setInputFiles({ name: DOCUMENT.name, mimeType: 'text/plain', buffer: Buffer.from(DOCUMENT.text) });
    await page.getByText('Uploaded when you save').waitFor();
    await page.getByRole('button', { name: 'Save' }).click();
    await page.getByRole('button', { name: `Download ${DOCUMENT.name}` }).waitFor();

    await settings(page);
    await page.getByRole('button', { name: 'Export' }).click();
    const dialog = page.getByRole('dialog', { name: 'Export your vault' });
    await dialog.getByLabel('Password for the file').fill(EXPORT_PASSWORD);
    await dialog.getByLabel('Confirm the password').fill(EXPORT_PASSWORD);
    await dialog.getByLabel('Master password').fill(PASSWORD);
    const [download] = await Promise.all([page.waitForEvent('download'), dialog.getByRole('button', { name: 'Export' }).click()]);
    expect(download.suggestedFilename()).toMatch(/^octapass-export-\d{4}-\d\d-\d\d\.octapass$/);
    exported = readFileSync(await download.path());
    expect(exported.subarray(0, 4).toString()).toBe('OPEX');
    for (const plaintext of [LOGIN.title, LOGIN.password, 'Maya Orchid', DOCUMENT.name]) {
      expect(exported.includes(plaintext), `the export contains ${JSON.stringify(plaintext)}`).toBe(false);
    }
  });

  it('imports it into a fresh account, with its files', async () => {
    const page = await newPage();
    await signUp(page, `import-${Date.now()}@example.com`);
    await settings(page);
    await page.getByLabel('Import from').selectOption('octapass');
    await page.getByLabel('File', { exact: true }).setInputFiles({ name: 'backup.octapass', mimeType: 'application/octet-stream', buffer: exported });
    await page.getByLabel('Export password').fill('not the password');
    await page.getByRole('button', { name: 'Import', exact: true }).click();
    await page.getByText('That password doesn’t open this file.').waitFor();
    await page.getByLabel('Export password').fill(EXPORT_PASSWORD);
    await page.getByRole('button', { name: 'Import', exact: true }).click();
    await page.getByText('Imported 2 items.').waitFor({ timeout: 30_000 });
    await page.getByText('1 attached file was restored.').waitFor();

    await page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: 'All items' }).click();
    await page.getByRole('link', { name: new RegExp(DOCUMENT.title) }).click();
    const [file] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: `Download ${DOCUMENT.name}` }).click()]);
    expect(readFileSync(await file.path()).toString()).toBe(DOCUMENT.text);
    await page.getByRole('link', { name: new RegExp(LOGIN.title) }).click();
    await page.getByRole('heading', { name: LOGIN.title }).waitFor();
  });
});
