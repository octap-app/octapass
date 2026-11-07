// Attachments and Document items in Chrome, on the real WASM core (in the worker) and the real
// server: files are encrypted in the browser before upload and decrypted there on download.
//
//   pnpm --filter @octapass/web e2e          (HEADED=1 to watch)

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { BrowserContext, Page } from 'playwright-core';
import { startStack, type Stack } from './stack';

const PASSWORD = 'Lantern ruby quiet anchor 42';
const EMAIL = `files-${Date.now()}@example.com`;
// Contents and names that must never reach the server in readable form.
const LEASE = { title: 'Harbour Lane lease', name: 'harbour-lane-lease.txt', text: 'Tenant: Maya Orchid. Deposit held at the gooseberry-lantern bank.\n'.repeat(3000) };
const SCAN = { name: 'passport-scan-otter.png', text: 'pretend PNG bytes: velvet-otter-4417' };

let stack: Stack;
let context: BrowserContext;
let page: Page;
const pageErrors: string[] = [];

beforeAll(async () => {
  stack = await startStack();
  context = await stack.browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
  context.on('weberror', (error) => pageErrors.push(error.error().message));
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

function storedAttachments(): number {
  return readdirSync(join(stack.server.dataDir, 'attachments')).length;
}

async function download(name: string): Promise<string> {
  const [file] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: `Download ${name}` }).click()]);
  expect(file.suggestedFilename()).toBe(name);
  return readFileSync(await file.path()).toString();
}

describe('files on the real server', () => {
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

  it('saves a Document whose file the server stores only encrypted', async () => {
    await page.getByRole('button', { name: 'New item' }).click();
    await page.getByRole('menuitem', { name: 'Document' }).click();
    await page.getByRole('textbox', { name: 'Title' }).fill(LEASE.title);
    await page.getByTestId('file-input').setInputFiles({ name: LEASE.name, mimeType: 'text/plain', buffer: Buffer.from(LEASE.text) });
    await page.getByText('Uploaded when you save').waitFor();
    await page.getByRole('button', { name: 'Save' }).click();
    await page.getByRole('heading', { name: LEASE.title }).waitFor();
    await page.getByRole('button', { name: `Download ${LEASE.name}` }).waitFor();
    expect(await page.getByText(/^\d+(\.\d)? kB · TXT$/).count()).toBe(1);

    expect(storedAttachments()).toBe(1);
    const stored = serverFiles();
    for (const plaintext of [LEASE.title, LEASE.name, 'gooseberry-lantern', 'Maya Orchid']) {
      expect(stored.includes(plaintext), `server data contains ${JSON.stringify(plaintext)}`).toBe(false);
    }
  });

  it('downloads the file decrypted', async () => {
    expect(await download(LEASE.name)).toBe(LEASE.text);
  });

  it('attaches a dropped file to the item, and removes it', async () => {
    // What the browser does when a file is dropped from the desktop.
    const dataTransfer = await page.evaluateHandle(({ name, text }) => {
      const transfer = new DataTransfer();
      transfer.items.add(new File([text], name, { type: 'image/png' }));
      return transfer;
    }, SCAN);
    const section = page.getByRole('region', { name: 'Files' });
    await section.dispatchEvent('dragenter', { dataTransfer });
    await section.dispatchEvent('drop', { dataTransfer });
    await page.getByRole('button', { name: `Download ${SCAN.name}` }).waitFor();
    expect(await download(SCAN.name)).toBe(SCAN.text);
    expect(storedAttachments()).toBe(2);
    expect(serverFiles().includes(SCAN.text)).toBe(false);

    await page.getByRole('button', { name: `Remove ${SCAN.name}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Remove file' }).click();
    await page.getByRole('button', { name: `Download ${SCAN.name}` }).waitFor({ state: 'detached' });
    await expect.poll(storedAttachments).toBe(1);
  });

  it('shows the storage used in Settings', async () => {
    await page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: 'Settings' }).click();
    await page.getByText(/\d+(\.\d)? kB of 1 GB used/).waitFor();
  });
});
