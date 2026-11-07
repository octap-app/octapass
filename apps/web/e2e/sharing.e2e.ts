// Milestone 5 in the browser: two accounts share a vault, live, through the real server; a share
// link opens for someone without an account. Each step builds on the one before.
//
//   pnpm --filter @octapass/web e2e          (HEADED=1 to watch)

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { BrowserContext, Page } from 'playwright-core';
import { startStack, type Stack } from './stack';

const PASSWORD = 'Lantern ruby quiet anchor 42';
const MAYA = `maya-${Date.now()}@example.com`;
const SAM = `sam-${Date.now()}@example.com`;
const VAULT = 'Quokka household';
const ITEM = { title: 'Quokka router admin', password: 'Xq7!plover-quartz-ochre-91' };
const PASSPHRASE = 'heron marmalade';

let stack: Stack;
let mayaContext: BrowserContext;
let samContext: BrowserContext;
let maya: Page;
let sam: Page;
let link: string;
const pageErrors: string[] = [];

beforeAll(async () => {
  stack = await startStack();
  mayaContext = await stack.browser.newContext({ viewport: { width: 1440, height: 900 } });
  samContext = await stack.browser.newContext({ viewport: { width: 1440, height: 900 } });
  for (const context of [mayaContext, samContext]) context.on('weberror', (error) => pageErrors.push(error.error().message));
  maya = await mayaContext.newPage();
  sam = await samContext.newPage();
});

afterAll(async () => {
  await stack?.stop();
});

afterEach(() => {
  expect(pageErrors, 'uncaught errors in the page').toEqual([]);
});

function serverFiles(): Buffer {
  const dir = stack.server.dataDir;
  const files = readdirSync(dir, { recursive: true, withFileTypes: true }).filter((entry) => entry.isFile());
  return Buffer.concat(files.map((entry) => readFileSync(join(entry.parentPath, entry.name))));
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

/** In-app navigation: a full page load would lock the vault, whose keys live in memory only. */
async function openSharing(page: Page): Promise<void> {
  await page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: 'Sharing' }).click();
  await page.getByRole('heading', { name: 'Sharing', level: 1 }).waitFor();
}

const sidebarVault = (page: Page) => page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: new RegExp(VAULT) });

describe('sharing between two accounts on the real server', () => {
  it('signs up both people', async () => {
    await Promise.all([signUp(maya, MAYA), signUp(sam, SAM)]);
  });

  it('creates a shared vault and adds Sam after comparing fingerprints', async () => {
    await openSharing(sam);
    const samSees = await sam.getByRole('figure', { name: 'Your fingerprint' }).innerText();

    await openSharing(maya);
    await maya.getByRole('main').getByRole('button', { name: 'New shared vault' }).click();
    const dialog = maya.getByRole('dialog', { name: 'New shared vault' });
    await dialog.getByRole('textbox', { name: 'Name' }).fill(VAULT);
    await dialog.getByRole('button', { name: 'Create vault' }).click();
    await maya.getByRole('heading', { name: VAULT, level: 1 }).waitFor();

    await maya.getByRole('textbox', { name: 'Their email' }).fill(SAM);
    await maya.getByRole('button', { name: 'Find' }).click();
    expect(await maya.getByRole('figure', { name: 'Fingerprint' }).innerText()).toBe(samSees);
    await maya.getByRole('checkbox', { name: `It matches what ${SAM} sees` }).check();
    await maya.getByRole('combobox', { name: 'Role' }).selectOption('write');
    await maya.getByRole('button', { name: 'Add to vault' }).click();
    const row = maya.getByRole('listitem').filter({ hasText: SAM });
    await row.getByText('Verified').waitFor();
    expect(await row.getByRole('combobox', { name: 'Role' }).inputValue()).toBe('write');
  });

  it('shows Maya’s new item to Sam live, and keeps the vault name and item away from the server', async () => {
    await maya.getByRole('button', { name: 'Open vault' }).click();
    await maya.getByRole('heading', { name: VAULT, level: 1 }).waitFor();
    await maya.getByRole('button', { name: 'New item' }).click();
    await maya.getByRole('menuitem', { name: 'Login' }).click();
    await maya.getByRole('textbox', { name: 'Title' }).fill(ITEM.title);
    await maya.getByRole('textbox', { name: 'Password', exact: true }).fill(ITEM.password);
    await maya.getByRole('button', { name: 'Save' }).click();
    await maya.getByRole('heading', { name: ITEM.title }).waitFor();

    // Sam never reloads: the WebSocket says when to sync.
    await sidebarVault(sam).click();
    await sam.getByRole('link', { name: new RegExp(ITEM.title) }).click();
    await sam.getByRole('heading', { name: ITEM.title }).waitFor();

    const stored = serverFiles();
    for (const plaintext of [VAULT, ITEM.title, ITEM.password]) {
      expect(stored.includes(plaintext), `server data contains ${JSON.stringify(plaintext)}`).toBe(false);
    }
  });

  it('removes Sam, who loses the vault straight away', async () => {
    await openSharing(maya);
    await maya.getByRole('main').getByRole('link', { name: new RegExp(VAULT) }).click();
    await maya.getByRole('button', { name: `Remove ${SAM}` }).click();
    await maya.getByRole('dialog', { name: `Remove ${SAM}?` }).getByRole('button', { name: 'Remove and change key' }).click();
    await maya.getByRole('listitem').filter({ hasText: SAM }).waitFor({ state: 'detached' });
    await sidebarVault(sam).waitFor({ state: 'detached' });
  });

  it('shares a copy through a one-time link with a passphrase', async () => {
    await sidebarVault(maya).click();
    await maya.getByRole('link', { name: new RegExp(ITEM.title) }).click();
    await maya.getByRole('button', { name: 'More actions' }).click();
    await maya.getByRole('menuitem', { name: 'Share a copy' }).click();
    const dialog = maya.getByRole('dialog');
    await dialog.getByRole('spinbutton', { name: 'Number of views' }).fill('1');
    await dialog.getByRole('textbox', { name: 'Passphrase (optional)' }).fill(PASSPHRASE);
    await dialog.getByRole('button', { name: 'Create link' }).click();
    link = await dialog.getByRole('textbox', { name: 'Link' }).inputValue();
    const url = new URL(link);
    expect(url.origin).toBe(stack.webUrl);
    // This build's default server is the stack's, so the link doesn't need to name it.
    expect(url.searchParams.has('server')).toBe(false);
    await dialog.getByRole('button', { name: 'Done' }).click();

    // The key in the fragment never reaches the server.
    expect(serverFiles().includes(url.hash.slice(1))).toBe(false);
  });

  async function visit(): Promise<{ page: Page; close: () => Promise<void> }> {
    const visitor = await stack.browser.newContext({ viewport: { width: 390, height: 844 } });
    visitor.on('weberror', (error) => pageErrors.push(error.error().message));
    const page = await visitor.newPage();
    await page.goto(link);
    return { page, close: () => visitor.close() };
  }

  it('opens once for someone without an account, then says it no longer works', async () => {
    const first = await visit();
    const { page } = first;
    await page.getByRole('button', { name: 'Show the item' }).click();
    await page.getByRole('textbox', { name: 'Passphrase' }).fill('wrong passphrase');
    await page.getByRole('button', { name: 'Unlock' }).click();
    await page.getByText('That passphrase isn’t right').waitFor();
    await page.getByRole('textbox', { name: 'Passphrase' }).fill(PASSPHRASE);
    await page.getByRole('button', { name: 'Unlock' }).click();
    await page.getByRole('heading', { name: ITEM.title }).waitFor();
    await page.getByText('That was the last view').waitFor();
    // The key is gone from the address bar once it has been used.
    expect(new URL(page.url()).hash).toBe('');
    await first.close();

    // Someone else with the same link: the view limit is spent.
    const second = await visit();
    await second.page.getByRole('button', { name: 'Show the item' }).click();
    await second.page.getByRole('heading', { name: 'This link no longer works' }).waitFor();
    await second.close();
  });
});
