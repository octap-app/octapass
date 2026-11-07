// Milestone 1, definition of done item 4: the web vault on the real WASM core and the real server,
// in Chrome. One account's whole life, in order; each step builds on the one before.
//
//   pnpm --filter @octapass/web e2e          (HEADED=1 to watch)

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { BrowserContext, CDPSession, Page } from 'playwright-core';
import { startStack, type Stack } from './stack';

const PASSWORD = 'Lantern ruby quiet anchor 42';
const EMAIL = `maya-${Date.now()}@example.com`;
// Distinctive strings that must never reach the server in readable form.
const ITEM = {
  title: 'Quokka Credit Union',
  url: 'https://quokka-credit.example',
  username: 'maya.orchid',
  password: 'Xq7!plover-quartz-ochre-91',
  note: 'Vault door code is tangerine-anvil-5531',
};
const EDITED_NOTE = 'Moved to the marmalade-kestrel branch';

let stack: Stack;
let context: BrowserContext;
let page: Page;
let secretKey: string;
const pageErrors: string[] = [];

beforeAll(async () => {
  stack = await startStack();
  context = await stack.browser.newContext({ viewport: { width: 1440, height: 900 } });
  context.on('weberror', (error) => pageErrors.push(error.error().message));
  page = await context.newPage();
});

afterAll(async () => {
  await stack?.stop();
});

afterEach(() => {
  expect(pageErrors, 'uncaught errors in the page').toEqual([]);
});

/** Every file the server keeps in its data directory (the database, its WAL and attachments), as raw bytes. */
function serverFiles(): Buffer {
  const dir = stack.server.dataDir;
  const files = readdirSync(dir, { recursive: true, withFileTypes: true }).filter((entry) => entry.isFile());
  return Buffer.concat(files.map((entry) => readFileSync(join(entry.parentPath, entry.name))));
}

function database(): DatabaseSync {
  return new DatabaseSync(join(stack.server.dataDir, 'octapass.db'), { readOnly: true });
}

async function signIn(target: Page, withSecretKey: boolean): Promise<void> {
  await target.goto(`${stack.webUrl}/welcome`);
  await target.getByRole('textbox', { name: 'Email' }).fill(EMAIL);
  await target.getByRole('textbox', { name: 'Master password' }).fill(PASSWORD);
  if (withSecretKey) await target.getByRole('textbox', { name: 'Secret Key' }).fill(secretKey);
  await target.getByRole('button', { name: 'Sign in' }).click();
  await target.getByRole('heading', { name: 'All items', level: 1 }).waitFor();
}

async function openItem(target: Page): Promise<void> {
  await target.getByRole('link', { name: new RegExp(ITEM.title) }).first().click();
  await target.getByRole('heading', { name: ITEM.title }).waitFor();
}

async function lock(target: Page): Promise<void> {
  await target.getByRole('button', { name: 'Lock now' }).first().click();
  await target.getByRole('heading', { name: 'Vault locked' }).waitFor();
}

async function openSettings(target: Page): Promise<void> {
  await target.getByRole('link', { name: 'Settings' }).click();
  await target.getByRole('heading', { name: 'Settings', level: 1 }).waitFor();
}

describe('the web vault on the real server', () => {
  it('signs up and shows the Recovery Kit with the server’s dev code', async () => {
    await page.goto(`${stack.webUrl}/signup`);
    await page.getByRole('textbox', { name: 'Email' }).fill(EMAIL);
    await page.getByRole('textbox', { name: 'Master password', exact: true }).fill(PASSWORD);
    await page.getByRole('textbox', { name: 'Confirm master password' }).fill(PASSWORD);
    await page.getByRole('button', { name: 'Continue' }).click();

    const devCode = page.getByRole('status').filter({ hasText: 'Development server' }).locator('strong');
    const code = (await devCode.innerText()).trim();
    expect(code).toMatch(/^\d{6}$/);
    await page.getByRole('textbox', { name: 'Verification code' }).fill(code);
    await page.getByRole('button', { name: 'Verify email' }).click();

    const kit = page.getByRole('article', { name: 'Octa Pass Recovery Kit' });
    await kit.waitFor();
    secretKey = (await kit.getByRole('definition').nth(2).innerText()).trim();
    expect(secretKey).toMatch(/^OP1-[0-9A-Z]{6}-[0-9A-Z]{6}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{4}$/);
    expect(await kit.innerText()).toContain(stack.server.url);

    await page.getByRole('checkbox', { name: /saved my Recovery Kit/ }).check();
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByRole('button', { name: 'Open my vault' }).click();
    await page.getByRole('heading', { name: 'Nothing here yet' }).waitFor();
  });

  it('saves a login that the server stores only as ciphertext', async () => {
    await page.getByRole('button', { name: 'New item' }).click();
    await page.getByRole('menuitem', { name: 'Login' }).click();
    await page.getByRole('textbox', { name: 'Title' }).fill(ITEM.title);
    await page.getByRole('textbox', { name: 'Username' }).fill(ITEM.username);
    await page.getByRole('textbox', { name: 'Password', exact: true }).fill(ITEM.password);
    await page.getByRole('textbox', { name: 'Website' }).first().fill(ITEM.url);
    await page.getByRole('textbox', { name: 'Notes' }).fill(ITEM.note);
    await page.getByRole('button', { name: 'Save' }).click();
    await page.getByRole('heading', { name: ITEM.title }).waitFor();

    const stored = serverFiles();
    expect(stored.includes(EMAIL), 'the email is the account identifier, so it is stored').toBe(true);
    for (const plaintext of [ITEM.title, ITEM.url, new URL(ITEM.url).hostname, ITEM.username, ITEM.password, ITEM.note, PASSWORD, secretKey]) {
      expect(stored.includes(plaintext), `server data contains ${JSON.stringify(plaintext)}`).toBe(false);
    }
    const db = database();
    expect((db.prepare('SELECT count(*) AS n FROM items').get() as { n: number }).n).toBe(1);
    db.close();
  });

  it('locks, and unlocks with the master password', async () => {
    await lock(page);
    await page.getByRole('textbox', { name: 'Master password' }).fill('not my password');
    await page.getByRole('button', { name: 'Unlock', exact: true }).click();
    await page.getByText(/don’t match an account/).waitFor();
    await page.getByRole('textbox', { name: 'Master password' }).fill(PASSWORD);
    await page.getByRole('button', { name: 'Unlock', exact: true }).click();
    await openItem(page);
  });

  it('signs out, and signs in again with the Secret Key', async () => {
    await openSettings(page);
    await page.getByRole('button', { name: 'Sign out' }).click();
    const confirm = page.getByRole('dialog');
    if (await confirm.isVisible().catch(() => false)) await confirm.getByRole('button', { name: 'Sign out' }).click();
    await page.getByRole('heading', { name: 'Welcome back' }).waitFor();
    await signIn(page, true);
    await openItem(page);
    expect(await page.getByText(ITEM.username).first().isVisible()).toBe(true);
  });

  it('unlocks with the device (a virtual platform authenticator with PRF)', async () => {
    const cdp: CDPSession = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, hasPrf: true, automaticPresenceSimulation: true },
    });

    await openSettings(page);
    await page.getByRole('switch', { name: /Unlock with/ }).click();
    await page.getByText(/is on for this browser/).first().waitFor();
    await lock(page);
    // The lock screen starts the device prompt by itself; the authenticator answers at once.
    await page.getByRole('heading', { name: 'Settings', level: 1 }).waitFor();
  });

  it('syncs an edit made on a second device', async () => {
    await page.getByRole('link', { name: /^All items/ }).click();
    await openItem(page);
    await page.getByText(ITEM.note).waitFor();

    const other = await stack.browser.newContext({ viewport: { width: 390, height: 844 } });
    const phone = await other.newPage();
    await signIn(phone, true);
    await openItem(phone);
    await phone.getByRole('link', { name: 'Edit' }).or(phone.getByRole('button', { name: 'Edit' })).first().click();
    await phone.getByRole('textbox', { name: 'Notes' }).fill(EDITED_NOTE);
    await phone.getByRole('button', { name: 'Save' }).click();
    await phone.getByText(EDITED_NOTE).waitFor();
    await other.close();

    // The vault syncs when the tab gets focus (and every 30 s while visible).
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    await page.getByText(EDITED_NOTE).waitFor();
  });

  it('deletes the account and leaves nothing behind on the server', async () => {
    let db = database();
    const { id: accountId } = db.prepare('SELECT id FROM accounts WHERE email = ?').get(EMAIL) as { id: string };
    db.close();

    await openSettings(page);
    await page.getByRole('button', { name: 'Delete account' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Continue' }).click();
    await dialog.getByRole('textbox', { name: `Type ${EMAIL}` }).fill(EMAIL);
    await dialog.getByRole('textbox', { name: 'Master password' }).fill(PASSWORD);
    await dialog.getByRole('button', { name: 'Delete account permanently' }).click();
    await page.getByRole('heading', { name: 'Your account has been deleted' }).waitFor();

    db = database();
    const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as { name: string }[]).map((t) => t.name);
    for (const table of tables) {
      for (const row of db.prepare(`SELECT * FROM "${table}"`).all()) {
        const text = JSON.stringify(row);
        expect(text.includes(accountId) || text.includes(EMAIL), `${table} still references the account: ${text}`).toBe(false);
      }
    }
    db.close();
    const local = await page.evaluate(
      () =>
        new Promise<string>((resolve, reject) => {
          const open = indexedDB.open('octapass');
          open.onerror = () => reject(open.error);
          open.onsuccess = () => {
            const all = open.result.transaction('kv', 'readonly').objectStore('kv').getAll();
            all.onsuccess = () => resolve(JSON.stringify(all.result));
          };
        }),
    );
    expect(local.includes(EMAIL) || local.includes(accountId), `this browser still holds the account: ${local}`).toBe(false);

    await page.getByRole('button', { name: 'Back to the start' }).click();
    await page.getByRole('heading', { name: 'Welcome back' }).waitFor();
    await page.goto(`${stack.webUrl}/signup`);
    await page.getByRole('textbox', { name: 'Email' }).fill(EMAIL);
    await page.getByRole('textbox', { name: 'Master password', exact: true }).fill(PASSWORD);
    await page.getByRole('textbox', { name: 'Confirm master password' }).fill(PASSWORD);
    await page.getByRole('button', { name: 'Continue' }).click();
    const code = (await page.getByRole('status').filter({ hasText: 'Development server' }).locator('strong').innerText()).trim();
    await page.getByRole('textbox', { name: 'Verification code' }).fill(code);
    await page.getByRole('button', { name: 'Verify email' }).click();
    await page.getByRole('heading', { name: 'Save your Recovery Kit' }).waitFor();
  });
});
