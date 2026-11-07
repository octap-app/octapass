// Website icons on the real server in Chrome: the server fetches them from local test sites (their
// names reach this process through OCTAPASS_DEV_ICON_HOSTS), the list shows them in place of the
// initials, and "Show website icons" off brings the initials back with no requests. Screenshots of
// the list go to screenshots/.
//
//   pnpm --filter @octapass/web e2e siteIcons          (HEADED=1 to watch)

import { mkdirSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { crc32, deflateSync } from 'node:zlib';
import type { BrowserContext, Page } from 'playwright-core';
import { freePort } from '@octapass/vault-client/remote/testing/server';
import { startStack, type Stack } from './stack';

const SCREENSHOTS = new URL('../screenshots/', import.meta.url).pathname;
const PASSWORD = 'Lantern ruby quiet anchor 42';
const EMAIL = `icons-${Date.now()}@example.com`;

/** A 64 px PNG: a rounded square in one colour with a white bar, so each site looks different. */
function png(rgb: [number, number, number]): Buffer {
  const size = 64;
  const rows = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    rows[y * (size * 4 + 1)] = 0;
    for (let x = 0; x < size; x++) {
      const corner = Math.max(0, Math.abs(x - 31.5) - 18) ** 2 + Math.max(0, Math.abs(y - 31.5) - 18) ** 2 > 14 ** 2;
      const bar = y > 26 && y < 38 && x > 14 && x < 50;
      const o = y * (size * 4 + 1) + 1 + x * 4;
      const [r, g, b] = bar ? [255, 255, 255] : rgb;
      rows.set([r, g, b, corner ? 0 : 255], o);
    }
  }
  const chunk = (type: string, data: Buffer) => {
    const body = Buffer.concat([Buffer.from(type), data]);
    const out = Buffer.alloc(body.length + 8);
    out.writeUInt32BE(data.length, 0);
    body.copy(out, 4);
    out.writeUInt32BE(crc32(body), body.length + 4);
    return out;
  };
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header.set([8, 6, 0, 0, 0], 8);
  return Buffer.concat([Buffer.from('\x89PNG\r\n\x1a\n', 'latin1'), chunk('IHDR', header), chunk('IDAT', deflateSync(rows)), chunk('IEND', Buffer.alloc(0))]);
}

/** The test websites: three with icons (linked from the page, or only at /favicon.ico), one without. */
const SITES: Record<string, { page?: string; icons: Record<string, Buffer> }> = {
  'harbor-bank.com': { page: '<link rel="icon" sizes="64x64" href="/static/icon.png">', icons: { '/static/icon.png': png([16, 95, 168]) } },
  'lumen-mail.net': { page: '<link rel="apple-touch-icon" href="/touch.png">', icons: { '/touch.png': png([229, 72, 77]) } },
  'parcel-post.org': { icons: { '/favicon.ico': png([245, 166, 35]) } },
  'plain-site.com': { page: '<title>No icon</title>', icons: {} },
};

const login = (name: string, uri: string) => ({ type: 1, name, login: { username: 'maya', password: 'x', uris: [{ uri }] } });
const BITWARDEN = JSON.stringify({
  encrypted: false,
  items: [
    login('Harbor Bank', 'https://online.harbor-bank.com/login'),
    login('Lumen Mail', 'https://lumen-mail.net'),
    login('Parcel Post', 'https://www.parcel-post.org/track'),
    login('Plain Site', 'https://plain-site.com'),
    login('Home router', 'http://192.168.1.1'),
    { type: 2, name: 'Wi-Fi at home', notes: 'tangerine', secureNote: { type: 0 } },
  ],
});

let stack: Stack;
let sites: Server;
const contexts: BrowserContext[] = [];
let page: Page;
const iconRequests: string[] = [];

beforeAll(async () => {
  const sitesPort = await freePort();
  sites = createServer((request, response) => {
    const site = SITES[(request.headers.host ?? '').replace(/:\d+$/, '').replace(/^www\./, '')];
    const path = new URL(request.url ?? '/', 'http://x').pathname;
    if (site && path === '/' && site.page) return void response.writeHead(200, { 'content-type': 'text/html' }).end(`<!doctype html><html><head>${site.page}</head></html>`);
    const icon = site?.icons[path];
    if (icon) return void response.writeHead(200, { 'content-type': 'image/png' }).end(icon);
    response.writeHead(404).end();
  });
  await new Promise<void>((resolve) => sites.listen(sitesPort, '127.0.0.1', resolve));
  const hosts = Object.keys(SITES).flatMap((host) => [host, `www.${host}`]);
  stack = await startStack({ serverEnv: { OCTAPASS_ICONS: 'on', OCTAPASS_DEV_ICON_HOSTS: hosts.map((host) => `${host}=127.0.0.1:${sitesPort}`).join(',') } });
  mkdirSync(SCREENSHOTS, { recursive: true });
  const context = await stack.browser.newContext({ viewport: { width: 1280, height: 800 } });
  contexts.push(context);
  page = await context.newPage();
  page.on('request', (request) => {
    if (request.url().includes('/v1/icons/')) iconRequests.push(new URL(request.url()).pathname);
  });
});

afterAll(async () => {
  for (const context of contexts) await context.close();
  await stack?.stop();
  sites?.close();
});

async function shoot(name: string): Promise<void> {
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: `${SCREENSHOTS}${name}.png`, animations: 'disabled' });
}

const row = (title: string) => page.locator('a[data-item-id]').filter({ hasText: title });

describe('website icons', () => {
  it('signs up and imports logins for the test sites', async () => {
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

    await page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: 'Settings' }).click();
    await page.getByLabel('Import from').selectOption('bitwarden-json');
    await page.getByLabel('File', { exact: true }).setInputFiles({ name: 'bitwarden.json', mimeType: 'application/json', buffer: Buffer.from(BITWARDEN) });
    await page.getByRole('button', { name: 'Import', exact: true }).click();
    await page.getByText('Imported 6 items.').waitFor({ timeout: 30_000 });
  });

  it('shows each site’s icon through the server, and initials where there is none', async () => {
    await page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: 'All items' }).click();
    await page.getByRole('heading', { name: 'Logins 5 items', level: 2 }).waitFor();
    for (const title of ['Harbor Bank', 'Lumen Mail', 'Parcel Post']) await row(title).locator('img').waitFor({ timeout: 20_000 });
    expect(await row('Plain Site').locator('img').count()).toBe(0);
    expect(await row('Home router').locator('img').count()).toBe(0);
    expect(iconRequests.sort()).toEqual(['/v1/icons/harbor-bank.com', '/v1/icons/lumen-mail.net', '/v1/icons/parcel-post.org', '/v1/icons/plain-site.com']);
    await row('Harbor Bank').click();
    await page.getByRole('heading', { name: 'Harbor Bank', level: 1 }).waitFor();
    await shoot('list-site-icons');
    await page.emulateMedia({ colorScheme: 'dark' });
    await shoot('list-site-icons-dark');
    await page.emulateMedia({ colorScheme: 'light' });
  });

  it('keeps them on the device: a reload asks for nothing', async () => {
    iconRequests.length = 0;
    await page.reload();
    await page.getByRole('heading', { name: 'Vault locked' }).waitFor();
    await page.getByRole('textbox', { name: 'Master password' }).fill(PASSWORD);
    await page.getByRole('button', { name: 'Unlock', exact: true }).click();
    await row('Harbor Bank').locator('img').first().waitFor({ timeout: 20_000 });
    await page.waitForTimeout(500);
    expect(iconRequests).toEqual([]);
  });

  it('asks for nothing with Show website icons off', async () => {
    await page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: 'Settings' }).click();
    await page.getByRole('switch', { name: 'Show website icons' }).click();
    iconRequests.length = 0;
    await page.getByRole('navigation', { name: 'Vault' }).getByRole('link', { name: 'All items' }).click();
    await page.getByRole('heading', { name: 'Logins 5 items', level: 2 }).waitFor();
    await page.waitForTimeout(800);
    expect(await page.locator('a[data-item-id] img').count()).toBe(0);
    expect(iconRequests).toEqual([]);
  });
});
