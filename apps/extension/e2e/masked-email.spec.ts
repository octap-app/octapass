// "Use a masked email" on a sign-up form, end to end: the provider is a local stand-in for a
// self-hosted SimpleLogin, so nothing reaches the real service.
//
//   pnpm --filter @octapass/extension e2e masked-email

import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import { expect, test } from '@playwright/test';
import { launchExtension, openApp, openMenu, pagesPort as port, pickFirstSuggestion, signIn, testAccount, WORKER_WAIT, type Extension } from './helpers';

const TOKEN = 'sl-e2e-token';
const ALIAS = 'aliasdemo.q8w1@sl.test';

let extension: Extension;
let provider: Server;
let providerUrl: string;
const calls: { url: string; headers: IncomingHttpHeaders; body: string }[] = [];

// Steps that go through the inline menu or a save prompt wait for the service worker (helpers.ts).
test.describe.configure({ mode: 'serial', timeout: 240_000 });

test.beforeAll(async () => {
  provider = createServer((request, response) => {
    let body = '';
    request.on('data', (chunk: Buffer) => (body += chunk.toString()));
    request.on('end', () => {
      calls.push({ url: request.url ?? '', headers: request.headers, body });
      const ok = request.method === 'POST' && request.url?.startsWith('/api/alias/random/new') && request.headers.authentication === TOKEN;
      response.writeHead(ok ? 201 : 401, { 'content-type': 'application/json' }).end(JSON.stringify(ok ? { alias: ALIAS, id: 314 } : { error: 'Wrong api key' }));
    });
  });
  await new Promise<void>((resolve) => provider.listen(0, '127.0.0.1', resolve));
  const address = provider.address();
  providerUrl = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
  extension = await launchExtension();
  await signIn(extension, testAccount('masked'));
});

test.afterAll(async () => {
  await extension?.context.close();
  provider?.close();
});

test('shows "Use a masked email" as needing setup until a provider is connected', async () => {
  const page = await extension.context.newPage();
  await page.goto(`http://join.maskless.test:${port()}/signup.html`);
  await openMenu(page, '#email');
  // The menu's shadow root is closed; its accessibility tree shows the entries.
  const cdp = await extension.context.newCDPSession(page);
  const options = async () => {
    const { nodes } = await cdp.send('Accessibility.getFullAXTree');
    return nodes.filter((n) => n.role?.value === 'option').map((n) => ({ name: String(n.name?.value ?? ''), disabled: n.properties?.some((p) => p.name === 'disabled' && p.value.value === true) ?? false }));
  };
  await expect.poll(options, { timeout: WORKER_WAIT }).toContainEqual({ name: expect.stringContaining('Use a masked email'), disabled: true });
  await cdp.detach();
  expect(calls).toEqual([]);
  await page.close();
});

test('connects a provider from the app tab’s settings', async () => {
  const app = await openApp(extension);
  await app.getByRole('link', { name: 'Settings' }).click();
  const form = app.getByRole('form', { name: 'Connect a provider' });
  await form.getByLabel('Provider').selectOption('simplelogin');
  await form.getByLabel('API token').fill(TOKEN);
  await form.getByLabel('Self-hosted server (optional)').fill(providerUrl);
  await form.getByRole('button', { name: 'Connect' }).click();
  await expect(app.getByRole('region', { name: 'Providers' }).getByRole('button', { name: 'Disconnect' })).toBeVisible();
  await app.close();
});

test('fills a new alias on a sign-up form and links it to the login it saves', async () => {
  const page = await extension.context.newPage();
  await page.goto(`http://join.aliasdemo.test:${port()}/signup.html`);
  await pickFirstSuggestion(page, '#email');
  await expect(page.locator('#email')).toHaveValue(ALIAS, { timeout: WORKER_WAIT });

  // The worker called the provider directly, with the token and the site's domain.
  expect(calls).toHaveLength(1);
  expect(calls[0]!.url).toBe('/api/alias/random/new?hostname=aliasdemo.test');
  expect(calls[0]!.headers.authentication).toBe(TOKEN);
  expect(calls[0]!.headers.cookie).toBeUndefined();
  expect(JSON.parse(calls[0]!.body)).toEqual({ note: 'aliasdemo.test' });

  // A suggested password saves the login at once, with the alias as its recovery email.
  await pickFirstSuggestion(page, '#new');
  await expect(page.locator('#confirm')).not.toHaveValue('', { timeout: WORKER_WAIT });
  const app = await openApp(extension, { tabOf: page });
  await app.getByRole('button', { name: /^join\.aliasdemo\.test/ }).click();
  await expect(app.getByText('Masked email from SimpleLogin')).toBeVisible();
  await expect(app.getByText(ALIAS).first()).toBeVisible();
  await app.close();
  await page.close();
});
