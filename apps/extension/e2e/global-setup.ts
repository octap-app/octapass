// Starts octapass-server (dev mode, no rate limits) and the test pages, builds the extension against
// that server, and creates the accounts the tests sign in with (one per spec that signs in). Everything stops after the run.

import 'fake-indexeddb/auto';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { extname, join } from 'node:path';
import type { ItemDraft } from '@octapass/vault-client';
import { RemoteVaultService, VaultEngine, directClient, type Core } from '@octapass/vault-client/remote';
import { buildServer, freePort, startServer } from '@octapass/vault-client/remote/testing/server';
import { openKeyValueStore } from '../src/background/storage';
import { CORPUS_ITEMS, FRAME_LOGIN, ICON_HOSTS, ICON_ITEMS, LOGIN, PASSWORD, ROUTER, TEAM_LOGINS } from './data';

const ROOT = new URL('..', import.meta.url).pathname;
const PAGES = join(ROOT, 'e2e/pages');
/** The autofill corpus, served on corpus.test (and other.test for its cross-origin frames). */
const CORPUS = join(ROOT, '../../tools/autofill-corpus/pages');
/** QR code images (crates/octapass-core/tests/qr-fixtures), served under /qr/. */
const QR = join(ROOT, '../../crates/octapass-core/tests/qr-fixtures');
const TYPES: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.png': 'image/png' };

/** The websites the server fetches icons from (site-icons.spec.ts): one with an icon, one without. */
function iconSite(host: string, path: string): { type: string; body: string | Buffer } | undefined {
  const site = host.replace(/^www\./, '').replace(/:\d+$/, '');
  if (site === 'octapass-e2e.com' && path === '') return { type: TYPES['.html']!, body: '<!doctype html><html><head><link rel="icon" sizes="64x64" href="/site-icon.png"></head><body>Shop</body></html>' };
  if (site === 'octapass-e2e.com' && path === 'site-icon.png') return { type: TYPES['.png']!, body: readFileSync(join(PAGES, 'site-icon.png')) };
  if (site === 'octapass-e2e.net' && path === '') return { type: TYPES['.html']!, body: '<!doctype html><title>No icon here</title>' };
  return undefined;
}

/**
 * HTTP sign-in prompts (http-auth.spec.ts): router.test answers 401 with `WWW-Authenticate: Basic`
 * until it gets ROUTER's username and password, and elsewhere.test frames it. `/other-realm` names
 * another realm and takes nothing (the browser sends the router's cached credentials there first).
 */
function httpAuthSite(host: string, path: string, authorization: string | undefined, port: number): { status: number; headers: Record<string, string>; body: string } | undefined {
  const html = { 'content-type': TYPES['.html']! };
  if (host.startsWith('elsewhere.test') && path === 'frames-router.html') {
    return { status: 200, headers: html, body: `<!doctype html><title>Elsewhere</title><iframe id="router" src="http://router.test:${port}/framed"></iframe>` };
  }
  if (!host.startsWith('router.test')) return undefined;
  const realm = path === 'other-realm' ? 'Other' : ROUTER.realm;
  if (realm !== ROUTER.realm || authorization !== `Basic ${Buffer.from(`${ROUTER.username}:${ROUTER.password}`).toString('base64')}`) {
    return { status: 401, headers: { ...html, 'www-authenticate': `Basic realm="${realm}"` }, body: '<!doctype html><title>Locked</title><h1>Locked</h1>' };
  }
  return { status: 200, headers: html, body: '<!doctype html><title>Router</title><h1>Signed in to the router</h1>' };
}

export default async function setup(): Promise<() => Promise<void>> {
  buildServer();
  const pagesPort = await freePort();
  // The icon fetcher only connects to public addresses; dev mode lets these names reach the test pages.
  const iconHosts = ICON_HOSTS.map((host) => `${host}=127.0.0.1:${pagesPort}`).join(',');
  const server = await startServer({ env: { OCTAPASS_ICONS: 'on', OCTAPASS_DEV_ICON_HOSTS: iconHosts } });

  const build = spawnSync('node', ['scripts/build.ts', '--target', 'chrome'], { cwd: ROOT, stdio: 'inherit', env: { ...process.env, VITE_SERVER_URL: server.url } });
  if (build.status !== 0) throw new Error('extension build failed');

  // The account, made the way any client would, on a throwaway "device".
  const core = createRequire(import.meta.url)('@octapass/core/node') as Core;
  const kv = await openKeyValueStore('e2e-setup');
  const service = await RemoteVaultService.create(directClient((emit) => new VaultEngine({ loadCore: async () => core, storage: kv, emit })), { watch: () => () => undefined });
  /** A new account holding `items`, as signed up on this throwaway device. Each spec that signs in has its own. */
  const account = async (name: string, items: Omit<ItemDraft, 'vaultId'>[]) => {
    const email = `e2e-${name}-${Date.now()}@example.com`;
    const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: server.url, email, password: PASSWORD });
    const { recoveryKit } = await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
    const [vault] = await service.listVaults();
    for (const item of items) await service.saveItem({ vaultId: vault!.id, ...item });
    await service.signOut();
    return { email, secretKey: recoveryKit.secretKey };
  };
  const login = (title: string, url: string, username?: string, password = PASSWORD) => ({
    overview: { schemaVersion: 1 as const, title, type: 'login' as const, ...(username ? { subtitle: username } : {}), urls: [url] },
    details: { schemaVersion: 1 as const, ...(username ? { username } : {}), password },
  });
  // The main account's corpus login has a code of its own: two-step.html's QR code has the corpus
  // one, and an import leaves out a code the vault already has (extension.spec.ts adds it).
  const mainCorpus = CORPUS_ITEMS.map((item) => ('totp' in item.details ? { ...item, details: { ...item.details, totp: 'KRSXG5CTMVRXEZLU' } } : item));
  const main = await account('main', [...[LOGIN, FRAME_LOGIN, ...TEAM_LOGINS].map((l) => login(l.title, l.url, l.username, l.password)), ...mainCorpus]);
  // The corpus and masked email specs save items; their own accounts keep the main one's lists as extension.spec.ts expects.
  const corpus = await account('corpus', CORPUS_ITEMS);
  const masked = await account('masked', []);
  // The website icon tests (site-icons.spec.ts): sites with and without icons.
  const icons = await account('icons', ICON_ITEMS.map((l) => login(l.title, l.url, 'maya@example.test')));

  const pages = createServer((request, response) => {
    const icon = iconSite(request.headers.host ?? '', new URL(request.url ?? '/', 'http://x').pathname.replace(/^\/+/, ''));
    if (icon) return void response.writeHead(200, { 'content-type': icon.type }).end(icon.body);
    const auth = httpAuthSite(request.headers.host ?? '', new URL(request.url ?? '/', 'http://x').pathname.replace(/^\/+/, ''), request.headers.authorization, pagesPort);
    if (auth) return void response.writeHead(auth.status, auth.headers).end(auth.body);
    const path = new URL(request.url ?? '/', 'http://x').pathname.replace(/^\/+/, '') || 'login.html';
    const corpus = /^(corpus|other)\.test/.test(request.headers.host ?? '');
    try {
      const qr = path.startsWith('qr/');
      let body: string | Buffer = readFileSync(join(corpus ? CORPUS : qr ? QR : PAGES, (qr ? path.slice(3) : path).replace(/\.\./g, '')));
      if (corpus && path.endsWith('.html')) body = body.toString().replaceAll('{{CROSS_ORIGIN}}', `http://other.test:${pagesPort}`);
      response.writeHead(200, { 'content-type': TYPES[extname(path)] ?? 'application/octet-stream' }).end(body);
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise<void>((resolve) => pages.listen(pagesPort, '127.0.0.1', resolve));

  process.env.E2E_SERVER_URL = server.url;
  process.env.E2E_EMAIL = main.email;
  process.env.E2E_SECRET_KEY = main.secretKey;
  process.env.E2E_CORPUS_EMAIL = corpus.email;
  process.env.E2E_CORPUS_SECRET_KEY = corpus.secretKey;
  process.env.E2E_MASKED_EMAIL = masked.email;
  process.env.E2E_MASKED_SECRET_KEY = masked.secretKey;
  process.env.E2E_PAGES_PORT = String(pagesPort);
  process.env.E2E_ICONS_EMAIL = icons.email;
  process.env.E2E_ICONS_SECRET_KEY = icons.secretKey;

  return async () => {
    pages.close();
    await server.stop();
  };
}
