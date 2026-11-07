// The stack the e2e suite runs against: octapass-server in dev mode with its own data directory,
// a production build of the web vault on the real backend, and system Chrome.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { freePort, startServer, type TestServer } from '@octapass/vault-client/remote/testing/server';
import { chromium, type Browser } from 'playwright-core';
import { build, preview, type PreviewServer } from 'vite';

// System Chrome on a Mac; elsewhere (CI) Playwright's own Chromium, from `playwright install chromium`.
export const CHROME: string | undefined =
  process.env.CHROME_PATH ??
  (process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : undefined);
const WEB_ROOT = resolve(import.meta.dirname, '..');

export interface Stack {
  server: TestServer;
  webUrl: string;
  browser: Browser;
  stop: () => Promise<void>;
}

/** `serverEnv`: extra `OCTAPASS_*` settings for the server. */
export async function startStack({ serverEnv }: { serverEnv?: Record<string, string> } = {}): Promise<Stack> {
  const webPort = await freePort();
  const webUrl = `http://localhost:${webPort}`;
  const server = await startServer({ webOrigins: [webUrl], ...(serverEnv ? { env: serverEnv } : {}) });

  const outDir = mkdtempSync(join(tmpdir(), 'octapass-web-'));
  process.env.VITE_VAULT_BACKEND = 'remote';
  process.env.VITE_SERVER_URL = server.url;
  await build({ root: WEB_ROOT, logLevel: 'warn', build: { outDir, emptyOutDir: true, sourcemap: false } });
  const web: PreviewServer = await preview({ root: WEB_ROOT, logLevel: 'warn', build: { outDir }, preview: { port: webPort, strictPort: true, host: 'localhost' } });

  const browser = await chromium.launch({ executablePath: CHROME, headless: process.env.HEADED !== '1' });
  return {
    server,
    webUrl,
    browser,
    stop: async () => {
      await browser.close();
      await web.close();
      await server.stop();
      rmSync(outDir, { recursive: true, force: true });
    },
  };
}
