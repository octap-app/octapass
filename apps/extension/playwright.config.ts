import { defineConfig } from '@playwright/test';

// The built extension (dist/chrome) in Playwright's Chromium, against a local octapass-server and
// local test pages. Branded Chrome ignores --load-extension, so this needs
// `pnpm exec playwright install chromium` once.
export default defineConfig({
  testDir: 'e2e',
  globalSetup: './e2e/global-setup.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [['list']],
  use: { trace: 'retain-on-failure' },
});
