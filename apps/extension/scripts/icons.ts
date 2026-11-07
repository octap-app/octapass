// Renders the toolbar and store icons from brand/logo-tile.svg into public/icons/, with
// Playwright's Chromium (`pnpm exec playwright install chromium` once). Rerun after a logo change.
//
//   node scripts/icons.ts

import { mkdirSync, readFileSync } from 'node:fs';
import { chromium } from '@playwright/test';

const SIZES = [16, 32, 48, 128];
const svg = readFileSync(new URL('../../../brand/logo-tile.svg', import.meta.url), 'utf8');
const out = new URL('../public/icons/', import.meta.url).pathname;
mkdirSync(out, { recursive: true });

const browser = await chromium.launch();
for (const size of SIZES) {
  const page = await browser.newPage({ viewport: { width: size, height: size } });
  await page.setContent(`<style>html,body{margin:0;background:transparent}svg{display:block;width:${size}px;height:${size}px}</style>${svg}`);
  await page.locator('svg').screenshot({ path: `${out}icon-${size}.png`, omitBackground: true });
  await page.close();
}
await browser.close();
console.log(`Icons in ${out}`);
