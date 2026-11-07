// The autofill corpus (tools/autofill-corpus) through the real extension: content script, service
// worker matching and the vault, instead of the corpus runner's fake host. Every fill scenario of
// every page runs on a fresh load, and the suite reports an accuracy score.
//
// Differences from the corpus runner's fixtures, by design: a suggested password is random (both
// new-password fields must hold the same one), a one-time code is the login's real TOTP code, and
// the identity model has no organization field, so that value is expected to stay empty.

import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { expect, test, type Page } from '@playwright/test';
import { launchExtension, pagesPort, signIn, testAccount, type Extension } from './helpers';

interface Fill {
  focus: string;
  pick: string;
  expect?: Record<string, string>;
  refused?: boolean;
}

const CORPUS = new URL('../../../tools/autofill-corpus/pages/', import.meta.url).pathname;
const GENERATED = 'Lantern-ruby-T7#qv-42';
const CODE = '123456';
const ORGANIZATION = 'Example Labs';
/** Below this share of passing checks, the suite fails (the engine's own corpus runner is at 100%). */
const MIN_ACCURACY = 0.9;
/** How long one try waits for the menu, then for the fill: a miss is tried once more. */
const ANSWER_WAIT = 20_000;

const core = createRequire(import.meta.url)('@octapass/core/node') as { totpCode: (secret: string, at: number) => { code: string } };
const totp = () => core.totpCode('JBSWY3DPEHPK3PXP', Math.floor(Date.now() / 1000)).code;

const pages = readdirSync(CORPUS)
  .filter((name) => name.endsWith('.json'))
  .map((name) => ({ slug: name.replace(/\.json$/, ''), fills: ((JSON.parse(readFileSync(`${CORPUS}${name}`, 'utf8')) as { fills?: Fill[] }).fills ?? []) }))
  .filter((page) => page.fills.length > 0);

let extension: Extension;

test.beforeAll(async () => {
  extension = await launchExtension();
  await signIn(extension, testAccount('corpus'));
});

test.afterAll(() => extension?.context.close());

/** `a >>> b` selectors through open shadow roots and same-origin frames, as in the corpus runner. */
function read(page: Page, selector: string): Promise<string | null> {
  return page.evaluate((selector) => {
    let root: Document | ShadowRoot = document;
    let element: Element | null = null;
    const parts = selector.split(' >>> ');
    for (let i = 0; i < parts.length; i++) {
      element = root.querySelector(parts[i]!);
      if (!element) return null;
      if (i < parts.length - 1) {
        const next: Document | ShadowRoot | null = element.shadowRoot ?? (element as HTMLIFrameElement).contentDocument;
        if (!next) return null;
        root = next;
      }
    }
    return element && 'value' in element && /^(INPUT|SELECT|TEXTAREA)$/.test(element.tagName) ? String((element as HTMLInputElement).value) : (element?.textContent?.trim() ?? null);
  }, selector);
}

function focus(page: Page, selector: string): Promise<boolean> {
  return page.evaluate((selector) => {
    let root: Document | ShadowRoot = document;
    let element: Element | null = null;
    for (const [i, part] of selector.split(' >>> ').entries()) {
      if (i > 0) root = (element!.shadowRoot ?? (element as HTMLIFrameElement).contentDocument)!;
      element = root.querySelector(part);
      if (!element) return false;
    }
    (element as HTMLElement).focus();
    return true;
  }, selector);
}

/** Whether the inline menu is open, in the page or one of its frames (its host element is there while it is). */
async function menuShowing(page: Page): Promise<boolean> {
  const found = await Promise.all(page.frames().map((frame) => frame.evaluate(() => document.querySelector('octapass-menu') !== null).catch(() => false)));
  return found.some(Boolean);
}

/** Polls `check` every 100 ms for up to `timeout` ms; says whether it came true. */
async function until(page: Page, check: () => Promise<boolean>, timeout: number): Promise<boolean> {
  for (const end = Date.now() + timeout; ; await page.waitForTimeout(100)) {
    if (await check()) return true;
    if (Date.now() > end) return false;
  }
}

/** What the extension should leave in each field, given the corpus's expectation. */
async function expected(page: Page, fill: Fill, value: string, code: string): Promise<string | RegExp> {
  if (value === GENERATED) return (await read(page, Object.keys(fill.expect!).find((s) => fill.expect![s] === GENERATED)!)) || /^.{12,}$/;
  if (value === CODE) return code;
  if (fill.pick === 'one-time-code' && /^\d$/.test(value) && CODE.includes(value)) return code[CODE.indexOf(value)]!;
  if (value === ORGANIZATION) return '';
  return value;
}

test('fills the autofill corpus through the extension', async () => {
  // Every fill waits for the service worker's answers, which on a busy machine take seconds each.
  test.setTimeout(45 * 60_000);
  const results: { name: string; ok: boolean; detail?: string }[] = [];
  for (const { slug, fills } of pages) {
    for (const fill of fills) {
      const name = `${slug}: ${fill.pick} from ${fill.focus}`;
      const page = await extension.context.newPage();
      try {
        await page.goto(`http://corpus.test:${pagesPort()}/${slug}.html`, { waitUntil: 'load' });
        await page.waitForTimeout(300);
        const before = Object.fromEntries(await Promise.all(Object.keys(fill.expect ?? {}).map(async (s) => [s, await read(page, s)] as const)));
        const unchanged = async () => (await Promise.all(Object.keys(before).map(async (s) => (await read(page, s)) === before[s]))).every(Boolean);
        // The menu opens, and a pick fills, once the service worker answers, which takes seconds on
        // a busy machine. A refused fill opens no menu (or fills nothing), so it waits less.
        const pick = async () => {
          if (!(await focus(page, fill.focus))) throw new Error(`no element for ${fill.focus}`);
          await page.keyboard.press('ArrowDown');
          await until(page, () => menuShowing(page), fill.refused ? 2000 : ANSWER_WAIT);
          // The engine ignores picks in the first 250 ms after the menu appears.
          await page.waitForTimeout(400);
          await page.keyboard.press('Enter');
          if (fill.refused) await page.waitForTimeout(700);
          else await until(page, async () => !(await unchanged()), ANSWER_WAIT);
        };
        await pick();
        // The first pages also wait for the content script to start: if the menu wasn't up in time,
        // nothing changed, and the user would simply have pressed ArrowDown again.
        if (!fill.refused && (await unchanged())) {
          await page.keyboard.press('Escape');
          await pick();
        }
        const code = totp();
        const misses: string[] = [];
        for (const [selector, value] of Object.entries(fill.expect ?? {})) {
          const actual = await read(page, selector);
          const want = fill.refused ? before[selector] : await expected(page, fill, value, code);
          const ok = want instanceof RegExp ? want.test(actual ?? '') : actual === want;
          if (!ok) misses.push(`${selector}: expected ${String(want)}, got ${JSON.stringify(actual)}`);
        }
        results.push({ name, ok: misses.length === 0, ...(misses.length ? { detail: misses.join('; ') } : {}) });
      } catch (error) {
        results.push({ name, ok: false, detail: String(error) });
      } finally {
        await page.close();
      }
    }
  }
  const passed = results.filter((r) => r.ok).length;
  const accuracy = passed / results.length;
  console.log(`Autofill corpus through the extension: ${passed}/${results.length} fills (${(accuracy * 100).toFixed(1)}%)`);
  for (const miss of results.filter((r) => !r.ok)) console.log(`  ✗ ${miss.name}: ${miss.detail}`);
  expect(accuracy).toBeGreaterThanOrEqual(MIN_ACCURACY);
});
