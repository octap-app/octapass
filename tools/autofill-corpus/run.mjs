#!/usr/bin/env node
// Runs @octapass/autofill against every corpus page in the system Chrome and prints an accuracy score.
// Usage: node run.mjs [name-filter] [--min-accuracy 0.95] [--verbose]   (see README.md)

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { dirname, extname, join, normalize } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pagesDir = join(here, 'pages');
const packageDir = join(here, '../../packages/autofill');
const require = createRequire(join(packageDir, 'package.json'));

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const option = (name, fallback) => {
  const at = args.indexOf(name);
  return at >= 0 && args[at + 1] ? args[at + 1] : fallback;
};
const minAccuracy = Number(option('--min-accuracy', '1'));
const verbose = flag('--verbose');
const filter = args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--min-accuracy');

// ---- bundle the engine ----

async function bundle() {
  const { build } = await import(pathToFileURL(require.resolve('vite')).href);
  const output = await build({
    configFile: false,
    logLevel: 'silent',
    build: {
      write: false,
      minify: false,
      target: 'es2022',
      lib: { entry: join(packageDir, 'src/index.ts'), formats: ['iife'], name: 'OctaPassAutofill', fileName: 'autofill' },
    },
  });
  const result = Array.isArray(output) ? output[0] : output;
  return result.output[0].code;
}

// ---- serve the pages on two origins ----

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.json': 'application/json', '.css': 'text/css' };

function serve(crossOrigin) {
  const server = createServer((req, res) => {
    const path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname)).replace(/^([/\\])+/, '');
    const file = join(pagesDir, path);
    if (!file.startsWith(pagesDir) || !existsSync(file)) {
      res.writeHead(404).end('not found');
      return;
    }
    let body = readFileSync(file);
    if (extname(file) === '.html') body = body.toString('utf8').replaceAll('{{CROSS_ORIGIN}}', crossOrigin());
    res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream', 'cache-control': 'no-store' });
    res.end(body);
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

// ---- the in-page harness ----

const FIXTURES = {
  login: {
    suggestion: { kind: 'login', id: 'login-1', title: 'Corpus login', username: 'alex@example.test' },
    values: { username: 'alex@example.test', 'current-password': 'correct-horse-42!' },
  },
  'generated-password': { suggestion: { kind: 'generated-password', id: 'gen-1', password: 'Lantern-ruby-T7#qv-42' } },
  'one-time-code': {
    suggestion: { kind: 'one-time-code', id: 'otp-1', title: 'Corpus login' },
    values: { 'one-time-code': '123456' },
  },
  card: {
    suggestion: { kind: 'card', id: 'card-1', title: 'Corpus Visa', subtitle: '•••• 1111' },
    values: { 'cc-name': 'Alex Doe', 'cc-number': '4111111111111111', 'cc-exp': '09/29', 'cc-csc': '123' },
  },
  identity: {
    suggestion: { kind: 'identity', id: 'id-1', title: 'Alex Doe', subtitle: '1 Test Street' },
    values: {
      name: 'Alex Doe', 'given-name': 'Alex', 'family-name': 'Doe', email: 'alex@example.test', tel: '+15555550100',
      organization: 'Example Labs', 'address-line1': '1 Test Street', 'address-line2': 'Apt 2',
      'address-level2': 'Springfield', 'address-level1': 'CA', 'postal-code': '90210', country: 'US', bday: '1990-04-12',
    },
  },
  'bank-account': {
    suggestion: { kind: 'bank-account', id: 'bank-1', title: 'Corpus Bank', subtitle: '•••• 3000' },
    values: {
      'bank-account-holder': 'Alex Doe', iban: 'DE89 3704 0044 0532 0130 00', bic: 'COBADEFFXXX', 'bank-name': 'Example Bank',
      'bank-account-number': '31926819', 'bank-routing': '12-34-56',
    },
  },
  database: {
    suggestion: { kind: 'database', id: 'db-1', title: 'Corpus database', subtitle: 'db.example.test' },
    values: { 'db-host': 'db.example.test', 'db-port': '5432', 'db-name': 'shop', username: 'shop_admin', 'current-password': 'db-pass-77!' },
  },
  'software-license': {
    suggestion: { kind: 'software-license', id: 'lic-1', title: 'Corpus Editor', subtitle: 'Alex Doe' },
    values: { 'license-key': 'CRPS-7Q2W-9X4K-ZT8M' },
  },
};

/** Runs in the page after the engine bundle: a fake host that records everything. */
function harness(fixtures) {
  const state = { pick: null, saves: [], blocked: [], fills: [], frames: [], requests: [] };
  window.__corpus = state;
  const start = () => {
    window.__engine = window.OctaPassAutofill.createAutofill({
      host: {
        async getSuggestions(request) {
          state.requests.push(request);
          return state.pick ? [fixtures[state.pick].suggestion] : [];
        },
        async resolve(suggestion) {
          return Object.values(fixtures).find((f) => f.suggestion.id === suggestion.id)?.values ?? null;
        },
        onSave: (report) => state.saves.push(report),
        onSaveDetails: (report) => state.saves.push(report),
        onBlocked: (reason) => state.blocked.push(reason),
        onFrame: (frame) => state.frames.push(frame.element),
      },
      onFill: (result) => state.fills.push({ filled: result.filled.length, skipped: result.skipped.map((s) => s.reason) }),
    });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
}

/** Resolves `a >>> b` selectors through open shadow roots and frames. Runs in the page. */
function resolver() {
  window.__resolve = (selector) => {
    let root = document;
    let element = null;
    const parts = selector.split(' >>> ');
    for (let i = 0; i < parts.length; i++) {
      element = root.querySelector(parts[i]);
      if (!element) return null;
      if (i < parts.length - 1) {
        root = element.shadowRoot ?? element.contentDocument;
        if (!root) return null;
      }
    }
    return element;
  };
  window.__read = (selector) => {
    const element = window.__resolve(selector);
    if (!element) return null;
    return 'value' in element && /^(INPUT|SELECT|TEXTAREA)$/.test(element.tagName) ? element.value : element.textContent.trim();
  };
}

// ---- checks ----

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function open(context, url, code) {
  const page = await context.newPage();
  // Init scripts run wrapped in a function, so the bundle's `var` needs exporting by hand.
  const content = `${code}\nwindow.OctaPassAutofill = OctaPassAutofill;\n(${resolver})();\n(${harness})(${JSON.stringify(FIXTURES)});`;
  await page.addInitScript({ content });
  await page.goto(url, { waitUntil: 'load' });
  await sleep(250);
  return page;
}

async function classification(page, spec) {
  return page.evaluate((spec) => {
    const scan = window.__engine.scan();
    const fieldOf = (element) => {
      for (const form of scan.forms) {
        const field = form.fields.find((f) => f.element === element);
        if (field) return { field, form };
      }
      return undefined;
    };
    const checks = [];
    for (const [selector, expected] of Object.entries(spec.fields ?? {})) {
      const element = window.__resolve(selector);
      const found = element && fieldOf(element);
      const actual = !element ? 'missing element' : !found || !found.field.fillable ? 'none' : found.field.type;
      const ok = expected === 'none' ? actual === 'none' || actual === 'unknown' || actual === 'search' : actual === expected;
      checks.push({ kind: 'field', name: selector, ok, expected, actual, why: found && !ok ? window.__engine.explain(element)?.text : undefined });
    }
    for (const { field, type } of spec.forms ?? []) {
      const element = window.__resolve(field);
      const found = element && fieldOf(element);
      const actual = found ? found.form.type : 'no form';
      checks.push({ kind: 'form', name: field, ok: actual === type, expected: type, actual, why: found ? found.form.reasons.join('; ') : undefined });
    }
    for (const frame of spec.frames ?? []) {
      const element = window.__resolve(frame.selector);
      const reported = window.__corpus.frames.includes(element) || scan.frames.some((f) => f.element === element);
      checks.push({ kind: 'frame', name: frame.selector, ok: reported === frame.crossOrigin, expected: frame.crossOrigin, actual: reported });
    }
    return checks;
  }, spec);
}

async function focus(page, selector) {
  const ok = await page.evaluate((selector) => {
    const element = window.__resolve(selector);
    element?.focus();
    return !!element;
  }, selector);
  if (!ok) throw new Error(`no element for ${selector}`);
}

async function fill(context, url, code, scenario) {
  const page = await open(context, url, code);
  try {
    const before = {};
    for (const selector of Object.keys(scenario.expect ?? {})) before[selector] = await page.evaluate((s) => window.__read(s), selector);
    await page.evaluate((pick) => (window.__corpus.pick = pick), scenario.pick);
    await focus(page, scenario.focus);
    await page.keyboard.press('ArrowDown');
    await sleep(400);
    await page.keyboard.press('Enter');
    await sleep(400);
    const state = await page.evaluate(() => ({ blocked: window.__corpus.blocked, fills: window.__corpus.fills }));
    const mismatches = [];
    for (const [selector, expected] of Object.entries(scenario.expect ?? {})) {
      const actual = await page.evaluate((s) => window.__read(s), selector);
      const want = scenario.refused ? before[selector] : expected;
      if (actual !== want) mismatches.push(`${selector}: expected ${JSON.stringify(want)}, got ${JSON.stringify(actual)}`);
    }
    if (scenario.refused && state.blocked.length === 0) mismatches.push('expected a refusal, none reported');
    if (!scenario.refused && state.blocked.length > 0) mismatches.push(`refused: ${state.blocked.join(', ')}`);
    return { kind: 'fill', name: `${scenario.pick} from ${scenario.focus}`, ok: mismatches.length === 0, actual: mismatches.join('; '), why: JSON.stringify(state) };
  } finally {
    await page.close();
  }
}

async function element(page, selector) {
  const handle = await page.evaluateHandle((s) => window.__resolve(s), selector);
  const result = handle.asElement();
  if (!result) throw new Error(`no element for ${selector}`);
  return result;
}

async function save(context, url, code, scenario, index) {
  const page = await open(context, url, code);
  try {
    for (const step of scenario.steps) {
      if (step.type) {
        await focus(page, step.type[0]);
        await page.keyboard.type(step.type[1], { delay: 5 });
      } else if (step.select) {
        await (await element(page, step.select[0])).selectOption(step.select[1]);
      } else if (step.click) {
        await (await element(page, step.click)).click();
      } else if (step.press) {
        await page.keyboard.press(step.press);
      } else if (step.wait) {
        await sleep(step.wait);
      }
    }
    const deadline = Date.now() + 1500;
    let saves = [];
    while (Date.now() < deadline) {
      saves = await page.evaluate(() => window.__corpus.saves.filter((s) => !s.draft));
      if (saves.length > 0 && scenario.expect !== 'none') break;
      await sleep(100);
    }
    let ok;
    let actual;
    if (scenario.expect === 'none') {
      ok = saves.length === 0;
      actual = ok ? 'none' : JSON.stringify(saves);
    } else {
      const got = saves[0];
      // An address or card report: the same kind and exactly these values. A login report: an empty
      // expected value means the report leaves that key out.
      const sorted = (values) => JSON.stringify(Object.entries(values ?? {}).sort());
      ok = scenario.expect.kind
        ? !!got && got.kind === scenario.expect.kind && sorted(got.values) === sorted(scenario.expect.values)
        : !!got && ['username', 'password', 'formType'].every((key) => (scenario.expect[key] || undefined) === got[key]);
      actual = got ? JSON.stringify(got) : 'no report';
    }
    return { kind: 'save', name: `save #${index + 1}`, ok, expected: scenario.expect, actual };
  } finally {
    await page.close();
  }
}

// ---- main ----

const chromePaths = [
  process.env.CHROME_PATH,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
].filter(Boolean);

async function main() {
  const executablePath = chromePaths.find((p) => existsSync(p));
  if (!executablePath) throw new Error('Chrome not found: set CHROME_PATH');
  const { chromium } = require('playwright-core');
  const code = await bundle();

  let alt;
  const main = await serve(() => `http://localhost:${alt.address().port}`);
  alt = await serve(() => `http://127.0.0.1:${main.address().port}`);
  const base = `http://127.0.0.1:${main.address().port}`;

  const browser = await chromium.launch({ executablePath, headless: !flag('--headed') });
  const specs = readdirSync(pagesDir)
    .filter((f) => f.endsWith('.json') && (!filter || f.includes(filter)))
    .sort();

  let passed = 0;
  let total = 0;
  for (const file of specs) {
    const name = file.replace(/\.json$/, '');
    const spec = JSON.parse(readFileSync(join(pagesDir, file), 'utf8'));
    const url = `${base}/${name}.html`;
    const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    const checks = [];
    try {
      const page = await open(context, url, code);
      checks.push(...(await classification(page, spec)));
      await page.close();
      for (const scenario of spec.fills ?? []) checks.push(await fill(context, url, code, scenario));
      for (const [i, scenario] of (spec.saves ?? []).entries()) checks.push(await save(context, url, code, scenario, i));
    } catch (error) {
      checks.push({ kind: 'page', name, ok: false, actual: String(error) });
    } finally {
      await context.close();
    }
    const ok = checks.filter((c) => c.ok).length;
    passed += ok;
    total += checks.length;
    console.log(`${ok === checks.length ? '✓' : '✗'} ${name}  ${ok}/${checks.length}`);
    for (const check of checks.filter((c) => !c.ok || verbose)) {
      console.log(`    ${check.ok ? '·' : '✗'} ${check.kind} ${check.name}: expected ${JSON.stringify(check.expected)}, got ${check.actual}`);
      if (check.why && verbose) console.log(check.why.replace(/^/gm, '        '));
    }
  }
  await browser.close();
  main.close();
  alt.close();

  const accuracy = total === 0 ? 0 : passed / total;
  console.log(`\nAccuracy: ${(accuracy * 100).toFixed(1)}% (${passed}/${total} checks, ${specs.length} pages)`);
  process.exitCode = accuracy >= minAccuracy ? 0 : 1;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
