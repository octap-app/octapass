// The generator end to end on a copy of the sources: it writes every file, `--check` passes, and
// `--check` fails naming a file that is stale or missing. Also: the committed files are current.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { appendFileSync, cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const GENERATE = fileURLToPath(new URL('../generate.mjs', import.meta.url));
const SOURCES = ['apps/web/src/i18n/en.ts', 'apps/web/src/i18n/ar.ts', 'apps/web/src/i18n/phone.ts', 'packages/ui/src/styles/tokens.css'];
const XML = 'apps/android/resources/src/main/res/values-ar/strings.xml';
const SWIFT = 'apps/ios/Packages/OctaPassResources/Sources/OctaPassResources/Tokens.swift';

const copy = mkdtempSync(join(tmpdir(), 'native-resources-root-'));
after(() => rmSync(copy, { recursive: true, force: true }));
for (const file of SOURCES) cpSync(join(ROOT, file), join(copy, file));

const run = (...args) => spawnSync(process.execPath, [GENERATE, ...args], { encoding: 'utf8' });

test('the committed files are up to date', () => {
  const result = run('--check');
  assert.equal(result.status, 0, result.stderr);
});

test('writes everything, then --check passes', () => {
  const first = run('--root', copy, '--check');
  assert.equal(first.status, 1);
  assert.match(first.stderr, /Localizable\.xcstrings \(missing\)/);
  const write = run('--root', copy);
  assert.equal(write.status, 0, write.stderr);
  assert.match(write.stdout, /Wrote:/);
  const check = run('--root', copy, '--check');
  assert.equal(check.status, 0, check.stderr);
  assert.match(check.stdout, /8 native resource files are up to date/);
});

test('--check fails on a stale or missing file and names it', () => {
  run('--root', copy);
  appendFileSync(join(copy, XML), '<!-- edited by hand -->\n');
  rmSync(join(copy, SWIFT));
  const check = run('--root', copy, '--check');
  assert.equal(check.status, 1);
  assert.match(check.stderr, new RegExp(`${XML.replaceAll('.', '\\.')}\\n`));
  assert.match(check.stderr, /Tokens\.swift \(missing\)/);
  assert.doesNotMatch(check.stderr, /Localizable\.xcstrings/);
  // Regenerating repairs both.
  run('--root', copy);
  assert.equal(run('--root', copy, '--check').status, 0);
});

test('a source change makes the outputs stale', () => {
  run('--root', copy);
  const css = join(copy, 'packages/ui/src/styles/tokens.css');
  writeFileSync(css, readFileSync(css, 'utf8').replace('--radius-sm: 0.5rem', '--radius-sm: 0.625rem'));
  const check = run('--root', copy, '--check');
  assert.equal(check.status, 1);
  assert.match(check.stderr, /Tokens\.swift/);
  assert.match(check.stderr, /Tokens\.kt/);
});
