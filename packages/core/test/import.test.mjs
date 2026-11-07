// Importers, URL matching and password rules through WASM.
// Run `pnpm --filter @octapass/core build` first.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';

const core = createRequire(import.meta.url)('../dist/node/octapass_core.js');
const fixture = (name) => readFileSync(new URL(`../../../crates/octapass-core/tests/import-fixtures/${name}`, import.meta.url));

test('importFile parses an export into items', () => {
  const result = core.importFile('chrome', fixture('chrome.csv'));
  assert.equal(result.items.length, 6);
  assert.deepEqual(result.items[0], {
    overview: { schemaVersion: 1, title: 'github.com', type: 'login', urls: ['https://github.com/login'], subtitle: 'octocat' },
    details: { schemaVersion: 1, username: 'octocat', password: 'pa,ss"word' },
  });
  assert.equal(result.items[1].details.notes, 'ملاحظة بالعربية\nسطر ثاني');
  assert.deepEqual(result.totpUpdates, []);
  assert.equal(result.skipped, 0);
});

test('importFile reports the wrong format with a sentence', () => {
  assert.throws(() => core.importFile('firefox', fixture('chrome.csv')), {
    name: 'OctaPassError',
    code: 'invalid_import_file',
    message: /Firefox/,
  });
  assert.throws(() => core.importFile('nope', fixture('chrome.csv')), { code: 'invalid_argument' });
});

test('password-protected Bitwarden exports', () => {
  const bytes = fixture('bitwarden-encrypted-pbkdf2.json');
  assert.throws(() => core.importFile('bitwarden-json', bytes), { code: 'import_password_required' });
  assert.throws(() => core.importFile('bitwarden-json', bytes, { password: 'nope' }), { code: 'wrong_import_password' });
  const result = core.importFile('bitwarden-json', bytes, { password: 'correct horse battery staple' });
  assert.deepEqual(result.items, core.importFile('bitwarden-json', fixture('bitwarden.json')).items);
  assert.deepEqual(result.items[0].overview.urlMatch, { 'https://gist.github.com': 'host', '^https://([a-z]+\\.)?github\\.com/': 'regex' });
});

test('generic CSV: preview, then import with a mapping', () => {
  const bytes = new TextEncoder().encode('c1,c2,c3,c4\nhttps://a.example,alice,secret,extra\n');
  const preview = core.previewCsv(bytes);
  assert.deepEqual(preview.headers, ['c1', 'c2', 'c3', 'c4']);
  assert.deepEqual(preview.suggested, {});
  assert.equal(preview.delimiter, ',');
  const result = core.importFile('generic-csv', bytes, { columns: { url: 'c1', username: 'c2', password: 'c3' } });
  assert.deepEqual(result.items[0].details.customFields, [{ label: 'c4', value: 'extra', hidden: false }]);
});

test('authenticator links join existing logins', () => {
  const id = core.newId();
  const result = core.importFile('otpauth', fixture('otpauth.txt'), {
    existingLogins: [{ id, title: 'Code host', urls: ['https://github.com'] }],
  });
  assert.equal(result.totpUpdates.length, 1);
  assert.equal(result.totpUpdates[0].itemId, id);
  assert.match(result.totpUpdates[0].totp, /^otpauth:\/\/totp\/GitHub:octocat\?secret=JBSWY3DPEHPK3PXP/);
  assert.equal(core.totpCode(result.totpUpdates[0].totp, 59).code.length, 6);
  assert.deepEqual(result.items.map((i) => i.overview.title), ['Example Bank', 'بنك', 'ACME', 'bob']);
});

test('matchItems ranks and refuses look-alikes', () => {
  const items = [
    { id: 'youtube', title: 'YouTube', type: 'login', urls: ['https://youtube.com'] },
    { id: 'google', urls: ['https://google.com'] },
    { id: 'accounts', urls: ['https://accounts.google.com'], urlMatch: { 'https://accounts.google.com': 'host' } },
    { id: 'none' },
  ];
  assert.deepEqual(core.matchItems('https://accounts.google.com/signin', items), [
    { id: 'accounts', url: 'https://accounts.google.com', quality: 'exact', schemeMismatch: false },
    { id: 'google', url: 'https://google.com', quality: 'domain', schemeMismatch: false },
    { id: 'youtube', url: 'https://youtube.com', quality: 'equivalent', schemeMismatch: false },
  ]);
  assert.deepEqual(core.matchItems('https://accounts.google.com', items, { defaultEquivalents: false }).map((m) => m.id), ['accounts', 'google']);
  assert.deepEqual(core.matchItems('https://google.com.evil.io/', items), []);
  assert.equal(core.matchItems('http://google.com', items)[0].schemeMismatch, true);
  assert.throws(() => core.matchItems('javascript:alert(1)', items), { code: 'invalid_url' });
  assert.equal(core.registrableDomain('https://user.github.io/x'), 'user.github.io');
  assert.equal(core.registrableDomain('BÜCHER.de'), 'xn--bcher-kva.de');
  assert.equal(core.registrableDomain('http://192.168.1.1'), undefined);
});

test('password rules: parse, look up and generate', () => {
  const rules = core.parsePasswordRules('minlength: 10; maxlength: 12; required: digit; required: [-_]; allowed: lower;');
  assert.deepEqual(rules, {
    minLength: 10,
    maxLength: 12,
    required: [{ named: ['digit'], custom: '' }, { named: [], custom: '-_' }],
    allowed: { named: ['lower'], custom: '' },
  });
  for (let i = 0; i < 20; i++) {
    const password = core.generateForRules(rules, { length: 30 });
    assert.match(password, /^[a-z0-9_-]{12}$/);
    assert.match(password, /\d/);
    assert.match(password, /[-_]/);
  }
  assert.equal(core.generateForRules(core.parsePasswordRules('')).length, 20);
  assert.throws(() => core.generateForRules(core.parsePasswordRules('minlength: 9; maxlength: 8')), { code: 'invalid_password_rules' });

  const site = core.passwordRulesTextForSite('https://mail.163.com/login');
  assert.equal(site, 'minlength: 6; maxlength: 16;');
  assert.equal(core.passwordRulesTextForSite('https://example.com'), undefined);
  const combined = core.parsePasswordRules(`${site} minlength: 8`);
  assert.deepEqual([combined.minLength, combined.maxLength], [8, 16]);
});
