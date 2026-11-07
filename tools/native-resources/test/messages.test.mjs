import assert from 'node:assert/strict';
import { test } from 'node:test';
import { argumentsFor, buildMessages, expectations, flatten, mergeCatalogs, placeholders, toFormat } from '../lib/messages.mjs';
import { androidSpecifier } from '../lib/strings.mjs';

test('placeholders come in order of first appearance, once each', () => {
  assert.deepEqual(placeholders('{b} and {a}, then {b} again'), ['b', 'a']);
  assert.deepEqual(placeholders('no placeholders {} {not-a-name}'), []);
});

test('arguments are numbered by the English general form, then the other forms', () => {
  const args = argumentsFor('x', { one: '{extra} one of {total}', other: '{left} of {count}' });
  assert.deepEqual(
    args.map((a) => [a.position, a.name, a.kind]),
    [
      [1, 'left', 'int'],
      [2, 'count', 'int'],
      [3, 'extra', 'text'],
      [4, 'total', 'text'],
    ],
  );
});

test('a counted message always takes count, last if its text never shows it', () => {
  const args = argumentsFor('deleteAccount.sharedVaults', { one: 'Owner of {vaults}. It goes.', other: 'Owner of {vaults}. They go.' });
  assert.deepEqual(
    args.map((a) => [a.position, a.name, a.kind]),
    [
      [1, 'vaults', 'text'],
      [2, 'count', 'int'],
    ],
  );
});

test('numbers: count and count-like names, plus per-message overrides', () => {
  assert.equal(argumentsFor('editor.websiteN', 'Website {n}')[0].kind, 'int');
  assert.equal(argumentsFor('settings.storageUsed', '{used} of {total} used')[1].kind, 'text');
  assert.equal(argumentsFor('signUp.stepOf', 'Step {step} of {total}')[1].kind, 'int');
  assert.equal(argumentsFor('emergency.receivedIdle', 'opens after {days}.')[0].kind, 'text');
  assert.equal(argumentsFor('trash.note', 'after {days} days.')[0].kind, 'int');
});

test('format strings escape % only when they take arguments', () => {
  const args = argumentsFor('k', '{name} is 100% {count}');
  assert.equal(toFormat('{name} is 100% {count}', args, androidSpecifier), '%1$s is 100%% %2$d');
  assert.equal(toFormat('Symbols (!#$%)', [], androidSpecifier), 'Symbols (!#$%)');
  assert.throws(() => toFormat('{nope}', args, androidSpecifier), /\{nope\} has no argument/);
});

test('flatten keeps plural objects as messages and groups as dots', () => {
  const flat = flatten({ a: { b: 'x', c: { one: '1', other: 'n' } }, d: 'y' });
  assert.deepEqual([...flat.keys()], ['a.b', 'a.c', 'd']);
});

test('translations: forms filled and dropped per language, problems reported', () => {
  const [plain, counted, englishPlain] = buildMessages({
    en: { a: 'Hi {name}', b: { zero: 'none', one: '{count} item', other: '{count} items' }, c: 'Hides in {count} s' },
    ar: { a: 'مرحبا {name}', b: { one: 'عنصر', other: '{count} عنصر' }, c: { two: 'ثانيتين', other: '{count} ثانية' } },
  });
  assert.equal(plain.plural, false);
  // English has no zero category, so `zero` is dropped as the web never picks it.
  assert.deepEqual(Object.keys(counted.text.en), ['one', 'other']);
  // Arabic needs all six; missing ones are the general form.
  assert.deepEqual(counted.text.ar, { zero: '{count} عنصر', one: 'عنصر', two: '{count} عنصر', few: '{count} عنصر', many: '{count} عنصر', other: '{count} عنصر' });
  // Counted in Arabic only: English gets the same text for each of its forms.
  assert.equal(englishPlain.plural, true);
  assert.deepEqual(englishPlain.text.en, { one: 'Hides in {count} s', other: 'Hides in {count} s' });

  assert.throws(() => buildMessages({ en: { a: 'x' }, ar: { a: 'x {y}', b: 'z' } }), (e) => /\{y\} isn't in en/.test(e.message) && /ar b: not in en/.test(e.message));
  assert.throws(() => buildMessages({ en: { a: 'x' }, ar: { a: { one: 'x', other: 'y' } } }), /counted in a translation, but en has no \{count\}/);
});

test('the phone catalog goes under phone., and may not clash', () => {
  const merged = mergeCatalogs({ en: { a: 'A' }, ar: { a: 'أ' } }, { en: { b: 'B' }, ar: { b: 'ب' } });
  assert.deepEqual(merged.en, { a: 'A', phone: { b: 'B' } });
  assert.throws(() => mergeCatalogs({ en: { phone: 'x' } }, { en: {} }), /already has a "phone" group/);
});

test('expectations follow the web format(): plural form by Intl.PluralRules, values substituted', () => {
  const messages = buildMessages({
    en: { v: { one: '{views} of {count} view', other: '{views} of {count} views' } },
    ar: { v: { zero: 'لا', one: 'واحد', two: 'اثنان', few: '{views} من {count}', many: '{count} كثير', other: '{count} آخر' } },
  });
  const cases = expectations(messages);
  const find = (locale, count) => cases.find((c) => c.locale === locale && c.args[1] === count);
  assert.deepEqual(find('en', 1), { key: 'v', locale: 'en', args: [7, 1], expected: '7 of 1 view' });
  assert.equal(find('ar', 0).expected, 'لا');
  assert.equal(find('ar', 3).expected, '7 من 3');
  assert.equal(find('ar', 11).expected, '11 كثير');
});

test('expectations isolate inserted text in Arabic, as the web vault does', () => {
  const cases = expectations(buildMessages({ en: { a: 'Hi {name}' }, ar: { a: 'مرحبا {name}' } }));
  assert.deepEqual(
    cases.map((c) => c.expected),
    ['Hi NAME', 'مرحبا \u2068NAME\u2069'],
  );
});
