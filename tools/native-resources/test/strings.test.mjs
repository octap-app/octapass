import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { buildMessages } from '../lib/messages.mjs';
import { androidName, identifier, swiftName, uniqueNames } from '../lib/names.mjs';
import { androidEscape, stringsXml, swiftAccessors, xcstrings } from '../lib/strings.mjs';

const catalogs = {
  en: {
    common: { back: 'Back', revealWhat: 'Show {what}' },
    list: { searchPlaceholder: { one: 'Search {count} item', other: 'Search {count} items' } },
    detail: { codesLeft: { one: '{left} of {count} backup code left', other: '{left} of {count} backup codes left' } },
    editor: { fixErrors: { one: 'Fix the highlighted field.', other: 'Fix the {count} highlighted fields.' } },
  },
  ar: {
    common: { back: 'رجوع', revealWhat: 'إظهار {what}' },
    list: { searchPlaceholder: { zero: 'لا', one: 'واحد', two: 'اثنان', few: '{count} عناصر', many: '{count} عنصرًا', other: '{count} عنصر' } },
    detail: { codesLeft: { zero: '{left} من {count}', one: '{left} من واحد', two: '{left} من اثنين', few: '{left} من {count} رموز', many: '{left} من {count} رمزًا', other: '{left} من {count} رمز' } },
  },
};

test('xcstrings: keys, manual extraction, positional specifiers', () => {
  const json = xcstrings(buildMessages(catalogs));
  assert.match(json, /^\{\n {2}"sourceLanguage" : "en",\n/);
  const { strings, version } = JSON.parse(json);
  assert.equal(version, '1.0');
  assert.deepEqual(Object.keys(strings), ['common.back', 'common.revealWhat', 'detail.codesLeft', 'editor.fixErrors', 'list.searchPlaceholder']);
  assert.equal(strings['common.back'].extractionState, 'manual');
  assert.equal(strings['common.revealWhat'].localizations.ar.stringUnit.value, 'إظهار %1$@');
  // A missing translation is left out, not copied from English.
  assert.equal(strings['editor.fixErrors'].localizations.ar, undefined);
});

test('xcstrings: a count-only plural varies the whole string, all six Arabic forms', () => {
  const { strings } = JSON.parse(xcstrings(buildMessages(catalogs)));
  const ar = strings['list.searchPlaceholder'].localizations.ar.variations.plural;
  assert.deepEqual(Object.keys(ar).sort(), ['few', 'many', 'one', 'other', 'two', 'zero']);
  assert.equal(ar.few.stringUnit.value, '%1$lld عناصر');
  assert.equal(strings['list.searchPlaceholder'].localizations.en.variations.plural.one.stringUnit.value, 'Search %1$lld item');
});

test('xcstrings: a plural with several arguments puts the forms in a count substitution', () => {
  const { strings } = JSON.parse(xcstrings(buildMessages(catalogs)));
  const en = strings['detail.codesLeft'].localizations.en;
  assert.equal(en.stringUnit.value, '%#@count@');
  assert.equal(en.substitutions.count.argNum, 2);
  assert.equal(en.substitutions.count.formatSpecifier, 'lld');
  assert.equal(en.substitutions.count.variations.plural.other.stringUnit.value, '%1$lld of %arg backup codes left');
  // A count the general form shows but another form doesn't still varies the whole string.
  assert.ok(strings['editor.fixErrors'].localizations.en.variations.plural);
});

test('Android escaping', () => {
  assert.equal(androidEscape("It's \"quoted\""), "It\\'s \\\"quoted\\\"");
  assert.equal(androidEscape('@string/x'), '\\@string/x');
  assert.equal(androidEscape('?attr'), '\\?attr');
  assert.equal(androidEscape('a @ b ? c'), 'a @ b ? c');
  assert.equal(androidEscape('A & B <b>'), 'A &amp; B &lt;b&gt;');
  assert.equal(androidEscape('one\ntwo\tthree'), 'one\\ntwo\\tthree');
  assert.equal(androidEscape('back\\slash'), 'back\\\\slash');
  assert.equal(androidEscape(' two  spaces '), '\\u0020two\\u0020\\u0020spaces\\u0020');
});

test('Android strings.xml: plurals, positional args, formatted="false" for a bare %', () => {
  const messages = buildMessages({ en: { ...catalogs.en, symbols: 'Symbols (!#$%)' }, ar: catalogs.ar });
  const en = stringsXml(messages, 'en');
  assert.match(en, /<string name="common_revealWhat">Show %1\$s<\/string>/);
  assert.match(en, /<string name="symbols" formatted="false">Symbols \(!#\$%\)<\/string>/);
  assert.match(en, /<plurals name="detail_codesLeft">\n {8}<item quantity="one">%1\$d of %2\$d backup code left<\/item>/);
  const ar = stringsXml(messages, 'ar');
  assert.equal((ar.match(/<item quantity=/g) ?? []).length, 12);
  assert.doesNotMatch(ar, /editor_fixErrors/);
});

test('key naming: Android and Swift names, collisions detected', () => {
  assert.equal(androidName('import.help.onepassword-1pux'), 'import_help_onepassword_1pux');
  assert.equal(identifier('onepassword-1pux'), 'onepassword1pux');
  assert.equal(swiftName('2fas'), '_2fas');
  assert.equal(swiftName('0'), '_0');
  assert.equal(swiftName('import'), '`import`');
  assert.equal(swiftName('extension'), '`extension`');
  assert.throws(() => uniqueNames(['a.b_c', 'a_b.c'], androidName, 'Android resource'), /"a\.b_c" and "a_b\.c" are both Android resource "a_b_c"/);
  assert.throws(() => stringsXml(buildMessages({ en: { a: { b: 'x' }, a_b: 'y' } }), 'en'), /Name collisions/);
  assert.throws(() => swiftAccessors(buildMessages({ en: { g: { 'x-y': 'one', xY: 'two' } } })), /Name collisions/);
  // A group may not take a name L10n uses itself.
  assert.throws(() => swiftAccessors(buildMessages({ en: { bundle: { x: 'one' } } })), /Name collisions/);
});

test('Swift accessors: properties, typed functions with arguments in format order', () => {
  const swift = swiftAccessors(buildMessages({ ...catalogs, en: { ...catalogs.en, import: { continue: 'Go', '2fas': 'In 2FAS' } } }));
  assert.match(swift, /public static var back: String \{ L10n\.string\("common\.back"\) \}/);
  assert.match(swift, /public static func searchPlaceholder\(count: Int\) -> String \{ L10n\.format\("list\.searchPlaceholder", count\) \}/);
  assert.match(swift, /public static func codesLeft\(left: Int, count: Int\) -> String \{ L10n\.format\("detail\.codesLeft", left, count\) \}/);
  assert.match(swift, /public enum `import` \{\n.*\n {8}public static var `continue`: String/);
  assert.match(swift, /public static var _2fas: String \{ L10n\.string\("import\.2fas"\) \}/);
  // Swift string interpolation survives the JavaScript template.
  assert.ok(swift.includes('Locale(identifier: "\\(language)@numbers=latn")'));
});

// aapt2 reads the files back: proves the escaping round-trips. Skipped without the Android SDK.
const aapt2 = (() => {
  const sdk = process.env.ANDROID_HOME;
  if (!sdk || !existsSync(join(sdk, 'build-tools'))) return null;
  const versions = readdirSync(join(sdk, 'build-tools')).sort();
  const path = join(sdk, 'build-tools', versions.at(-1), 'aapt2');
  return existsSync(path) ? { path, jar: findPlatformJar(sdk) } : null;
})();

function findPlatformJar(sdk) {
  const platforms = existsSync(join(sdk, 'platforms')) ? readdirSync(join(sdk, 'platforms')).filter((p) => existsSync(join(sdk, 'platforms', p, 'android.jar'))) : [];
  return platforms.length ? join(sdk, 'platforms', platforms.sort().at(-1), 'android.jar') : null;
}

test('aapt2 compiles and reads back tricky strings', { skip: !aapt2?.jar && 'no Android SDK' }, () => {
  const tricky = {
    apostrophe: "Don't",
    quotes: 'Say "hi" to {name}',
    at: '@home',
    question: '?really',
    amp: 'Import & Export <now>',
    newline: 'one\ntwo',
    percent: '100% sure',
    percentArgs: '{count}% of {name}',
    spaces: '  padded  ',
    backslash: 'C:\\path',
  };
  const messages = buildMessages({ en: { t: tricky } });
  const dir = mkdtempSync(join(tmpdir(), 'native-resources-'));
  try {
    mkdirSync(join(dir, 'res/values'), { recursive: true });
    writeFileSync(join(dir, 'res/values/strings.xml'), stringsXml(messages, 'en'));
    writeFileSync(join(dir, 'AndroidManifest.xml'), '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="app.octap.check" />');
    execFileSync(aapt2.path, ['compile', '--dir', join(dir, 'res'), '-o', join(dir, 'res.zip')]);
    execFileSync(aapt2.path, ['link', '-I', aapt2.jar, '--manifest', join(dir, 'AndroidManifest.xml'), '-o', join(dir, 'out.apk'), join(dir, 'res.zip')]);
    const dump = execFileSync(aapt2.path, ['dump', 'resources', join(dir, 'out.apk')], { encoding: 'utf8' });
    // The dump prints each value raw between quotes, a newline in it followed by indentation.
    const value = (name) => {
      const m = new RegExp(`string/t_${name}\\n\\s+\\(\\) "([\\s\\S]*?)"\\n(?=\\s+resource|\\s*$)`).exec(dump);
      assert.ok(m, `t_${name} not in the dump`);
      return m[1].replace(/\n +/g, '\n');
    };
    assert.equal(value('apostrophe'), "Don't");
    assert.equal(value('quotes'), 'Say "hi" to %1$s');
    assert.equal(value('at'), '@home');
    assert.equal(value('question'), '?really');
    assert.equal(value('amp'), 'Import & Export <now>');
    assert.equal(value('newline'), 'one\ntwo');
    assert.equal(value('percent'), '100% sure');
    assert.equal(value('percentArgs'), '%1$d%% of %2$s');
    assert.equal(value('spaces'), '  padded  ');
    assert.equal(value('backslash'), 'C:\\path');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
