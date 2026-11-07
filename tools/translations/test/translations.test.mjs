import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { COMPONENTS, parseCatalog, patchCatalog, toI18next } from '../catalogs.mjs';
import { checkPage, fixAnchors } from '../check-docs.mjs';
import { headings, links } from '../docs.mjs';

const root = new URL('../../../', import.meta.url);
const source = `import x from 'y';
// a comment with { braces }
export const en = {
  // comment: with a colon
  common: { back: 'Back', quote: 'It\\'s here' },
  count: { one: '{count} day', other: "{count} days" },
  nested: {
    deep: {
      line: \`plain\`,
    },
  },
};
const other = { nope: 1 };
`;

test('reads strings, plural groups and nesting', () => {
  const { catalog } = parseCatalog(source, 'export const en = {');
  assert.deepEqual(toI18next(catalog), {
    common: { back: 'Back', quote: "It's here" },
    count_one: '{count} day',
    count_other: '{count} days',
    nested: { deep: { line: 'plain' } },
  });
});

test('refuses what it can’t read as plain text', () => {
  assert.throws(() => parseCatalog('const en = { a: `x${y}` };', 'const en = {'), /substitution/);
  assert.throws(() => parseCatalog('const en = { a: b };', 'const en = {'), /isn't a string/);
});

test('patching changes only the strings that differ', () => {
  const { text, changed } = patchCatalog(source, 'export const en = {', {
    common: { back: 'رجوع', quote: "It's here" },
    count_other: 'أيام',
    unknown: 'ignored',
  });
  assert.equal(changed, 2);
  assert.ok(text.includes("back: 'رجوع', quote: 'It\\'s here'"));
  assert.ok(text.includes("other: 'أيام' }"));
  assert.ok(text.includes('// a comment with { braces }'));
  assert.ok(!text.includes('ignored'));
});

test('an apostrophe survives a patch', () => {
  const { text } = patchCatalog(source, 'export const en = {', { common: { back: "don't" } });
  assert.deepEqual(parseCatalog(text, 'export const en = {').catalog.common.back, "don't");
});

for (const component of COMPONENTS) {
  test(`${component.name}: every catalog reads, and patching with its own values changes nothing`, () => {
    for (const language of ['en', 'ar']) {
      const { file, start } = component[language];
      const text = readFileSync(new URL(file, root), 'utf8');
      const { catalog } = parseCatalog(text, start);
      assert.ok(Object.keys(catalog).length > 0);
      const { changed } = patchCatalog(text, start, toI18next(catalog));
      assert.equal(changed, 0);
    }
  });
}

const page = (body, status = 'stable') => `---\ntitle: T\ndescription: D\nstatus: ${status}\nsidebar:\n  order: 1\n---\n\n${body}`;
const check = (english, translated, extra = {}) =>
  checkPage({ english, translated, language: 'ar', exists: () => true, headingsOf: () => null, ...extra });

test('a faithful translation passes', () => {
  const en = page('## One\n\n[a](/docs/x/)\n\n```bash\nls\n```\n');
  const ar = page('## واحد\n\n[أ](/ar/docs/x/)\n\n```bash\nls\n```\n');
  assert.deepEqual(check(en, ar), []);
});

test('finds a changed status, lost heading, changed code and a link that leaves the language', () => {
  const en = page('## One\n\n## Two\n\n```bash\nls\n```\n');
  const ar = page('## واحد\n\n[x](/docs/y/)\n\n```bash\nrm\n```\n', 'beta');
  const problems = check(en, ar).join('\n');
  assert.match(problems, /status is beta/);
  assert.match(problems, /headings differ/);
  assert.match(problems, /code block 1 differs/);
  assert.match(problems, /link leaves ar/);
});

test('headings inside code blocks are not headings, and links inside them are not links', () => {
  const text = '## Real\n\n```md\n## Fake\n[x](/docs/y/)\n```\n';
  assert.deepEqual(headings(text).map((h) => h.text), ['Real']);
  assert.deepEqual(links(text), []);
});

test('English anchors become the translated heading’s id, by position', () => {
  const english = headings('## First\n\n## Auto-type\n');
  const translated = headings('## الأول\n\n## الكتابة التلقائية\n');
  const text = 'انظر [هنا](/ar/docs/platforms/desktop/#auto-type) و[هنا](#auto-type) و[خارج](https://example.com/#auto-type).';
  const fixed = fixAnchors(text, { language: 'ar', source: 'a.md', englishOf: () => english, translatedOf: () => translated });
  assert.equal(fixed, 'انظر [هنا](/ar/docs/platforms/desktop/#الكتابة-التلقائية) و[هنا](#الكتابة-التلقائية) و[خارج](https://example.com/#auto-type).');
});
