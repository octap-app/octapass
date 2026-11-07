#!/usr/bin/env node
// Keeps translated docs in step with the English pages.
//
//   node tools/translations/check-docs.mjs         # report; exits 1 on a broken translation
//   node tools/translations/check-docs.mjs --fix-anchors
//
// A page with no translation is fine: Starlight shows the English with a notice. These fail:
// a translation with no English page, a changed status or sidebar order, a different heading
// structure or code block, a page link that leaves the language, and an anchor that doesn't exist.
// --fix-anchors rewrites English #anchors to the translated heading's id, using heading positions.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fenced, field, fileForPage, frontMatter, headings, links, relativePath, sidebarOrder, walk } from './docs.mjs';

const LANGUAGES = ['ar'];

export function checkPage({ english, translated, language, exists, headingsOf }) {
  const problems = [];
  const a = frontMatter(english);
  const b = frontMatter(translated);
  for (const name of ['title', 'description']) if (!field(b, name)) problems.push(`front matter has no ${name}`);
  if (field(a, 'status') !== field(b, 'status')) problems.push(`status is ${field(b, 'status')}, English says ${field(a, 'status')}`);
  if (sidebarOrder(a) !== sidebarOrder(b)) problems.push(`sidebar order is ${sidebarOrder(b)}, English says ${sidebarOrder(a)}`);

  const from = headings(english);
  const to = headings(translated);
  if (from.map((h) => h.level).join() !== to.map((h) => h.level).join()) {
    problems.push(`headings differ: ${to.length} here, ${from.length} in English, or their levels changed`);
  }
  const codeA = fenced(english);
  const codeB = fenced(translated);
  if (codeA.length !== codeB.length) problems.push(`${codeB.length} code blocks, English has ${codeA.length}`);
  else codeA.forEach((block, i) => block !== codeB[i] && problems.push(`code block ${i + 1} differs from English`));

  for (const { url } of links(translated)) {
    const [path, anchor] = url.split('#');
    if (path.startsWith('/docs')) problems.push(`link leaves ${language}: ${url}`);
    if (path.startsWith(`/${language}/docs`) && !exists(fileForPage(path))) problems.push(`link to a missing page: ${url}`);
    if (anchor) {
      const target = path ? fileForPage(path) : null;
      const ids = headingsOf(target);
      if (ids && !ids.includes(decodeURIComponent(anchor))) problems.push(`anchor not found: ${url}`);
    }
  }
  return problems;
}

/** English anchors → translated ids, by heading position. Returns the new text. */
export function fixAnchors(text, { language, source, englishOf, translatedOf }) {
  const out = [];
  let last = 0;
  for (const { url, index } of links(text)) {
    const [path, anchor] = url.split('#');
    if (!anchor) continue;
    if (path && !path.startsWith(`/${language}/docs`)) continue;
    const file = path ? fileForPage(path) : source;
    const en = englishOf(file);
    const tr = translatedOf(file);
    if (!en || !tr) continue;
    const at = en.findIndex((h) => h.id === decodeURIComponent(anchor));
    if (at < 0 || !tr[at] || tr.some((h) => h.id === decodeURIComponent(anchor))) continue;
    out.push(text.slice(last, index), `${path}#${tr[at].id}`);
    last = index + url.length;
  }
  return out.join('') + text.slice(last);
}

function main() {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../docs');
  const fix = process.argv.includes('--fix-anchors');
  let failed = 0;
  for (const language of LANGUAGES) {
    const dir = join(root, language);
    const isLanguageDir = (path) => LANGUAGES.some((code) => path === join(root, code));
    const englishPages = walk(root, isLanguageDir).map((file) => relativePath(root, file));
    const translatedPages = existsSync(dir) ? walk(dir).map((file) => relativePath(dir, file)) : [];
    const read = (base, page) => (existsSync(join(base, page)) ? readFileSync(join(base, page), 'utf8') : null);

    if (fix) {
      const englishOf = (page) => (read(root, page) === null ? null : headings(read(root, page)));
      const translatedOf = (page) => (read(dir, page) === null ? null : headings(read(dir, page)));
      for (const page of translatedPages) {
        const text = read(dir, page);
        const next = fixAnchors(text, { language, source: page, englishOf, translatedOf });
        if (next !== text) writeFileSync(join(dir, page), next);
      }
    }

    for (const page of translatedPages) {
      const english = read(root, page);
      if (english === null) {
        console.error(`${language}/${page}: no English page`);
        failed += 1;
        continue;
      }
      const problems = checkPage({
        english,
        translated: read(dir, page),
        language,
        exists: (target) => read(dir, target) !== null || read(root, target) !== null,
        headingsOf: (target) => {
          const body = read(dir, target ?? page) ?? read(root, target ?? page);
          return body === null ? null : headings(body).map((h) => h.id);
        },
      });
      for (const problem of problems) console.error(`${language}/${page}: ${problem}`);
      failed += problems.length;
    }

    const missing = englishPages.filter((page) => !translatedPages.includes(page));
    console.log(`${language}: ${translatedPages.length} of ${englishPages.length} pages translated`);
    for (const page of missing) console.log(`  not translated: ${page}`);
  }
  if (failed) {
    console.error(`${failed} problem(s)`);
    process.exit(1);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
