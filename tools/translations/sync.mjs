#!/usr/bin/env node
// Keeps translations/ (what Weblate edits) in step with the apps' TypeScript catalogs.
//
//   node tools/translations/sync.mjs export          catalogs → translations/<component>/{en,ar}.json
//   node tools/translations/sync.mjs export --check  write nothing; exit 1 if the JSON is out of date
//   node tools/translations/sync.mjs import          Arabic fixes in translations/ → the catalogs
//
// English always comes from the catalogs. Other languages exist only as JSON until they're wired
// into the apps (docs/contributing/translations.md).
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { COMPONENTS, parseCatalog, patchCatalog, toI18next } from './catalogs.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const read = (path) => readFileSync(join(ROOT, path), 'utf8');
const json = (value) => `${JSON.stringify(value, null, 2)}\n`;

function exportAll({ check }) {
  const stale = [];
  for (const component of COMPONENTS) {
    for (const language of ['en', 'ar']) {
      const { file, start } = component[language];
      const path = `translations/${component.name}/${language}.json`;
      const contents = json(toI18next(parseCatalog(read(file), start).catalog));
      const current = existsSync(join(ROOT, path)) ? read(path) : null;
      if (current === contents) continue;
      if (check) {
        stale.push(path);
        continue;
      }
      mkdirSync(dirname(join(ROOT, path)), { recursive: true });
      writeFileSync(join(ROOT, path), contents);
      console.log(`wrote ${path}`);
    }
  }
  if (stale.length) {
    console.error(`Out of date. Run: node tools/translations/sync.mjs export\n${stale.map((path) => `  ${path}`).join('\n')}`);
    process.exit(1);
  }
}

function importArabic() {
  for (const component of COMPONENTS) {
    const path = `translations/${component.name}/ar.json`;
    if (!existsSync(join(ROOT, path))) continue;
    const { file, start } = component.ar;
    const { text, changed } = patchCatalog(read(file), start, JSON.parse(read(path)));
    if (changed) {
      writeFileSync(join(ROOT, file), text);
      console.log(`${file}: ${changed} string(s)`);
    }
  }
}

const [command, flag] = process.argv.slice(2);
if (command === 'export') exportAll({ check: flag === '--check' });
else if (command === 'import') importArabic();
else {
  console.error('usage: sync.mjs export [--check] | import');
  process.exit(2);
}
