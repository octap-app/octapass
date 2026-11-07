// Reads the catalogs straight from their TypeScript sources. The web vault's (`en.ts`, `ar.ts`)
// only import types, so Node imports them as they are. The phone app's `strings.ts` also imports
// `translator` through a workspace package name, which needs pnpm's links; that import is swapped
// for a stub and the file loaded from memory, which only its `catalogs` export is read from.

import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const CORE_IMPORT = /^import\s*\{[^}]*\}\s*from\s*'\.\/core';?\s*$/m;

/** Runs `fn` without Node's one-time "experimental feature" warning for it. */
function quietly(fn) {
  const emit = process.emitWarning;
  process.emitWarning = (warning, ...rest) => {
    const type = typeof rest[0] === 'string' ? rest[0] : rest[0]?.type;
    if (type !== 'ExperimentalWarning') emit.call(process, warning, ...rest);
  };
  try {
    return fn();
  } finally {
    process.emitWarning = emit;
  }
}

export async function loadPhoneCatalogs(file) {
  const source = await readFile(file, 'utf8');
  if (!CORE_IMPORT.test(source)) throw new Error(`${file}: expected its import of ./core; update lib/catalogs.mjs`);
  const stubbed = source.replace(CORE_IMPORT, 'const translator = () => () => "";');
  const js = quietly(() => stripTypeScriptTypes(stubbed));
  const module = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);
  if (!module.catalogs?.en) throw new Error(`${file}: no \`catalogs\` export with \`en\``);
  return module.catalogs;
}

export async function loadCatalogs(root) {
  const [{ en }, { ar }, phone] = await Promise.all([
    import(pathToFileURL(join(root, 'apps/web/src/i18n/en.ts')).href),
    import(pathToFileURL(join(root, 'apps/web/src/i18n/ar.ts')).href),
    loadPhoneCatalogs(join(root, 'apps/web/src/i18n/phone.ts')),
  ]);
  return { web: { en, ar }, phone };
}
