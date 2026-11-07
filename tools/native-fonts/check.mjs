// Checks that the native apps' brand fonts are the ones the web vault bundles: the same
// @fontsource versions, converted from the same files, and unchanged since (fonts.json, written
// by convert.py). Node built-ins only.
//
//   node tools/native-fonts/check.mjs     # exit 1 and list what doesn't match; needs pnpm install

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
export const ROOT = join(here, '../..');

const sha256 = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

export function readManifest() {
  return JSON.parse(readFileSync(join(here, 'fonts.json'), 'utf8'));
}

/** What doesn't match, one line each; empty when everything does. */
export function checkFonts(manifest = readManifest(), root = ROOT) {
  const problems = [];
  const web = (name) => join(root, 'apps/web/node_modules', name);
  const version = (name) => {
    const path = join(web(name), 'package.json');
    return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')).version : undefined;
  };
  const sameVersion = (entry) => {
    const installed = version(entry.package);
    if (installed === undefined) problems.push(`${entry.package} isn't installed for apps/web: run pnpm install`);
    else if (installed !== entry.version) problems.push(`${entry.output}: made from ${entry.package} ${entry.version}, the web vault has ${installed}`);
    return installed === entry.version;
  };
  const unchanged = (output, expected) => {
    const path = join(root, output);
    if (!existsSync(path)) problems.push(`${output} is missing`);
    else if (sha256(path) !== expected) problems.push(`${output} changed since it was converted`);
  };

  for (const font of manifest.fonts) {
    if (sameVersion(font)) {
      const source = join(web(font.package), font.source);
      if (!existsSync(source)) problems.push(`${font.package}/${font.source} is missing`);
      else if (sha256(source) !== font.sourceSha256) problems.push(`${font.output}: ${font.package}/${font.source} isn't the file it was made from`);
    }
    unchanged(font.output, font.outputSha256);
  }
  for (const license of manifest.licenses) {
    if (sameVersion(license)) {
      const source = join(web(license.package), 'LICENSE');
      if (existsSync(source) && sha256(source) !== license.sha256) problems.push(`${license.output} differs from ${license.package}'s LICENSE`);
    }
    unchanged(license.output, license.sha256);
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const problems = checkFonts();
  for (const problem of problems) console.error(problem);
  if (problems.length) {
    console.error('Run tools/native-fonts/convert.py (see its header) and commit the result.');
    process.exit(1);
  }
  console.log('The native fonts match the web vault’s.');
}
