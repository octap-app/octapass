#!/usr/bin/env node
// Writes the native apps' generated resources: strings and design tokens for iOS and Android.
//
//   node tools/native-resources/generate.mjs           write every file
//   node tools/native-resources/generate.mjs --check   write nothing; exit 1 listing files that are out of date
//   --root <dir>                                       another checkout to read and write (the tests use it)
//
// See README.md next to this file.

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCatalogs } from './lib/catalogs.mjs';
import { buildMessages, expectations, mergeCatalogs } from './lib/messages.mjs';
import { stringsXml, swiftAccessors, xcstrings } from './lib/strings.mjs';
import { buildTokens, kotlinTokens, swiftTokens } from './lib/tokens.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../..');

const IOS_PACKAGE = 'apps/ios/Packages/OctaPassResources';
const IOS = `${IOS_PACKAGE}/Sources/OctaPassResources`;
const ANDROID = 'apps/android/resources/src/main';

/** Every generated file: repo-relative path → contents. */
export async function outputs(root = ROOT) {
  const { web, phone } = await loadCatalogs(root);
  const messages = buildMessages(mergeCatalogs(web, phone));
  const tokens = buildTokens(await readFile(join(root, 'packages/ui/src/styles/tokens.css'), 'utf8'));
  return new Map([
    [`${IOS}/Resources/Localizable.xcstrings`, xcstrings(messages)],
    [`${IOS}/L10n.swift`, swiftAccessors(messages)],
    [`${IOS}/Tokens.swift`, swiftTokens(tokens)],
    // The keys an APNs alert names (`title-loc-key`, `loc-key`): iOS looks them up in the app's own
    // bundle, never a package's, so the push alert's strings go there too (plan 04, "Push relay").
    ['apps/ios/OctaPass/Resources/Localizable.xcstrings', xcstrings(messages.filter((m) => m.key.startsWith('phone.native.pushAlert')))],
    // What the web vault shows for a sample of messages, which the package's tests compare L10n with.
    [`${IOS_PACKAGE}/Tests/OctaPassResourcesTests/Resources/expected.json`, casesJson(expectations(messages, { plainSamples: 20 }))],
    [`${ANDROID}/res/values/strings.xml`, stringsXml(messages, 'en')],
    [`${ANDROID}/res/values-ar/strings.xml`, stringsXml(messages, 'ar')],
    [`${ANDROID}/kotlin/app/octapass/resources/Tokens.kt`, kotlinTokens(tokens)],
  ]);
}

/** One case per line, so a change to a message shows up as a small diff. */
function casesJson(cases) {
  return `[\n${cases.map((c) => JSON.stringify(c)).join(',\n')}\n]\n`;
}

async function current(path) {
  try {
    return await readFile(path, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return undefined;
    throw error;
  }
}

async function main(args) {
  const check = args.includes('--check');
  const rootAt = args.indexOf('--root');
  const root = rootAt === -1 ? ROOT : resolve(args[rootAt + 1]);
  const files = await outputs(root);
  const stale = [];
  for (const [path, contents] of files) {
    const full = join(root, path);
    const existing = await current(full);
    if (existing === contents) continue;
    stale.push(`${path}${existing === undefined ? ' (missing)' : ''}`);
    if (!check) {
      await mkdir(dirname(full), { recursive: true });
      await writeFile(full, contents);
    }
  }
  if (check) {
    if (stale.length) {
      console.error(`Out of date; run \`node ${relative(process.cwd(), fileURLToPath(import.meta.url))}\`:\n  ${stale.join('\n  ')}`);
      process.exitCode = 1;
    } else console.log(`${files.size} native resource files are up to date.`);
  } else console.log(stale.length ? `Wrote:\n  ${stale.join('\n  ')}` : `${files.size} native resource files were already up to date.`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
