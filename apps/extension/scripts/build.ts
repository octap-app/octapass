// Builds the unpacked extension for every browser: dist/chrome (Chrome, Edge and other Chromium
// browsers) and dist/firefox. `--target safari` builds dist/safari, which apps/safari/scripts/build.sh
// packages into the Safari apps. `--watch` rebuilds on change for development; reload the extension
// in the browser afterwards. `--store` leaves out the development key, for store uploads.
//
//   node scripts/build.ts [--watch] [--store] [--target chrome|firefox|safari]

import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { build } from 'vite';
import { createManifest, type Target } from '../src/manifest.ts';
import { extensionConfig, type Part } from '../vite.config.ts';

const PARTS: Part[] = ['pages', 'background', 'content', 'page'];
const root = new URL('..', import.meta.url);
const { values } = parseArgs({ options: { watch: { type: 'boolean', default: false }, store: { type: 'boolean', default: false }, target: { type: 'string' } } });
const targets: Target[] = values.target ? [values.target as Target] : ['chrome', 'firefox'];
const mode = values.watch ? 'development' : 'production';
const { version } = JSON.parse(readFileSync(new URL('package.json', root), 'utf8')) as { version: string };

for (const target of targets) {
  const outDir = new URL(`dist/${target}/`, root).pathname;
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  writeFileSync(`${outDir}manifest.json`, `${JSON.stringify(createManifest(target, version, { store: values.store }), null, 2)}\n`);
  for (const part of PARTS) {
    const config = extensionConfig(part, outDir, mode, target);
    await build({ ...config, configFile: false, logLevel: 'warn', build: { ...config.build, ...(values.watch ? { watch: {} } : {}) } });
  }
  console.log(`Built ${target}: ${outDir}`);
}
