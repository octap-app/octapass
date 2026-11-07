// Builds the WASM package four times from crates/octapass-wasm:
//   dist/web   ES module for the browser worker: no test helpers, and no zxcvbn (the web vault
//              estimates strength in TypeScript). Built with the size-optimized `wasm-release`
//              profile, since every visitor downloads it
//   dist/tools ES module the web vault's worker loads when the Tools section opens: the developer
//              toolkit and OpenPGP, without zxcvbn. Size-optimized, like dist/web
//   dist/full  ES module with strength, local vaults and backups, for clients that offer local mode
//              (browser extension, desktop and mobile webviews)
//   dist/node  CommonJS for Node tests, with everything plus the in-WASM OPAQUE test server
//
// Each build records a hash of its sources in dist/.sources-hash (scripts/lib/sources-hash.mjs):
// the crates it compiles, the workspace's Cargo.toml, Cargo.lock and rust-toolchain.toml, and this
// script. With `--if-stale` (`pnpm --filter @octapass/core build:if-stale`) nothing is rebuilt while
// that hash still matches, so the app builds can call it every time and still never use a dist/
// left over from older sources.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sourcesHash } from '../../../scripts/lib/sources-hash.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const repo = fileURLToPath(new URL('../../..', import.meta.url));
const crate = join(repo, 'crates/octapass-wasm');
const stamp = `${root}dist/.sources-hash`;
const outputs = ['web', 'tools', 'full', 'node'];

function build(target, outDir, cargoArgs = [], profile) {
  const args = ['build', crate, ...(profile ? ['--profile', profile] : ['--release']), '--target', target, '--out-dir', `${root}dist/${outDir}`, '--out-name', 'octapass_core', '--no-pack'];
  if (cargoArgs.length) args.push('--', ...cargoArgs);
  execFileSync('wasm-pack', args, { stdio: 'inherit' });
}

const hash = sourcesHash('octapass-wasm', [fileURLToPath(import.meta.url)]);
if (process.argv.includes('--if-stale')) {
  const missing = outputs.filter((out) => !existsSync(`${root}dist/${out}/octapass_core_bg.wasm`));
  const recorded = existsSync(stamp) ? readFileSync(stamp, 'utf8').trim() : undefined;
  if (!missing.length && recorded === hash) {
    console.log('@octapass/core: dist/ is up to date with the Rust sources');
    process.exit(0);
  }
  const reason = missing.length ? `dist/${missing.join(', dist/')} missing` : recorded ? 'the Rust sources changed' : 'dist/ has no record of its sources';
  console.log(`@octapass/core: building the WASM core (${reason})`);
}

rmSync(`${root}dist`, { recursive: true, force: true });
build('web', 'web', ['--no-default-features'], 'wasm-release');
build('web', 'tools', ['--no-default-features', '--features', 'toolkit,pgp'], 'wasm-release');
build('web', 'full');
build('nodejs', 'node', ['--features', 'test-server']);
// This package is "type": "module"; the nodejs target emits CommonJS.
writeFileSync(`${root}dist/node/package.json`, '{ "type": "commonjs" }\n');
// Last, so a build that fails part-way is redone by the next `--if-stale`.
writeFileSync(stamp, `${hash}\n`);
