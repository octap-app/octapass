// The hash of the sources a Rust crate is built from: the crate and the local crates it depends
// on (from Cargo's own metadata, without dev-dependencies, following path dependencies into other
// workspaces), the root Cargo.toml, Cargo.lock and rust-toolchain.toml, and any extra files given,
// such as the build scripts. Builds record it next to their output and rebuild when it changes, so
// a build left over from older sources is never used:
//
//   node scripts/lib/sources-hash.mjs <crate> [extra file…]
//
// packages/core/scripts/build.mjs imports sourcesHash for the WebAssembly core, and
// scripts/lib/stale.sh calls it for the iPhone and Android libraries.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../..', import.meta.url));

// Tests, benchmarks, examples and fuzz targets at a crate's root don't go into the library.
const notBuilt = new Set(['tests', 'benches', 'examples', 'fuzz']);

function metadata(manifest) {
  const output = execFileSync('cargo', ['metadata', '--no-deps', '--format-version', '1', '--manifest-path', manifest], {
    cwd: repo,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
    maxBuffer: 64 * 1024 * 1024,
  });
  return JSON.parse(output).packages;
}

// The crate's directory and those of the local crates it compiles.
function crateDirs(crate) {
  const byDir = new Map(metadata(join(repo, 'Cargo.toml')).map((p) => [dirname(p.manifest_path), p]));
  const start = [...byDir.values()].find((p) => p.name === crate);
  if (!start) throw new Error(`No crate named ${crate} in the workspace`);
  const dirs = new Set();
  const visit = (dir) => {
    if (dirs.has(dir)) return;
    dirs.add(dir);
    if (!byDir.has(dir) && existsSync(join(dir, 'Cargo.toml'))) {
      // A crate of another workspace, like apps/desktop's: read that workspace too.
      for (const p of metadata(join(dir, 'Cargo.toml'))) if (!byDir.has(dirname(p.manifest_path))) byDir.set(dirname(p.manifest_path), p);
    }
    for (const dep of byDir.get(dir)?.dependencies ?? []) if (dep.path && dep.kind !== 'dev') visit(dep.path);
  };
  visit(dirname(start.manifest_path));
  return [...dirs].sort();
}

function addFile(hash, file) {
  const content = readFileSync(file);
  hash.update(`${relative(repo, file)}\0${content.length}\0`);
  hash.update(content);
}

function addDir(hash, dir, top) {
  const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of entries) {
    if (entry.name === 'target' || entry.name === 'node_modules' || (top && notBuilt.has(entry.name))) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) addDir(hash, path, false);
    else if (entry.isFile()) addFile(hash, path);
  }
}

export function sourcesHash(crate, extraFiles = []) {
  const hash = createHash('sha256');
  for (const file of ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml']) if (existsSync(join(repo, file))) addFile(hash, join(repo, file));
  for (const file of extraFiles) addFile(hash, resolve(file));
  for (const dir of crateDirs(crate)) addDir(hash, dir, true);
  return hash.digest('hex');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [crate, ...extra] = process.argv.slice(2);
  if (!crate) {
    console.error('usage: node scripts/lib/sources-hash.mjs <crate> [extra file…]');
    process.exit(2);
  }
  console.log(sourcesHash(crate, extra));
}
