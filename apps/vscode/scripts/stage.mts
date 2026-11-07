// Lays the extension out in dist/stage, ready to load or package. VS Code extension names can't be
// scoped, so the manifest there is named `octapass` and the workspace keeps @octapass/vscode.

import { cpSync, globSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const stage = join(root, 'dist', 'stage');

rmSync(stage, { recursive: true, force: true });
mkdirSync(join(stage, 'dist'), { recursive: true });
for (const file of globSync('*.js', { cwd: join(root, 'dist') })) {
  cpSync(join(root, 'dist', file), join(stage, 'dist', file));
}
for (const path of ['media', 'l10n', 'README.md', 'package.nls.json', 'package.nls.ar.json']) {
  cpSync(join(root, path), join(stage, path), { recursive: true });
}
cpSync(join(root, '../../LICENSE'), join(stage, 'LICENSE'));

const { scripts, devDependencies, private: _private, ...manifest } = JSON.parse(
  readFileSync(join(root, 'package.json'), 'utf8'),
);
writeFileSync(join(stage, 'package.json'), `${JSON.stringify({ ...manifest, name: 'octapass' }, null, 2)}\n`);
