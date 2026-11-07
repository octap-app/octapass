// What each build of the core leaves out. Run `pnpm --filter @octapass/core build` first.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';

const node = createRequire(import.meta.url)('../dist/node/octapass_core.js');
const fixture = (name) => readFileSync(new URL(`../../../crates/octapass-core/tests/import-fixtures/${name}`, import.meta.url));
const wasm = (build) => readFileSync(new URL(`../dist/${build}/octapass_core_bg.wasm`, import.meta.url));
const options = { password: 'correct horse battery staple' };
// An error message only rPGP has.
const PGP_MARKER = 'even the ring can not decrypt plaintext';

test('the web build has no OpenPGP: it asks for the full build to read a PGP-encrypted export', async () => {
  assert.equal(wasm('web').includes(PGP_MARKER), false);
  assert.equal(wasm('full').includes(PGP_MARKER), true);
  const web = await import('../dist/web/octapass_core.js');
  await web.default({ module_or_path: wasm('web') });
  for (const name of ['protonpass-encrypted.zip', 'protonpass-data.pgp']) {
    assert.throws(() => web.importFile('protonpass', fixture(name), options), { code: 'pgp_unavailable' }, name);
    assert.throws(() => web.importFile('protonpass', fixture(name)), { code: 'import_password_required' }, name);
    assert.equal(node.importFile('protonpass', fixture(name), options).items.length, node.importFile('protonpass', fixture('protonpass.zip')).items.length);
  }
  // Plain exports still work.
  assert.ok(web.importFile('protonpass', fixture('protonpass.zip')).items.length > 0);
});
