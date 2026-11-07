// Reading QR codes and the authenticator import review through WASM.
// Run `pnpm --filter @octapass/core build` first.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';

const core = createRequire(import.meta.url)('../dist/node/octapass_core.js');
const qr = (name) => readFileSync(new URL(`../../../crates/octapass-core/tests/qr-fixtures/${name}`, import.meta.url));
const fixture = (name) => readFileSync(new URL(`../../../crates/octapass-core/tests/import-fixtures/${name}`, import.meta.url));

test('readQrImage reads the QR codes in an image', () => {
  assert.deepEqual(core.readQrImage(qr('github.png')), ['otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub']);
  assert.deepEqual(core.readQrImage(qr('not-a-code.png')), ['https://example.com/']);
  assert.throws(() => core.readQrImage(new TextEncoder().encode('not an image')), { code: 'invalid_image' });
});

test('readQrPixels reads greyscale pixels', () => {
  assert.deepEqual(core.readQrPixels(2, 2, new Uint8Array([255, 255, 255, 255])), []);
});

test('summarizeQrScans joins a Google Authenticator export split over two QR codes', () => {
  const [first] = core.readQrImage(qr('google-authenticator-1-of-2.png'));
  const [second] = core.readQrImage(qr('google-authenticator-2-of-2.png'));
  const partial = core.summarizeQrScans([first, 'https://example.com/']);
  assert.equal(partial.codes.length, 2);
  assert.deepEqual(partial.incomplete, [{ id: 42, size: 2, scanned: [1] }]);
  assert.equal(partial.other, 1);
  const whole = core.summarizeQrScans([first, second, first]);
  assert.deepEqual(whole.incomplete, []);
  assert.deepEqual(
    whole.codes.map((c) => [c.issuer, c.account, c.counterBased]),
    [
      ['GitHub', 'octo', false],
      ['ACME', 'jane', false],
      ['Example', 'bob@example.com', false],
    ],
  );
  assert.match(whole.codes[0].uri, /^otpauth:\/\/totp\/GitHub:octo\?secret=/);
});

test('linkImportedCodes applies the import review', () => {
  const github = core.newId();
  const bank = core.newId();
  const result = core.importFile('otpauth', fixture('otpauth.txt'), { existingLogins: [{ id: github, title: 'Code host', urls: ['https://github.com'] }] });
  assert.deepEqual(
    result.codes.map((c) => [c.title, c.item, c.update]),
    [
      ['GitHub', undefined, 0],
      ['Example Bank', 0, undefined],
      ['بنك', 1, undefined],
      ['ACME', 2, undefined],
      // A counter-based (HOTP) code is a real code now, on its own login.
      ['bob', 3, undefined],
    ],
  );
  const linked = core.linkImportedCodes(result, [
    { code: 1, loginId: bank },
    { code: 0 },
  ]);
  assert.equal(linked.codes, undefined);
  assert.deepEqual(linked.totpUpdates.map((u) => u.itemId), [bank]);
  assert.deepEqual(linked.items.map((i) => i.overview.title), ['بنك', 'ACME', 'bob', 'GitHub']);
  assert.throws(() => core.linkImportedCodes(result, [{ code: 'x' }]), { code: 'invalid_argument' });
});
