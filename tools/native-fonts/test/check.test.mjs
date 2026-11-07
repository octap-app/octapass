import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkFonts, readManifest } from '../check.mjs';

test('the Android fonts match the web vault’s', () => {
  assert.deepEqual(checkFonts(), []);
});

test('a font made from another version or file, or changed since, is reported', () => {
  const manifest = readManifest();
  const [mona, mono] = manifest.fonts;
  const problems = checkFonts({
    fonts: [
      { ...mona, version: '1.0.0' },
      { ...mono, sourceSha256: '0'.repeat(64), outputSha256: '1'.repeat(64) },
    ],
    licenses: [{ ...manifest.licenses[0], sha256: '2'.repeat(64) }],
  });
  assert.deepEqual(problems, [
    `${mona.output}: made from ${mona.package} 1.0.0, the web vault has ${mona.version}`,
    `${mono.output}: ${mono.package}/${mono.source} isn't the file it was made from`,
    `${mono.output} changed since it was converted`,
    `${manifest.licenses[0].output} differs from ${manifest.licenses[0].package}'s LICENSE`,
    `${manifest.licenses[0].output} changed since it was converted`,
  ]);
});
