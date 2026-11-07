// Writes protonpass-data.pgp and protonpass-aead.pgp with OpenPGP.js, the library Proton Pass
// encrypts its export with (independent of rPGP, which reads them). make-protonpass.py then puts
// protonpass-data.pgp into protonpass-encrypted.zip as `Proton Pass/data.pgp`.
//
//   protonpass-data.pgp  data.json, as Proton's `encryptPassExport` does: a passphrase only,
//                        iterated and salted S2K with count byte 255, armored (SKESK v4 + SEIPD v1)
//   protonpass-aead.pgp  protonpass.zip, with OpenPGP.js's newer settings: Argon2 S2K and AEAD
//                        (SKESK v6 + SEIPD v2), the way Proton says it will switch to
//
// OpenPGP.js isn't a dependency of this repository; install it anywhere and point OPENPGP at it:
//
//   npm install --prefix /tmp/openpgp openpgp@6.1.1
//   OPENPGP=/tmp/openpgp/node_modules/openpgp/dist/node/openpgp.mjs \
//     node crates/octapass-core/tests/import-fixtures/make-protonpass-pgp.mjs
//   python3 crates/octapass-core/tests/import-fixtures/make-protonpass.py
//
// OpenPGP.js picks random salts and session keys, so each run writes different (equally valid)
// files.
import { readFileSync, writeFileSync } from 'node:fs';

const openpgp = await import(process.env.OPENPGP ?? 'openpgp');
const dir = new URL('.', import.meta.url);
const passwords = ['correct horse battery staple'];

const data = await openpgp.encrypt({
  message: await openpgp.createMessage({ binary: readFileSync(new URL('protonpass-data.json', dir)) }),
  passwords,
  config: { s2kIterationCountByte: 255 },
  format: 'armored',
});
writeFileSync(new URL('protonpass-data.pgp', dir), data);

const aead = await openpgp.encrypt({
  message: await openpgp.createMessage({ binary: readFileSync(new URL('protonpass.zip', dir)) }),
  passwords,
  // Small Argon2 settings keep the tests fast (2^16 KiB = 64 MiB is OpenPGP.js's default).
  config: { aeadProtect: true, s2kType: openpgp.enums.s2k.argon2, s2kArgon2Params: { passes: 1, parallelism: 1, memoryExponent: 10 } },
  format: 'armored',
});
writeFileSync(new URL('protonpass-aead.pgp', dir), aead);
