// Writes bitwarden-encrypted-{pbkdf2,argon2}.json: bitwarden.json as Bitwarden's
// password-protected export, using Node's crypto only (independent of the Rust importer).
// Fixed salts and IVs keep the output reproducible; real exports use random ones.
import { argon2Sync, createCipheriv, createHash, createHmac, pbkdf2Sync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const dir = new URL('.', import.meta.url);
const password = 'correct horse battery staple';
const plaintext = readFileSync(new URL('bitwarden.json', dir), 'utf8');

// HKDF-Expand only (no extract), as Bitwarden stretches keys.
const expand = (prk, info) => createHmac('sha256', prk).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();

function encrypt(key, text, ivByte) {
  const encKey = expand(key, 'enc');
  const macKey = expand(key, 'mac');
  const iv = Buffer.alloc(16, ivByte);
  const cipher = createCipheriv('aes-256-cbc', encKey, iv);
  const ct = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const mac = createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();
  return `2.${iv.toString('base64')}|${ct.toString('base64')}|${mac.toString('base64')}`;
}

function write(name, kdf, key) {
  const salt = kdf.salt;
  const doc = {
    encrypted: true,
    passwordProtected: true,
    salt,
    ...kdf.fields,
    encKeyValidation_DO_NOT_EDIT: encrypt(key, '3f6f5a7e-0000-4000-8000-00000000abcd', 1),
    data: encrypt(key, plaintext, 2),
  };
  writeFileSync(new URL(name, dir), `${JSON.stringify(doc, null, 2)}\n`);
}

const pbkdf2Salt = Buffer.alloc(16, 7).toString('base64');
write(
  'bitwarden-encrypted-pbkdf2.json',
  { salt: pbkdf2Salt, fields: { kdfType: 0, kdfIterations: 100000 } },
  pbkdf2Sync(password, pbkdf2Salt, 100000, 32, 'sha256'),
);

const argonSalt = Buffer.alloc(16, 9).toString('base64');
write(
  'bitwarden-encrypted-argon2.json',
  { salt: argonSalt, fields: { kdfType: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 } },
  argon2Sync('argon2id', {
    message: password,
    nonce: createHash('sha256').update(argonSalt).digest(),
    parallelism: 4,
    tagLength: 32,
    memory: 64 * 1024,
    passes: 3,
  }),
);
