// Writes aegis-encrypted.json and aegis-damaged.json: the vault contents of aegis.json in Aegis'
// encrypted vault format, using Node's crypto only (independent of the Rust importer).
// Fixed keys, salts and nonces keep the output reproducible; real exports use random ones.
// scrypt uses N = 2^10 so the tests stay fast; Aegis itself uses N = 2^15 (same layout).
import { createCipheriv, scryptSync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const dir = new URL('.', import.meta.url);
const password = 'correct horse battery staple';
const { db } = JSON.parse(readFileSync(new URL('aegis.json', dir), 'utf8'));

function seal(key, nonce, plaintext) {
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { data, nonce: nonce.toString('hex'), tag: cipher.getAuthTag().toString('hex') };
}

const masterKey = Buffer.alloc(32, 0x4d);
const [n, r, p] = [1024, 8, 1];
const salt = Buffer.alloc(32, 0x51);
const slotKey = scryptSync(Buffer.from(password, 'utf8'), salt, 32, { N: n, r, p });
const wrapped = seal(slotKey, Buffer.alloc(12, 0x0a), masterKey);
const content = seal(masterKey, Buffer.alloc(12, 0x0b), Buffer.from(JSON.stringify(db), 'utf8'));

function write(name, tag) {
  const vault = {
    version: 1,
    header: {
      slots: [
        // A biometric slot (Android KeyStore key), which an export can't use: it must be skipped.
        {
          type: 2,
          uuid: '7c4a1f00-0000-4000-8000-000000000002',
          key: Buffer.alloc(32, 0x22).toString('hex'),
          key_params: { nonce: Buffer.alloc(12, 0x23).toString('hex'), tag: Buffer.alloc(16, 0x24).toString('hex') },
        },
        {
          type: 1,
          uuid: '7c4a1f00-0000-4000-8000-000000000001',
          key: wrapped.data.toString('hex'),
          key_params: { nonce: wrapped.nonce, tag: wrapped.tag },
          n,
          r,
          p,
          salt: salt.toString('hex'),
          repaired: true,
          is_backup: false,
        },
      ],
      params: { nonce: content.nonce, tag },
    },
    db: content.data.toString('base64'),
  };
  writeFileSync(new URL(name, dir), `${JSON.stringify(vault, null, 4)}\n`);
}

write('aegis-encrypted.json', content.tag);
// The right password opens the slot, but the contents' tag no longer matches.
write('aegis-damaged.json', `${content.tag.slice(0, -2)}${content.tag.endsWith('00') ? '01' : '00'}`);
