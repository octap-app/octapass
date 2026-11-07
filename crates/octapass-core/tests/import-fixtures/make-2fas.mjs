// Writes 2fas-encrypted.2fas and 2fas-damaged.2fas: the services of 2fas.2fas in 2FAS's
// password-protected backup format, using Node's crypto only (independent of the Rust importer).
// Fixed salt and IVs keep the output reproducible; real backups use random ones.
import { createCipheriv, pbkdf2Sync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const dir = new URL('.', import.meta.url);
const password = 'correct horse battery staple';
const backup = JSON.parse(readFileSync(new URL('2fas.2fas', dir), 'utf8'));

// The fixed text 2FAS encrypts as `reference` (BackupContent.Reference in the Android app).
const reference =
  'tRViSsLKzd86Hprh4ceC2OP7xazn4rrt4xhfEUbOjxLX8Rc3mkISXE0lWbmnWfggogbBJhtYgpK6fMl1D6mtsy92R3HkdGfwuXbzLebqVFJsR7IZ2w58t938iymwG4824igYy1wi6n2WDpO1Q1P69zwJGs2F5a1qP4MyIiDSD7NCV2OvidXQCBnDlGfmz0f1BQySRkkt4ryiJeCjD2o4QsveJ9uDBUn8ELyOrESv5R5DMDkD4iAF8TXU7KyoJujd';

const salt = Buffer.alloc(32, 0x5a);
const key = pbkdf2Sync(password, salt, 10000, 32, 'sha256');

// base64(ciphertext ‖ tag) ":" base64(salt) ":" base64(iv)
function seal(text, ivByte) {
  const iv = Buffer.alloc(12, ivByte);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return [data, salt, iv].map((part) => part.toString('base64')).join(':');
}

function write(name, servicesEncrypted) {
  const encrypted = {
    ...backup,
    services: [],
    servicesEncrypted,
    reference: seal(reference, 0x01),
  };
  writeFileSync(new URL(name, dir), `${JSON.stringify(encrypted, null, 2)}\n`);
}

const sealed = seal(JSON.stringify(backup.services), 0x02);
write('2fas-encrypted.2fas', sealed);
// The salt and IV are missing, as if the file was cut off.
write('2fas-damaged.2fas', sealed.split(':')[0]);
