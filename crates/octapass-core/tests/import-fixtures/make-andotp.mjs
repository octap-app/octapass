// Writes andotp.json.aes and andotp-legacy.json.aes (andotp.json in andOTP's encrypted backup
// formats, using Node's crypto only, independent of the Rust importer) and andotp-damaged.json.
// Fixed salts and nonces keep the output reproducible; real backups use random ones. andOTP picks
// 140,000 to 160,000 iterations at random; 10,000 keeps the tests fast (same layout).
import { createCipheriv, createHash, pbkdf2Sync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const dir = new URL('.', import.meta.url);
const password = 'correct horse battery staple';
const plaintext = readFileSync(new URL('andotp.json', dir));

// nonce (12) ‖ ciphertext ‖ tag (16)
function seal(key, nonceByte) {
  const nonce = Buffer.alloc(12, nonceByte);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  return Buffer.concat([nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

// iterations (4, big-endian) ‖ salt (12) ‖ nonce ‖ ciphertext ‖ tag; PBKDF2-HMAC-SHA1.
const iterations = 10000;
const salt = Buffer.alloc(12, 0x3c);
const header = Buffer.alloc(4);
header.writeUInt32BE(iterations);
const current = Buffer.concat([header, salt, seal(pbkdf2Sync(password, salt, iterations, 32, 'sha1'), 0x0c)]);
writeFileSync(new URL('andotp.json.aes', dir), current);

// Older andOTP versions: the key is SHA-256 of the password, with no header.
const legacyKey = createHash('sha256').update(password, 'utf8').digest();
writeFileSync(new URL('andotp-legacy.json.aes', dir), seal(legacyKey, 0x9d));

// A plain backup cut off in the middle (of a multi-byte character, too).
writeFileSync(new URL('andotp-damaged.json', dir), plaintext.subarray(0, plaintext.indexOf('بنك') + 1));
