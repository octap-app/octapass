// Signs the health report's site lists (plan 06) into packages/vault-client/src/data/health-data.json,
// the copy every release bundles, and apps/website/public/data/health-data.json, the copy servers
// fetch. See README.md.
//
//   node tools/health-data/sign.mjs --key <private-key.pem> [--version <n>]
//   node tools/health-data/sign.mjs --check
//   node tools/health-data/sign.mjs --keygen <new-private-key.pem>
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PASSKEY_DOMAINS } from '../../packages/vault-client/src/data/passkey-domains.ts';
import { TWO_FACTOR_DOMAINS } from '../../packages/vault-client/src/data/two-factor-domains.ts';

const here = (path) => fileURLToPath(new URL(path, import.meta.url));
const BUNDLED = here('../../packages/vault-client/src/data/health-data.json');
const PUBLISHED = here('../../apps/website/public/data/health-data.json');
const CONTEXT = 'openpass/v1/health-data';
const FORMAT = 1;

const args = process.argv.slice(2);
const option = (name) => {
  const at = args.indexOf(name);
  return at === -1 ? undefined : args[at + 1];
};
const fail = (message) => {
  console.error(message);
  process.exit(1);
};

/** The key the clients pin, read from the source so the two can't drift apart. */
function pinnedKey() {
  const source = readFileSync(here('../../packages/vault-client/src/tools/healthData.ts'), 'utf8');
  const match = /HEALTH_DATA_PUBLIC_KEY = '([A-Za-z0-9+/=]+)'/.exec(source);
  if (!match) fail('HEALTH_DATA_PUBLIC_KEY not found in healthData.ts');
  // An Ed25519 SPKI is a fixed 12-byte header and the 32-byte key.
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(match[1], 'base64')]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

const message = (payload) => Buffer.concat([Buffer.from(CONTEXT), Buffer.from([0]), payload]);

function readFile(path) {
  const file = JSON.parse(readFileSync(path, 'utf8'));
  const payload = Buffer.from(file.payload, 'base64');
  if (!verify(null, message(payload), pinnedKey(), Buffer.from(file.signature, 'base64'))) fail(`${path}: the signature doesn't match the pinned key`);
  return JSON.parse(payload.toString('utf8'));
}

const sorted = (set) => [...set].sort();

if (args.includes('--keygen')) {
  const out = option('--keygen');
  if (!out || existsSync(out)) fail('usage: --keygen <new-file.pem> (the file must not exist)');
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(out, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  console.log(`private key: ${out} (keep it out of the repository)`);
  console.log(`public key, for HEALTH_DATA_PUBLIC_KEY and HEALTH_DATA_PUBLIC_KEY in Rust: ${raw.toString('base64')}`);
  process.exit(0);
}

if (args.includes('--check')) {
  const bundled = readFile(BUNDLED);
  const published = readFile(PUBLISHED);
  if (bundled.version !== published.version) fail(`bundled version ${bundled.version}, published ${published.version}`);
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  if (!same(bundled.passkeyDomains, sorted(PASSKEY_DOMAINS)) || !same(bundled.twoFactorDomains, sorted(TWO_FACTOR_DOMAINS))) {
    fail('the signed lists differ from passkey-domains.ts and two-factor-domains.ts: sign again');
  }
  console.log(`health data version ${bundled.version}: signed, published, and matching the lists`);
  process.exit(0);
}

const keyPath = option('--key') ?? process.env.OCTAPASS_HEALTH_DATA_KEY;
if (!keyPath) fail('usage: node tools/health-data/sign.mjs --key <private-key.pem> [--version <n>] | --check | --keygen <file>');
const privateKey = createPrivateKey(readFileSync(keyPath));
const pinned = pinnedKey().export({ type: 'spki', format: 'der' });
if (!createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).equals(pinned)) fail("that key isn't the one the clients pin");

const previous = existsSync(BUNDLED) ? readFile(BUNDLED).version : 0;
const version = option('--version') ? Number(option('--version')) : previous + 1;
if (!Number.isSafeInteger(version) || version <= previous) fail(`the version must be a whole number above ${previous}: clients refuse older files`);

const payload = Buffer.from(
  JSON.stringify({
    format: FORMAT,
    version,
    issuedAt: new Date().toISOString(),
    passkeyDomains: sorted(PASSKEY_DOMAINS),
    twoFactorDomains: sorted(TWO_FACTOR_DOMAINS),
  }),
);
const signature = sign(null, message(payload), privateKey);
const file = `${JSON.stringify({ payload: payload.toString('base64'), signature: signature.toString('base64') }, null, 2)}\n`;
for (const path of [BUNDLED, PUBLISHED]) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, file);
}
console.log(`signed version ${version}: ${PASSKEY_DOMAINS.size} passkey and ${TWO_FACTOR_DOMAINS.size} two-step domains`);
