// Measures the Argon2id unlock (DerivedKeys.derive, default parameters) in WASM under Node.
// Run `pnpm --filter @octapass/core build` first, then `pnpm --filter @octapass/core bench`.
import { createRequire } from 'node:module';

const { DerivedKeys } = createRequire(import.meta.url)('../dist/node/octapass_core.js');
const prelogin = {
  kdf: { algorithm: 'argon2id', memoryKib: 65536, iterations: 3, parallelism: 1 },
  accountSalt: 'AAECAwQFBgcICQoLDA0ODw',
};
const secretKey = 'OP1-000G40-R40M30-E2091-85GR3-8E1W';
const runs = 7;

const times = [];
for (let i = 0; i <= runs; i++) {
  const start = performance.now();
  DerivedKeys.derive('alice@example.com', `password ${i}`, secretKey, prelogin).free();
  if (i > 0) times.push(performance.now() - start); // the first run includes WASM warm-up
}
times.sort((a, b) => a - b);
const ms = (t) => `${Math.round(t)} ms`;
console.log(`Argon2id unlock (64 MiB, t=3, p=1), ${runs} runs on Node ${process.version} ${process.arch}:`);
console.log(`  median ${ms(times[runs >> 1])}, min ${ms(times[0])}, max ${ms(times[runs - 1])}`);
