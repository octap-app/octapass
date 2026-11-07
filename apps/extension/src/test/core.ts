import { createRequire } from 'node:module';
import type * as Full from '@octapass/core/full';

/** The WASM core's Node build (same API as `@octapass/core/full`), for tests. Run `pnpm --filter @octapass/core build` first. */
export const testCore = createRequire(import.meta.url)('@octapass/core/node') as typeof Full;
