import { spawnSync } from 'node:child_process';
import { buildServer, REPO_ROOT } from '@octapass/vault-client/remote/testing/server';

export default function setup(): void {
  buildServer();
  // Rebuilds the WASM core only when the Rust sources changed since its last build.
  const result = spawnSync('pnpm', ['--filter', '@octapass/core', 'build:if-stale'], { cwd: REPO_ROOT, stdio: 'inherit' });
  if (result.status !== 0) throw new Error('pnpm --filter @octapass/core build:if-stale failed');
}
