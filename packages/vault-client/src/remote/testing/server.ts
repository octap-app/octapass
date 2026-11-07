// Runs the real octapass-server for tests: dev mode, a fresh data directory, a free port.
// Node only. Build it first with `cargo build -p octapass-server` (the test setups do).

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../../../../..');
export const SERVER_BINARY = join(REPO_ROOT, 'target/debug/octapass-server');

export interface TestServer {
  url: string;
  dataDir: string;
  /** Everything the server printed, for failure messages. */
  output: () => string;
  stop: () => Promise<void>;
}

/** Set `OCTAPASS_TEST_REUSE_SERVER=1` to skip the build and use the binary already in `target/debug`. */
export function buildServer(): void {
  if (process.env.OCTAPASS_TEST_REUSE_SERVER === '1' && existsSync(SERVER_BINARY)) return;
  const result = spawnSync('cargo', ['build', '-p', 'octapass-server'], { cwd: REPO_ROOT, stdio: 'inherit' });
  if (result.status !== 0) throw new Error('cargo build -p octapass-server failed');
}

export function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address() as { port: number };
      probe.close(() => resolvePort(port));
    });
  });
}

export async function startServer(opts: { webOrigins?: string[]; port?: number; env?: Record<string, string> } = {}): Promise<TestServer> {
  const port = opts.port ?? (await freePort());
  const dataDir = mkdtempSync(join(tmpdir(), 'octapass-test-'));
  let log = '';
  const child: ChildProcess = spawn(SERVER_BINARY, [], {
    env: {
      ...process.env,
      OCTAPASS_DEV_MODE: 'true',
      OCTAPASS_BIND: `127.0.0.1:${port}`,
      OCTAPASS_DATA_DIR: dataDir,
      OCTAPASS_WEB_ORIGINS: (opts.webOrigins ?? ['http://localhost:5174']).join(','),
      OCTAPASS_LOG: 'warn',
      // Test suites sign in many times from one address.
      OCTAPASS_RATE_LIMITS: 'off',
      // No fetching real websites from tests; the icon tests turn it on with local sites only.
      OCTAPASS_ICONS: 'off',
      ...opts.env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout!.on('data', (chunk: Buffer) => (log += chunk.toString()));
  child.stderr!.on('data', (chunk: Buffer) => (log += chunk.toString()));
  const exited = new Promise<void>((resolveExit) => child.once('exit', () => resolveExit()));

  const url = `http://localhost:${port}`;
  const deadline = Date.now() + 15_000;
  for (;;) {
    if (child.exitCode !== null) throw new Error(`octapass-server exited early:\n${log}`);
    try {
      if ((await fetch(`${url}/readyz`)).ok) break;
    } catch {
      // Not listening yet.
    }
    if (Date.now() > deadline) throw new Error(`octapass-server didn't become ready:\n${log}`);
    await new Promise((r) => setTimeout(r, 100));
  }

  return {
    url,
    dataDir,
    output: () => log,
    stop: async () => {
      if (child.exitCode === null) {
        child.kill('SIGTERM');
        await exited;
      }
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}
