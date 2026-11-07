import { defineConfig } from 'vitest/config';

// The service worker's vault against a real octapass-server (cargo build -p octapass-server first).
export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    include: ['src/**/*.server.test.ts'],
    setupFiles: ['fake-indexeddb/auto'],
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
});
