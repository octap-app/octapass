import { defineConfig } from 'vitest/config';

// The real service against a real octapass-server (see src/remote/testing/server.ts).
export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    include: ['src/**/*.server.test.ts'],
    setupFiles: ['fake-indexeddb/auto'],
    globalSetup: ['src/remote/testing/globalSetup.ts'],
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
});
