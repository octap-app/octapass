import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['fake-indexeddb/auto'],
    // Needs a running octapass-server: `pnpm test:server`.
    exclude: ['**/node_modules/**', 'src/**/*.server.test.ts'],
  },
});
