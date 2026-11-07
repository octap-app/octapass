import { defineConfig } from 'vitest/config';

// Browser tests against a real octapass-server and a production build (e2e/stack.ts).
export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    include: ['e2e/**/*.e2e.ts'],
    globalSetup: ['e2e/globalSetup.ts'],
    testTimeout: 60_000,
    hookTimeout: 300_000,
    fileParallelism: false,
  },
});
