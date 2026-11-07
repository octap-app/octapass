import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  server: { port: 5174 },
  // The WASM core resolves its .wasm file relative to itself; pre-bundling would break that.
  optimizeDeps: { exclude: ['@octapass/core'] },
  worker: { format: 'es' },
  build: {
    target: 'es2023',
    sourcemap: true,
    rolldownOptions: {
      output: {
        // Separate chunks that rarely change, so app updates don't re-download them.
        codeSplitting: {
          groups: [
            { name: 'react', test: /node_modules[\\/](react|react-dom|react-router|scheduler)[\\/]/ },
            { name: 'wordlists', test: /vault-client[\\/]src[\\/]data[\\/]/ },
          ],
        },
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    // Component tests run on the mock; the real service is covered by the e2e suite.
    env: { VITE_VAULT_BACKEND: 'mock' },
    css: { modules: { classNameStrategy: 'non-scoped' } },
  },
});
