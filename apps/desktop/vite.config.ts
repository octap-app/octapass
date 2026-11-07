import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import type { Plugin } from 'vite';
import { defineConfig } from 'vitest/config';

const webService = fileURLToPath(new URL('../web/src/app/service.ts', import.meta.url));
const desktopService = fileURLToPath(new URL('./src/webService.ts', import.meta.url));

/**
 * The web vault picks its backend in `app/service.ts`; the desktop app injects its own, so that
 * module is swapped for one that only keeps the server default (and the WASM worker stays out).
 */
function desktopBackend(): Plugin {
  return {
    name: 'octapass-desktop-backend',
    enforce: 'pre',
    async resolveId(source, importer, options) {
      const resolved = await this.resolve(source, importer, { ...options, skipSelf: true });
      return resolved?.id === webService ? desktopService : null;
    },
  };
}

export default defineConfig({
  plugins: [desktopBackend(), react()],
  // Tauri expects a fixed port and its own output folder.
  server: { port: 1420, strictPort: true },
  clearScreen: false,
  resolve: { dedupe: ['react', 'react-dom', 'react-router'] },
  build: {
    target: 'safari16',
    outDir: 'dist',
    rolldownOptions: {
      input: {
        main: fileURLToPath(new URL('./index.html', import.meta.url)),
        quick: fileURLToPath(new URL('./quick.html', import.meta.url)),
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: { modules: { classNameStrategy: 'non-scoped' } },
  },
});
