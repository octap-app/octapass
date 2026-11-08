import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';
import type { Plugin, UserConfig } from 'vite';
import { defineConfig } from 'vitest/config';
import type { Target } from './src/manifest';

// One config, four bundles per browser (scripts/build.ts runs them):
// - `pages`: the app page (a tab) and the passkey prompt (ES modules, code-split like any web app),
// - `background`: one ES module file, because service workers can't import() chunks,
// - `content` and `page`: classic scripts, because content scripts can't be modules.
// Safari has no side panel, and its background and pages start from `safari/background.ts` and
// `safari/pages.ts`, which install Safari's fixes (`safari/compat.ts`) before the shared code runs.

export type Part = 'pages' | 'background' | 'content' | 'page';

const src = (path: string) => fileURLToPath(new URL(`./src/${path}`, import.meta.url));
const WEB_SERVICE = fileURLToPath(new URL('../web/src/app/service.ts', import.meta.url));

/**
 * The web vault's screens import its service factory, which starts a Web Worker. The extension's
 * engine lives in the service worker instead, so those imports get the extension's own module.
 */
function webServiceShim(): Plugin {
  return {
    name: 'octapass:web-service-shim',
    enforce: 'pre',
    async resolveId(source, importer, options) {
      if (!importer?.includes('/apps/web/src/')) return null;
      const resolved = await this.resolve(source, importer, { ...options, skipSelf: true });
      return resolved?.id === WEB_SERVICE ? src('popup/webService.ts') : null;
    },
  };
}

/** Puts `safari/pages.ts` ahead of each page's own script, so it runs first. */
function safariPages(): Plugin {
  return {
    name: 'octapass:safari-pages',
    transformIndexHtml: { order: 'pre', handler: () => [{ tag: 'script', attrs: { type: 'module', src: './safari/pages.ts' }, injectTo: 'head' }] },
  };
}

const shared = {
  // The WASM core resolves its .wasm file relative to itself; pre-bundling would break that.
  optimizeDeps: { exclude: ['@octapass/core'] },
  resolve: { dedupe: ['react', 'react-dom', 'react-router'] },
} satisfies UserConfig;

/** `__OCTAPASS_TARGET__` lets a build leave out other browsers' code paths (AMO flags `chrome.dom`). */
export function extensionConfig(part: Part, outDir: string, mode: string, target: Target = 'chrome'): UserConfig {
  const config = partConfig(part, outDir, mode, target);
  return { ...config, define: { ...config.define, __OCTAPASS_TARGET__: JSON.stringify(target) } };
}

function partConfig(part: Part, outDir: string, mode: string, target: Target): UserConfig {
  const safari = target === 'safari';
  const build = { outDir, emptyOutDir: false, target: 'es2023', sourcemap: mode === 'development', minify: mode !== 'development', modulePreload: false } as const;
  switch (part) {
    case 'pages':
      return {
        ...shared,
        mode,
        root: src(''),
        base: '',
        publicDir: fileURLToPath(new URL('./public', import.meta.url)),
        plugins: [webServiceShim(), react(), ...(safari ? [safariPages()] : [])],
        build: {
          ...build,
          rolldownOptions: {
            input: { app: src('app.html'), passkey: src('passkey.html') },
            output: {
              codeSplitting: {
                groups: [
                  { name: 'react', test: /node_modules[\\/](react|react-dom|react-router|scheduler)[\\/]/ },
                  { name: 'wordlists', test: /vault-client[\\/]src[\\/]data[\\/]/ },
                ],
              },
            },
          },
        },
      };
    case 'background':
    case 'content':
    case 'page':
      return {
        ...shared,
        mode,
        publicDir: false,
        build: {
          ...build,
          rolldownOptions: {
            input: { [part]: src(safari && part === 'background' ? 'safari/background.ts' : `${part}/index.ts`) },
            output: {
              format: part === 'background' ? 'es' : 'iife',
              entryFileNames: `${part}.js`,
              assetFileNames: 'assets/[name]-[hash][extname]',
              codeSplitting: false,
            },
          },
        },
      };
  }
}

export default defineConfig({
  ...shared,
  plugins: [webServiceShim(), react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    exclude: ['src/**/*.server.test.ts'],
    css: { modules: { classNameStrategy: 'non-scoped' } },
  },
});
