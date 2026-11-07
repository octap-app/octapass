import '@testing-library/jest-dom/vitest';
import 'fake-indexeddb/auto';
import { cleanup } from '@testing-library/react';

// The parts of `chrome` every module touches; tests that need more stub them themselves.
const EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop';
const stored: Record<string, unknown> = {};

afterEach(() => {
  cleanup();
  for (const key of Object.keys(stored)) delete stored[key];
});

globalThis.chrome = {
  runtime: {
    id: EXTENSION_ID,
    getURL: (path: string) => `chrome-extension://${EXTENSION_ID}/${path.replace(/^\//, '')}`,
    // The popup's settings read the optional permissions (the browser autofill setting).
    getManifest: () => ({ manifest_version: 3, name: 'Octa Pass', version: '0.0.0', optional_permissions: [] }),
  },
  storage: {
    local: {
      get: async (keys: string | string[]) => {
        const wanted = Array.isArray(keys) ? keys : [keys];
        return Object.fromEntries(wanted.filter((key) => key in stored).map((key) => [key, stored[key]]));
      },
      set: async (values: Record<string, unknown>) => {
        Object.assign(stored, values);
      },
      remove: async (keys: string | string[]) => {
        for (const key of Array.isArray(keys) ? keys : [keys]) delete stored[key];
      },
    },
  },
  permissions: {
    contains: async () => false,
    request: async () => false,
    remove: async () => false,
  },
} as unknown as typeof chrome;

// jsdom has no matchMedia; report a wide desktop screen, as the web vault's tests do.
window.matchMedia ??= (query: string) =>
  ({ matches: false, media: query, addEventListener: () => {}, removeEventListener: () => {} }) as unknown as MediaQueryList;
