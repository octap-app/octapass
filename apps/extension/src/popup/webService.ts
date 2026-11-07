// Stands in for the web vault's `app/service.ts` inside the extension (see vite.config.ts): the web
// screens only need the default server, and the extension's engine runs in the service worker.

import { HOSTED_SERVER_URL } from '@octapass/vault-client';

/** The "Octa Pass" server choice. A local server in development, unless `VITE_SERVER_URL` says otherwise. */
export const DEFAULT_SERVER_URL: string = import.meta.env.VITE_SERVER_URL || (import.meta.env.DEV ? 'http://localhost:8080' : HOSTED_SERVER_URL);
