import { HOSTED_SERVER_URL } from '@octapass/vault-client';

// Replaces the web vault's `app/service.ts` in this build (see vite.config.ts): the desktop app
// injects `TauriVaultService` into the web vault's <App>, so only the server default is needed.

/** The "Octa Pass" server choice. `VITE_SERVER_URL` points development builds at a local server. */
export const DEFAULT_SERVER_URL: string = import.meta.env.VITE_SERVER_URL || HOSTED_SERVER_URL;
