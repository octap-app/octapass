import { HOSTED_SERVER_URL, type VaultService } from '@octapass/vault-client';

/** `remote` (default): the WASM core and a real server. `mock`: everything in the browser, for demos and UI work. */
const BACKEND = import.meta.env.VITE_VAULT_BACKEND === 'mock' ? 'mock' : 'remote';

/**
 * The "Octa Pass" server choice: `VITE_SERVER_URL`, where `same-origin` means the server this page
 * came from (the web vault the server itself serves). Otherwise a local server in development and
 * the hosted service in production.
 */
export function defaultServerUrl(configured: string | undefined, origin: string, localDev: boolean): string {
  if (configured === 'same-origin') return origin;
  return configured || (localDev ? 'http://localhost:8080' : HOSTED_SERVER_URL);
}

export const DEFAULT_SERVER_URL: string = defaultServerUrl(
  import.meta.env.VITE_SERVER_URL,
  globalThis.location?.origin ?? '',
  BACKEND === 'remote' && import.meta.env.DEV,
);

export async function createVaultService(): Promise<VaultService> {
  if (BACKEND === 'mock') {
    const { MockVaultService } = await import('@octapass/vault-client/mock');
    // SSH keys and Nearby need the real core, loaded in the page here (the remote build runs it in the worker).
    let loaded: Promise<typeof import('@octapass/core')> | undefined;
    const core = () =>
      (loaded ??= (async () => {
        const [module, { default: wasmUrl }] = await Promise.all([import('@octapass/core'), import('@octapass/core/octapass_core_bg.wasm?url')]);
        await module.default({ module_or_path: wasmUrl });
        return module;
      })());
    return MockVaultService.create({ sshCore: core, placesCore: core });
  }
  const { RemoteVaultService, portClient } = await import('@octapass/vault-client/remote');
  const worker = new Worker(new URL('../worker/vault.worker.ts', import.meta.url), { type: 'module', name: 'vault' });
  return RemoteVaultService.create(portClient(worker));
}
