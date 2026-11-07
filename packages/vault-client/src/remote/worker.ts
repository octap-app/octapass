// Hosts the engine in a dedicated Web Worker: the WASM core, the session keys and the decrypted
// vault live here, away from page scripts. The page talks to it through `portClient(worker)`.

import { openKeyValueStore } from '../idb';
import { VaultEngine, type Core, type EngineOptions } from './engine';
import { postEvents, serveEngine, type Port } from './protocol';

export const DATABASE_NAME = 'octapass';

// First match wins: Edge and Chrome both say "Chrome", Chrome says "Safari", iPads say "Mac OS X".
const BROWSERS: [RegExp, string][] = [
  [/Edg\//, 'Edge'],
  [/Firefox\//, 'Firefox'],
  [/Chrome\//, 'Chrome'],
  [/Safari\//, 'Safari'],
];
const SYSTEMS: [RegExp, string][] = [
  [/iPhone|iPad/, 'iOS'],
  [/Mac OS X/, 'Mac'],
  [/Windows/, 'Windows'],
  [/Android/, 'Android'],
  [/Linux/, 'Linux'],
];

/** "Chrome on Mac", for the account's device list. */
export function describeBrowser(userAgent: string): string {
  const browser = BROWSERS.find(([pattern]) => pattern.test(userAgent))?.[1] ?? 'Browser';
  const system = SYSTEMS.find(([pattern]) => pattern.test(userAgent))?.[1];
  return system ? `${browser} on ${system}` : browser;
}

/** `loadFullCore`: see {@link EngineOptions.loadFullCore}. */
export function startVaultWorker(loadCore: () => Promise<Core>, scope: Port = self as unknown as Port, loadFullCore?: EngineOptions['loadFullCore'], loadToolsCore?: EngineOptions['loadToolsCore']): void {
  const withLock = <T>(name: string, fn: () => Promise<T>): Promise<T> => navigator.locks.request(name, fn);
  const engine = openKeyValueStore(DATABASE_NAME).then(
    (storage) =>
      new VaultEngine({
        loadCore,
        loadFullCore,
        loadToolsCore,
        storage,
        emit: postEvents(scope),
        withLock,
        device: { name: describeBrowser(navigator.userAgent), platform: 'web' },
      }),
  );
  serveEngine(engine, scope);
}
