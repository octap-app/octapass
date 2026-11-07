// The storage the vault engine is given: IndexedDB for what survives restarts (same records as the
// web vault, never plaintext), and `chrome.storage.session` (memory only) for the unlocked session.

/** The engine's key/value storage (`@octapass/vault-client`'s `KeyValueStore`). */
export interface KeyValueStore {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<void>;
  clear(): Promise<void>;
}

const STORE = 'kv';

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function openKeyValueStore(name: string): Promise<KeyValueStore> {
  const open = indexedDB.open(name, 1);
  open.onupgradeneeded = () => open.result.createObjectStore(STORE);
  const db = await request(open);
  const run = <T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>) => request(fn(db.transaction(STORE, mode).objectStore(STORE)));
  return {
    get: async <T>(key: string) => (await run('readonly', (s) => s.get(key))) as T | undefined,
    set: async (key, value) => void (await run('readwrite', (s) => s.put(value, key))),
    delete: async (key) => void (await run('readwrite', (s) => s.delete(key))),
    clear: async () => void (await run('readwrite', (s) => s.clear())),
  };
}

/** A `chrome.storage` area as a key/value store (`chrome.storage.session` for the session). */
export function storageArea(area: chrome.storage.StorageArea): KeyValueStore {
  return {
    get: async <T>(key: string) => (await area.get(key))[key] as T | undefined,
    set: (key, value) => area.set({ [key]: value }),
    delete: (key) => area.remove(key),
    clear: () => area.clear(),
  };
}
