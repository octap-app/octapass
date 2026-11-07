/** A one-store key/value wrapper over IndexedDB, enough for a few records per account. */
export interface KeyValueStore {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<void>;
  /** Deletes every record. */
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

  const run = <T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>) =>
    request(fn(db.transaction(STORE, mode).objectStore(STORE)));

  return {
    get: async <T>(key: string) => (await run('readonly', (s) => s.get(key))) as T | undefined,
    set: async (key, value) => {
      await run('readwrite', (s) => s.put(value, key));
    },
    delete: async (key) => {
      await run('readwrite', (s) => s.delete(key));
    },
    clear: async () => {
      await run('readwrite', (s) => s.clear());
    },
  };
}
