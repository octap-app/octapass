import type { KeyValueStore } from '../background/storage';

/** A key/value store in a Map, copying values like a real store would. */
export function memoryStore(): KeyValueStore & { data: Map<string, unknown> } {
  const data = new Map<string, unknown>();
  return {
    data,
    get: async <T>(key: string) => structuredClone(data.get(key)) as T | undefined,
    set: async (key, value) => void data.set(key, structuredClone(value)),
    delete: async (key) => void data.delete(key),
    clear: async () => data.clear(),
  };
}
