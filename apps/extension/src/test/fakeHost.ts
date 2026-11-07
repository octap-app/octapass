import { matchesFilter, summarizeItem, type ApiCredentialDetails, type Item, type ItemDraft, type ItemFilter } from '@octapass/vault-client';
import type { VaultHost } from '../background/vault';

/** Just enough of the service worker's vault for the content-script handlers: items in memory. */
export function fakeHost(initial: Item[] = []) {
  const items = new Map(initial.map((i) => [i.id, structuredClone(i)]));
  const saved: ItemDraft[] = [];
  /** The items whose use was counted (fills), in order. */
  const used: string[] = [];
  /** What `usage.read()` answers: when each item was last used, by id. */
  const usage: Record<string, { count: number; lastUsedAt: string }> = {};
  let next = 1;
  const state = { status: 'unlocked' as 'unlocked' | 'locked' | 'signedOut', local: false };
  const host = {
    get snapshot() {
      return { session: { status: state.status }, remembered: [] };
    },
    get unlocked() {
      return state.status === 'unlocked';
    },
    get local() {
      return state.local;
    },
    listItems: async () => [...items.values()].map(summarizeItem).filter((s) => matchesFilter(s)),
    getItem: async (id: string) => {
      const item = items.get(id);
      if (!item) throw new Error('notFound');
      return structuredClone(item);
    },
    usage: {
      record: (id: string) => void used.push(id),
      read: async () => ({ ...usage }),
      clear: () => undefined,
    },
    engine: {
      call: async (method: string, args: unknown[]) => {
        if (method === 'listVaults') return [{ id: 'v1', name: 'Personal', type: 'personal', role: 'owner' }];
        if (method === 'totpCode') return { code: '123456', period: 30, remaining: 10 };
        if (method === 'listItems') return [...items.values()].map(summarizeItem).filter((s) => matchesFilter(s, args[0] as ItemFilter));
        if (method === 'deleteItem') return void (items.get(args[0] as string)!.deletedAt = '2026-10-24T00:00:00Z');
        if (method === 'saveItem') {
          const draft = args[0] as ItemDraft;
          saved.push(structuredClone(draft));
          const id = draft.id ?? `new-${next++}`;
          const item: Item = { id, vaultId: draft.vaultId, revision: (draft.revision ?? 0) + 1, createdAt: new Date(Date.UTC(2026, 9, 24) + next * 1000).toISOString(), updatedAt: '', overview: draft.overview, details: draft.details };
          items.set(id, item);
          return item;
        }
        throw new Error(`unexpected ${method}`);
      },
    },
  };
  return { host: host as unknown as VaultHost, items, saved, state, used, usage };
}

export function login(id: string, url: string, username: string, password: string, extra: Partial<Item['overview']> = {}, details: object = {}): Item {
  return {
    id,
    vaultId: 'v1',
    revision: 1,
    createdAt: '2026-10-24T00:00:00Z',
    updatedAt: '2026-10-24T00:00:00Z',
    overview: { schemaVersion: 1, title: id, type: 'login', urls: [url], subtitle: username, ...extra },
    details: { schemaVersion: 1, username, password, ...details } as Item['details'],
  };
}

export function credential(id: string, url: string, details: Partial<ApiCredentialDetails>, extra: Partial<Item> = {}): Item {
  return {
    id,
    vaultId: 'v1',
    revision: 1,
    createdAt: '2026-10-24T00:00:00Z',
    updatedAt: '2026-10-24T00:00:00Z',
    overview: { schemaVersion: 1, title: id, type: 'apiCredential', urls: [url], subtitle: new URL(url).hostname },
    details: { schemaVersion: 1, ...details },
    ...extra,
  };
}
