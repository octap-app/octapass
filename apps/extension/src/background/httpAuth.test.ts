import type { Item, ItemSummary, LoginDetails } from '@octapass/vault-client';
import { HttpAuth, type AuthChallenge, type HttpAuthHost } from './httpAuth';
import type { KeyValueStore } from './storage';

function memoryStore(): KeyValueStore {
  const values = new Map<string, unknown>();
  return {
    get: async <T,>(key: string) => values.get(key) as T | undefined,
    set: async (key: string, value: unknown) => void values.set(key, value),
    delete: async (key: string) => void values.delete(key),
    clear: async () => values.clear(),
  } as KeyValueStore;
}

function login(id: string, url: string, details: Partial<LoginDetails>, extra: Partial<ItemSummary> = {}): Item {
  return {
    id,
    vaultId: 'v',
    type: 'login',
    title: id,
    urls: [url],
    favorite: false,
    hasTotp: false,
    hasPasskey: false,
    createdAt: '',
    updatedAt: '',
    revision: 1,
    overview: { type: 'login', title: id, urls: [url] },
    details: { schemaVersion: 1, username: `${id}-user`, password: `${id}-secret`, ...details },
    ...extra,
  } as unknown as Item;
}

function setup(items: Item[], { unlocked = true } = {}) {
  const host: HttpAuthHost & { unlocked: boolean } = {
    unlocked,
    listItems: async () => items as unknown as ItemSummary[],
    getItem: async (id) => items.find((i) => i.id === id)!,
  };
  const prompts: string[] = [];
  const closed: number[] = [];
  let next = 0;
  const auth = new HttpAuth(host, memoryStore(), {
    openPrompt: async (id) => {
      prompts.push(id);
      return 40 + prompts.length;
    },
    closePrompt: async (windowId) => void closed.push(windowId),
    newId: () => `prompt-${++next}`,
    now: () => Date.parse('2026-10-25T09:00:00Z'),
  });
  return { auth, host, prompts, closed };
}

const page = (url: string, extra: Partial<AuthChallenge> = {}): AuthChallenge => ({ requestId: `r-${Math.random()}`, url, type: 'main_frame', scheme: 'basic', ...extra });
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('HTTP sign-in prompts', () => {
  it('asks the first time, then answers the site without asking', async () => {
    const { auth, prompts, closed } = setup([login('router', 'http://192.168.1.1/', {})]);
    const first = auth.answer(page('http://192.168.1.1/admin', { realm: 'Router' }));
    await flush();
    expect(prompts).toEqual(['prompt-1']);
    // The window never gets a password.
    expect(auth.prompt('prompt-1')).toEqual({ origin: 'http://192.168.1.1', realm: 'Router', logins: [{ itemId: 'router', title: 'router', username: 'router-user' }] });
    await auth.approve('prompt-1', 'router');
    await expect(first).resolves.toEqual({ authCredentials: { username: 'router-user', password: 'router-secret' } });
    expect(closed).toEqual([41]);

    await expect(auth.answer(page('http://192.168.1.1/status'))).resolves.toEqual({ authCredentials: { username: 'router-user', password: 'router-secret' } });
    expect(prompts).toHaveLength(1);
    expect(await auth.approvals()).toEqual([{ origin: 'http://192.168.1.1', itemId: 'router', approvedAt: '2026-10-25T09:00:00.000Z' }]);
  });

  it('needs the exact origin, and the realm when the login has one', async () => {
    const { auth, prompts } = setup([login('nas', 'https://nas.example.test/', { httpRealm: 'Files' })]);
    expect(await auth.answer(page('https://other.example.test/'))).toEqual({});
    expect(await auth.answer(page('http://nas.example.test/'))).toEqual({});
    expect(await auth.answer(page('https://nas.example.test:8443/'))).toEqual({});
    expect(await auth.answer(page('https://nas.example.test/', { realm: 'Admin' }))).toEqual({});
    expect(prompts).toEqual([]);
    const answer = auth.answer(page('https://nas.example.test/share', { realm: 'Files' }));
    await flush();
    await auth.approve(prompts[0]!, 'nas');
    expect((await answer).authCredentials?.username).toBe('nas-user');
  });

  it('offers the login for the realm ahead of logins without one', async () => {
    const { auth, prompts } = setup([login('any', 'https://admin.example.test', {}), login('exact', 'https://admin.example.test/x', { httpRealm: 'Staff' })]);
    void auth.answer(page('https://admin.example.test/', { realm: 'Staff' }));
    await flush();
    expect(auth.prompt(prompts[0]!).logins.map((l) => l.itemId)).toEqual(['exact', 'any']);
  });

  it('answers nothing while locked, for proxies, other schemes, or logins in the trash', async () => {
    const trashed = login('old', 'https://site.example.test', {}, { deletedAt: '2026-10-01T00:00:00Z' });
    expect(await setup([trashed]).auth.answer(page('https://site.example.test/'))).toEqual({});
    const items = [login('site', 'https://site.example.test', {})];
    expect(await setup(items, { unlocked: false }).auth.answer(page('https://site.example.test/'))).toEqual({});
    const { auth, prompts } = setup(items);
    expect(await auth.answer(page('https://site.example.test/', { isProxy: true }))).toEqual({});
    expect(await auth.answer(page('https://site.example.test/', { scheme: 'ntlm' }))).toEqual({});
    expect(prompts).toEqual([]);
  });

  it('never answers a frame, image or fetch started by another site, even once allowed', async () => {
    const { auth, prompts } = setup([login('site', 'https://site.example.test', {})]);
    const answer = auth.answer(page('https://site.example.test/'));
    await flush();
    await auth.approve(prompts[0]!, 'site');
    await answer;

    const sub = (extra: Partial<AuthChallenge>) => auth.answer(page('https://site.example.test/inner', { type: 'sub_frame', ...extra }));
    expect(await sub({ initiator: 'https://evil.example', topOrigin: 'https://evil.example/' })).toEqual({});
    // A frame of the site inside another site's page.
    expect(await sub({ initiator: 'https://site.example.test', topOrigin: 'https://evil.example/' })).toEqual({});
    expect(await auth.answer(page('https://site.example.test/pic.png', { type: 'image', originUrl: 'https://evil.example/page', topOrigin: 'https://evil.example/page' }))).toEqual({});
    // No tab (a service worker): nothing.
    expect(await auth.answer(page('https://site.example.test/api', { type: 'xmlhttprequest', initiator: 'https://site.example.test' }))).toEqual({});
    // The site's own page fetching from itself.
    expect((await auth.answer(page('https://site.example.test/api', { type: 'xmlhttprequest', initiator: 'https://site.example.test', topOrigin: 'https://site.example.test/' }))).authCredentials).toBeDefined();
    expect(prompts).toHaveLength(1);
  });

  it('lets the browser ask when the credentials were turned down', async () => {
    const { auth, prompts } = setup([login('site', 'https://site.example.test', {})]);
    const challenge = page('https://site.example.test/');
    const answer = auth.answer(challenge);
    await flush();
    await auth.approve(prompts[0]!, 'site');
    expect((await answer).authCredentials).toBeDefined();
    // The browser asks again for the same request after a wrong password.
    expect(await auth.answer(challenge)).toEqual({});
  });

  it('shows one window per site, and "Not now" stops asking until removed', async () => {
    const { auth, prompts, closed } = setup([login('site', 'https://site.example.test', {})]);
    const one = auth.answer(page('https://site.example.test/a'));
    const two = auth.answer(page('https://site.example.test/b'));
    await flush();
    expect(prompts).toEqual(['prompt-1']);
    auth.decline('prompt-1');
    expect(await one).toEqual({});
    expect(await two).toEqual({});
    expect(closed).toEqual([41]);
    expect(await auth.answer(page('https://site.example.test/c'))).toEqual({});
    expect(prompts).toHaveLength(1);
    expect(() => auth.prompt('prompt-1')).toThrow();

    await auth.remove('https://site.example.test');
    void auth.answer(page('https://site.example.test/d'));
    await flush();
    expect(prompts).toHaveLength(2);
  });

  it('treats a closed window as "Not now", and locking ends every prompt', async () => {
    const { auth, prompts } = setup([login('a', 'https://a.example.test', {}), login('b', 'https://b.example.test', {})]);
    const a = auth.answer(page('https://a.example.test/'));
    const b = auth.answer(page('https://b.example.test/'));
    await flush();
    auth.windowClosed(41);
    expect(await a).toEqual({});
    auth.cancelAll();
    expect(await b).toEqual({});
    await expect(auth.approve(prompts[1]!, 'b')).rejects.toThrow();
  });

  it('refuses a login that wasn’t offered', async () => {
    const { auth, prompts } = setup([login('a', 'https://a.example.test', {}), login('b', 'https://b.example.test', {})]);
    void auth.answer(page('https://a.example.test/'));
    await flush();
    await expect(auth.approve(prompts[0]!, 'b')).rejects.toThrow();
    expect(await auth.approvals()).toEqual([]);
  });

  it('gives up after a while, so the browser asks', async () => {
    vi.useFakeTimers();
    try {
      const { auth } = setup([login('site', 'https://site.example.test', {})]);
      const answer = auth.answer(page('https://site.example.test/'));
      await vi.advanceTimersByTimeAsync(2 * 60_000);
      expect(await answer).toEqual({});
    } finally {
      vi.useRealTimers();
    }
  });
});
