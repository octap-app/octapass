import type { CardDetails, LoginDetails } from '@octapass/vault-client';
import { testCore } from '../test/core';
import { fakeHost, login } from '../test/fakeHost';
import { memoryStore } from '../test/memoryStore';
import { DetailsSaver } from './detailsSaves';
import { SaveInbox } from './inbox';
import { Matcher } from './matching';
import { NeverSave } from './neverSave';
import { LoginSaver, UNCONFIRMED_TAG } from './saves';
import type { PageSender } from './senders';

const sender = (url: string, tabId = 1): PageSender => ({ tabId, frameId: 0, url, origin: new URL(url).origin, topOrigin: new URL(url).origin });
const submit = (username: string, password: string) => ({ username, password, formType: 'login' as const, trigger: 'submit' as const, draft: false });

/** A fake vault host whose engine pins and opens the inbox with a real local vault's keys. */
function setup(items = [login('shop', 'https://shop.example', 'maya', 'old', { tags: ['Work'] })]) {
  const fake = fakeHost(items);
  fake.state.local = true;
  const vault = testCore.LocalVault.create('vexed-kiwi-trumpet-galaxy-oboe', { memoryKib: 65_536 });
  const call = fake.host.engine.call.bind(fake.host.engine);
  (fake.host.engine as { call: (method: string, args: unknown[]) => Promise<unknown> }).call = async (method, args) => {
    if (method === 'pinInbox') return vault.inboxPin(args[0] as string);
    if (method === 'openInbox') return vault.inboxOpen(args[0] as string);
    if (method === 'equivalentDomains') throw new Error('none');
    return call(method as never, args as never);
  };
  const store = memoryStore();
  const matcher = new Matcher(testCore);
  const inbox = new SaveInbox(fake.host, store, async () => testCore, matcher);
  const never = new NeverSave(memoryStore(), matcher);
  return { ...fake, store, matcher, inbox, never, saver: new LoginSaver(fake.host, matcher, Date.now, undefined, never, inbox) };
}

async function saveLocked(saver: LoginSaver, url: string, username: string, password: string) {
  const response = await saver.report(submit(username, password), sender(url));
  const { prompt } = response as { prompt: { id: string; kind: string; locked?: boolean } };
  await saver.answer(prompt.id, 'save', sender(url));
  return prompt;
}

describe('SaveInbox', () => {
  it('asks while locked, seals the save, and merges it at the next unlock', { timeout: 60_000 }, async () => {
    const { saver, inbox, items, store, state } = setup();
    // An unlock pins the vault's own public keys; nothing waits yet.
    expect(await inbox.unlocked()).toBeUndefined();
    state.status = 'locked';
    expect(await inbox.accepts()).toBe(true);

    // Locked, nothing can be compared with the vault: always "Save", even for the saved login.
    expect(await saveLocked(saver, 'https://new.example/join', 'samuel-rivers', 'fresh-password-1')).toMatchObject({ kind: 'save', locked: true });
    // Exactly what the vault has: dropped at the merge.
    expect(await saveLocked(saver, 'https://shop.example/login', 'maya', 'old')).toMatchObject({ kind: 'save', locked: true });
    await saveLocked(saver, 'https://shop.example/login', 'maya', 'changed-password-2');
    // The same new login twice: one is dropped.
    await saveLocked(saver, 'https://new.example/login', 'samuel-rivers', 'fresh-password-1');

    const sealed = JSON.stringify(store.data.get('inbox:local'));
    expect(JSON.parse(store.data.get('inbox:local') as string).entries).toHaveLength(4);
    for (const secret of ['fresh-password-1', 'changed-password-2', 'samuel-rivers', 'new.example', 'shop.example']) expect(sealed).not.toContain(secret);
    expect(items.size).toBe(1);

    state.status = 'unlocked';
    expect(await inbox.unlocked()).toEqual({ added: 1, updated: 1, duplicates: 2, failed: 0 });
    const added = [...items.values()].find((i) => i.id !== 'shop')!;
    expect(added.overview).toMatchObject({ title: 'new.example', urls: ['https://new.example'], tags: [UNCONFIRMED_TAG] });
    expect(added.details).toMatchObject({ username: 'samuel-rivers', password: 'fresh-password-1' });
    // The existing login gets the new password (the engine keeps the old one in its history) and keeps its tags.
    const shop = items.get('shop')!;
    expect((shop.details as LoginDetails).password).toBe('changed-password-2');
    expect(shop.overview.tags).toEqual(['Work']);
    expect(JSON.parse(store.data.get('inbox:local') as string).entries).toEqual([]);
  });

  it('keeps an entry whose merge fails, for the next unlock', { timeout: 60_000 }, async () => {
    const { saver, inbox, items, store, state, host } = setup([]);
    await inbox.unlocked();
    state.status = 'locked';
    await saveLocked(saver, 'https://new.example', 'samuel-rivers', 'pw');
    state.status = 'unlocked';
    const call = host.engine.call;
    (host.engine as { call: unknown }).call = async (method: string, args: unknown[]) => {
      if (method === 'saveItem') throw new Error('offline');
      return call(method as never, args as never);
    };
    expect(await inbox.unlocked()).toEqual({ added: 0, updated: 0, duplicates: 0, failed: 1 });
    expect(JSON.parse(store.data.get('inbox:local') as string).entries).toHaveLength(1);
    (host.engine as { call: unknown }).call = call;
    expect(await inbox.unlocked()).toMatchObject({ added: 1 });
    expect(items.size).toBe(1);
  });

  it('offers nothing with no pinned key, at never-save sites, when signed out, or when full', { timeout: 60_000 }, async () => {
    const { saver, inbox, never, state, store } = setup();
    state.status = 'locked';
    // Never unlocked here: no key to seal to.
    expect(await saver.report(submit('maya', 'pw'), sender('https://a.example'))).toBeNull();
    state.status = 'unlocked';
    await inbox.unlocked();
    state.status = 'locked';
    await never.add('login', 'https://never.example');
    expect(await saver.report(submit('maya', 'pw'), sender('https://never.example'))).toBeNull();
    // A suggested password while locked waits for the submit, which asks.
    expect(await saver.report({ ...submit('maya', 'pw'), trigger: 'generated', draft: true }, sender('https://a.example'))).toBeNull();
    // Full: the core refuses more, so nothing is offered.
    for (let n = 0; n < testCore.inboxCap(); n++) await saveLocked(saver, `https://site${n}.example`, 'u', 'p');
    expect(await inbox.accepts()).toBe(false);
    expect(await saver.report(submit('maya', 'pw'), sender('https://a.example'))).toBeNull();
    expect(JSON.parse(store.data.get('inbox:local') as string).entries).toHaveLength(testCore.inboxCap());
    state.local = false;
    state.status = 'signedOut';
    expect(await saver.report(submit('maya', 'pw'), sender('https://a.example'))).toBeNull();
  });

  it('saves a card typed while locked as a new card for review, with the security code only if ticked', { timeout: 60_000 }, async () => {
    const { host, inbox, items, never, matcher, state } = setup([]);
    const details = new DetailsSaver(host, matcher, never, Date.now, inbox);
    await inbox.unlocked();
    state.status = 'locked';
    const page = sender('https://shop.example/checkout');
    const values = { 'cc-number': '4242 4242 4242 4242', 'cc-exp': '12/29', 'cc-csc': '123', 'cc-name': 'Maya Patel' };
    const response = (await details.report({ kind: 'card', values, trigger: 'submit' }, page)) as { prompt: { id: string; kind: string; locked: boolean; offerCode: boolean } };
    expect(response.prompt).toMatchObject({ kind: 'save', item: 'card', locked: true, offerCode: true, card: { last4: '4242' } });
    await details.answer(response.prompt.id, 'save', false, page);
    state.status = 'unlocked';
    expect(await inbox.unlocked()).toMatchObject({ failed: 0 });
    const [card] = [...items.values()];
    expect(card!.overview).toMatchObject({ type: 'card', tags: [UNCONFIRMED_TAG] });
    expect(card!.details as CardDetails).toMatchObject({ number: '4242 4242 4242 4242', expiry: '12/29', cardholder: 'Maya Patel' });
    expect((card!.details as CardDetails).cvv).toBeUndefined();
  });
});
