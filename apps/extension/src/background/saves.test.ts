import type { LoginDetails } from '@octapass/vault-client';
import { testCore } from '../test/core';
import { fakeHost, login } from '../test/fakeHost';
import { Matcher } from './matching';
import { LoginSaver, UNCONFIRMED_TAG } from './saves';
import type { PageSender } from './senders';

const sender = (url: string, tabId = 1): PageSender => ({ tabId, frameId: 0, url, origin: new URL(url).origin, topOrigin: new URL(url).origin });
const signup = sender('https://www.shop.example/join');

describe('LoginSaver', () => {
  it('saves a suggested password as an unconfirmed draft at once, and confirms it on submit', async () => {
    const { host, items } = fakeHost();
    const saver = new LoginSaver(host, new Matcher(testCore));
    expect(await saver.report({ username: 'maya', password: 'Gen-1', formType: 'signup', trigger: 'generated', draft: true }, signup)).toEqual({ saved: 'draft' });
    const [draft] = [...items.values()];
    expect(draft!.overview).toMatchObject({ title: 'shop.example', urls: ['https://www.shop.example'], tags: [UNCONFIRMED_TAG] });
    expect(draft!.details).toMatchObject({ username: 'maya', password: 'Gen-1' });

    expect(await saver.report({ username: 'maya', password: 'Gen-1', formType: 'signup', trigger: 'submit', draft: false }, signup)).toEqual({ saved: 'confirmed' });
    expect([...items.values()][0]!.overview.tags).toBeUndefined();
  });

  it('asks before saving a new login, and only the tab that saw it can answer', async () => {
    const { host, items } = fakeHost();
    const saver = new LoginSaver(host, new Matcher(testCore));
    const response = await saver.report({ username: 'maya', password: 'typed', formType: 'login', trigger: 'submit', draft: false }, signup);
    expect(response).toMatchObject({ prompt: { kind: 'save', item: 'login', host: 'www.shop.example', username: 'maya' } });
    const { id } = (response as { prompt: { id: string } }).prompt;

    // Still shown after navigating within the site, not on another site.
    expect(saver.waiting(sender('https://shop.example/welcome'))?.id).toBe(id);
    await saver.answer(id, 'save', sender('https://shop.example/welcome', 2));
    expect(items.size).toBe(0);
    await saver.answer(id, 'save', sender('https://shop.example/welcome'));
    expect([...items.values()][0]!.details).toMatchObject({ username: 'maya', password: 'typed' });
    expect(saver.waiting(signup)).toBeNull();
  });

  it('offers to update a changed password, keeping the old one in the history', async () => {
    const { host, items } = fakeHost([login('shop', 'https://shop.example', 'Maya', 'old')]);
    const saver = new LoginSaver(host, new Matcher(testCore));
    const response = (await saver.report({ username: 'maya', password: 'new', formType: 'login', trigger: 'submit', draft: false }, signup)) as { prompt: { id: string; kind: string } };
    expect(response.prompt.kind).toBe('update');
    await saver.answer(response.prompt.id, 'save', signup);
    expect((items.get('shop')!.details as LoginDetails).password).toBe('new');
  });

  it('stays quiet after signing in with a login for another part of the site, and asks for a new password there', async () => {
    const { host } = fakeHost([login('mail', 'https://mail.shop.example', 'maya', 'same')]);
    const saver = new LoginSaver(host, new Matcher(testCore));
    const page = sender('https://login.shop.example/signin');
    expect(await saver.report({ username: 'maya', password: 'same', formType: 'login', trigger: 'submit', draft: false }, page)).toBeNull();
    // Another password: a login of its own for this part of the site, not an update to mail's.
    expect(await saver.report({ username: 'maya', password: 'other', formType: 'login', trigger: 'submit', draft: false }, page)).toMatchObject({ prompt: { kind: 'save', host: 'login.shop.example' } });
  });

  it('stays quiet for a password it already has, and when locked', async () => {
    const { host, state } = fakeHost([login('shop', 'https://shop.example', 'maya', 'same')]);
    const saver = new LoginSaver(host, new Matcher(testCore));
    expect(await saver.report({ username: 'maya', password: 'same', formType: 'login', trigger: 'submit', draft: false }, signup)).toBeNull();
    state.status = 'locked';
    expect(await saver.report({ username: 'maya', password: 'other', formType: 'login', trigger: 'submit', draft: false }, signup)).toBeNull();
  });
});
