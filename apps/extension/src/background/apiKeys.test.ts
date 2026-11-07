import type { ApiCredentialDetails, Item } from '@octapass/vault-client';
import { testCore } from '../test/core';
import { credential, fakeHost } from '../test/fakeHost';
import { memoryStore } from '../test/memoryStore';
import { apiCredentialFillValues, ApiKeySaver, API_KEY_OFFERS_KEY, apiKeyOffersEnabled, credentialValue } from './apiKeys';
import { Matcher } from './matching';
import { NeverSave } from './neverSave';
import { PROMPT_TTL_MS } from './saves';
import type { PageSender } from './senders';

const KEY = 'FAKE-key-value';

const sender = (url: string, extra: Partial<PageSender> = {}): PageSender => ({ tabId: 1, frameId: 0, url, origin: new URL(url).origin, topOrigin: new URL(url).origin, ...extra });
const portal = sender('https://www.dev.example/settings/tokens');

function setup(items: Item[] = [], enabled = true) {
  const fake = fakeHost(items);
  const matcher = new Matcher(testCore);
  const never = new NeverSave(memoryStore(), matcher);
  let now = 1_000;
  const saver = new ApiKeySaver(fake.host, matcher, never, async () => enabled, () => now);
  return { ...fake, saver, never, advance: (ms: number) => (now += ms) };
}

const idOf = (response: unknown) => (response as { prompt: { id: string } }).prompt.id;

describe('ApiKeySaver', () => {
  it('asks without ever having the value, and names the service', async () => {
    const { saver, items } = setup();
    const response = await saver.offer('github', portal);
    expect(response).toEqual({ prompt: { id: expect.any(String), kind: 'save', item: 'apiKey', host: 'www.dev.example', service: 'GitHub' } });
    expect(JSON.stringify(response)).not.toContain(KEY);
    expect(items.size).toBe(0);
  });

  it('saves on Save as an apiCredential for the page’s origin', async () => {
    const { saver, items } = setup();
    const id = idOf(await saver.offer('github', portal));
    expect(await saver.answer(id, 'save', KEY, portal)).toBe(true);
    const [item] = [...items.values()];
    expect(item!.overview).toEqual({ schemaVersion: 1, title: 'GitHub (dev.example)', type: 'apiCredential', urls: ['https://www.dev.example'], subtitle: 'www.dev.example' });
    expect(item!.details).toEqual({ schemaVersion: 1, credential: KEY, hostname: 'www.dev.example', key: KEY, host: 'www.dev.example', credentialType: 'apiKey' });
  });

  it('calls a key the field named just an API key', async () => {
    const { saver, items } = setup();
    expect(await saver.offer('generic', portal)).not.toHaveProperty('prompt.service');
    await saver.answer(idOf(await saver.offer('generic', portal)), 'save', KEY, portal);
    expect([...items.values()][0]!.overview.title).toBe('API key (dev.example)');
  });

  it('saves nothing on Not now or Never, and Never holds for the site', async () => {
    const { saver, items, never } = setup();
    expect(await saver.answer(idOf(await saver.offer('github', portal)), 'notNow', undefined, portal)).toBe(false);
    expect(await saver.offer('github', portal)).not.toBeNull();
    await saver.answer(idOf(await saver.offer('github', portal)), 'never', undefined, portal);
    expect(items.size).toBe(0);
    expect(await never.has('apiKey', 'https://dev.example/other')).toBe(true);
    expect(await never.has('login', portal.url)).toBe(false);
    expect(await saver.offer('github', portal)).toBeNull();
  });

  it('won’t add a key this site already has', async () => {
    const { saver, saved } = setup([credential('old', 'https://dev.example', { key: KEY })]);
    expect(await saver.answer(idOf(await saver.offer('github', portal)), 'save', KEY, portal)).toBe(true);
    expect(saved).toEqual([]);
  });

  it.each([
    ['locked', { locked: true }],
    ['switched off', { off: true }],
  ])('stays quiet when %s', async (_name, { locked, off }: { locked?: boolean; off?: boolean }) => {
    const { saver, state } = setup([], !off);
    if (locked) state.status = 'locked';
    expect(await saver.offer('github', portal)).toBeNull();
  });

  it.each([
    ['the hosted web vault', sender('https://vault.octap.app/settings')],
    ['a plain http page', sender('http://dev.example/')],
    ['a frame', sender('https://dev.example/', { frameId: 3 })],
  ])('never offers on %s', async (_name, page) => {
    const { saver } = setup();
    expect(await saver.offer('github', page)).toBeNull();
  });

  it('never offers on the web vault of the account’s own server', async () => {
    const { saver, host } = setup();
    Object.defineProperty(host, 'snapshot', { value: { session: { status: 'unlocked', serverUrl: 'https://vault.self-hosted.example/' }, remembered: [] } });
    expect(await saver.offer('github', sender('https://vault.self-hosted.example/items'))).toBeNull();
    expect(await saver.offer('github', portal)).not.toBeNull();
  });

  it('offers on the user’s own machine', async () => {
    const { saver } = setup();
    expect(await saver.offer('github', sender('http://localhost:3000/'))).not.toBeNull();
  });

  it('refuses a kind it doesn’t know', async () => {
    const { saver } = setup();
    expect(await saver.offer('constructor' as never, portal)).toBeNull();
  });

  it('only the tab and origin that saw the key can answer, and only for a while', async () => {
    const { saver, items, advance } = setup();
    let id = idOf(await saver.offer('github', portal));
    expect(await saver.answer(id, 'save', KEY, sender(portal.url, { tabId: 2 }))).toBe(false);
    expect(await saver.answer('other', 'save', KEY, portal)).toBe(false);
    expect(await saver.answer(id, 'save', KEY, sender('https://evil.example/'))).toBe(false);
    id = idOf(await saver.offer('github', portal));
    advance(PROMPT_TTL_MS);
    expect(await saver.answer(id, 'save', KEY, portal)).toBe(false);
    expect(items.size).toBe(0);
  });

  it('won’t save after the vault locks', async () => {
    const { saver, state, items } = setup();
    const id = idOf(await saver.offer('github', portal));
    state.status = 'locked';
    expect(await saver.answer(id, 'save', KEY, portal)).toBe(false);
    expect(items.size).toBe(0);
  });
});

describe('apiKeyOffersEnabled', () => {
  it('is on until switched off', async () => {
    expect(await apiKeyOffersEnabled()).toBe(true);
    await chrome.storage.local.set({ [API_KEY_OFFERS_KEY]: false });
    expect(await apiKeyOffersEnabled()).toBe(false);
  });
});

describe('credentialValue', () => {
  const now = 1_800_000_000;

  it.each<[string, Partial<ApiCredentialDetails>, string | undefined]>([
    ['the credential', { credential: 'c' }, 'c'],
    ['the editor’s key over an older copy', { credential: 'old', key: 'edited' }, 'edited'],
    ['the secret when there’s no key', { secret: 's' }, 's'],
    ['a live token first', { key: 'k', oauth2: { accessToken: 'live', expiresAt: now + 60 } }, 'live'],
    ['a token with no expiry recorded', { oauth2: { accessToken: 'live' } }, 'live'],
    ['the key when the token ran out', { key: 'k', oauth2: { accessToken: 'stale', expiresAt: now - 60 } }, 'k'],
    ['the key at the very second it ran out', { key: 'k', oauth2: { accessToken: 'stale', expiresAt: now } }, 'k'],
    ['nothing with only a stale token', { oauth2: { accessToken: 'stale', expiresAt: now - 60 } }, undefined],
    ['nothing for a garbled expiry', { oauth2: { accessToken: 'stale', expiresAt: 'soon' as never } }, undefined],
    ['nothing at all', {}, undefined],
  ])('gives %s', (_name, details, expected) => {
    expect(credentialValue({ schemaVersion: 1, ...details }, now)).toBe(expected);
  });
});

describe('apiCredentialFillValues', () => {
  const matcher = new Matcher(testCore);
  const item = credential('c', 'https://dev.example', { key: KEY });

  it('fills on the item’s site and subdomains, by the login rule', () => {
    expect(apiCredentialFillValues(matcher, item, 'https://portal.dev.example/keys')).toEqual({ 'api-credential': KEY });
  });

  it.each(['https://dev.example.evil.io/', 'https://evil.example/', 'http://dev.example/'])('gives %s nothing', (url) => {
    expect(apiCredentialFillValues(matcher, item, url)).toBeNull();
  });

  it('gives nothing for a deleted item or another type', () => {
    expect(apiCredentialFillValues(matcher, { ...item, deletedAt: '2026-10-24T00:00:00Z' }, 'https://dev.example/')).toBeNull();
    expect(apiCredentialFillValues(matcher, { ...item, overview: { ...item.overview, type: 'secureNote' } }, 'https://dev.example/')).toBeNull();
  });
});
