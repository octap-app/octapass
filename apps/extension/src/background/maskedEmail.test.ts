import { testCore } from '../test/core';
import { fakeHost } from '../test/fakeHost';
import { MaskedEmailFiller } from './maskedEmail';
import { Matcher } from './matching';
import type { PageSender } from './senders';

const sender = (url: string, tabId = 1): PageSender => ({ tabId, frameId: 0, url, origin: new URL(url).origin, topOrigin: new URL(url).origin });
const http = vi.fn(async () => ({ status: 201, headers: {}, body: JSON.stringify({ alias: 'shop.k2@simplelogin.com', id: 5 }) }));

async function connected(now: () => number = Date.now) {
  const fake = fakeHost();
  const filler = new MaskedEmailFiller(fake.host, new Matcher(testCore), http, now);
  await fake.host.engine.call('saveItem', [{ vaultId: 'v1', overview: { schemaVersion: 1, type: 'maskedEmailProvider', title: 'SimpleLogin' }, details: { schemaVersion: 1, provider: 'simplelogin', token: 't' } }]);
  return { ...fake, filler };
}

describe('MaskedEmailFiller', () => {
  it('links only the login saved on the same tab and site, with the alias as its username', async () => {
    const { filler } = await connected();
    await filler.create(sender('https://www.shop.example/join'));
    const link = { email: 'shop.k2@simplelogin.com', emailSource: { kind: 'alias', provider: 'simplelogin', aliasId: '5' } };
    expect(filler.linkFor(1, 'https://shop.example/welcome', 'Shop.K2@simplelogin.com')).toEqual(link);
    expect(filler.linkFor(2, 'https://shop.example/welcome', 'shop.k2@simplelogin.com')).toBeUndefined();
    expect(filler.linkFor(1, 'https://other.example/', 'shop.k2@simplelogin.com')).toBeUndefined();
    expect(filler.linkFor(1, 'https://shop.example/', 'maya@example.com')).toBeUndefined();
  });

  it('forgets an alias after half an hour', async () => {
    let now = 0;
    const { filler } = await connected(() => now);
    await filler.create(sender('https://shop.example/join'));
    now = 31 * 60_000;
    expect(filler.linkFor(1, 'https://shop.example/', 'shop.k2@simplelogin.com')).toBeUndefined();
  });

  it('is available only unlocked, with an account, and a provider', async () => {
    const { filler, state } = await connected();
    expect(await filler.available()).toBe(true);
    state.local = true;
    expect(await filler.available()).toBe(false);
    state.local = false;
    state.status = 'locked';
    expect(await filler.available()).toBe(false);
    expect(await new MaskedEmailFiller(fakeHost().host, new Matcher(testCore), http).available()).toBe(false);
  });
});
