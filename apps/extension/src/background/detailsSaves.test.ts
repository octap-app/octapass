import type { CardDetails, IdentityDetails, Item } from '@octapass/vault-client';
import { testCore } from '../test/core';
import { fakeHost } from '../test/fakeHost';
import { memoryStore } from '../test/memoryStore';
import { handleContent, type ContentContext } from './content';
import { DetailsSaver, identityFrom } from './detailsSaves';
import { FrameApprovals } from './frames';
import { Matcher } from './matching';
import { NeverSave } from './neverSave';
import { LoginSaver } from './saves';
import type { PageSender } from './senders';

const sender = (url: string, extra: Partial<PageSender> = {}): PageSender => ({ tabId: 1, frameId: 0, url, origin: new URL(url).origin, topOrigin: new URL(url).origin, ...extra });
const checkout = sender('https://www.shop.example/checkout');

const ADDRESS = {
  name: 'Maya Haddad',
  email: 'maya@example.test',
  tel: '+44 20 7946 0000',
  'address-line1': '1 High Street',
  'address-level2': 'London',
  'postal-code': 'N1 9GU',
  country: 'United Kingdom',
};

function item(id: string, type: 'card' | 'identity', details: CardDetails | IdentityDetails): Item {
  return { id, vaultId: 'v1', revision: 1, createdAt: '', updatedAt: '', overview: { schemaVersion: 1, title: id, type }, details };
}

function setup(initial: Item[] = []) {
  const fake = fakeHost(initial);
  const matcher = new Matcher(testCore);
  const never = new NeverSave(memoryStore(), matcher);
  return { ...fake, never, saver: new DetailsSaver(fake.host, matcher, never) };
}

type Answerable = { prompt: { id: string } };

describe('DetailsSaver', () => {
  it('asks to save a new address, and saves it as an Identity', async () => {
    const { saver, items } = setup();
    const response = await saver.report({ kind: 'identity', values: ADDRESS, trigger: 'submit' }, checkout);
    expect(response).toEqual({ prompt: { id: expect.any(String), kind: 'save', item: 'identity', host: 'www.shop.example', address: 'Maya Haddad, 1 High Street, London' } });
    await saver.answer((response as Answerable).prompt.id, 'save', false, checkout);
    const [saved] = [...items.values()];
    expect(saved!.overview).toMatchObject({ type: 'identity', title: '1 High Street, London', subtitle: 'Maya Haddad' });
    expect(saved!.details).toEqual({
      schemaVersion: 1,
      firstName: 'Maya',
      lastName: 'Haddad',
      email: 'maya@example.test',
      phone: '+44 20 7946 0000',
      address: { line1: '1 High Street', city: 'London', postalCode: 'N1 9GU', country: 'United Kingdom' },
    });
  });

  it('offers to update the Identity with the same email, keeping what the form didn’t have', async () => {
    const saved = item('home', 'identity', { schemaVersion: 1, firstName: 'Maya', lastName: 'Haddad', email: 'Maya@Example.test', birthDate: '1990-01-01', address: { line1: '9 Old Road', city: 'Leeds' } });
    const { saver, items } = setup([saved]);
    const response = (await saver.report({ kind: 'identity', values: ADDRESS, trigger: 'submit' }, checkout)) as Answerable & { prompt: { kind: string } };
    expect(response.prompt.kind).toBe('update');
    await saver.answer(response.prompt.id, 'save', false, checkout);
    expect(items.get('home')!.details).toMatchObject({ birthDate: '1990-01-01', email: 'Maya@Example.test', address: { line1: '1 High Street', city: 'London', postalCode: 'N1 9GU' } });
    expect(items.size).toBe(1);
  });

  it('stays quiet for an address it already has, however it’s written', async () => {
    const { saver } = setup([item('home', 'identity', { ...identityFrom(ADDRESS), notes: 'Home' })]);
    expect(await saver.report({ kind: 'identity', values: ADDRESS, trigger: 'submit' }, checkout)).toBeNull();
    expect(await saver.report({ kind: 'identity', values: { ...ADDRESS, email: undefined, 'postal-code': 'n19gu' }, trigger: 'submit' }, checkout)).toBeNull();
    expect(await saver.report({ kind: 'identity', values: { ...ADDRESS, tel: '+44 20 7946 1111' }, trigger: 'submit' }, checkout)).toEqual({ prompt: expect.objectContaining({ kind: 'update' }) });
  });

  it('names a card by brand and last four digits only, and keeps the security code only when asked', async () => {
    const { saver, items } = setup();
    const values = { 'cc-name': 'Maya Haddad', 'cc-number': '4242424242424242', 'cc-exp': '08/27', 'cc-csc': '123' };
    const response = await saver.report({ kind: 'card', values, trigger: 'submit' }, checkout);
    expect(response).toEqual({ prompt: { id: expect.any(String), kind: 'save', item: 'card', host: 'www.shop.example', card: { brand: 'Visa', last4: '4242', expiry: '08/27' }, offerCode: true } });
    expect(JSON.stringify(response)).not.toMatch(/424242|123/);
    await saver.answer((response as Answerable).prompt.id, 'save', false, checkout);
    const [saved] = [...items.values()];
    expect(saved!.overview).toMatchObject({ type: 'card', title: 'Visa ending 4242', subtitle: 'Maya Haddad' });
    expect(saved!.details).toEqual({ schemaVersion: 1, cardholder: 'Maya Haddad', number: '4242424242424242', expiry: '08/27', brand: 'Visa' });

    const again = setup();
    const ticked = (await again.saver.report({ kind: 'card', values, trigger: 'submit' }, checkout)) as Answerable;
    await again.saver.answer(ticked.prompt.id, 'save', true, checkout);
    expect([...again.items.values()][0]!.details).toMatchObject({ cvv: '123' });
  });

  it('offers to update a saved card with the same number when the expiry changed', async () => {
    const { saver, items } = setup([item('visa', 'card', { schemaVersion: 1, number: '4242 4242 4242 4242', expiry: '08/24', cvv: '999' })]);
    expect(await saver.report({ kind: 'card', values: { 'cc-number': '4242424242424242', 'cc-exp': '08/24' }, trigger: 'submit' }, checkout)).toBeNull();
    const response = (await saver.report({ kind: 'card', values: { 'cc-number': '4242424242424242', 'cc-exp': '08/28' }, trigger: 'submit' }, checkout)) as Answerable & { prompt: { kind: string } };
    expect(response.prompt.kind).toBe('update');
    await saver.answer(response.prompt.id, 'save', false, checkout);
    expect(items.get('visa')!.details).toMatchObject({ number: '4242 4242 4242 4242', expiry: '08/28', cvv: '999' });
  });

  it('never asks on a plain-http page, except on the user’s own machine', async () => {
    const { saver } = setup();
    const report = { kind: 'identity', values: ADDRESS, trigger: 'submit' } as const;
    expect(await saver.report(report, sender('http://shop.example/checkout'))).toBeNull();
    expect(await saver.report(report, sender('http://localhost:8080/checkout'))).not.toBeNull();
  });

  it('remembers “Never for this site” per kind', async () => {
    const { saver, never } = setup();
    const response = (await saver.report({ kind: 'card', values: { 'cc-number': '4242424242424242' }, trigger: 'submit' }, checkout)) as Answerable;
    await saver.answer(response.prompt.id, 'never', false, checkout);
    expect(await never.list()).toEqual([{ site: 'shop.example', kind: 'card', addedAt: expect.any(String) }]);
    expect(await saver.report({ kind: 'card', values: { 'cc-number': '5555555555554444' }, trigger: 'submit' }, sender('https://pay.shop.example/'))).toBeNull();
    expect(await saver.report({ kind: 'identity', values: ADDRESS, trigger: 'submit' }, checkout)).not.toBeNull();
    await never.remove('shop.example', 'card');
    expect(await saver.report({ kind: 'card', values: { 'cc-number': '5555555555554444' }, trigger: 'submit' }, checkout)).not.toBeNull();
  });

  it('shows the prompt again after a navigation on the same site, and only that tab can answer', async () => {
    const { saver, items } = setup();
    const { prompt } = (await saver.report({ kind: 'identity', values: ADDRESS, trigger: 'navigation' }, checkout)) as Answerable;
    expect(saver.waiting(sender('https://shop.example/thanks'))?.id).toBe(prompt.id);
    expect(saver.waiting(sender('https://elsewhere.example/'))).toBeNull();
    await saver.answer(prompt.id, 'save', false, sender('https://shop.example/thanks', { tabId: 2 }));
    expect(items.size).toBe(0);
  });

  it('stays quiet while locked', async () => {
    const { saver, state } = setup();
    state.status = 'locked';
    expect(await saver.report({ kind: 'identity', values: ADDRESS, trigger: 'submit' }, checkout)).toBeNull();
  });
});

describe('address and card saves through the content handler', () => {
  function context() {
    const { host, items, never, saver } = setup();
    const matcher = new Matcher(testCore);
    const ctx: ContentContext = {
      host,
      saver: new LoginSaver(host, matcher, Date.now, undefined, never),
      details: saver,
      apiKeys: { answer: async () => false } as never,
      matcher,
      frames: new FrameApprovals(memoryStore(), matcher),
      rules: testCore,
      masked: {} as never,
      icons: {} as never,
      websites: {} as never,
      openApp: vi.fn(async () => undefined),
      touch: vi.fn(),
    };
    return { ctx, items };
  }

  it('saves nothing from a frame from another site until the user allows it', async () => {
    const { ctx, items } = context();
    const framed = sender('https://pay.example/form', { frameId: 3, topOrigin: 'https://shop.example' });
    const message = { type: 'saveDetails', report: { kind: 'card', values: { 'cc-number': '4242424242424242' }, trigger: 'submit' } } as const;
    expect(await handleContent(ctx, message, framed)).toBeNull();
    expect(await handleContent(ctx, { type: 'approveFrame' }, framed)).toBe(true);
    const response = (await handleContent(ctx, message, framed)) as Answerable;
    expect(response.prompt).toMatchObject({ item: 'card', host: 'pay.example' });
    expect(await handleContent(ctx, { type: 'pendingSave' }, framed)).toMatchObject({ id: response.prompt.id });
    await handleContent(ctx, { type: 'answerSave', id: response.prompt.id, answer: 'save' }, framed);
    expect([...items.values()][0]!.overview.type).toBe('card');
  });
});
