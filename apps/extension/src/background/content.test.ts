import type { HttpRequest, Item, LoginDetails } from '@octapass/vault-client';
import { testCore } from '../test/core';
import { credential, fakeHost, login } from '../test/fakeHost';
import { memoryStore } from '../test/memoryStore';
import { ApiKeySaver } from './apiKeys';
import { DetailsSaver } from './detailsSaves';
import { FrameApprovals } from './frames';
import { MaskedEmailFiller } from './maskedEmail';
import { Matcher } from './matching';
import { NeverSave } from './neverSave';
import { WebsiteAdder } from './addWebsite';
import { handleContent, MASKED_EMAIL_SUGGESTION, otherLoginFillValues, OTHER_LOGINS_SUGGESTION, suggestPassword, UNLOCK_SUGGESTION, type ContentContext } from './content';
import { LoginSaver } from './saves';
import { SiteIcons } from './siteIcons';
import { memoryIconStore, type IconAnswer } from '@octapass/vault-client';
import type { PageSender } from './senders';

const page = (url: string): PageSender => ({ tabId: 1, frameId: 0, url, origin: new URL(url).origin, topOrigin: new URL(url).origin });
const shop = page('https://login.shop.example/signin');
const lookalike = page('https://shop.example.evil.io/signin');

const card: Item = {
  id: 'card',
  vaultId: 'v1',
  revision: 1,
  createdAt: '',
  updatedAt: '',
  overview: { schemaVersion: 1, title: 'Visa', type: 'card' },
  details: { schemaVersion: 1, cardholder: 'Maya Orchid', number: '4111 1111 1111 1234', expiry: '08/29', cvv: '123' },
};

/** Answers like Firefox Relay; no real network. */
const relay = vi.fn(async (_request: HttpRequest) => ({ status: 201, headers: {}, body: JSON.stringify({ id: 7, full_address: 'r4nd0m@mozmail.com' }) }));

const relayToken: Item = {
  id: 'relay',
  vaultId: 'v1',
  revision: 1,
  createdAt: '2026-10-24T00:00:00Z',
  updatedAt: '',
  overview: { schemaVersion: 1, title: 'Firefox Relay', type: 'maskedEmailProvider' },
  details: { schemaVersion: 1, provider: 'firefoxRelay', token: 'relay-token' },
};

function setup(extra: Item[] = []) {
  const fake = fakeHost([login('shop', 'https://shop.example', 'maya', 'pw-1', {}, { totp: 'JBSWY3DPEHPK3PXP' }), login('other', 'https://other.example', 'maya', 'pw-2'), card, ...extra]);
  const matcher = new Matcher(testCore);
  const frames = new FrameApprovals(memoryStore(), matcher);
  const masked = new MaskedEmailFiller(fake.host, matcher, relay);
  const never = new NeverSave(memoryStore(), matcher);
  const fetchIcon = vi.fn(async (): Promise<IconAnswer> => ({ kind: 'icon', png: new Uint8Array([0x89, 0x50]) }));
  const icons = new SiteIcons({ serverUrl: () => 'https://vault.example.org', defaultServer: 'https://vault.octap.app', enabled: async () => true, fetchIcon, store: memoryIconStore() });
  const context: ContentContext = {
    host: fake.host,
    saver: new LoginSaver(fake.host, matcher, Date.now, masked, never),
    details: new DetailsSaver(fake.host, matcher, never),
    apiKeys: new ApiKeySaver(fake.host, matcher, never, async () => true),
    matcher,
    frames,
    rules: testCore,
    masked,
    icons,
    websites: new WebsiteAdder(fake.host, matcher),
    openApp: vi.fn(async () => undefined),
    touch: vi.fn(),
  };
  return { ...fake, context, fetchIcon };
}

const field = (fieldType: string, formType = 'login') => ({ type: 'suggestions' as const, field: { fieldType, formType } as never });

describe('handleContent, API credentials', () => {
  const portal = page('https://portal.shop.example/keys');
  const keyField = field('api-credential', 'unknown');
  const later = Math.floor(Date.now() / 1000) + 3600;
  const items = [
    credential('key', 'https://shop.example', { key: 'FAKE-key' }),
    credential('oauth', 'https://shop.example', { oauth2: { accessToken: 'FAKE-live', expiresAt: later } }),
    credential('stale', 'https://shop.example', { oauth2: { accessToken: 'FAKE-stale', expiresAt: 1000 } }),
    credential('other', 'https://other.example', { key: 'FAKE-other' }),
  ];
  const pick = (id: string) => ({ type: 'resolve' as const, suggestion: { kind: 'api-credential' as const, id } });

  it('suggests what matches the page and has a value, never the value itself', async () => {
    const { context } = setup(items);
    const response = await handleContent(context, keyField, portal);
    expect(response).toEqual({
      status: 'unlocked',
      suggestions: [
        { kind: 'api-credential', id: 'key', title: 'key', subtitle: 'shop.example' },
        { kind: 'api-credential', id: 'oauth', title: 'oauth', subtitle: 'shop.example' },
      ],
    });
    expect(JSON.stringify(response)).not.toContain('FAKE');
  });

  it('keeps keys out of login fields and logins out of key fields', async () => {
    const { context } = setup(items);
    expect(await handleContent(context, field('current-password'), portal)).toMatchObject({ suggestions: [expect.objectContaining({ kind: 'login', id: 'shop' })] });
    expect(JSON.stringify(await handleContent(context, keyField, portal))).not.toContain('"login"');
  });

  it('fills the key or the live token, and refuses a look-alike that asks by id', async () => {
    const { context } = setup(items);
    expect(await handleContent(context, pick('key'), portal)).toEqual({ 'api-credential': 'FAKE-key' });
    expect(await handleContent(context, pick('oauth'), portal)).toEqual({ 'api-credential': 'FAKE-live' });
    expect(await handleContent(context, pick('stale'), portal)).toBeNull();
    expect(await handleContent(context, keyField, lookalike)).toEqual({ status: 'unlocked', suggestions: [] });
    expect(await handleContent(context, pick('key'), lookalike)).toBeNull();
    expect(await handleContent(context, pick('shop'), portal)).toBeNull();
  });

  it('goes through the autofill device-auth gate, as a login does', async () => {
    const { context } = setup(items);
    const request = vi.fn(async () => false);
    context.fillAuth = { request } as unknown as ContentContext['fillAuth'];
    expect(await handleContent(context, pick('key'), portal)).toBeNull();
    expect(request).toHaveBeenCalledTimes(1);
    request.mockResolvedValue(true);
    expect(await handleContent(context, pick('key'), portal)).toEqual({ 'api-credential': 'FAKE-key' });
  });

  it('offers to unlock while locked, and fills nothing', async () => {
    const { context, state } = setup(items);
    state.status = 'locked';
    expect(await handleContent(context, keyField, portal)).toEqual({ status: 'locked', suggestions: [{ kind: 'api-credential', id: UNLOCK_SUGGESTION, title: 'Unlock Octa Pass' }] });
    expect(await handleContent(context, pick('key'), portal)).toBeNull();
    await handleContent(context, { type: 'resolve', suggestion: { kind: 'api-credential', id: UNLOCK_SUGGESTION } }, portal);
    expect(context.openApp).toHaveBeenCalled();
  });

  it('gives a frame from another site nothing until the user allows it', async () => {
    const { context } = setup(items);
    const frame: PageSender = { tabId: 1, frameId: 2, url: 'https://portal.shop.example/keys', origin: 'https://portal.shop.example', topOrigin: 'https://evil.example' };
    expect(await handleContent(context, keyField, frame)).toMatchObject({ suggestions: [expect.objectContaining({ kind: 'frame-approval' })] });
    expect(await handleContent(context, pick('key'), frame)).toBeNull();
    expect(await handleContent(context, { type: 'offerApiKey', apiKey: 'github' }, frame)).toBeNull();
  });

  it('takes a pasted key through offer and Save', async () => {
    const { context, saved } = setup();
    const response = (await handleContent(context, { type: 'offerApiKey', apiKey: 'github' }, portal)) as { prompt: { id: string } };
    expect(await handleContent(context, { type: 'answerSave', id: response.prompt.id, answer: 'save', credential: 'FAKE-new' }, portal)).toBe(true);
    expect(saved[0]!.details).toMatchObject({ credential: 'FAKE-new' });
  });
});

describe('handleContent', () => {
  it('suggests only the logins for the page and fills them, which counts as using them', async () => {
    const { context, used } = setup();
    expect(await handleContent(context, field('username'), shop)).toEqual({ status: 'unlocked', suggestions: [{ kind: 'login', id: 'shop', title: 'shop', username: 'maya' }] });
    expect(used).toEqual([]);
    expect(await handleContent(context, { type: 'resolve', suggestion: { kind: 'login', id: 'shop' } }, shop)).toEqual({ username: 'maya', 'current-password': 'pw-1' });
    expect(context.touch).toHaveBeenCalled();
    expect(used).toEqual(['shop']);
  });

  it('gives a look-alike page nothing, even when it asks for an item by ID', async () => {
    const { context, used } = setup();
    expect(await handleContent(context, field('username'), lookalike)).toEqual({ status: 'unlocked', suggestions: [] });
    expect(await handleContent(context, { type: 'resolve', suggestion: { kind: 'login', id: 'shop' } }, lookalike)).toBeNull();
    expect(await handleContent(context, { type: 'resolve', suggestion: { kind: 'one-time-code', id: 'shop' } }, lookalike)).toBeNull();
    // A card isn't a login, whatever the page claims.
    expect(await handleContent(context, { type: 'resolve', suggestion: { kind: 'login', id: 'card' } }, shop)).toBeNull();
    // Nothing was filled, so nothing was used.
    expect(used).toEqual([]);
  });

  it('gives website icons only for the page’s own logins', async () => {
    const { context, fetchIcon } = setup();
    expect(await handleContent(context, { type: 'siteIcon', id: 'shop' }, shop)).toBe('iVA=');
    expect(fetchIcon).toHaveBeenCalledWith('https://vault.example.org', 'shop.example');
    fetchIcon.mockClear();
    for (const [id, sender] of [['shop', lookalike], ['other', shop], ['card', shop], ['missing', shop]] as const) {
      expect(await handleContent(context, { type: 'siteIcon', id }, sender)).toBeNull();
    }
    expect(fetchIcon).not.toHaveBeenCalled();
  });

  it('fills one-time codes, cards and suggested passwords in their own fields', async () => {
    const { context } = setup();
    expect(await handleContent(context, field('one-time-code', 'one-time-code'), shop)).toMatchObject({ suggestions: [{ kind: 'one-time-code', id: 'shop' }] });
    expect(await handleContent(context, { type: 'resolve', suggestion: { kind: 'one-time-code', id: 'shop' } }, shop)).toEqual({ 'one-time-code': '123456' });
    expect(await handleContent(context, field('cc-number', 'card'), lookalike)).toMatchObject({ suggestions: [{ kind: 'card', id: 'card', subtitle: '•••• 1234' }] });
    expect(await handleContent(context, { type: 'resolve', suggestion: { kind: 'card', id: 'card' } }, shop)).toEqual({
      'cc-name': 'Maya Orchid',
      'cc-number': '4111111111111234',
      'cc-exp': '08/29',
      'cc-csc': '123',
    });
    const generated = (await handleContent(context, field('new-password', 'signup'), shop)) as { suggestions: { kind: string; password: string }[] };
    expect(generated.suggestions[0]!.kind).toBe('generated-password');
    expect(generated.suggestions[0]!.password).toHaveLength(20);
  });

  it('leaves the security code out when the card prompt refused it', async () => {
    const { context } = setup();
    context.fillAuth = { requestCard: vi.fn(async () => ({ fill: true, cvv: false })), request: vi.fn(async () => true) } as unknown as ContentContext['fillAuth'];
    const values = await handleContent(context, { type: 'resolve', suggestion: { kind: 'card', id: 'card' } }, shop);
    expect(values).toEqual({ 'cc-name': 'Maya Orchid', 'cc-number': '4111111111111234', 'cc-exp': '08/29' });
  });

  it('fills nothing from a card when filling was refused', async () => {
    const { context } = setup();
    context.fillAuth = { requestCard: vi.fn(async () => ({ fill: false, cvv: false })), request: vi.fn(async () => true) } as unknown as ContentContext['fillAuth'];
    expect(await handleContent(context, { type: 'resolve', suggestion: { kind: 'card', id: 'card' } }, shop)).toBeNull();
  });

  it('offers to unlock while locked, and nothing else', async () => {
    const { context, state } = setup();
    state.status = 'locked';
    expect(await handleContent(context, field('current-password'), shop)).toEqual({ status: 'locked', suggestions: [{ kind: 'login', id: UNLOCK_SUGGESTION, title: 'Unlock Octa Pass' }] });
    expect(await handleContent(context, { type: 'resolve', suggestion: { kind: 'login', id: 'shop' } }, shop)).toBeNull();
    expect(await handleContent(context, { type: 'resolve', suggestion: { kind: 'login', id: UNLOCK_SUGGESTION } }, shop)).toBeNull();
    expect(context.openApp).toHaveBeenCalledOnce();
  });

  it('asks before anything happens in a frame from another site, then matches the frame’s own origin', async () => {
    const { context, saved, state } = setup();
    // shop.example's login form, framed by another site: its logins, but only once allowed there.
    const framed: PageSender = { tabId: 1, frameId: 4, url: 'https://shop.example/embed', origin: 'https://shop.example', topOrigin: 'https://blog.example' };
    const resolveShop = { type: 'resolve' as const, suggestion: { kind: 'login' as const, id: 'shop' } };
    expect(await handleContent(context, field('username'), framed)).toEqual({
      status: 'unlocked',
      suggestions: [{ kind: 'frame-approval', id: expect.any(String), frameHost: 'shop.example', site: 'blog.example' }],
    });
    expect(await handleContent(context, resolveShop, framed)).toBeNull();
    expect(await handleContent(context, { type: 'save', report: { username: 'maya', password: 'new', formType: 'login', trigger: 'submit', draft: false } }, framed)).toBeNull();
    expect(saved).toEqual([]);

    // Locked, it still asks first.
    state.status = 'locked';
    expect(await handleContent(context, field('username'), framed)).toMatchObject({ suggestions: [{ kind: 'frame-approval' }] });
    state.status = 'unlocked';

    expect(await handleContent(context, { type: 'approveFrame' }, framed)).toBe(true);
    expect(await handleContent(context, field('username'), framed)).toEqual({ status: 'unlocked', suggestions: [{ kind: 'login', id: 'shop', title: 'shop', username: 'maya' }] });
    expect(await handleContent(context, resolveShop, framed)).toEqual({ username: 'maya', 'current-password': 'pw-1' });

    // Allowed or not, a frame only gets logins for its own origin.
    const other: PageSender = { ...framed, url: 'https://idp.example/embed', origin: 'https://idp.example' };
    await handleContent(context, { type: 'approveFrame' }, other);
    expect(await handleContent(context, field('username'), other)).toEqual({ status: 'unlocked', suggestions: [] });
    expect(await handleContent(context, resolveShop, other)).toBeNull();
  });

  it('needs no approval in a frame from the page’s own site', async () => {
    const { context } = setup();
    const framed: PageSender = { tabId: 1, frameId: 4, url: 'https://login.shop.example/embed', origin: 'https://login.shop.example', topOrigin: 'https://www.shop.example' };
    expect(await handleContent(context, field('username'), framed)).toMatchObject({ suggestions: [{ kind: 'login', id: 'shop' }] });
  });
});

describe('suggestPassword', () => {
  const url = 'https://shop.example/join';
  it('offers a masked email on sign-up email fields once a provider is connected', async () => {
    const without = setup();
    expect(await handleContent(without.context, field('email', 'signup'), shop)).toEqual({ status: 'unlocked', suggestions: [] });
    const { context, state } = setup([relayToken]);
    expect(await handleContent(context, field('email', 'signup'), shop)).toEqual({ status: 'unlocked', suggestions: [{ kind: 'masked-email', id: MASKED_EMAIL_SUGGESTION }] });
    // Not in other email fields, nor in a vault on this device only.
    expect(await handleContent(context, field('email', 'identity'), shop)).toEqual({ status: 'unlocked', suggestions: [] });
    state.local = true;
    expect(await handleContent(context, field('email', 'signup'), shop)).toEqual({ status: 'unlocked', suggestions: [] });
  });

  it('makes the alias for the page, fills it, and links the login saved next', async () => {
    const { context, items } = setup([relayToken]);
    relay.mockClear();
    expect(await handleContent(context, { type: 'resolve', suggestion: { kind: 'masked-email', id: MASKED_EMAIL_SUGGESTION } }, shop)).toEqual({ email: 'r4nd0m@mozmail.com' });
    expect(relay).toHaveBeenCalledOnce();
    expect(relay.mock.calls[0]![0]).toMatchObject({ url: 'https://relay.firefox.com/api/v1/relayaddresses/', headers: { Authorization: 'Token relay-token' }, body: expect.stringContaining('"generated_for":"shop.example"') });
    expect(context.touch).toHaveBeenCalled();

    const signup = page('https://shop.example/join');
    expect(await handleContent(context, { type: 'save', report: { username: 'r4nd0m@mozmail.com', password: 'Gen-1', formType: 'signup', trigger: 'generated', draft: true } }, signup)).toEqual({ saved: 'draft' });
    const saved = [...items.values()].find((item) => (item.details as LoginDetails).username === 'r4nd0m@mozmail.com')!;
    expect((saved.details as LoginDetails).recovery).toEqual({ email: 'r4nd0m@mozmail.com', emailSource: { kind: 'alias', provider: 'firefoxRelay', aliasId: '7' } });
  });

  it('tells the page why no alias was made', async () => {
    const { context } = setup([relayToken]);
    relay.mockResolvedValueOnce({ status: 401, headers: {}, body: '{"detail":"Invalid token."}' });
    expect(await handleContent(context, { type: 'resolve', suggestion: { kind: 'masked-email', id: MASKED_EMAIL_SUGGESTION } }, shop)).toEqual({ error: 'maskedEmailToken' });
    const none = setup();
    expect(await handleContent(none.context, { type: 'resolve', suggestion: { kind: 'masked-email', id: MASKED_EMAIL_SUGGESTION } }, shop)).toEqual({ error: 'maskedEmailNotSetUp' });
  });

  it('fits the field’s length, rules and pattern', () => {
    expect(suggestPassword(testCore, url, { maxLength: 12 })).toHaveLength(12);
    expect(suggestPassword(testCore, url, { minLength: 32 })).toHaveLength(32);
    expect(suggestPassword(testCore, url, { pattern: '[A-Za-z0-9]+' })).toMatch(/^[A-Za-z0-9]+$/);
    expect(suggestPassword(testCore, url, { rules: 'required: digit; allowed: lower; maxlength: 10' })).toMatch(/^[a-z0-9]{8,10}$/);
  });
});

describe('handleContent, logins for other parts of the site', () => {
  // The page is login.shop.example: shop.example is above it, mail.shop.example another part.
  const mail = () => login('mail', 'https://mail.shop.example', 'maya@mail', 'pw-mail');
  const pickOther = (id: string) => ({ type: 'resolve' as const, suggestion: { kind: 'other-login' as const, id } });
  const promptFor = (id: string) => ({ type: 'websitePrompt' as const, id });

  it('lists them last, in one entry, by host, and never with a password', async () => {
    const { context } = setup([mail(), login('below', 'https://eu.login.shop.example', 'maya', 'pw-3')]);
    const response = await handleContent(context, field('username'), shop);
    expect(response).toEqual({
      status: 'unlocked',
      suggestions: [
        { kind: 'login', id: 'shop', title: 'shop', username: 'maya' },
        { kind: 'login', id: 'below', title: 'below', username: 'maya' },
        { kind: 'other-logins', id: OTHER_LOGINS_SUGGESTION, site: 'shop.example', logins: [{ id: 'mail', title: 'mail', username: 'maya@mail', host: 'mail.shop.example' }] },
      ],
    });
    expect(JSON.stringify(response)).not.toContain('pw-');
    // Only in sign-in fields: not with one-time codes, and nothing at all for a look-alike.
    expect(await handleContent(context, field('one-time-code', 'one-time-code'), shop)).toMatchObject({ suggestions: [{ kind: 'one-time-code', id: 'shop' }] });
    expect(await handleContent(context, field('username'), lookalike)).toEqual({ status: 'unlocked', suggestions: [] });
  });

  it('leaves the entry out when there are none', async () => {
    const { context } = setup();
    expect(await handleContent(context, field('current-password'), shop)).toEqual({ status: 'unlocked', suggestions: [{ kind: 'login', id: 'shop', title: 'shop', username: 'maya' }] });
  });

  it('fills one only when it was picked from that entry, and only for another part of this site', async () => {
    const { context, used } = setup([mail()]);
    // Not as one of the page's own logins, whatever the page asks for.
    expect(await handleContent(context, { type: 'resolve', suggestion: { kind: 'login', id: 'mail' } }, shop)).toBeNull();
    expect(await handleContent(context, { type: 'resolve', suggestion: { kind: 'one-time-code', id: 'mail' } }, shop)).toBeNull();
    // A forged pick for what isn't another part of the page's site: the page's own login, another site, a card.
    expect(await handleContent(context, pickOther('shop'), shop)).toBeNull();
    expect(await handleContent(context, pickOther('other'), shop)).toBeNull();
    expect(await handleContent(context, pickOther('card'), shop)).toBeNull();
    expect(await handleContent(context, pickOther('mail'), lookalike)).toBeNull();
    expect(await handleContent(context, pickOther('mail'), page('https://mail.other.example/'))).toBeNull();
    expect(used).toEqual([]);

    expect(await handleContent(context, pickOther('mail'), shop)).toEqual({ username: 'maya@mail', 'current-password': 'pw-mail' });
    expect(used).toEqual(['mail']);
  });

  it('never gives an https login to its site’s plain-http page', async () => {
    const { context } = setup([mail()]);
    const plain = page('http://login.shop.example/signin');
    expect(await handleContent(context, field('username'), plain)).toEqual({ status: 'unlocked', suggestions: [] });
    expect(await handleContent(context, pickOther('mail'), plain)).toBeNull();
  });

  it('goes through the autofill device-auth gate', async () => {
    const { context, used } = setup([mail()]);
    context.fillAuth = { request: vi.fn(async () => false) } as unknown as ContentContext['fillAuth'];
    expect(await handleContent(context, pickOther('mail'), shop)).toBeNull();
    expect(await handleContent(context, promptFor('mail'), shop)).toBeNull();
    expect(used).toEqual([]);
  });

  it('then offers to add the page, and Add makes it the page’s own login', async () => {
    const { context, saved } = setup([mail()]);
    expect(await handleContent(context, promptFor('mail'), shop)).toBeNull();
    await handleContent(context, pickOther('mail'), shop);
    // Only for the login filled, on the page it was filled into.
    expect(await handleContent(context, promptFor('shop'), shop)).toBeNull();
    expect(await handleContent(context, promptFor('mail'), page('https://mail.shop.example/'))).toBeNull();
    const offer = (await handleContent(context, promptFor('mail'), shop)) as { id: string };
    expect(offer).toEqual({ id: expect.any(String), host: 'login.shop.example', title: 'mail' });

    expect(await handleContent(context, { type: 'answerWebsite', id: 'forged', answer: 'add' }, shop)).toBe(false);
    expect(await handleContent(context, { type: 'answerWebsite', id: offer.id, answer: 'add' }, shop)).toBe(true);
    expect(saved).toHaveLength(1);
    expect(saved[0]).toMatchObject({ id: 'mail', revision: 1, overview: { urls: ['https://mail.shop.example', 'https://login.shop.example'] } });
    // Answered once.
    expect(await handleContent(context, { type: 'answerWebsite', id: offer.id, answer: 'add' }, shop)).toBe(false);
    expect(saved).toHaveLength(1);
    // Next time it's the page's own login, first.
    expect(await handleContent(context, field('username'), shop)).toMatchObject({ suggestions: [{ kind: 'login', id: 'mail' }, { kind: 'login', id: 'shop' }] });
  });

  it('adds nothing on Not now, nor a website the login already has', async () => {
    const { context, items, saved } = setup([mail()]);
    await handleContent(context, pickOther('mail'), shop);
    const first = (await handleContent(context, promptFor('mail'), shop)) as { id: string };
    expect(await handleContent(context, { type: 'answerWebsite', id: first.id, answer: 'notNow' }, shop)).toBe(false);
    expect(saved).toEqual([]);

    await handleContent(context, pickOther('mail'), shop);
    const second = (await handleContent(context, promptFor('mail'), shop)) as { id: string };
    // Added somewhere else meanwhile (with www., the same website).
    items.get('mail')!.overview.urls = ['https://mail.shop.example', 'https://www.login.shop.example/signin'];
    expect(await handleContent(context, { type: 'answerWebsite', id: second.id, answer: 'add' }, shop)).toBe(true);
    expect(saved).toEqual([]);
  });

  it('keeps each website once when adding', async () => {
    const { context, saved } = setup([login('mail', 'https://mail.shop.example', 'maya@mail', 'pw-mail', { urls: ['https://mail.shop.example', 'mail.shop.example/inbox'] })]);
    await handleContent(context, pickOther('mail'), shop);
    const offer = (await handleContent(context, promptFor('mail'), shop)) as { id: string };
    expect(await handleContent(context, { type: 'answerWebsite', id: offer.id, answer: 'add' }, shop)).toBe(true);
    expect(saved[0]!.overview.urls).toEqual(['https://mail.shop.example', 'https://login.shop.example']);
  });

  it('doesn’t offer for a login in a vault the user can only read', async () => {
    const { context, host, saved } = setup([{ ...mail(), vaultId: 'team' }]);
    const call = host.engine.call.bind(host.engine);
    host.engine.call = (async (method: string, args: unknown[]) =>
      method === 'listVaults' ? [{ id: 'v1', name: 'Personal', type: 'personal', role: 'owner' }, { id: 'team', name: 'Team', type: 'shared', role: 'read' }] : call(method as never, args as never)) as typeof host.engine.call;
    expect(await handleContent(context, pickOther('mail'), shop)).toEqual({ username: 'maya@mail', 'current-password': 'pw-mail' });
    expect(await handleContent(context, promptFor('mail'), shop)).toBeNull();
    expect(saved).toEqual([]);
  });

  it('gives a frame from another site nothing until the user allows it', async () => {
    const { context } = setup([mail()]);
    const framed: PageSender = { tabId: 1, frameId: 4, url: shop.url, origin: shop.origin, topOrigin: 'https://blog.example' };
    expect(await handleContent(context, pickOther('mail'), framed)).toBeNull();
    expect(await handleContent(context, promptFor('mail'), framed)).toBeNull();
  });

  it('fills the popup’s pick by the same rule', async () => {
    const { context, host } = setup([mail()]);
    const item = await host.getItem('mail');
    expect(otherLoginFillValues(context.matcher, item, shop.url)).toEqual({ username: 'maya@mail', 'current-password': 'pw-mail' });
    expect(otherLoginFillValues(context.matcher, await host.getItem('shop'), shop.url)).toBeNull();
    expect(otherLoginFillValues(context.matcher, item, lookalike.url)).toBeNull();
    expect(otherLoginFillValues(context.matcher, item, 'https://mail.shop.example/')).toBeNull();
  });
});

describe('handleContent, fill on page load', () => {
  const autoFill = { type: 'autoFill' as const };
  const own = page('https://shop.example/signin');

  function on(extra: Item[] = []) {
    const setup_ = setup(extra);
    setup_.context.fillOnLoad = async () => true;
    return setup_;
  }

  it('fills nothing unless the setting is on', async () => {
    const { context } = setup();
    expect(await handleContent(context, autoFill, own)).toBeNull();
    context.fillOnLoad = async () => false;
    expect(await handleContent(context, autoFill, own)).toBeNull();
  });

  it("fills the page's only login for its own host, and doesn't count it as a use", async () => {
    const { context, used } = on();
    expect(await handleContent(context, autoFill, own)).toEqual({ username: 'maya', 'current-password': 'pw-1' });
    expect(used).toEqual([]);
  });

  it('takes the login used last when there are several, and none when it would be a guess', async () => {
    const { context, usage } = on([login('shop2', 'https://shop.example', 'sam', 'pw-3')]);
    expect(await handleContent(context, autoFill, own)).toBeNull();
    usage.shop = { count: 9, lastUsedAt: '2026-11-01T00:00:00Z' };
    usage.shop2 = { count: 1, lastUsedAt: '2026-11-05T00:00:00Z' };
    expect(await handleContent(context, autoFill, own)).toEqual({ username: 'sam', 'current-password': 'pw-3' });
  });

  it('never fills on another host of the site, in a frame, on http, or while locked', async () => {
    const { context, state } = on();
    expect(await handleContent(context, autoFill, shop)).toBeNull();
    expect(await handleContent(context, autoFill, { ...own, frameId: 3 })).toBeNull();
    expect(await handleContent(context, autoFill, page('http://shop.example/signin'))).toBeNull();
    expect(await handleContent(context, autoFill, lookalike)).toBeNull();
    state.status = 'locked';
    expect(await handleContent(context, autoFill, own)).toBeNull();
  });

  it('never fills when filling would ask to confirm it’s you first, and never prompts', async () => {
    const { context } = on();
    const request = vi.fn(async () => true);
    context.fillAuth = { wouldAsk: async () => true, request } as unknown as ContentContext['fillAuth'];
    expect(await handleContent(context, autoFill, own)).toBeNull();
    expect(request).not.toHaveBeenCalled();
    context.fillAuth = { wouldAsk: async () => false, request } as unknown as ContentContext['fillAuth'];
    expect(await handleContent(context, autoFill, own)).toEqual({ username: 'maya', 'current-password': 'pw-1' });
    expect(request).not.toHaveBeenCalled();
  });
});

describe('handleContent, the newer item types', () => {
  const item = (id: string, type: string, details: object, overview: object = {}): Item => ({
    id,
    vaultId: 'v1',
    revision: 1,
    createdAt: '',
    updatedAt: '',
    overview: { schemaVersion: 1, title: id, type: type as never, ...overview },
    details: { schemaVersion: 1, ...details } as never,
  });
  const bank = item('savings', 'bankAccount', { accountHolder: 'Maya Orchid', iban: 'DE89 3704 0044 0532 0130 00', swift: 'COBADEFFXXX', bankName: 'Example Bank', pin: '1234' }, { subtitle: 'Example Bank' });
  const emptyBank = item('empty', 'bankAccount', { bankName: 'Nothing here' });
  const database = item('prod', 'database', { host: 'db.internal', port: '5432', database: 'shop', username: 'admin', password: 'db-pw', connectionString: 'postgres://admin:db-pw@db.internal/shop' }, { subtitle: 'db.internal' });
  const onPage = item('console', 'database', { host: 'login.shop.example', username: 'root', password: 'root-pw' });
  const licence = item('editor', 'softwareLicense', { product: 'Editor', licenseKey: 'AAAA-BBBB-CCCC', licensedTo: 'Maya' }, { subtitle: 'Maya' });
  const passport = item('passport', 'idDocument', { documentType: 'passport', number: 'X1234567', fullName: 'Maya Orchid' }, { subtitle: 'Maya Orchid' });
  const wallet = item('wallet', 'cryptoWallet', { walletName: 'Cold', seedPhrase: 'abandon abandon about', passphrase: 'p', addresses: [{ network: 'bitcoin', address: 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq' }, { network: 'ethereum', address: '0x52908400098527886E0F7030069857D2E4169EE7' }] });
  const all = [bank, emptyBank, database, onPage, licence, passport, wallet];
  const resolve = (kind: string, id: string) => ({ type: 'resolve' as const, suggestion: { kind, id } as never });

  it('offers bank accounts on any page, with no secret in the list, and fills the account', async () => {
    const { context } = setup(all);
    expect(await handleContent(context, field('iban', 'bank'), lookalike)).toEqual({ status: 'unlocked', suggestions: [{ kind: 'bank-account', id: 'savings', title: 'savings', subtitle: '•••• 3000' }] });
    const values = await handleContent(context, resolve('bank-account', 'savings'), lookalike);
    expect(values).toEqual({ 'bank-account-holder': 'Maya Orchid', iban: 'DE89 3704 0044 0532 0130 00', bic: 'COBADEFFXXX', 'bank-name': 'Example Bank' });
    expect(JSON.stringify(values)).not.toContain('1234');
  });

  it('offers databases in a console’s sign-in, the one on the page’s host first, and fills it', async () => {
    const { context } = setup(all);
    const inServer = (await handleContent(context, field('db-host', 'database'), shop)) as { suggestions: { id: string }[] };
    expect(inServer.suggestions.map((s) => s.id)).toEqual(['console', 'prod']);
    const inUsername = (await handleContent(context, field('username', 'database'), shop)) as { suggestions: { kind: string; id: string }[] };
    expect(inUsername.suggestions.map((s) => `${s.kind}:${s.id}`)).toEqual(['login:shop', 'database:console', 'database:prod']);
    expect(await handleContent(context, resolve('database', 'prod'), shop)).toEqual({ 'db-host': 'db.internal', 'db-port': '5432', 'db-name': 'shop', username: 'admin', 'current-password': 'db-pw' });
    // An ordinary sign-in gets no databases.
    const plain = (await handleContent(context, field('username', 'login'), shop)) as { suggestions: { kind: string }[] };
    expect(plain.suggestions.map((s) => s.kind)).toEqual(['login']);
  });

  it('fills a licence key, an ID number and one wallet address, never the seed phrase', async () => {
    const { context } = setup(all);
    expect(await handleContent(context, field('license-key', 'unknown'), shop)).toMatchObject({ suggestions: [{ kind: 'software-license', id: 'editor', subtitle: 'Maya' }] });
    expect(await handleContent(context, resolve('software-license', 'editor'), shop)).toEqual({ 'license-key': 'AAAA-BBBB-CCCC' });
    expect(await handleContent(context, field('document-number', 'unknown'), shop)).toMatchObject({ suggestions: [{ kind: 'id-document', id: 'passport' }] });
    expect(await handleContent(context, resolve('id-document', 'passport'), shop)).toEqual({ 'document-number': 'X1234567' });
    const addresses = (await handleContent(context, field('wallet-address', 'unknown'), shop)) as { suggestions: { id: string; subtitle: string }[] };
    expect(addresses.suggestions.map((s) => [s.id, s.subtitle])).toEqual([
      ['wallet#0', 'bitcoin · bc1qar0s…wf5mdq'],
      ['wallet#1', 'ethereum · 0x529084…169EE7'],
    ]);
    const filled = await handleContent(context, resolve('crypto-wallet', 'wallet#1'), shop);
    expect(filled).toEqual({ 'wallet-address': '0x52908400098527886E0F7030069857D2E4169EE7' });
    expect(JSON.stringify(addresses) + JSON.stringify(filled)).not.toContain('abandon');
  });

  it('fills nothing when the kind and the item don’t agree, or the address isn’t there', async () => {
    const { context } = setup(all);
    expect(await handleContent(context, resolve('bank-account', 'editor'), shop)).toBeNull();
    expect(await handleContent(context, resolve('software-license', 'savings'), shop)).toBeNull();
    expect(await handleContent(context, resolve('crypto-wallet', 'wallet#7'), shop)).toBeNull();
    expect(await handleContent(context, resolve('crypto-wallet', 'wallet'), shop)).toBeNull();
  });

  it('goes through the autofill device-auth gate and counts as a use', async () => {
    const { context, used } = setup(all);
    const request = vi.fn(async () => false);
    context.fillAuth = { request, requestCard: vi.fn() } as unknown as ContentContext['fillAuth'];
    expect(await handleContent(context, resolve('database', 'prod'), shop)).toBeNull();
    expect(request).toHaveBeenCalled();
    request.mockResolvedValue(true);
    expect(await handleContent(context, resolve('crypto-wallet', 'wallet#0'), shop)).not.toBeNull();
    expect(used).toEqual(['wallet']);
  });
});
