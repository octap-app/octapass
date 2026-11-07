import type { Item, ItemDraft, LoginDetails } from '@octapass/vault-client';
import { cleanDraft, detectCardBrand, validateDraft } from './editorModel';

const login = (overrides: Partial<ItemDraft['details']> = {}, overview: Partial<ItemDraft['overview']> = {}): ItemDraft => ({
  vaultId: 'v1',
  overview: { schemaVersion: 1, type: 'login', title: 'GitHub', ...overview },
  details: { schemaVersion: 1, ...overrides },
});

describe('validateDraft', () => {
  it('requires a title', () => {
    expect(validateDraft(login({}, { title: '  ' }))).toEqual({ title: 'validation.titleRequired' });
  });

  it('checks URLs, one-time code secrets and recovery emails', () => {
    const errors = validateDraft(login({ totp: 'not a secret!', recovery: { email: 'nope' } }, { urls: ['github.com', 'not a url'] }));
    expect(errors).toEqual({ 'urls.1': 'validation.url', totp: 'validation.totp', 'recovery.email': 'validation.email' });
  });

  it('checks card expiry dates', () => {
    const card: ItemDraft = { vaultId: 'v1', overview: { schemaVersion: 1, type: 'card', title: 'Visa' }, details: { schemaVersion: 1, expiry: '13/27' } };
    expect(validateDraft(card).expiry).toBe('validation.expiry');
  });
});

describe('cleanDraft', () => {
  it('trims values and drops empty optional fields, keeping unknown ones', () => {
    const draft = login({ username: ' maya ', password: '', customFields: [{ label: '', value: '', hidden: false }], futureField: { a: 1 } } as never, { urls: ['  '], tags: ['work', ' work ', ''] });
    const cleaned = cleanDraft(draft);
    expect(cleaned.details).toEqual({ schemaVersion: 1, username: 'maya', futureField: { a: 1 } });
    expect(cleaned.overview).toEqual({ schemaVersion: 1, type: 'login', title: 'GitHub', tags: ['work'], subtitle: 'maya' });
  });

  it('leaves fields it doesn’t know exactly as they were', () => {
    const unknown = { list: [], note: ' padded ', nested: { empty: '' } };
    const draft = login({ username: 'maya', futureField: unknown, recovery: { email: 'a@b.co', futureRecovery: '' } } as never, { futureOverview: [''] } as never);
    const cleaned = cleanDraft(draft);
    expect((cleaned.details as unknown as Record<string, unknown>).futureField).toEqual(unknown);
    expect((cleaned.details as LoginDetails).recovery).toEqual({ email: 'a@b.co', futureRecovery: '' });
    expect((cleaned.overview as unknown as Record<string, unknown>).futureOverview).toEqual(['']);
  });

  it('keeps where a recovery email or phone came from, and drops a link left without its value', () => {
    const emailSource = { kind: 'alias', provider: 'simplelogin', aliasId: '42' } as const;
    const phoneSource = { kind: 'identity', itemId: 'me' } as const;
    const kept = cleanDraft(login({ recovery: { email: ' a@alias.example ', emailSource, phone: '+1 555', phoneSource } }));
    expect((kept.details as LoginDetails).recovery).toEqual({ email: 'a@alias.example', emailSource, phone: '+1 555', phoneSource });
    const dropped = cleanDraft(login({ recovery: { email: ' ', emailSource, phoneSource } }));
    expect((dropped.details as LoginDetails).recovery).toBeUndefined();
  });

  it('keeps spaces that may be part of a password', () => {
    expect(cleanDraft(login({ password: ' pass phrase ' })).details).toMatchObject({ password: ' pass phrase ' });
  });

  it('keeps a custom subtitle but follows the username when it matched before', () => {
    const original = { details: { schemaVersion: 1, username: 'old' } } as Item;
    expect(cleanDraft(login({ username: 'new' }, { subtitle: 'old' }), original).overview.subtitle).toBe('new');
    expect(cleanDraft(login({ username: 'new' }, { subtitle: 'API credential' }), original).overview.subtitle).toBe('API credential');
  });

  it('names cards by brand and last four digits', () => {
    const card: ItemDraft = { vaultId: 'v1', overview: { schemaVersion: 1, type: 'card', title: 'Travel' }, details: { schemaVersion: 1, number: '4242 4242 4242 4242' } };
    const cleaned = cleanDraft(card);
    expect(cleaned.overview.subtitle).toBe('Visa ending 4242');
    expect(cleaned.details).toMatchObject({ brand: 'Visa' });
  });
});

describe('detectCardBrand', () => {
  it('recognises the common networks', () => {
    expect(detectCardBrand('5454 5454')).toBe('Mastercard');
    expect(detectCardBrand('3782 822463 10005')).toBe('American Express');
    expect(detectCardBrand('9999')).toBeUndefined();
  });
});

describe('Wi-Fi networks', () => {
  const wifi = (details: Record<string, unknown>, title = 'Home'): ItemDraft => ({
    vaultId: 'v1',
    overview: { schemaVersion: 1, type: 'wifi', title },
    details: { schemaVersion: 1, ssid: 'Home-5G', security: 'wpa2', ...details } as ItemDraft['details'],
  });

  it('need a network name, and passwords the security type can use', () => {
    expect(validateDraft(wifi({ ssid: ' ' }))).toEqual({ ssid: 'validation.ssidRequired' });
    expect(validateDraft(wifi({ password: 'short' }))).toEqual({ password: 'validation.wpaPassword' });
    expect(validateDraft(wifi({ password: 'z'.repeat(64) }))).toEqual({ password: 'validation.wpaPassword' });
    expect(validateDraft(wifi({ password: 'ab12'.repeat(16) }))).toEqual({});
    expect(validateDraft(wifi({ security: 'wep', password: 'abcd' }))).toEqual({ password: 'validation.wepKey' });
    expect(validateDraft(wifi({ security: 'wep', password: '0123456789' }))).toEqual({});
    // Enterprise passwords are people's own, and open networks ignore theirs.
    expect(validateDraft(wifi({ security: 'wpa3Enterprise', password: 'pw' }))).toEqual({});
    expect(validateDraft(wifi({ security: 'open', password: 'x' }))).toEqual({});
  });

  it('are named after the network when the title is empty, which is always the subtitle', () => {
    expect(validateDraft(wifi({}, ' '))).toEqual({});
    const cleaned = cleanDraft(wifi({}, ''));
    expect(cleaned.overview).toEqual({ schemaVersion: 1, type: 'wifi', title: 'Home-5G', subtitle: 'Home-5G' });
    expect(cleanDraft({ ...wifi({}), overview: { ...wifi({}).overview, subtitle: 'custom' } }).overview.subtitle).toBe('Home-5G');
  });

  it('keep the network name exactly, and drop what the security type doesn’t use', () => {
    const cleaned = cleanDraft(
      wifi({
        ssid: ' Home 5G ',
        security: 'open',
        password: 'leftover',
        hidden: false,
        managed: true,
        eapMethod: 'peap',
        username: 'maya',
        customFields: [{ label: '', value: '', hidden: false }],
      }),
    );
    expect(cleaned.details).toEqual({ schemaVersion: 1, ssid: ' Home 5G ', security: 'open', managed: true });
    const enterprise = cleanDraft(wifi({ security: 'wpa2Enterprise', eapMethod: 'tls', phase2: 'mschapv2', username: ' maya ', password: ' pw ' }));
    expect(enterprise.details).toEqual({ schemaVersion: 1, ssid: 'Home-5G', security: 'wpa2Enterprise', eapMethod: 'tls', username: 'maya', password: ' pw ' });
  });
});

describe('match rules and security questions', () => {
  const url = 'https://app.example.com';

  it('keeps a rule for a saved website only, and not the default', () => {
    const cleaned = cleanDraft(login({}, { urls: [` ${url} `], urlMatch: { [` ${url} `]: 'host', 'https://gone.example': 'never' } }));
    expect(cleaned.overview.urlMatch).toEqual({ [url]: 'host' });
    expect(cleanDraft(login({}, { urls: [url], urlMatch: { [url]: 'subdomains' } })).overview.urlMatch).toBeUndefined();
  });

  it('keeps "every part of the domain" now that it isn’t the default', () => {
    expect(cleanDraft(login({}, { urls: [url], urlMatch: { [url]: 'baseDomain' } })).overview.urlMatch).toEqual({ [url]: 'baseDomain' });
  });

  it('saves a site written twice once, with the first one’s rule', () => {
    const cleaned = cleanDraft(login({}, { urls: [url, `${url}/`, 'app.example.com/login', 'https://other.example'], urlMatch: { [url]: 'host', 'app.example.com/login': 'never' } }));
    expect(cleaned.overview.urls).toEqual([url, 'https://other.example']);
    expect(cleaned.overview.urlMatch).toEqual({ [url]: 'host' });
  });

  it('checks a regular expression rule as a pattern, not an address', () => {
    expect(validateDraft(login({}, { urls: ['^https://[a-z]+\\.example\\.com/'], urlMatch: { '^https://[a-z]+\\.example\\.com/': 'regex' } }))).toEqual({});
    expect(validateDraft(login({}, { urls: ['(unclosed'], urlMatch: { '(unclosed': 'regex' } }))).toEqual({ 'urls.0': 'validation.regex' });
  });

  it('keeps answers exactly as typed and drops empty questions', () => {
    const cleaned = cleanDraft(login({ recovery: { securityQuestions: [{ question: ' First pet? ', answer: ' spaced ' }, { question: '', answer: '' }] } }));
    expect((cleaned.details as LoginDetails).recovery?.securityQuestions).toEqual([{ question: 'First pet?', answer: ' spaced ' }]);
  });

  it('drops recovery info with nothing left in it', () => {
    const cleaned = cleanDraft(login({ recovery: { securityQuestions: [{ question: '', answer: '' }] } }));
    expect((cleaned.details as LoginDetails).recovery).toBeUndefined();
  });

  it('accepts a counter-based code', () => {
    expect(validateDraft(login({ totp: 'otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=3' }))).toEqual({});
  });
});
