import { isVaultError } from '../errors';
import type { MaskedEmailProviderDetails, MaskedEmailProviderId } from '../types';
import { canManageAlias, changeProviderAlias, checkBaseUrl, createProviderAlias, fetchHttp, MASKED_EMAIL_PROVIDERS, MaskedEmailError, type HttpRequest, type HttpResponse, type MaskedEmailHttp } from './providers';

const SITE = { domain: 'github.com', origin: 'https://github.com' };

/** A fake network: answers each request in turn and records what was sent. No real calls are made. */
function mockHttp(...answers: (Partial<HttpResponse> & { json?: unknown })[]) {
  const sent: HttpRequest[] = [];
  const http: MaskedEmailHttp = async (request) => {
    sent.push(request);
    const answer = answers.shift();
    if (!answer) throw new Error('unexpected request');
    return { status: answer.status ?? 200, headers: answer.headers ?? {}, body: answer.body ?? JSON.stringify(answer.json ?? {}) };
  };
  return { http, sent };
}

const details = (provider: MaskedEmailProviderId, extra: Partial<MaskedEmailProviderDetails> = {}) => ({ provider, token: 'tok-123', ...extra });

async function failure(promise: Promise<unknown>): Promise<MaskedEmailError> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(MaskedEmailError);
  return error as MaskedEmailError;
}

describe('SimpleLogin', () => {
  it('makes a random alias with the site as hostname and note, using the Authentication header', async () => {
    const { http, sent } = mockHttp({ status: 201, json: { alias: 'github.x7k2@simplelogin.com', id: 42 } });
    expect(await createProviderAlias(http, details('simplelogin'), SITE)).toEqual({ email: 'github.x7k2@simplelogin.com', aliasId: '42', provider: 'simplelogin' });
    expect(sent).toEqual([
      {
        url: 'https://app.simplelogin.io/api/alias/random/new?hostname=github.com',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authentication: 'tok-123' },
        body: JSON.stringify({ note: 'github.com' }),
      },
    ]);
  });

  it('uses a self-hosted server', async () => {
    const { http, sent } = mockHttp({ status: 201, json: { alias: 'a@sl.example', id: 1 } });
    await createProviderAlias(http, details('simplelogin', { baseUrl: 'https://sl.example/' }), SITE);
    expect(sent[0]!.url).toBe('https://sl.example/api/alias/random/new?hostname=github.com');
  });
});

describe('addy.io', () => {
  it('posts the domain and description with a bearer token', async () => {
    const { http, sent } = mockHttp({ status: 201, json: { data: { id: '50c9e585', email: 'k3j1@anonaddy.me' } } });
    expect(await createProviderAlias(http, details('addy', { domain: 'anonaddy.me' }), SITE)).toEqual({ email: 'k3j1@anonaddy.me', aliasId: '50c9e585', provider: 'addy' });
    expect(sent[0]).toEqual({
      url: 'https://app.addy.io/api/v1/aliases',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: 'Bearer tok-123', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ domain: 'anonaddy.me', description: 'github.com' }),
    });
  });

  it('needs a domain', async () => {
    const { http, sent } = mockHttp();
    expect((await failure(createProviderAlias(http, details('addy'), SITE))).code).toBe('maskedEmailFailed');
    expect(sent).toEqual([]);
  });
});

describe('Firefox Relay', () => {
  it('creates a relay address with a Token header', async () => {
    const { http, sent } = mockHttp({ status: 201, json: { id: 7, full_address: 'abc123@mozmail.com' } });
    expect(await createProviderAlias(http, details('firefoxRelay'), SITE)).toEqual({ email: 'abc123@mozmail.com', aliasId: '7', provider: 'firefoxRelay' });
    expect(sent[0]).toEqual({
      url: 'https://relay.firefox.com/api/v1/relayaddresses/',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: 'Token tok-123' },
      body: JSON.stringify({ enabled: true, generated_for: 'github.com', description: 'github.com' }),
    });
  });
});

describe('Fastmail', () => {
  const SESSION = { apiUrl: 'https://api.fastmail.com/jmap/api/', primaryAccounts: { 'https://www.fastmail.com/dev/maskedemail': 'u123' } };

  it('reads the session, then calls MaskedEmail/set for the site', async () => {
    const { http, sent } = mockHttp(
      { json: SESSION },
      { json: { methodResponses: [['MaskedEmail/set', { created: { octapass: { id: 'me-1', email: 'quiet.fox1@fastmail.com' } } }, '0']] } },
    );
    expect(await createProviderAlias(http, details('fastmail'), SITE)).toEqual({ email: 'quiet.fox1@fastmail.com', aliasId: 'me-1', provider: 'fastmail' });
    expect(sent[0]).toEqual({ url: 'https://api.fastmail.com/jmap/session', method: 'GET', headers: { Authorization: 'Bearer tok-123', Accept: 'application/json' } });
    expect(sent[1]!.url).toBe('https://api.fastmail.com/jmap/api/');
    expect(sent[1]!.headers.Authorization).toBe('Bearer tok-123');
    expect(JSON.parse(sent[1]!.body!)).toEqual({
      using: ['urn:ietf:params:jmap:core', 'https://www.fastmail.com/dev/maskedemail'],
      methodCalls: [['MaskedEmail/set', { accountId: 'u123', create: { octapass: { state: 'enabled', description: 'github.com', forDomain: 'https://github.com' } } }, '0']],
    });
  });

  it('treats a token without the Masked Email scope as a token problem', async () => {
    const { http } = mockHttp({ json: { apiUrl: SESSION.apiUrl, primaryAccounts: {} } });
    expect((await failure(createProviderAlias(http, details('fastmail'), SITE))).code).toBe('maskedEmailToken');
  });

  it('reports a JMAP refusal in its own words', async () => {
    const { http } = mockHttp({ json: SESSION }, { json: { methodResponses: [['MaskedEmail/set', { notCreated: { octapass: { type: 'overQuota', description: 'Too many masked emails' } } }, '0']] } });
    const error = await failure(createProviderAlias(http, details('fastmail'), SITE));
    expect([error.code, error.message]).toEqual(['maskedEmailFailed', 'Too many masked emails']);
  });

  it('reports a JMAP method error', async () => {
    const { http } = mockHttp({ json: SESSION }, { json: { methodResponses: [['error', { type: 'forbidden' }, '0']] } });
    const error = await failure(createProviderAlias(http, details('fastmail'), SITE));
    expect([error.code, error.message]).toEqual(['maskedEmailFailed', 'forbidden']);
  });
});

describe('DuckDuckGo', () => {
  it('makes a new duck.com address with a bearer token', async () => {
    const { http, sent } = mockHttp({ status: 201, json: { address: 'cheerful-otter-42' } });
    expect(await createProviderAlias(http, details('duckduckgo'), SITE)).toEqual({ email: 'cheerful-otter-42@duck.com', aliasId: 'cheerful-otter-42@duck.com', provider: 'duckduckgo' });
    expect(sent[0]).toEqual({ url: 'https://quack.duckduckgo.com/api/email/addresses', method: 'POST', headers: { Accept: 'application/json', Authorization: 'Bearer tok-123' } });
  });

  it("refuses an address that isn't one", async () => {
    const { http } = mockHttp({ status: 201, json: { address: 'x@evil.example' } });
    expect((await failure(createProviderAlias(http, details('duckduckgo'), SITE))).code).toBe('maskedEmailFailed');
  });
});

describe('Forward Email', () => {
  it('adds an alias on the domain with basic auth (token as user name)', async () => {
    const { http, sent } = mockHttp({ json: { id: 'fe1', name: 'r4nd0m', domain: { name: 'mine.example' } } });
    expect(await createProviderAlias(http, details('forwardEmail', { domain: 'mine.example' }), SITE)).toEqual({ email: 'r4nd0m@mine.example', aliasId: 'fe1', provider: 'forwardEmail' });
    expect(sent[0]).toEqual({
      url: 'https://api.forwardemail.net/v1/domains/mine.example/aliases',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Basic ${btoa('tok-123:')}` },
      body: JSON.stringify({ description: 'github.com', labels: 'github.com', is_enabled: true }),
    });
  });
});

describe('errors, for every provider', () => {
  const configs = MASKED_EMAIL_PROVIDERS.map((p) => details(p.id, p.needsDomain ? { domain: 'mine.example' } : {}));

  it.each(configs)('$provider: a refused token is maskedEmailToken', async (config) => {
    for (const status of [401, 403]) {
      const { http } = mockHttp({ status, json: { error: 'Wrong api key' } });
      const error = await failure(createProviderAlias(http, config, SITE));
      expect([error.code, error.message]).toEqual(['maskedEmailToken', 'Wrong api key']);
    }
  });

  it.each(configs)('$provider: a rate limit carries Retry-After', async (config) => {
    const { http } = mockHttp({ status: 429, headers: { 'retry-after': '30' }, json: { detail: 'Request was throttled.' } });
    const error = await failure(createProviderAlias(http, config, SITE));
    expect([error.code, error.retryAfter, error.message]).toEqual(['maskedEmailRateLimited', 30, 'Request was throttled.']);
  });

  it.each(configs)('$provider: other errors keep the status or the provider message', async (config) => {
    const { http } = mockHttp({ status: 500, body: '<html>oops</html>' });
    const error = await failure(createProviderAlias(http, config, SITE));
    expect([error.code, error.message]).toEqual(['maskedEmailFailed', 'HTTP 500']);
  });

  it.each(configs)('$provider: no answer at all is maskedEmailUnreachable', async (config) => {
    const http: MaskedEmailHttp = async () => {
      throw new TypeError('Failed to fetch');
    };
    expect((await failure(createProviderAlias(http, config, SITE))).code).toBe('maskedEmailUnreachable');
  });

  it.each(configs)('$provider: an answer without an address is an error', async (config) => {
    const { http } = mockHttp({ status: 200, json: {} });
    expect((await failure(createProviderAlias(http, config, SITE))).code).toMatch(/maskedEmail(Failed|Token)/);
  });

  it('reads an HTTP date in Retry-After', async () => {
    const at = new Date(Date.now() + 60_000).toUTCString();
    const { http } = mockHttp({ status: 429, headers: { 'retry-after': at } });
    const error = await failure(createProviderAlias(http, details('simplelogin'), SITE));
    expect(error.retryAfter).toBeGreaterThan(50);
    expect(isVaultError(error, 'maskedEmailRateLimited')).toBe(true);
  });
});

describe('checkBaseUrl', () => {
  it('takes HTTPS, or HTTP on this computer', () => {
    expect(checkBaseUrl(' https://sl.example/base/ ')).toBe('https://sl.example/base');
    expect(checkBaseUrl('http://127.0.0.1:4010')).toBe('http://127.0.0.1:4010');
    expect(() => checkBaseUrl('http://sl.example')).toThrow();
    expect(() => checkBaseUrl('not a url')).toThrow();
  });
});

describe('fetchHttp', () => {
  it('sends no cookies or referrer, and lower-cases header names', async () => {
    const fetchImpl = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => new Response('{"ok":1}', { status: 201, headers: { 'Retry-After': '5' } }));
    const http = fetchHttp(fetchImpl as unknown as typeof fetch);
    expect(await http({ url: 'https://p.example/x', method: 'POST', headers: { A: 'b' }, body: '{}' })).toEqual({ status: 201, headers: expect.objectContaining({ 'retry-after': '5' }), body: '{"ok":1}' });
    expect(fetchImpl.mock.calls[0]![1]).toMatchObject({ method: 'POST', credentials: 'omit', referrerPolicy: 'no-referrer', headers: { A: 'b' }, body: '{}' });
  });
});

describe('changing an alias', () => {
  const FASTMAIL = { apiUrl: 'https://api.fastmail.com/jmap/api/', primaryAccounts: { 'https://www.fastmail.com/dev/maskedemail': 'u1' } };

  it('SimpleLogin reads the state, then toggles only when it has to', async () => {
    const off = mockHttp({ json: { enabled: true } }, { json: { enabled: false } });
    await changeProviderAlias(off.http, details('simplelogin'), '42', 'disable');
    expect(off.sent.map((r) => [r.method, r.url])).toEqual([
      ['GET', 'https://app.simplelogin.io/api/aliases/42'],
      ['POST', 'https://app.simplelogin.io/api/aliases/42/toggle'],
    ]);
    const already = mockHttp({ json: { enabled: false } });
    await changeProviderAlias(already.http, details('simplelogin'), '42', 'disable');
    expect(already.sent).toHaveLength(1);
  });

  it('addy.io has an active-aliases list and a delete', async () => {
    const off = mockHttp({ status: 204, body: '' });
    await changeProviderAlias(off.http, details('addy'), 'a/b', 'disable');
    expect([off.sent[0]!.method, off.sent[0]!.url]).toEqual(['DELETE', 'https://app.addy.io/api/v1/active-aliases/a%2Fb']);
    const on = mockHttp({ json: {} });
    await changeProviderAlias(on.http, details('addy'), 'x', 'enable');
    expect([on.sent[0]!.method, on.sent[0]!.url, on.sent[0]!.body]).toEqual(['POST', 'https://app.addy.io/api/v1/active-aliases', JSON.stringify({ id: 'x' })]);
    const gone = mockHttp({ status: 204, body: '' });
    await changeProviderAlias(gone.http, details('addy'), 'x', 'delete');
    expect([gone.sent[0]!.method, gone.sent[0]!.url]).toEqual(['DELETE', 'https://app.addy.io/api/v1/aliases/x']);
  });

  it('Firefox Relay patches enabled, and Forward Email puts is_enabled', async () => {
    const relay = mockHttp({ json: {} });
    await changeProviderAlias(relay.http, details('firefoxRelay'), '9', 'disable');
    expect(relay.sent[0]).toMatchObject({ method: 'PATCH', url: 'https://relay.firefox.com/api/v1/relayaddresses/9/', body: JSON.stringify({ enabled: false }) });
    const forward = mockHttp({ json: {} });
    await changeProviderAlias(forward.http, details('forwardEmail', { domain: 'mail.example' }), '9', 'enable');
    expect(forward.sent[0]).toMatchObject({ method: 'PUT', url: 'https://api.forwardemail.net/v1/domains/mail.example/aliases/9', body: JSON.stringify({ is_enabled: true }) });
  });

  it('Fastmail sets the state over JMAP', async () => {
    const { http, sent } = mockHttp({ json: FASTMAIL }, { json: { methodResponses: [['MaskedEmail/set', { updated: { m1: null } }, '0']] } });
    await changeProviderAlias(http, details('fastmail'), 'm1', 'delete');
    expect(JSON.parse(sent[1]!.body!).methodCalls[0][1].update).toEqual({ m1: { state: 'deleted' } });
  });

  it('Fastmail reports a refused change, except deleting what is already gone', async () => {
    const refused = [['MaskedEmail/set', { notUpdated: { m1: { type: 'notFound' } } }, '0']];
    const gone = mockHttp({ json: FASTMAIL }, { json: { methodResponses: refused } });
    await changeProviderAlias(gone.http, details('fastmail'), 'm1', 'delete');
    const off = mockHttp({ json: FASTMAIL }, { json: { methodResponses: refused } });
    expect((await failure(changeProviderAlias(off.http, details('fastmail'), 'm1', 'disable'))).code).toBe('maskedEmailFailed');
  });

  it('deleting an alias that is already gone succeeds; turning one off does not', async () => {
    const gone = mockHttp({ status: 404, body: '' });
    await changeProviderAlias(gone.http, details('firefoxRelay'), '9', 'delete');
    const off = mockHttp({ status: 404, body: '' });
    expect((await failure(changeProviderAlias(off.http, details('firefoxRelay'), '9', 'disable'))).code).toBe('maskedEmailFailed');
  });

  it('maps a bad token and a rate limit like every other call', async () => {
    const token = mockHttp({ status: 401, body: '' });
    expect((await failure(changeProviderAlias(token.http, details('addy'), 'x', 'delete'))).code).toBe('maskedEmailToken');
    const limited = mockHttp({ status: 429, headers: { 'retry-after': '30' }, body: '' });
    expect((await failure(changeProviderAlias(limited.http, details('addy'), 'x', 'delete'))).retryAfter).toBe(30);
  });

  it('has no call for DuckDuckGo, or for an alias with no id of its own', async () => {
    expect(canManageAlias('duckduckgo', 'a', 'a@duck.com')).toBe(false);
    expect(canManageAlias('simplelogin', 'a@sl.co', 'a@sl.co')).toBe(false);
    expect(canManageAlias('simplelogin', '42', 'a@sl.co')).toBe(true);
    await failure(changeProviderAlias(mockHttp().http, details('duckduckgo'), 'a', 'delete'));
  });
});
