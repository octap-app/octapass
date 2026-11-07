import { isVaultError } from '../errors';
import { ApiProblem, HttpClient, toVaultError, type HttpOptions } from './http';

const problem = (status: number, type: string, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify({ type: `https://octap.app/problems/${type}`, title: type, status, detail: `detail of ${type}` }), {
    status,
    headers: { 'Content-Type': 'application/problem+json', ...headers },
  });

const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });

function client(responses: Response[], overrides: Partial<HttpOptions> = {}) {
  let token = 'old-token';
  const fetch = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => responses.shift()!);
  const refresh = vi.fn(async () => {
    token = 'new-token';
  });
  const onAccountDeleted = vi.fn(async () => undefined);
  const sleep = vi.fn(async () => undefined);
  const http = new HttpClient({ baseUrl: 'https://vault.example', fetch, accessToken: () => token, refresh, onAccountDeleted, sleep, ...overrides });
  const header = (call: number, name: string) => new Headers(fetch.mock.calls[call]![1]!.headers).get(name);
  return { http, fetch, refresh, onAccountDeleted, sleep, header };
}

describe('HttpClient', () => {
  it('sends JSON with the bearer token and never cookies', async () => {
    const { http, fetch, header } = client([json({ revision: 3 })]);
    expect(await http.request('PUT', '/v1/x', { body: { a: 1 }, headers: { 'If-Match': '"2"' } })).toEqual({ revision: 3 });
    const [url, init] = fetch.mock.calls[0]!;
    expect(url).toBe('https://vault.example/v1/x');
    expect(init).toMatchObject({ method: 'PUT', body: '{"a":1}', credentials: 'omit', referrerPolicy: 'no-referrer' });
    expect(header(0, 'Authorization')).toBe('Bearer old-token');
    expect(header(0, 'If-Match')).toBe('"2"');
    expect(header(0, 'Content-Type')).toBe('application/json');
  });

  it('accepts answers without a body, such as 202 for an invite and 204 for a delete', async () => {
    const { http } = client([new Response(null, { status: 202 }), new Response(null, { status: 204 })]);
    expect(await http.request('POST', '/v1/vaults/v/members', { body: {} })).toBeUndefined();
    expect(await http.request('DELETE', '/v1/share-links/x')).toBeUndefined();
  });

  it('leaves the token off anonymous calls', async () => {
    const { http, header } = client([json({})]);
    await http.request('POST', '/v1/auth/prelogin', { auth: false, body: {} });
    expect(header(0, 'Authorization')).toBeNull();
  });

  it('refreshes once on 401 and retries with the new token', async () => {
    const { http, refresh, header } = client([problem(401, 'unauthorized'), json({ ok: true })]);
    expect(await http.request('GET', '/v1/sync')).toEqual({ ok: true });
    expect(refresh).toHaveBeenCalledOnce();
    expect(header(1, 'Authorization')).toBe('Bearer new-token');
  });

  it('gives up when the retry is refused too', async () => {
    const { http, refresh } = client([problem(401, 'unauthorized'), problem(401, 'unauthorized')]);
    await expect(http.request('GET', '/v1/sync')).rejects.toMatchObject({ status: 401, type: 'unauthorized' });
    expect(refresh).toHaveBeenCalledOnce();
  });

  it('reports a deleted account instead of refreshing', async () => {
    const { http, refresh, onAccountDeleted } = client([problem(401, 'account-deleted')]);
    await expect(http.request('GET', '/v1/sync')).rejects.toMatchObject({ type: 'account-deleted' });
    expect(onAccountDeleted).toHaveBeenCalledOnce();
    expect(refresh).not.toHaveBeenCalled();
  });

  it('waits out a short Retry-After once, and gives up on a long one', async () => {
    const short = client([problem(429, 'rate-limited', { 'Retry-After': '2' }), json({ ok: true })]);
    expect(await short.http.request('POST', '/v1/auth/prelogin', { auth: false })).toEqual({ ok: true });
    expect(short.sleep).toHaveBeenCalledWith(2000);

    const long = client([problem(429, 'rate-limited', { 'Retry-After': '60' })]);
    const error = await long.http.request('POST', '/v1/auth/prelogin', { auth: false }).catch((e: unknown) => e);
    expect(error).toMatchObject({ type: 'rate-limited', retryAfter: 60 });
    expect(long.sleep).not.toHaveBeenCalled();
  });

  it('turns network failures into serverUnreachable', async () => {
    const { http } = client([], { fetch: () => Promise.reject(new TypeError('Failed to fetch')) });
    await expect(http.request('GET', '/v1/server-info')).rejects.toSatisfy((e) => isVaultError(e, 'serverUnreachable'));
  });

  it('keeps the problem body, e.g. the current item of a conflict', async () => {
    const current = { id: 'i', revision: 9 };
    const response = new Response(JSON.stringify({ type: 'https://octap.app/problems/conflict', status: 409, current }), { status: 409 });
    const { http } = client([response]);
    await expect(http.request('PUT', '/v1/x')).rejects.toMatchObject({ status: 409, type: 'conflict', body: { current } });
  });

  it('copes with error answers that aren’t problem+json', async () => {
    const { http } = client([new Response('<html>Bad gateway</html>', { status: 502 })]);
    await expect(http.request('GET', '/v1/sync')).rejects.toMatchObject({ status: 502, type: 'http-502' });
  });
});

describe('toVaultError', () => {
  it.each([
    ['login-failed', 'invalidCredentials'],
    ['account-exists', 'emailTaken'],
    ['invalid-verification-code', 'invalidVerificationCode'],
    ['signups-closed', 'signupsClosed'],
    ['invite-required', 'signupsClosed'],
    ['not-found', 'notFound'],
    ['forbidden', 'readOnlyVault'],
    ['rate-limited', 'rateLimited'],
    ['account-deleted', 'accountDeleted'],
    ['invalid-second-factor', 'invalidTwoStepCode'],
    ['reauth-required', 'reauthRequired'],
    ['internal', 'serverError'],
    ['email-unavailable', 'serverError'],
  ])('%s → %s', (type, code) => {
    expect(toVaultError(new ApiProblem(400, type, {}))).toMatchObject({ name: 'VaultError', code });
  });
});
