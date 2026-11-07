import { createBreachChecker, PWNED_PASSWORDS_URL } from './breach';

// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
const PASSWORD_SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';

function fakeFetch(body: string, status = 200) {
  return vi.fn<typeof fetch>(async () => new Response(body, { status }));
}

describe('createBreachChecker', () => {
  it('sends only the 5-character prefix, with padding requested', async () => {
    const fetchMock = fakeFetch(`0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n${PASSWORD_SUFFIX}:9659365\r\n`);
    const check = createBreachChecker({ fetch: fetchMock });

    expect(await check('password')).toBe(9659365);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`${PWNED_PASSWORDS_URL}/range/5BAA6`);
    expect(new Headers(init?.headers).get('Add-Padding')).toBe('true');
    expect(init?.referrerPolicy).toBe('no-referrer');
    expect(init?.body).toBeUndefined();
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain('1E4C9B93');
  });

  it('returns 0 for unknown suffixes and ignores padding entries', async () => {
    const check = createBreachChecker({ fetch: fakeFetch(`${PASSWORD_SUFFIX}:0\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\n`) });
    expect(await check('password')).toBe(0);
  });

  it('caches each prefix', async () => {
    const fetchMock = fakeFetch(`${PASSWORD_SUFFIX}:3`);
    const check = createBreachChecker({ fetch: fetchMock, baseUrl: 'https://hibp.example/' });
    await Promise.all([check('password'), check('password')]);
    expect(await check('password')).toBe(3);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]![0]).toBe('https://hibp.example/range/5BAA6');
  });

  it('rejects on an error response and retries afterwards', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response('busy', { status: 503 }))
      .mockResolvedValueOnce(new Response(`${PASSWORD_SUFFIX}:5`));
    const check = createBreachChecker({ fetch: fetchMock });
    await expect(check('password')).rejects.toThrow('503');
    expect(await check('password')).toBe(5);
  });

  it('rejects when the network fails', async () => {
    const check = createBreachChecker({ fetch: vi.fn<typeof fetch>().mockRejectedValue(new TypeError('offline')) });
    await expect(check('password')).rejects.toThrow('offline');
  });
});
