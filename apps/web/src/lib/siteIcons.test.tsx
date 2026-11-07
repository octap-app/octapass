import { screen, within } from '@testing-library/react';
import { createSignedInService, renderApp } from '../test/renderApp';

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/** The icon server: GitHub has an icon, every other site none. */
function stubServer() {
  const fetchMock = vi.fn(async (url: string, _init?: RequestInit) =>
    url.endsWith('/v1/icons/github.com')
      ? new Response(PNG, { status: 200, headers: { 'content-type': 'image/png' } })
      : new Response(JSON.stringify({ type: 'https://octap.app/problems/not-found' }), { status: 404, headers: { 'content-type': 'application/problem+json' } }),
  );
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

const iconRequests = (fetchMock: ReturnType<typeof stubServer>) => fetchMock.mock.calls.map(([url]) => String(url)).filter((url) => url.includes('/v1/icons/'));

function row(title: string): HTMLElement {
  return screen.getAllByRole('link').find((link) => link.textContent?.includes(title) && link.getAttribute('data-item-id'))!;
}

describe('website icons', { timeout: 30_000 }, () => {
  afterEach(() => vi.unstubAllGlobals());

  it('shows the site’s icon from the Octa Pass server, and the initial for the rest', async () => {
    const fetchMock = stubServer();
    const service = await createSignedInService();
    renderApp(service, '/items/all');
    await screen.findByRole('heading', { name: 'All items', level: 1 });
    await vi.waitFor(() => expect(row('GitHub').querySelector('img')?.getAttribute('src')).toMatch(/^data:image\/png;base64,/), { timeout: 10_000 });
    expect(row('Google').querySelector('img')).toBeNull();
    expect(row('Google')).toHaveTextContent('G');

    const requests = iconRequests(fetchMock);
    expect(requests).toContain(`${service.getSession().serverUrl}/v1/icons/github.com`);
    // The registrable domain only: accounts.google.com is asked as google.com.
    expect(requests).toContain(`${service.getSession().serverUrl}/v1/icons/google.com`);
    expect(requests.some((url) => url.includes('accounts.google.com'))).toBe(false);
    expect(new Set(requests).size).toBe(requests.length);
    const [, init] = fetchMock.mock.calls.find(([url]) => String(url).includes('/v1/icons/'))!;
    expect(init).toMatchObject({ credentials: 'omit', referrerPolicy: 'no-referrer' });
  });

  it('asks for nothing with Show website icons off', async () => {
    const fetchMock = stubServer();
    const service = await createSignedInService();
    const { user } = renderApp(service, '/settings');
    const appearance = await screen.findByRole('region', { name: 'Appearance' });
    const toggle = within(appearance).getByRole('switch', { name: 'Show website icons' });
    expect(toggle).toBeChecked();
    expect(within(appearance).getByText(/Icons come through your Octa Pass server, which sees which websites/)).toBeInTheDocument();
    await user.click(toggle);
    expect(toggle).not.toBeChecked();
    expect(JSON.parse(localStorage.getItem('octapass:settings')!)).toMatchObject({ showSiteIcons: false });
    fetchMock.mockClear();

    await user.click(screen.getAllByRole('link', { name: /All items/ })[0]!);
    await screen.findByRole('heading', { name: 'All items', level: 1 });
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(iconRequests(fetchMock)).toEqual([]);
    expect(row('GitHub').querySelector('img')).toBeNull();
    expect(row('GitHub')).toHaveTextContent('G');
  });

  it('says so in Arabic', async () => {
    stubServer();
    localStorage.setItem('octapass:settings', JSON.stringify({ language: 'ar' }));
    const service = await createSignedInService();
    renderApp(service, '/settings');
    const appearance = await screen.findByRole('region', { name: 'المظهر' });
    expect(within(appearance).getByRole('switch', { name: 'إظهار أيقونات المواقع' })).toBeChecked();
  });
});
