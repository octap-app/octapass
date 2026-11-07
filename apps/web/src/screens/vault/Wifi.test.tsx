import { emptyDraft, wifiDraft, type DeviceWifiNetwork, type WifiPermission, type WifiService, type WifiSighting } from '@octapass/vault-client';
import { DEFAULT_SERVER_URL, MockVaultService } from '@octapass/vault-client/mock';
import { act, screen, waitFor, within } from '@testing-library/react';
import { vi } from 'vitest';
import { EMAIL, PASSWORD, renderApp } from '../../test/renderApp';

let db = 0;

/** A computer's or phone's Wi-Fi that the test sets. */
function fakeWifi(platform: WifiService['platform'] = 'mac') {
  const state = { permission: 'granted' as WifiPermission, connected: undefined as string | undefined, nearby: [] as WifiSighting[], saved: [] as DeviceWifiNetwork[], passwords: {} as Record<string, string> };
  const joins = new Set<(ssid: string) => void>();
  const computer = platform === 'mac' || platform === 'windows' || platform === 'linux';
  const wifi = {
    platform,
    features: { current: true, nearby: platform !== 'ios', savedNetworks: computer, joins: computer },
    permission: vi.fn(async (): Promise<WifiPermission> => state.permission),
    requestPermission: vi.fn(async (): Promise<WifiPermission> => (state.permission = 'granted')),
    currentNetwork: vi.fn(async () => (state.permission === 'granted' ? state.connected : undefined)),
    nearbyNetworks: vi.fn(async () => (state.permission === 'granted' ? state.nearby : [])),
    ...(computer
      ? {
          savedNetworks: vi.fn(async () => state.saved),
          readSavedPasswords: vi.fn(async (ssids: string[]) => ssids.map((ssid) => ({ ...state.saved.find((n) => n.ssid === ssid), ssid, ...(state.passwords[ssid] ? { password: state.passwords[ssid] } : {}) }))),
          onJoin: (cb: (ssid: string) => void) => {
            joins.add(cb);
            return () => joins.delete(cb);
          },
        }
      : {}),
  } satisfies WifiService;
  return { wifi, state, join: (ssid: string) => joins.forEach((cb) => cb(ssid)) };
}

/** A signed-in account with these networks (title, SSID) and the device's Wi-Fi. */
async function withNetworks(networks: [string, string][], wifi?: WifiService) {
  const service = await MockVaultService.create({ dbName: `wifi-${db++}`, latency: [0, 0], seed: false, fetch: async () => new Response('') });
  const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: EMAIL, password: PASSWORD });
  await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
  const [vault] = await service.listVaults();
  for (const [title, ssid] of networks) {
    const draft = wifiDraft({ ssid, security: 'wpa2', password: 'correct-horse' }, vault!.id);
    await service.saveItem({ ...draft, overview: { ...draft.overview, title } });
  }
  if (wifi) Object.assign(service, { wifi });
  return { service, vaultId: vault!.id };
}

function sections() {
  return Array.from(document.querySelectorAll('section[data-section]')).map((section) => [
    section.querySelector('h2 bdi')!.textContent,
    Array.from(section.querySelectorAll('a[data-item-id]')).map((row) => row.querySelector('bdi')!.textContent),
  ]);
}

beforeEach(() => localStorage.clear());

describe('Wi-Fi networks', { timeout: 30_000 }, () => {
  it('have their own category, where the networks in range come first with their marks', async () => {
    const { wifi, state } = fakeWifi();
    state.connected = 'Office';
    state.nearby = [
      { ssid: 'Cafe', signal: 40 },
      { ssid: 'Home-5G', signal: 80 },
    ];
    const { service } = await withNetworks([['Home', 'Home-5G'], ['Office', 'Office'], ['Cafe Lumen', 'Cafe'], ['Beach house', 'Beach']], wifi);
    renderApp(service, '/items/wifi');

    expect(await screen.findByRole('heading', { name: 'Wi-Fi', level: 1 })).toBeInTheDocument();
    await waitFor(() => expect(sections()[0]).toEqual(['In range', ['Office', 'Home', 'Cafe Lumen']]));
    expect(sections()[1]).toEqual(['B', ['Beach house']]);
    const office = screen.getByRole('link', { name: /Office/ });
    expect(within(office).getByText('Connected')).toBeInTheDocument();
    const home = screen.getByRole('link', { name: /^Home/ });
    expect(within(home).getByText('In range')).toBeInTheDocument();
    expect(within(home).getByRole('img', { name: 'Signal 4 of 4' })).toBeInTheDocument();
    expect(within(screen.getByRole('link', { name: /Beach house/ })).queryByText('In range')).toBeNull();
    expect(screen.getByRole('link', { name: /^Wi-Fi\s*\d/ })).toHaveAttribute('href', '/items/wifi');

    // Look again: a new scan.
    await screen.findByRole('button', { name: 'Look for networks again' }).then((button) => button.click());
    await waitFor(() => expect(wifi.nearbyNetworks).toHaveBeenLastCalledWith(true));
  });

  it('ask for location access only when Wi-Fi is open, and mark networks once allowed', async () => {
    const { wifi, state } = fakeWifi('android');
    state.permission = 'prompt';
    state.connected = 'Home-5G';
    const { service } = await withNetworks([['Home', 'Home-5G']], wifi);
    const { user } = renderApp(service, '/items/all');
    await screen.findByRole('link', { name: /Home/ });
    expect(screen.queryByRole('button', { name: 'Allow' })).toBeNull();
    expect(wifi.requestPermission).not.toHaveBeenCalled();

    await user.click(screen.getByRole('link', { name: /^Wi-Fi\s*\d/ }));
    await user.click(await screen.findByRole('button', { name: 'Allow' }));
    expect(wifi.requestPermission).toHaveBeenCalledOnce();
    expect(await within(screen.getByRole('link', { name: /Home/ })).findByText('Connected')).toBeInTheDocument();
  });

  it('are made and shown in their own editor and view, open networks without a password', async () => {
    const { service } = await withNetworks([]);
    const { user } = renderApp(service, '/items/wifi/new?type=wifi');
    await user.type(await screen.findByLabelText('Network name'), 'Cafe Lumen');
    await user.selectOptions(screen.getByLabelText('Security'), 'open');
    expect(screen.queryByLabelText('Password')).toBeNull();
    await user.click(screen.getByRole('switch', { name: 'Has a sign-in page' }));
    await user.click(screen.getByRole('button', { name: 'Save' }));

    // Named after the network when the title is left empty.
    expect(await screen.findByRole('heading', { name: 'Cafe Lumen', level: 1 }, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByText('None. It’s an open network')).toBeInTheDocument();
    expect(screen.getByText('Has a sign-in page')).toBeInTheDocument();
    // The web vault shows the join code (phones have their own sheet).
    await user.click(screen.getByRole('button', { name: 'Show QR code' }));
    expect(screen.getByRole('img', { name: 'QR code to join Cafe Lumen' })).toBeInTheDocument();
  });

  it('check WPA passwords and show Enterprise settings only for Enterprise networks', async () => {
    const { service } = await withNetworks([]);
    const { user } = renderApp(service, '/items/wifi/new?type=wifi');
    await user.type(await screen.findByLabelText('Network name'), 'Home');
    await user.type(screen.getByLabelText('Password'), 'short');
    expect(screen.queryByLabelText('EAP method')).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(screen.getByLabelText('Password')).toHaveAccessibleDescription(/8 to 63 characters/);
    await user.selectOptions(screen.getByLabelText('Security'), 'wpa3Enterprise');
    await user.selectOptions(screen.getByLabelText('EAP method'), 'peap');
    expect(screen.getByLabelText('Inner sign-in (phase 2)')).toBeInTheDocument();
    expect(screen.getByLabelText('Server domain')).toBeInTheDocument();
  });

  it('import the computer’s saved networks after the user chooses them, saying macOS will ask', async () => {
    const { wifi, state } = fakeWifi('mac');
    state.saved = [{ ssid: 'Home-5G', security: 'wpa2Wpa3' }, { ssid: 'Office', security: 'wpa2' }, { ssid: 'Free Cafe', security: 'open' }];
    state.passwords = { Office: 'office-pass' };
    const { service } = await withNetworks([['Home', 'Home-5G']], wifi);
    const { user } = renderApp(service, '/items/wifi');
    await user.click(await screen.findByRole('button', { name: 'Import saved networks' }));

    const dialog = await screen.findByRole('dialog', { name: 'Import Wi-Fi networks' });
    expect(within(dialog).getByText(/macOS asks for an administrator’s name and password/)).toBeInTheDocument();
    expect(await within(dialog).findByRole('checkbox', { name: 'Home-5G' })).not.toBeChecked();
    expect(within(dialog).getByText('Already in Octa Pass')).toBeInTheDocument();
    expect(within(dialog).getByRole('checkbox', { name: 'Office' })).toBeChecked();
    await user.click(within(dialog).getByRole('button', { name: 'Import 2 networks' }));

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(wifi.readSavedPasswords).toHaveBeenCalledWith(['Office', 'Free Cafe']);
    const imported = await Promise.all((await service.listItems({ type: 'wifi' })).map((s) => service.getItem(s.id)));
    expect(imported.map((i) => [i.overview.title, i.details])).toEqual(
      expect.arrayContaining([
        ['Office', { schemaVersion: 1, ssid: 'Office', security: 'wpa2', password: 'office-pass' }],
        ['Free Cafe', { schemaVersion: 1, ssid: 'Free Cafe', security: 'open' }],
      ]),
    );
  });

  it('say on a phone why saved networks can’t be read, and how to bring one in', async () => {
    const { wifi } = fakeWifi('android');
    const { service } = await withNetworks([], wifi);
    const { user } = renderApp(service, '/items/wifi');
    await user.click(await screen.findByRole('button', { name: 'Import saved networks' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add networks from this phone' });
    expect(within(dialog).getByText(/Android doesn’t let apps read saved Wi-Fi passwords.*tap Share/)).toBeInTheDocument();
  });

  it('offer once to save a network the computer joins, filled in with its password', async () => {
    const { wifi, state, join } = fakeWifi('mac');
    state.saved = [{ ssid: 'New Net', security: 'wpa2' }];
    state.passwords = { 'New Net': 'new-net-pass' };
    const { service } = await withNetworks([['Home', 'Home-5G']], wifi);
    const { user, router } = renderApp(service, '/items/all');
    await screen.findByRole('link', { name: /Home/ });

    act(() => join('Home-5G'));
    expect(screen.queryByText(/Save “Home-5G”/)).toBeNull();
    act(() => join('New Net'));
    await user.click(await screen.findByRole('button', { name: 'Save' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/items/wifi/new'));
    expect(await screen.findByLabelText('Network name', {}, { timeout: 5000 })).toHaveValue('New Net');
    expect(screen.getByLabelText('Password')).toHaveValue('new-net-pass');

    // Asked once: not again for the same network.
    act(() => join('New Net'));
    expect(screen.queryByText(/Save “New Net” in Octa Pass\?/)).toBeNull();
  });

  it('never offer a network again after “Never for this network”, and not at all when turned off', async () => {
    const { wifi, join } = fakeWifi('windows');
    const { service } = await withNetworks([], wifi);
    const { user } = renderApp(service, '/items/all');
    await screen.findByRole('heading', { name: 'All items' });
    act(() => join('Neighbour'));
    await user.click(await screen.findByRole('button', { name: 'Never for this network' }));
    act(() => join('Neighbour'));
    expect(screen.queryByText(/Neighbour/)).toBeNull();

    await user.click(screen.getAllByRole('link', { name: 'Settings' })[0]!);
    expect(await screen.findByText('1 network set to Never')).toBeInTheDocument();
    await user.click(screen.getByRole('switch', { name: 'Offer to save new networks' }));
    await user.click(screen.getAllByRole('link', { name: /^All items/ })[0]!);
    act(() => join('Another'));
    expect(screen.queryByText(/Another/)).toBeNull();
  });

  it('older Wi-Fi items (a password with an SSID field) move to the Wi-Fi category on unlock', async () => {
    const { service, vaultId } = await withNetworks([]);
    const draft = emptyDraft('password', vaultId);
    await service.saveItem({ ...draft, overview: { ...draft.overview, title: 'Studio Wi-Fi' }, details: { schemaVersion: 1, password: 'pw-12345', customFields: [{ label: 'SSID', value: 'Studio', hidden: false }] } });
    renderApp(service, '/items/wifi');
    expect(await screen.findByRole('link', { name: /Studio Wi-Fi/ }, { timeout: 5000 })).toBeInTheDocument();
    const [moved] = await service.listItems({ type: 'wifi' });
    expect(moved).toMatchObject({ title: 'Studio Wi-Fi', subtitle: 'Studio' });
  });
});
