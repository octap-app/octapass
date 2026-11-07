// The app tab's "This site": logins in match order, Fill, and the vault's sidebar around it.

import { emptyDraft, type ItemSummary, type ItemType } from '@octapass/vault-client';
import { DEFAULT_SERVER_URL, MockVaultService } from '@octapass/vault-client/mock';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { PopupApp } from './App';
import type { ExtensionApi } from './service';

let db = 0;

async function withItems(items: [ItemType, string, string?][]): Promise<MockVaultService> {
  const service = await MockVaultService.create({ dbName: `popup-list-${db++}`, latency: [0, 0], fetch: async () => new Response(''), seed: false });
  const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: 'maya@example.com', password: 'Lantern ruby quiet anchor 42' });
  await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
  const [vault] = await service.listVaults();
  for (const [type, title, url] of items) {
    const draft = emptyDraft(type, vault!.id);
    await service.saveItem({ ...draft, overview: { ...draft.overview, title, ...(url ? { urls: [url] } : {}) } });
  }
  return service;
}

const tabs = (url = 'https://login.example.com/') =>
  ({
    get: async (id: number) => ({ id, url, windowId: 1, index: 0 }),
    update: vi.fn(async (id: number) => ({ id, windowId: 1 })),
  }) as unknown as typeof chrome.tabs;

/** The rows of "This site", which is labelled with the page's host. */
const titles = (host = 'login.example.com') =>
  within(screen.getByRole('list', { name: host }))
    .getAllByRole('listitem')
    .map((row) => row.querySelector('bdi')!.textContent);

describe('the app tab', { timeout: 20_000 }, () => {
  afterEach(() => localStorage.clear());

  it('opens on “This site”, with the rest of the vault in the sidebar', async () => {
    const service = await withItems([['login', 'Zoom']]);
    const api = { siteItems: async () => [], siteOtherLogins: async () => [], desktopStatus: async () => ({ appRunning: true }) } as unknown as ExtensionApi;
    chrome.tabs = tabs();
    render(<PopupApp service={service} api={api} view="tab" tabId={7} initialPath="/" />);
    expect(await screen.findByRole('heading', { name: 'This site' }, { timeout: 5000 })).toBeInTheDocument();
    const nav = screen.getByRole('navigation', { name: 'Vault' });
    for (const name of ['This site', 'All items', 'Generator', 'Settings']) expect(within(nav).getByRole('link', { name: new RegExp(name) })).toBeInTheDocument();
    expect(await screen.findByText('No logins for login.example.com', undefined, { timeout: 10_000 })).toBeInTheDocument();
  });

  it('fills a login and goes back to the page', async () => {
    const service = await withItems([]);
    const row: ItemSummary = { id: 'own', vaultId: 'v', type: 'login', title: 'Own login', favorite: false, hasTotp: false, hasPasskey: false, createdAt: '', updatedAt: '' };
    const api = { siteItems: async () => [row], siteOtherLogins: async () => [], fillTab: vi.fn(async () => true) } as unknown as ExtensionApi;
    chrome.tabs = tabs();
    render(<PopupApp service={service} api={api} view="tab" tabId={7} initialPath="/items/site" />);
    await userEvent.click(await screen.findByRole('button', { name: 'Fill Own login' }, { timeout: 5000 }));
    expect(api.fillTab).toHaveBeenCalledWith(7, 'own');
    await waitFor(() => expect(chrome.tabs.update).toHaveBeenCalledWith(7, { active: true }));
  });

  it('keeps “This site” in the order the matcher gives, best match first', async () => {
    const service = await withItems([]);
    const row = (id: string, title: string): ItemSummary => ({ id, vaultId: 'v', type: 'login', title, favorite: false, hasTotp: false, hasPasskey: false, createdAt: '', updatedAt: '' });
    const api = { siteItems: async () => [row('b', 'Zeta exact match'), row('a', 'Alpha other subdomain')], siteOtherLogins: async () => [] } as unknown as ExtensionApi;
    chrome.tabs = tabs();
    render(<PopupApp service={service} api={api} view="tab" tabId={7} initialPath="/items/site" />);
    await screen.findByText('Zeta exact match', undefined, { timeout: 5000 });
    expect(titles()).toEqual(['Zeta exact match', 'Alpha other subdomain']);
    expect(screen.queryByRole('button', { name: 'Sort and group' })).not.toBeInTheDocument();
    expect(screen.queryByText(/Logins for other parts/)).not.toBeInTheDocument();
  });

  it('folds logins for other parts of the site away, fills one when picked, and offers to add the page to it', async () => {
    const service = await withItems([]);
    const row = (id: string, title: string, subtitle?: string): ItemSummary => ({ id, vaultId: 'v', type: 'login', title, ...(subtitle ? { subtitle } : {}), favorite: false, hasTotp: false, hasPasskey: false, createdAt: '', updatedAt: '' });
    const api = {
      siteItems: async () => [row('own', 'Own login')],
      siteOtherLogins: async () => [{ item: row('shop', 'Shop', 'maya'), host: 'shop.example.com', site: 'example.com' }],
      fillTab: vi.fn(async () => true),
      fillOtherLogin: vi.fn(async () => ({ offer: { id: 'offer-1', host: 'login.example.com', title: 'Shop' } })),
      answerWebsite: vi.fn(async () => true),
    } as unknown as ExtensionApi;
    chrome.tabs = tabs();
    render(<PopupApp service={service} api={api} view="tab" tabId={7} initialPath="/items/site" />);
    const summary = await screen.findByText('Logins for other parts of example.com', undefined, { timeout: 5000 });
    expect(summary.closest('details')!.open).toBe(false);
    await userEvent.click(summary);
    expect(screen.getByText('shop.example.com')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Fill Shop' }));
    expect(api.fillOtherLogin).toHaveBeenCalledWith(7, 'shop');
    expect(api.fillTab).not.toHaveBeenCalled();
    const offer = await screen.findByRole('group', { name: 'Add login.example.com to this login?' });
    await userEvent.click(within(offer).getByRole('button', { name: 'Add' }));
    expect(api.answerWebsite).toHaveBeenCalledWith(7, 'offer-1', 'add');
    expect((await screen.findAllByText('Added login.example.com to Shop')).length).toBeGreaterThan(0);
  });
});
