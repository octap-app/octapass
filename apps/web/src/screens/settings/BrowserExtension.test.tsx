import type { BrowserExtensionService, BrowserExtensionStatus } from '@octapass/vault-client';
import { screen, waitFor, within } from '@testing-library/react';
import { EXTENSION_OFFER_DISMISSED, extensionOffer } from '../../lib/browserExtension';
import { createSignedInService, renderApp } from '../../test/renderApp';

function fakeExtension(start: Partial<BrowserExtensionStatus> = {}) {
  let status: BrowserExtensionStatus = {
    browsers: [
      { name: 'Chrome', store: 'chrome' },
      { name: 'Firefox', store: 'firefox' },
    ],
    connected: [],
    seen: [],
    ...start,
  };
  const extension = {
    status: vi.fn(() => Promise.resolve(status)),
    connect: vi.fn(() => {
      status = { ...status, connected: status.browsers.map((browser) => browser.name) };
      return Promise.resolve(status);
    }),
    disconnect: vi.fn(() => {
      status = { ...status, connected: [] };
      return Promise.resolve(status);
    }),
    get: vi.fn((_browser: string) => Promise.resolve()),
  } satisfies BrowserExtensionService;
  return extension;
}

function withExtension<T extends object>(service: T, extension: BrowserExtensionService): T {
  Object.defineProperty(service, 'browserExtension', { value: extension });
  return service;
}

const offerCard = () => screen.findByRole('complementary', { name: 'Fill passwords in your browser' }, { timeout: 10_000 });

describe('what the desktop app offers', () => {
  it('offers the extension until one has reached the app, and Connect when it can’t any more', () => {
    const browsers = [{ name: 'Edge', store: 'edge' as const }];
    expect(extensionOffer({ browsers, connected: [], seen: [] })).toBe('get');
    expect(extensionOffer({ browsers, connected: ['Edge'], seen: [] })).toBe('get');
    expect(extensionOffer({ browsers: [], connected: [], seen: [] })).toBeUndefined();
    expect(extensionOffer({ browsers, connected: ['Edge'], seen: ['Microsoft Edge'] })).toBeUndefined();
    expect(extensionOffer({ browsers, connected: [], seen: ['Microsoft Edge'] })).toBe('connect');
  });
});

describe('the browser extension in the desktop app', { timeout: 30_000 }, () => {
  beforeEach(() => localStorage.removeItem(EXTENSION_OFFER_DISMISSED));

  it('stays out of apps that can’t', async () => {
    renderApp(await createSignedInService(), '/settings');
    expect(await screen.findByRole('heading', { name: 'Security' }, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Browser extension' })).not.toBeInTheDocument();
  });

  it('offers it in the sidebar for the browsers here, opens each one’s page and connects', async () => {
    const extension = fakeExtension();
    const { user } = renderApp(withExtension(await createSignedInService(), extension), '/items/all');
    const card = await offerCard();
    expect(within(card).getByText('Get the Octa Pass extension for Chrome and Firefox. It unlocks through this app.')).toBeInTheDocument();
    await user.click(within(card).getByRole('button', { name: /Get it for Firefox/ }));
    expect(extension.get).toHaveBeenCalledWith('Firefox');
    await user.click(within(card).getByRole('button', { name: 'Have it already? Connect it' }));
    expect(extension.connect).toHaveBeenCalledTimes(1);
    // Connected, but no extension has come yet: still offered, without Connect.
    await waitFor(() => expect(within(card).queryByRole('button', { name: 'Have it already? Connect it' })).not.toBeInTheDocument());
    expect(within(card).getByRole('button', { name: /Get it for Chrome/ })).toBeInTheDocument();
  });

  it('hides the card on this device once closed, and keeps the links in Settings', async () => {
    const extension = fakeExtension();
    const service = withExtension(await createSignedInService(), extension);
    const first = renderApp(service, '/items/all');
    const card = await offerCard();
    await first.user.click(within(card).getByRole('button', { name: 'Don’t show this again' }));
    expect(screen.queryByRole('complementary', { name: 'Fill passwords in your browser' })).not.toBeInTheDocument();
    expect(localStorage.getItem(EXTENSION_OFFER_DISMISSED)).not.toBeNull();
    first.unmount();

    const { user } = renderApp(service, '/settings');
    expect(await screen.findByRole('heading', { name: 'Browser extension' }, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.queryByRole('complementary', { name: 'Fill passwords in your browser' })).not.toBeInTheDocument();
    expect(screen.getByText('Not connected to any browser')).toBeInTheDocument();
    expect(screen.getByText('No Octa Pass extension has reached this app yet.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Get it for Chrome/ }));
    expect(extension.get).toHaveBeenCalledWith('Chrome');
    await user.click(screen.getByRole('button', { name: 'Connect browser extension' }));
    expect(await screen.findByText('Connected in Chrome and Firefox')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Disconnect browser extension' }));
    expect(await screen.findByText('Not connected to any browser')).toBeInTheDocument();
  });

  it('says to connect when the extension came before but can’t reach the app now', async () => {
    const extension = fakeExtension({ seen: ['Google Chrome'] });
    const { user } = renderApp(withExtension(await createSignedInService(), extension), '/items/all');
    const card = await screen.findByRole('complementary', { name: 'Connect the browser extension' }, { timeout: 10_000 });
    expect(within(card).queryByRole('button', { name: /Get it for/ })).not.toBeInTheDocument();
    await user.click(within(card).getByRole('button', { name: 'Connect browser extension' }));
    await waitFor(() => expect(screen.queryByRole('complementary', { name: 'Connect the browser extension' })).not.toBeInTheDocument());
  });

  it('offers nothing once the extension has reached the app', async () => {
    const extension = fakeExtension({ connected: ['Chrome'], seen: ['Google Chrome'] });
    renderApp(withExtension(await createSignedInService(), extension), '/items/all');
    await screen.findByRole('heading', { name: 'All items' }, { timeout: 10_000 });
    await waitFor(() => expect(extension.status).toHaveBeenCalled());
    expect(screen.queryByRole('complementary', { name: 'Fill passwords in your browser' })).not.toBeInTheDocument();
  });
});
