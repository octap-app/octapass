import { installFakeAuthenticator } from '@octapass/vault-client/testing';
import type { LoginDetails, SessionState, VaultService } from '@octapass/vault-client';
import { screen, waitFor, within } from '@testing-library/react';
import { vi } from 'vitest';
import { STORAGE_KEY } from '../app/settings';
import { createSignedInService, renderApp } from '../test/renderApp';
import { unlockCoversReveal } from './identityGate';

vi.mock('./download', () => ({ downloadBlob: vi.fn() }));

afterEach(() => vi.unstubAllGlobals());

async function withLogin() {
  const service = await createSignedInService();
  const [vault] = await service.listVaults();
  const item = await service.saveItem({
    vaultId: vault!.id,
    overview: { schemaVersion: 1, type: 'login', title: 'Shop', urls: ['https://shop.example'] },
    details: { schemaVersion: 1, username: 'maya', password: 'orchid-quartz-77' } as LoginDetails,
  });
  return { service, item };
}

// Plan 03 History, 2026-11-05: the user's own unlock covers reveal and copy, not exports.
describe('reveal and copy after the user opened the vault', { timeout: 30_000 }, () => {
  it('don’t ask again on a device with a lock', async () => {
    installFakeAuthenticator();
    const { service, item } = await withLogin();
    expect(service.getSession().confirmed).toBe(true);
    const { user } = renderApp(service, `/items/all/${item.id}`);
    expect(await screen.findByRole('heading', { name: 'Shop' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /show password/i }));
    expect(await screen.findByText('orchid-quartz-77')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Copy Password' }));
    await waitFor(async () => expect(await navigator.clipboard.readText()).toBe('orchid-quartz-77'));
    expect(screen.queryByRole('dialog', { name: 'Confirm it’s you' })).not.toBeInTheDocument();
  });

  it('don’t ask when opening the app didn’t ask either (maintainer decision, 2026-11-06)', async () => {
    installFakeAuthenticator();
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ requireDeviceAuthOnAppOpen: false }));
    const { service, item } = await withLogin();
    const { user } = renderApp(service, `/items/all/${item.id}`);
    expect(await screen.findByRole('heading', { name: 'Shop' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /show password/i }));
    expect(await screen.findByText('orchid-quartz-77')).toBeInTheDocument();
    expect(screen.queryByRole('dialog', { name: 'Confirm it’s you' })).not.toBeInTheDocument();
  });

  it('don’t cover an export', async () => {
    installFakeAuthenticator();
    const { service } = await withLogin();
    const exportVault = vi.spyOn(service, 'exportVault').mockResolvedValue(new Blob(['{}']));
    const { user } = renderApp(service, '/settings');
    await user.click(await screen.findByRole('button', { name: 'Export' }));
    const dialog = await screen.findByRole('dialog', { name: 'Export your vault' });
    await user.click(within(dialog).getByRole('radio', { name: 'JSON' }));
    await user.click(within(dialog).getByRole('button', { name: 'Export' }));
    expect(await screen.findByRole('dialog', { name: 'Confirm it’s you' })).toBeInTheDocument();
    expect(exportVault).not.toHaveBeenCalled();
  });
});

describe('unlockCoversReveal', () => {
  const service = (session: SessionState) => ({ getSession: () => session }) as unknown as VaultService;
  const opened: SessionState = { status: 'unlocked', email: 'maya@example.com', serverUrl: 'https://example.com' };

  // Maintainer decision, plan 03 History 2026-11-06: an open vault covers reveal and copy, however it opened.
  it('covers any unlocked session, confirmed or not', async () => {
    expect(await unlockCoversReveal(service(opened))).toBe(true);
    expect(await unlockCoversReveal(service({ ...opened, confirmed: true }))).toBe(true);
  });

  it('doesn’t cover a locked session', async () => {
    expect(await unlockCoversReveal(service({ status: 'locked', email: 'maya@example.com' }))).toBe(false);
  });
});
