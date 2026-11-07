// The app tab's settings: the extension's own sections, plus the account's from the web vault.

import { DEFAULT_SERVER_URL, MockVaultService } from '@octapass/vault-client/mock';
import { render, screen } from '@testing-library/react';
import { PopupApp } from './App';
import type { ExtensionApi } from './service';

describe('the app tab’s settings', { timeout: 20_000 }, () => {
  it('has the account’s security and devices, as in the web vault', async () => {
    const service = await MockVaultService.create({ dbName: 'extension-settings', latency: [0, 0], fetch: async () => new Response(''), seed: false });
    const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: 'maya@example.com', password: 'Lantern ruby quiet anchor 42' });
    await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
    chrome.tabs = { query: async () => [] } as unknown as typeof chrome.tabs;
    // Lists are empty; the status calls answer with nothing on.
    const api = new Proxy({}, { get: (_, key) => async () => (String(key).endsWith('Status') ? {} : []) }) as ExtensionApi;
    render(<PopupApp service={service} api={api} view="tab" initialPath="/settings" />);

    expect(await screen.findByRole('heading', { name: 'Settings', level: 1 }, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.getByText('Secret Key')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Change' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'View log' })).toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: 'Devices' })).toBeInTheDocument();
  });
});
