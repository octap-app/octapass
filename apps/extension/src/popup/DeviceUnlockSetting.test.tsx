import { Toaster } from '@octapass/ui';
import type { UnlockMethods, VaultService } from '@octapass/vault-client';
import { ServiceProvider } from '@octapass/web/src/app/ServiceContext';
import { render, screen } from '@testing-library/react';
import { DeviceUnlockSetting } from './DeviceUnlockSetting';

const METHODS: UnlockMethods = { deviceUnlockSupported: true, deviceUnlockEnabled: false, label: 'Touch ID', platform: 'mac', passwordRequired: false };

function renderIn(scheme: 'moz-extension' | 'chrome-extension') {
  vi.spyOn(chrome.runtime, 'getURL').mockImplementation((path: string) => `${scheme}://3f1a2b3c-0000-4000-8000-000000000000/${path}`);
  const session = { status: 'unlocked', email: 'maya@example.com', serverUrl: 'https://s.example' };
  const service = {
    getSession: () => session,
    onSessionChange: () => () => undefined,
    getUnlockMethods: vi.fn(async () => METHODS),
    enableDeviceUnlock: vi.fn(async () => undefined),
  } as unknown as VaultService;
  render(
    <ServiceProvider service={service}>
      <Toaster>
        <DeviceUnlockSetting />
      </Toaster>
    </ServiceProvider>,
  );
  return service;
}

afterEach(() => vi.restoreAllMocks());

describe('DeviceUnlockSetting', () => {
  it('points to the desktop app in Firefox, which won’t let the extension make a passkey for itself', async () => {
    const service = renderIn('moz-extension');
    expect(await screen.findByText('Unlock with Touch ID')).toBeInTheDocument();
    expect(screen.getByText(/In Firefox, the extension can’t unlock with Touch ID by itself yet\./)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Get the desktop app' })).toHaveAttribute('href', expect.stringContaining('/docs/platforms/desktop/'));
    // No switch, so nothing can start the WebAuthn call Firefox refuses with "The operation is insecure".
    expect(screen.queryByRole('switch')).not.toBeInTheDocument();
    expect(service.enableDeviceUnlock).not.toHaveBeenCalled();
  });

  it('keeps the switch where the browser accepts the extension as the passkey’s site', async () => {
    renderIn('chrome-extension');
    expect(await screen.findByRole('switch', { name: /Unlock with Touch ID/ })).toBeEnabled();
    expect(screen.queryByRole('link', { name: 'Get the desktop app' })).not.toBeInTheDocument();
  });
});
