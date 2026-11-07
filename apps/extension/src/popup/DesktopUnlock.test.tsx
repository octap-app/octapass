import { VaultError, type VaultService } from '@octapass/vault-client';
import { ServiceProvider } from '@octapass/web/src/app/ServiceContext';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { DesktopStatus } from '../background/desktop';
import { DesktopUnlock } from './DesktopUnlock';
import { ExtensionProvider } from './ExtensionContext';
import type { ExtensionApi } from './service';

function renderWith(status: DesktopStatus, unlock: () => Promise<void> = async () => undefined) {
  const session = { status: 'locked', email: 'maya@example.com', serverUrl: 'https://s.example' };
  const service = { getSession: () => session, onSessionChange: () => () => undefined } as unknown as VaultService;
  const api = { desktopStatus: vi.fn(async () => status), unlockWithDesktop: vi.fn(unlock) } as unknown as ExtensionApi;
  render(
    <ServiceProvider service={service}>
      <ExtensionProvider value={{ api, view: 'tab' }}>
        <DesktopUnlock />
      </ExtensionProvider>
    </ServiceProvider>,
  );
  return api;
}

describe('DesktopUnlock', () => {
  it('offers the app’s unlock when it runs signed in to the same account', async () => {
    renderWith({ appRunning: true, status: 'unlocked', email: 'maya@example.com', label: 'Touch ID' });
    expect(await screen.findByRole('button', { name: 'Unlock with Touch ID in the desktop app' })).toBeInTheDocument();
  });

  it('says so when the app refused this browser, instead of saying nothing', async () => {
    renderWith({ appRunning: false, browserNotTrusted: true });
    expect(await screen.findByText(/doesn’t recognise this browser, so it can’t unlock it\. Unlock with your master password\./)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Which browsers work' })).toHaveAttribute('href', expect.stringContaining('/docs/platforms/desktop/#supported-browsers'));
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('shows the same note when the app refuses the browser at unlock time', async () => {
    renderWith({ appRunning: true, status: 'unlocked', email: 'maya@example.com' }, async () => {
      throw new VaultError('deviceUnlockUnsupported', 'browserNotTrusted');
    });
    await userEvent.click(await screen.findByRole('button', { name: 'Unlock with the desktop app' }));
    expect(await screen.findByText(/doesn’t recognise this browser/)).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('stays out of the way when the app isn’t running', async () => {
    const api = renderWith({ appRunning: false });
    await vi.waitFor(() => expect(api.desktopStatus).toHaveBeenCalled());
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(document.body.textContent).toBe('');
  });
});
