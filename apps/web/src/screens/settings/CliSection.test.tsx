import type { BackgroundService, BackgroundStatus } from '@octapass/vault-client';
import { screen } from '@testing-library/react';
import { createSignedInService, renderApp } from '../../test/renderApp';

function withPlatform<T extends object>(service: T, platform: BackgroundStatus['platform']): T {
  const status: BackgroundStatus = { tray: true, openAtLogin: false, installed: true, platform };
  const background: BackgroundService = {
    status: () => Promise.resolve(status),
    setTray: () => Promise.resolve(status),
    setOpenAtLogin: () => Promise.resolve(status),
  };
  Object.defineProperty(service, 'background', { value: background });
  return service;
}

describe('the command-line tool in Settings', { timeout: 30_000 }, () => {
  it('stays out of the web vault', async () => {
    renderApp(await createSignedInService(), '/settings');
    expect(await screen.findByRole('heading', { name: 'Security' }, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Command-line tool' })).not.toBeInTheDocument();
  });

  it('gives Windows the PowerShell line', async () => {
    renderApp(withPlatform(await createSignedInService(), 'windows'), '/settings');
    await screen.findByRole('heading', { name: 'Command-line tool' }, { timeout: 10_000 });
    expect(screen.getByText('irm https://octap.app/install.ps1 | iex')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /install command/ })).toBeInTheDocument();
  });

  it('tells Linux the packages have it, and gives the script otherwise', async () => {
    renderApp(withPlatform(await createSignedInService(), 'linux'), '/settings');
    await screen.findByRole('heading', { name: 'Command-line tool' }, { timeout: 10_000 });
    expect(screen.getByText(/install it in \/usr\/bin/)).toBeInTheDocument();
    expect(screen.getByText('curl -fsSL https://octap.app/install.sh | sh')).toBeInTheDocument();
  });
});
