import type { BackgroundService, BackgroundStatus } from '@octapass/vault-client';
import { screen } from '@testing-library/react';
import { createSignedInService, renderApp } from '../../test/renderApp';

function fakeBackground(start: Partial<BackgroundStatus> = {}): BackgroundService {
  let status: BackgroundStatus = { tray: true, openAtLogin: true, installed: true, platform: 'windows', ...start };
  const change = (patch: Partial<BackgroundStatus>) => {
    status = { ...status, ...patch };
    return Promise.resolve(status);
  };
  return {
    status: () => Promise.resolve(status),
    setTray: (tray) => change({ tray }),
    setOpenAtLogin: (openAtLogin) => change({ openAtLogin }),
  };
}

function withBackground<T extends object>(service: T, background: BackgroundService): T {
  Object.defineProperty(service, 'background', { value: background });
  return service;
}

describe('running in the background, in Settings', { timeout: 30_000 }, () => {
  it('stays out of apps that can’t', async () => {
    renderApp(await createSignedInService(), '/settings');
    expect(await screen.findByRole('heading', { name: 'Security' }, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Running in the background' })).not.toBeInTheDocument();
  });

  it('shows both on by default and turns them off and on', async () => {
    const service = withBackground(await createSignedInService(), fakeBackground());
    const { user } = renderApp(service, '/settings');
    await screen.findByRole('heading', { name: 'Running in the background' }, { timeout: 10_000 });
    const tray = screen.getByRole('switch', { name: /Show in the system tray/ });
    const login = screen.getByRole('switch', { name: /Open when I sign in to this computer/ });
    expect(tray).toHaveAttribute('aria-checked', 'true');
    expect(login).toHaveAttribute('aria-checked', 'true');
    await user.click(tray);
    expect(await screen.findByRole('switch', { name: /Show in the system tray/ })).toHaveAttribute('aria-checked', 'false');
    await user.click(login);
    expect(await screen.findByRole('switch', { name: /Open when I sign in/ })).toHaveAttribute('aria-checked', 'false');
    await user.click(screen.getByRole('switch', { name: /Open when I sign in/ }));
    expect(await screen.findByRole('switch', { name: /Open when I sign in/ })).toHaveAttribute('aria-checked', 'true');
  });

  it('says menu bar on a Mac and asks to move an app opened from a disk image', async () => {
    const service = withBackground(await createSignedInService(), fakeBackground({ platform: 'macos', openAtLogin: false, installed: false }));
    renderApp(service, '/settings');
    expect(await screen.findByRole('switch', { name: /Show in the menu bar/ }, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: /Open when I sign in/ })).toBeDisabled();
    expect(screen.getByText(/move Octa Pass to your Applications folder/)).toBeInTheDocument();
  });

  it('says why something doesn’t work', async () => {
    const service = withBackground(await createSignedInService(), fakeBackground({ error: 'no AppIndicator library' }));
    renderApp(service, '/settings');
    expect(await screen.findByText('Octa Pass couldn’t do this: no AppIndicator library', undefined, { timeout: 10_000 })).toBeInTheDocument();
  });
});
