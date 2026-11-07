import { installFakeAuthenticator } from '@octapass/vault-client/testing';
import { screen, waitFor } from '@testing-library/react';
import { createSignedInService, PASSWORD, renderApp } from '../../test/renderApp';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('lock screen', () => {
  it('unlocks with the master password', async () => {
    const service = await createSignedInService();
    service.lock();
    const { user, router } = renderApp(service, '/items/all');

    await user.type(await screen.findByLabelText('Master password'), 'wrong');
    await user.click(screen.getByRole('button', { name: 'Unlock' }));
    expect(await screen.findByText(/don’t match an account/)).toBeInTheDocument();

    await user.type(screen.getByLabelText('Master password'), PASSWORD);
    await user.click(screen.getByRole('button', { name: 'Unlock' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/items/all'));
  });

  it('starts the device prompt by itself, with the master password one click away', async () => {
    const auth = installFakeAuthenticator();
    const service = await createSignedInService();
    await service.enableDeviceUnlock();
    service.lock();
    auth.cancelNext();
    const { user, router } = renderApp(service, '/items/all');

    expect(await screen.findByText(/The device check didn’t finish.*Your browser said: NotAllowedError/)).toBeInTheDocument();
    expect(auth.get).toHaveBeenCalledTimes(2);
    expect(screen.getByRole('button', { name: 'Use master password' })).toBeVisible();

    await user.click(screen.getByRole('button', { name: /Unlock with/ }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/items/all'));
    expect(service.getSession().status).toBe('unlocked');
  });

  it('asks for the master password when 14 days have passed', async () => {
    installFakeAuthenticator();
    const service = await createSignedInService();
    await service.enableDeviceUnlock();
    service.lock();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + 15 * 86_400_000);
    renderApp(service, '/lock');

    expect(await screen.findByText(/asks for it every 14 days/)).toBeInTheDocument();
    expect(screen.getByLabelText('Master password')).toBeInTheDocument();
  });
});
