import { installFakeAuthenticator } from '@octapass/vault-client/testing';
import { screen, waitFor } from '@testing-library/react';
import { createSignedInService, renderApp } from '../../test/renderApp';

afterEach(() => vi.unstubAllGlobals());

describe('unlock with this device', { timeout: 30_000 }, () => {
  it('turns on with one prompt where the browser gives the key while creating the passkey', async () => {
    const auth = installFakeAuthenticator({ prfAtCreate: true });
    const service = await createSignedInService();
    const { user } = renderApp(service, '/settings');

    await user.click(await screen.findByRole('switch', { name: /Unlock with your device/ }, { timeout: 5000 }));
    expect(await screen.findAllByText('your device is on for this browser')).not.toHaveLength(0);
    expect(auth.create).toHaveBeenCalledTimes(1);
    expect(auth.get).not.toHaveBeenCalled();
    expect((await service.getUnlockMethods()).deviceUnlockEnabled).toBe(true);
  });

  it('asks for one more click when the browser refuses the second prompt', async () => {
    const auth = installFakeAuthenticator();
    auth.cancelNext();
    const service = await createSignedInService();
    const { user } = renderApp(service, '/settings');

    await user.click(await screen.findByRole('switch', { name: /Unlock with your device/ }, { timeout: 5000 }));
    expect(await screen.findByText(/One more step/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Finish with your device' }));
    expect(await screen.findAllByText('your device is on for this browser')).not.toHaveLength(0);
    expect(screen.queryByText(/One more step/)).not.toBeInTheDocument();
    expect(auth.create).toHaveBeenCalledTimes(1);
  });

  it('shows what the browser said when setting up fails', async () => {
    const auth = installFakeAuthenticator();
    auth.failNext(new DOMException('The authenticator failed.', 'ConstraintError'), 'create');
    const service = await createSignedInService();
    const { user } = renderApp(service, '/settings');

    await user.click(await screen.findByRole('switch', { name: /Unlock with your device/ }, { timeout: 5000 }));
    expect(await screen.findAllByText(/Couldn’t turn on unlock with this device.*Your browser said: ConstraintError: The authenticator failed\./)).not.toHaveLength(0);
    await waitFor(async () => expect((await service.getUnlockMethods()).deviceUnlockEnabled).toBe(false));
  });
});
