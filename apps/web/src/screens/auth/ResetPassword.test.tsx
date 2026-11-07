import { screen, waitFor } from '@testing-library/react';
import { DEFAULT_SERVER_URL } from '@octapass/vault-client/mock';
import { createService, EMAIL, PASSWORD, renderApp } from '../../test/renderApp';

const NEW_PASSWORD = 'Copper meadow lantern swift 77';

describe('reset master password', () => {
  it('goes from the lock screen through the emailed code and the recovery code to a new Recovery Kit', async () => {
    const service = await createService();
    const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: EMAIL, password: PASSWORD });
    const { recoveryKit } = await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
    service.lock();
    const { user, router } = renderApp(service, '/lock');

    await user.click(await screen.findByRole('button', { name: 'Forgot your master password?' }));
    expect(await screen.findByRole('heading', { name: 'Reset your master password' })).toBeInTheDocument();
    expect(screen.getByLabelText('Email')).toHaveValue(EMAIL);
    await user.click(screen.getByRole('button', { name: 'Email me a code' }));

    const code = (await screen.findByText(/^\d{6}$/)).textContent!;
    await user.type(screen.getByLabelText('Verification code'), code);
    await user.click(screen.getByRole('button', { name: 'Continue' }));

    expect(await screen.findByRole('heading', { name: 'Choose a new master password' })).toBeInTheDocument();
    await user.type(screen.getByLabelText('Recovery code'), 'AAAAA-BBBBB');
    await user.type(screen.getByLabelText('New master password'), NEW_PASSWORD);
    await user.type(screen.getByLabelText('Confirm master password'), NEW_PASSWORD);
    await user.click(screen.getByRole('button', { name: 'Reset master password' }));
    expect(await screen.findByText(/doesn’t open this account/)).toBeInTheDocument();

    await user.clear(screen.getByLabelText('Recovery code'));
    await user.type(screen.getByLabelText('Recovery code'), recoveryKit.recoveryCode);
    await user.click(screen.getByRole('button', { name: 'Reset master password' }));

    // The reset derives new keys with Argon2 first: longer than the 1 s default under load.
    expect(await screen.findByRole('heading', { name: 'Save your new Recovery Kit' }, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.queryByText(recoveryKit.recoveryCode)).not.toBeInTheDocument();
    expect(screen.getByText(recoveryKit.secretKey)).toBeInTheDocument();
    await user.click(screen.getByLabelText('I’ve saved my new Recovery Kit and destroyed the old one'));
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/items/all'));

    service.lock();
    await expect(service.unlock(PASSWORD)).rejects.toThrow();
    await service.unlock(NEW_PASSWORD);
  });

  it('is offered from the sign-in screen', async () => {
    const service = await createService();
    const { user, router } = renderApp(service, '/welcome');
    await user.click(await screen.findByRole('link', { name: 'Forgot your master password?' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/reset'));
  });
});
