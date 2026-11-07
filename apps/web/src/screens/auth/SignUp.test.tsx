import { screen, waitFor } from '@testing-library/react';
import { createService, EMAIL, PASSWORD, renderApp } from '../../test/renderApp';

describe('create account', () => {
  it('goes from the form through email verification and the Recovery Kit to the vault', async () => {
    const service = await createService();
    const { user, router } = renderApp(service, '/signup');

    await user.type(screen.getByLabelText('Email'), EMAIL);
    await user.type(screen.getByLabelText('Master password'), 'short');
    await user.type(screen.getByLabelText('Confirm master password'), 'short');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(screen.getByLabelText('Master password')).toHaveAccessibleDescription(/stronger master password/);

    await user.clear(screen.getByLabelText('Master password'));
    await user.type(screen.getByLabelText('Master password'), PASSWORD);
    await user.clear(screen.getByLabelText('Confirm master password'));
    await user.type(screen.getByLabelText('Confirm master password'), PASSWORD);
    await user.click(screen.getByRole('button', { name: 'Continue' }));

    const code = (await screen.findByText(/^\d{6}$/)).textContent!;
    await user.type(screen.getByLabelText('Verification code'), '000000');
    await user.click(screen.getByRole('button', { name: 'Verify email' }));
    expect(await screen.findByText(/That code isn’t right/)).toBeInTheDocument();

    await user.clear(screen.getByLabelText('Verification code'));
    await user.type(screen.getByLabelText('Verification code'), code);
    await user.click(screen.getByRole('button', { name: 'Verify email' }));

    expect(await screen.findByRole('heading', { name: 'Save your Recovery Kit' })).toBeInTheDocument();
    expect(screen.getByText(/^OP1-/)).toBeInTheDocument();
    const continueButton = screen.getByRole('button', { name: 'Continue' });
    expect(continueButton).toBeDisabled();
    await user.click(screen.getByLabelText('I’ve saved my Recovery Kit somewhere safe'));
    await user.click(continueButton);

    await user.click(await screen.findByRole('button', { name: 'Open my vault' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/items/all'));
    expect(await screen.findByRole('heading', { name: 'All items' })).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: /GitHub/ })).toBeInTheDocument();
  });
});
