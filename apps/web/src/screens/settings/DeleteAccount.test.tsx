import { screen, waitFor, within } from '@testing-library/react';
import { createSignedInService, EMAIL, PASSWORD, renderApp } from '../../test/renderApp';

describe('delete account', () => {
  it('explains, confirms with email and password, wipes the device and says goodbye', async () => {
    const service = await createSignedInService();
    localStorage.setItem('octapass:settings', '{"theme":"dark"}');
    const { user, router } = renderApp(service, '/settings');

    await user.click(await screen.findByRole('button', { name: 'Delete account' }));
    const dialog = await screen.findByRole('dialog', { name: 'Delete your account' });
    expect(await within(dialog).findByText(/You’re the only owner of Family/)).toBeInTheDocument();
    expect(within(dialog).getByText(/This can’t be undone/)).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'JSON' })).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }));

    const destroy = within(dialog).getByRole('button', { name: 'Delete account permanently' });
    expect(destroy).toBeDisabled();
    await user.type(within(dialog).getByLabelText(`Type ${EMAIL}`), EMAIL);
    await user.type(within(dialog).getByLabelText('Master password'), 'wrong password');
    await user.click(destroy);
    expect(await within(dialog).findByText(/don’t match an account/)).toBeInTheDocument();
    expect(service.getSession().status).toBe('unlocked');

    await user.type(within(dialog).getByLabelText('Master password'), PASSWORD);
    await user.click(destroy);

    await waitFor(() => expect(router.state.location.pathname).toBe('/deleted'));
    expect(await screen.findByRole('heading', { name: 'Your account has been deleted' })).toBeInTheDocument();
    expect(service.getSession().status).toBe('signedOut');
    expect(service.rememberedAccounts()).toEqual([]);
    expect(localStorage.getItem('octapass:settings')).toBeNull();
  });
});
