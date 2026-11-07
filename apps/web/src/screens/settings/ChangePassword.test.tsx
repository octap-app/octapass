import { screen, waitFor, within } from '@testing-library/react';
import { createSignedInService, PASSWORD, renderApp } from '../../test/renderApp';

const NEW_PASSWORD = 'Copper meadow lantern swift 77';

describe('change master password', () => {
  it('checks the current password, then unlocks with the new one only', async () => {
    const service = await createSignedInService();
    const { user } = renderApp(service, '/settings');

    await user.click(await screen.findByRole('button', { name: 'Change' }));
    const dialog = await screen.findByRole('dialog', { name: 'Change your master password' });
    await user.type(within(dialog).getByLabelText('Current master password'), 'wrong password');
    await user.type(within(dialog).getByLabelText('New master password'), NEW_PASSWORD);
    await user.type(within(dialog).getByLabelText('Confirm master password'), NEW_PASSWORD);
    await user.click(within(dialog).getByRole('button', { name: 'Change password' }));
    expect(await within(dialog).findByText('That isn’t your current master password.')).toBeInTheDocument();

    await user.type(within(dialog).getByLabelText('Current master password'), PASSWORD);
    await user.click(within(dialog).getByRole('button', { name: 'Change password' }));
    // Argon2 for the new password comes first: longer than the 1 s default under load.
    expect((await screen.findAllByText('Master password changed', {}, { timeout: 10_000 })).length).toBeGreaterThan(0);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    service.lock();
    await expect(service.unlock(PASSWORD)).rejects.toThrow();
    await service.unlock(NEW_PASSWORD);
  });
});
