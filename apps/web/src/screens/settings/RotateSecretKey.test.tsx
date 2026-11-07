import { screen, waitFor, within } from '@testing-library/react';
import { createSignedInService, PASSWORD, renderApp } from '../../test/renderApp';

// The mock runs Argon2id for the reauth and again for the new key.
const slow = { timeout: 20_000 };

describe('replacing the Secret Key', { timeout: 60_000 }, () => {
  async function open() {
    const service = await createSignedInService();
    const before = await service.getSecretKey();
    const { user } = renderApp(service, '/settings');
    await user.click(await screen.findByRole('button', { name: 'Replace' }));
    const dialog = await screen.findByRole('dialog', { name: 'Replace your Secret Key' });
    return { service, before, user, dialog };
  }

  it('checks the password, then keeps the new kit up until the user saved it', async () => {
    const { service, before, user, dialog } = await open();
    await user.type(within(dialog).getByLabelText('Master password'), 'wrong password');
    await user.click(within(dialog).getByRole('button', { name: 'Replace Secret Key' }));
    expect(await within(dialog).findByText('That isn’t your current master password.', {}, slow)).toBeInTheDocument();

    await user.type(within(dialog).getByLabelText('Master password'), PASSWORD);
    await user.click(within(dialog).getByRole('button', { name: 'Replace Secret Key' }));
    const kit = await screen.findByRole('dialog', { name: 'Save your new Recovery Kit' }, slow);
    const after = await service.getSecretKey();
    expect(after).not.toBe(before);
    expect(within(kit).getByText(after)).toBeInTheDocument();
    expect(within(kit).getByText('Your recovery code hasn’t changed. Keep using the one from your previous Recovery Kit.')).toBeInTheDocument();

    const done = within(kit).getByRole('button', { name: 'Continue' });
    expect(done).toBeDisabled();
    await user.click(within(kit).getByRole('checkbox'));
    await user.click(done);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument(), slow);

    // The same password still unlocks this device.
    service.lock();
    await service.unlock(PASSWORD);
  });

  it('shows a new recovery code when one was asked for', async () => {
    const { user, dialog } = await open();
    await user.type(within(dialog).getByLabelText('Master password'), PASSWORD);
    await user.click(within(dialog).getByRole('checkbox'));
    await user.click(within(dialog).getByRole('button', { name: 'Replace Secret Key' }));
    const kit = await screen.findByRole('dialog', { name: 'Save your new Recovery Kit' }, slow);
    expect(within(kit).queryByText('Your recovery code hasn’t changed. Keep using the one from your previous Recovery Kit.')).not.toBeInTheDocument();
  });
});
