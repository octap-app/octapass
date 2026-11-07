import { screen, waitFor, within } from '@testing-library/react';
import { createSignedInService, renderApp } from '../../test/renderApp';

describe('devices', { timeout: 30_000 }, () => {
  it('renames this device and signs another one out', async () => {
    const service = await createSignedInService();
    const { user } = renderApp(service, '/settings');
    const section = await screen.findByRole('region', { name: 'Devices' });
    const current = (await within(section).findByText('This browser')).closest('li')!;
    expect(within(current).getByText('This device')).toBeInTheDocument();
    await user.click(within(current).getByRole('button', { name: 'Rename' }));
    await user.clear(within(current).getByLabelText('Device name'));
    await user.type(within(current).getByLabelText('Device name'), 'Kitchen laptop');
    await user.click(within(current).getByRole('button', { name: 'Save' }));
    expect(await within(section).findByText('Kitchen laptop', undefined, { timeout: 5000 })).toBeInTheDocument();

    await user.click(within(section).getByRole('button', { name: 'Sign out Firefox on Windows' }));
    const dialog = await screen.findByRole('dialog', { name: 'Sign out Firefox on Windows?' });
    await user.click(within(dialog).getByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(within(section).queryByText('Firefox on Windows')).not.toBeInTheDocument(), { timeout: 5000 });
    expect(await service.sharing.listDevices()).toHaveLength(2);
  });

  it('lists the security log', async () => {
    const service = await createSignedInService();
    renderApp(service, '/settings/security-log');
    expect(await screen.findByText('leila.rahman@example.com asked for emergency access')).toBeInTheDocument();
    expect(screen.getByText('You added leila.rahman@example.com as a trusted contact')).toBeInTheDocument();
  });
});
