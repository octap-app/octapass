import type { StayUnlockedStatus } from '@octapass/vault-client';
import { screen, waitFor, within } from '@testing-library/react';
import { vi } from 'vitest';
import { createSignedInService, renderApp } from '../../test/renderApp';

describe('Settings → Device auth', () => {
  it('shows the rule, not switches, in the web vault', async () => {
    const service = await createSignedInService();
    renderApp(service, '/settings');

    const section = await screen.findByRole('region', { name: 'Device auth' });
    expect(within(section).getByText(/The web vault always asks/)).toBeInTheDocument();
    expect(within(section).queryByRole('switch')).not.toBeInTheDocument();
  });

  // Plan 18, in the desktop app and the extension (hosts with `getStayUnlocked`).
  it('shows "Stay unlocked" with the gates greyed out under it while it’s on', async () => {
    const service = await createSignedInService();
    let status: StayUnlockedStatus = { on: true, available: true, enrolled: true, passwordRequired: false };
    const setStayUnlocked = vi.fn(async (on: boolean) => (status = { ...status, on, enrolled: on }));
    const methods = await service.getUnlockMethods();
    Object.assign(service, {
      setFillGate: async () => undefined,
      getStayUnlocked: async () => status,
      setStayUnlocked,
      // Device unlock set up here, so the gates aren't greyed out for want of a lock.
      getUnlockMethods: async () => ({ ...methods, deviceUnlockSupported: true, deviceUnlockEnabled: true }),
    });
    const { user } = renderApp(service, '/settings');

    const section = await screen.findByRole('region', { name: 'Device auth' });
    const stay = await within(section).findByRole('switch', { name: /Stay unlocked while you’re logged in to this device/ });
    expect(stay).toBeChecked();
    expect(within(section).getByText(/Anyone who can use this device while it’s unlocked/)).toBeInTheDocument();
    expect(within(section).getByRole('switch', { name: /Use device auth when Octa Pass opens/ })).toBeDisabled();
    expect(within(section).getByRole('switch', { name: /Ask on every fill/ })).toBeDisabled();
    expect(within(section).getByText('These apply when “Stay unlocked” is off.')).toBeInTheDocument();
    // No lock timer while it's on.
    expect(screen.getByLabelText('Lock after')).toBeDisabled();

    await user.click(stay);
    expect(setStayUnlocked).toHaveBeenCalledWith(false);
    await waitFor(() => expect(within(section).getByRole('switch', { name: /Use device auth when Octa Pass opens/ })).toBeEnabled());
    expect(screen.getByLabelText('Lock after')).toBeEnabled();
  });

  it('says why it can’t stay unlocked without a keyring', async () => {
    const service = await createSignedInService();
    const status: StayUnlockedStatus = { on: true, available: false, unavailable: 'noKeyring', enrolled: false, passwordRequired: false };
    Object.assign(service, { setFillGate: async () => undefined, getStayUnlocked: async () => status, setStayUnlocked: async () => status });
    renderApp(service, '/settings');
    const section = await screen.findByRole('region', { name: 'Device auth' });
    expect(await within(section).findByText('No system keyring found, so Octa Pass locks as usual.')).toBeInTheDocument();
    expect(within(section).getByRole('switch', { name: /Stay unlocked/ })).toBeDisabled();
  });
});
