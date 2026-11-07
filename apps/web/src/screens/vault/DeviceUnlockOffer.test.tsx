import { Toaster } from '@octapass/ui';
import { VaultError, type UnlockMethods, type VaultService } from '@octapass/vault-client';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ServiceProvider } from '../../app/ServiceContext';
import { DeviceUnlockOffer } from './DeviceUnlockOffer';

const TITLE = 'Use Face ID to unlock Octa Pass?';
const SESSION = { status: 'unlocked', email: 'maya@example.com' } as const;

function fakeService(methods: Partial<UnlockMethods> = {}) {
  const state: UnlockMethods = { deviceUnlockSupported: true, deviceUnlockEnabled: false, label: 'Face ID', platform: 'ios', passwordRequired: false, ...methods };
  const service = {
    offerDeviceUnlock: true,
    getSession: () => SESSION,
    onSessionChange: () => () => {},
    getUnlockMethods: vi.fn(async () => ({ ...state })),
    enableDeviceUnlock: vi.fn(async () => {
      state.deviceUnlockEnabled = true;
    }),
  };
  return service;
}

/** One mount is one unlock of the vault. */
function unlock(service: ReturnType<typeof fakeService>) {
  const user = userEvent.setup();
  const view = render(
    <ServiceProvider service={service as unknown as VaultService}>
      <Toaster>
        <DeviceUnlockOffer />
      </Toaster>
    </ServiceProvider>,
  );
  return { user, unmount: view.unmount };
}

describe('DeviceUnlockOffer', () => {
  it('offers device unlock after sign-in and turns it on with the system check', async () => {
    const service = fakeService();
    const { user, unmount } = unlock(service);
    expect(await screen.findByText(TITLE)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Turn on' }));
    expect(service.enableDeviceUnlock).toHaveBeenCalledTimes(1);
    expect((await screen.findAllByText('Done. Octa Pass will ask for Face ID next time.')).length).toBeGreaterThan(0);
    expect(screen.queryByText(TITLE)).not.toBeInTheDocument();
    unmount();

    // Never again, even if it's turned off later in Settings.
    service.getUnlockMethods.mockResolvedValue({ deviceUnlockSupported: true, deviceUnlockEnabled: false, label: 'Face ID', platform: 'ios', passwordRequired: false });
    unlock(service);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(screen.queryByText(TITLE)).not.toBeInTheDocument();
  });

  it('reminds once after Not now, then never', async () => {
    const service = fakeService();
    const first = unlock(service);
    await first.user.click(await screen.findByRole('button', { name: 'Not now' }));
    expect(screen.queryByText(TITLE)).not.toBeInTheDocument();
    first.unmount();

    const second = unlock(service);
    expect(await screen.findByText(TITLE)).toBeInTheDocument();
    await second.user.click(screen.getByRole('button', { name: 'Not now' }));
    second.unmount();

    unlock(service);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(screen.queryByText(TITLE)).not.toBeInTheDocument();
    expect(service.enableDeviceUnlock).not.toHaveBeenCalled();
  });

  it('treats cancelling the system prompt as Not now', async () => {
    const service = fakeService();
    service.enableDeviceUnlock.mockRejectedValueOnce(new VaultError('deviceUnlockCancelled', 'cancelled'));
    const { user } = unlock(service);
    await user.click(await screen.findByRole('button', { name: 'Turn on' }));
    expect(screen.queryByText(TITLE)).not.toBeInTheDocument();
    expect(localStorage.getItem('octapass.deviceUnlockOffer:maya@example.com')).toBe('declined');
  });

  it('isn’t shown when the device has no lock or it’s already on', async () => {
    for (const methods of [{ deviceUnlockSupported: false }, { deviceUnlockEnabled: true }]) {
      const service = fakeService(methods);
      const { unmount } = unlock(service);
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(service.getUnlockMethods).toHaveBeenCalled();
      expect(screen.queryByText(TITLE)).not.toBeInTheDocument();
      unmount();
    }
  });

  it('names the lock the way each platform does', async () => {
    const cases: [Partial<UnlockMethods>, string][] = [
      [{ label: 'Passcode', platform: 'ios' }, 'Use your passcode to unlock Octa Pass?'],
      [{ label: 'Fingerprint', platform: 'android' }, 'Use your fingerprint, face or screen lock to unlock Octa Pass?'],
      [{ label: 'Windows Hello', platform: 'windows' }, 'Use Windows Hello to unlock Octa Pass?'],
    ];
    for (const [methods, title] of cases) {
      localStorage.clear();
      const { unmount } = unlock(fakeService(methods));
      expect(await screen.findByText(title)).toBeInTheDocument();
      unmount();
    }
  });
});
