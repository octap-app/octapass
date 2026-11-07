// The popup closes whenever the user switches away to read a code. Reopened, it goes straight back to
// the second step of a sign-in that's still waiting, with "Start over" still there.

import { totpCode, type TotpSetup } from '@octapass/vault-client';
import { DEFAULT_SERVER_URL, MockVaultService } from '@octapass/vault-client/mock';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { PopupApp } from './App';
import type { ExtensionApi } from './service';
import { startPath } from './startPath';

const EMAIL = 'maya@example.com';
const PASSWORD = 'Lantern ruby quiet anchor 42';
const api = {} as ExtensionApi;
let db = 0;

/** An account with two-step sign-in on, and a sign-in on this browser waiting for its second step. */
async function waitingSignIn(): Promise<{ service: MockVaultService; setup: TotpSetup }> {
  const service = await MockVaultService.create({ dbName: `popup-two-step-${db++}`, latency: [0, 0], fetch: async () => new Response(''), seed: false });
  const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: EMAIL, password: PASSWORD });
  const { recoveryKit } = await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
  const setup = await service.twoStep.startTotpSetup(PASSWORD);
  await service.twoStep.confirmTotpSetup((await totpCode(setup.otpauthUri)).code);
  await service.signOut();
  expect(await service.signIn({ serverUrl: DEFAULT_SERVER_URL, email: EMAIL, password: PASSWORD, secretKey: recoveryKit.secretKey })).toMatchObject({ status: 'twoStepRequired' });
  return { service, setup };
}

async function reopen(service: MockVaultService) {
  const initialPath = await startPath(service, null);
  return render(<PopupApp service={service} api={api} view="tab" initialPath={initialPath} />);
}

describe('the app tab and two-step sign-in', { timeout: 20_000 }, () => {
  it('reopens onto the second step and signs in with the code', async () => {
    const { service, setup } = await waitingSignIn();
    expect(await startPath(service, null)).toBe('/signin');
    await reopen(service);
    expect(await screen.findByRole('heading', { name: 'Two-step sign-in' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Use a recovery code' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Use a security key' })).not.toBeInTheDocument();

    await userEvent.type(screen.getByLabelText('Authenticator code'), (await totpCode(setup.otpauthUri)).code);
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(service.getSession().status).toBe('unlocked'));
  });

  it('keeps “Start over”, which drops the waiting sign-in', async () => {
    const { service } = await waitingSignIn();
    const { unmount } = await reopen(service);
    await userEvent.click(await screen.findByRole('button', { name: 'Start over' }));
    expect(await screen.findByRole('heading', { name: 'Welcome back' })).toBeInTheDocument();
    unmount();
    expect(await service.pendingTwoStep()).toBeUndefined();
    expect(await startPath(service, null)).toBe('/');
  });

  it('lands on the password form with a short message when the sign-in was lost', async () => {
    const { service } = await waitingSignIn();
    // What the background answers after a worker restart lost the sign-in.
    vi.spyOn(service, 'pendingTwoStep').mockResolvedValue({ status: 'twoStepExpired' });
    const cancel = vi.spyOn(service, 'cancelTwoStep');
    expect(await startPath(service, null)).toBe('/signin');
    await reopen(service);
    expect(await screen.findByRole('heading', { name: 'Welcome back' })).toBeInTheDocument();
    expect(screen.getByText(/took too long or had too many tries/)).toBeInTheDocument();
    await waitFor(() => expect(cancel).toHaveBeenCalled());
  });

  it('opens as usual when nothing is waiting', async () => {
    const service = await MockVaultService.create({ dbName: `popup-two-step-${db++}`, latency: [0, 0], fetch: async () => new Response('') });
    expect(await startPath(service, null)).toBe('/');
    expect(await startPath(service, '/items/all')).toBe('/items/all');
  });
});
