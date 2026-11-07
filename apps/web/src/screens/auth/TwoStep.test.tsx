import { totpCode, type TotpSetup } from '@octapass/vault-client';
import type { MockVaultService } from '@octapass/vault-client/mock';
import { screen, waitFor } from '@testing-library/react';
import { createSignedInService, EMAIL, PASSWORD, renderApp } from '../../test/renderApp';

async function withTwoStep(): Promise<{ service: MockVaultService; setup: TotpSetup; recoveryCodes: string[]; secretKey: string }> {
  const service = await createSignedInService();
  const secretKey = await service.getSecretKey();
  const setup = await service.twoStep.startTotpSetup(PASSWORD);
  const { recoveryCodes } = await service.twoStep.confirmTotpSetup((await totpCode(setup.otpauthUri)).code);
  await service.signOut();
  return { service, setup, recoveryCodes: recoveryCodes!, secretKey };
}

async function signIn(user: ReturnType<typeof renderApp>['user'], secretKey: string) {
  await user.type(await screen.findByLabelText('Email'), EMAIL);
  await user.type(screen.getByLabelText('Master password'), PASSWORD);
  await user.type(screen.getByLabelText('Secret Key'), secretKey);
  await user.click(screen.getByRole('button', { name: 'Sign in' }));
}

afterEach(() => vi.unstubAllGlobals());

describe('two-step sign-in', () => {
  it('asks for the authenticator code after the password, and signs in with it', async () => {
    const { service, setup, secretKey } = await withTwoStep();
    const { user, router } = renderApp(service, '/welcome');
    await signIn(user, secretKey);

    expect(await screen.findByRole('heading', { name: 'Two-step sign-in' })).toBeInTheDocument();
    const field = screen.getByLabelText('Authenticator code');
    expect(field).toHaveAttribute('autocomplete', 'one-time-code');
    expect(field).toHaveAttribute('inputmode', 'numeric');
    expect(field).toHaveFocus();
    // No security key on this account, so no option for one.
    expect(screen.queryByRole('button', { name: 'Use a security key' })).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByText('Enter the 6-digit code.')).toBeInTheDocument();
    await user.type(field, '000000');
    await user.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByText(/That code isn’t right/)).toBeInTheDocument();
    expect(screen.getByLabelText('Authenticator code')).toHaveValue('');

    await user.type(screen.getByLabelText('Authenticator code'), (await totpCode(setup.otpauthUri)).code);
    await user.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(service.getSession().status).toBe('unlocked'));
    await waitFor(() => expect(router.state.location.pathname).not.toBe('/welcome'));
  });

  it('signs in with a recovery code instead', async () => {
    const { service, recoveryCodes, secretKey } = await withTwoStep();
    const { user } = renderApp(service, '/welcome');
    await signIn(user, secretKey);

    await user.click(await screen.findByRole('button', { name: 'Use a recovery code' }));
    expect(screen.getByText(/one of the recovery codes you saved/)).toBeInTheDocument();
    await user.type(screen.getByLabelText('Recovery code'), recoveryCodes[0]!);
    await user.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(service.getSession().status).toBe('unlocked'));
  });

  it('goes back to the password when the sign-in runs out of tries', async () => {
    const { service, secretKey } = await withTwoStep();
    const { user } = renderApp(service, '/welcome');
    await signIn(user, secretKey);
    for (let i = 0; i < 5; i++) {
      await user.type(await screen.findByLabelText('Authenticator code'), '000000');
      await user.click(screen.getByRole('button', { name: 'Verify' }));
      await screen.findByText(/That code isn’t right/);
    }
    await user.type(screen.getByLabelText('Authenticator code'), '000000');
    await user.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByRole('heading', { name: 'Welcome back' })).toBeInTheDocument();
    expect(screen.getByText(/took too long or had too many tries/)).toBeInTheDocument();
    expect(screen.getByLabelText('Master password')).toHaveValue('');
    expect(service.getSession().status).toBe('signedOut');
  });

  it('starts over from the password on request', async () => {
    const { service, secretKey } = await withTwoStep();
    const { user } = renderApp(service, '/welcome');
    await signIn(user, secretKey);
    await user.click(await screen.findByRole('button', { name: 'Start over' }));
    expect(await screen.findByRole('heading', { name: 'Welcome back' })).toBeInTheDocument();
    expect(screen.getByLabelText('Email')).toHaveValue(EMAIL);
  });

  it('offers a security key when the account has one, and tries again after a dismissed prompt', async () => {
    const id = new Uint8Array([1, 2, 3]);
    const bytes = () => new Uint8Array(8).buffer;
    const get = vi
      .fn()
      .mockRejectedValueOnce(new DOMException('Dismissed', 'NotAllowedError'))
      .mockResolvedValue({ rawId: id.buffer, response: { clientDataJSON: bytes(), authenticatorData: bytes(), signature: bytes() } });
    const create = vi.fn(async () => ({ rawId: id.buffer, response: { clientDataJSON: bytes(), attestationObject: bytes() } }));
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get, create } });
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});

    const service = await createSignedInService();
    const secretKey = await service.getSecretKey();
    const setup = await service.twoStep.startTotpSetup(PASSWORD);
    await service.twoStep.confirmTotpSetup((await totpCode(setup.otpauthUri)).code);
    await service.twoStep.addSecurityKey({ password: PASSWORD, name: 'Blue key' });
    await service.signOut();

    const { user } = renderApp(service, '/welcome');
    await signIn(user, secretKey);
    await user.click(await screen.findByRole('button', { name: 'Use a security key' }));
    expect(await screen.findByText(/security key prompt was closed/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Try the security key again' }));
    await waitFor(() => expect(service.getSession().status).toBe('unlocked'));
    expect(get).toHaveBeenCalledTimes(2);
  });
});
