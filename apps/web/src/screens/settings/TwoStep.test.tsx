import { totpCode } from '@octapass/vault-client';
import { screen, waitFor, within } from '@testing-library/react';
import { createSignedInService, PASSWORD, renderApp } from '../../test/renderApp';

const section = () => screen.getByRole('region', { name: 'Two-step sign-in' });

async function codeFor(dialog: HTMLElement): Promise<string> {
  const setupKey = within(dialog).getByLabelText('Setup key').textContent!.replace(/\s/g, '');
  return (await totpCode(setupKey)).code;
}

afterEach(() => vi.unstubAllGlobals());

describe('Settings → Two-step sign-in', () => {
  it('turns on with the master password, a QR code and a code, then shows recovery codes once', async () => {
    const service = await createSignedInService();
    const { user } = renderApp(service, '/settings');

    await user.click(await within(await screen.findByRole('region', { name: 'Two-step sign-in' })).findByRole('button', { name: 'Turn on' }));
    let dialog = await screen.findByRole('dialog', { name: 'Turn on two-step sign-in' });
    await user.type(within(dialog).getByLabelText('Master password'), 'wrong');
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }));
    expect(await within(dialog).findByText(/don’t match an account/)).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText('Master password'), PASSWORD);
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }));

    expect(await within(dialog).findByRole('img', { name: 'QR code for your authenticator app' })).toBeInTheDocument();
    const field = within(dialog).getByLabelText('Authenticator code');
    expect(field).toHaveAttribute('autocomplete', 'one-time-code');
    await user.type(field, '000000');
    await user.click(within(dialog).getByRole('button', { name: 'Turn on' }));
    expect(await within(dialog).findByText(/That code isn’t right/)).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText('Authenticator code'), await codeFor(dialog));
    await user.click(within(dialog).getByRole('button', { name: 'Turn on' }));

    const codes = await within(dialog).findByRole('list', { name: 'Recovery codes' });
    expect(within(codes).getAllByRole('listitem')).toHaveLength(10);
    const done = within(dialog).getByRole('button', { name: 'Done' });
    expect(done).toBeDisabled();
    await user.click(within(dialog).getByRole('checkbox', { name: 'I’ve saved these codes' }));
    await user.click(done);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    expect(await within(section()).findByText('Authenticator app')).toBeInTheDocument();
    expect(within(section()).getByText(/10 codes left/)).toBeInTheDocument();
    // No WebAuthn in this browser: keys can't be added here.
    expect(within(section()).queryByRole('button', { name: 'Add security key' })).not.toBeInTheDocument();
    expect(within(section()).getByText(/can’t add security keys/)).toBeInTheDocument();

    // New recovery codes, again after the master password.
    await user.click(within(section()).getByRole('button', { name: 'New codes' }));
    dialog = await screen.findByRole('dialog', { name: 'New recovery codes' });
    await user.type(within(dialog).getByLabelText('Master password'), PASSWORD);
    await user.click(within(dialog).getByRole('button', { name: 'New codes' }));
    expect(within(await within(dialog).findByRole('list', { name: 'Recovery codes' })).getAllByRole('listitem')).toHaveLength(10);
    await user.click(within(dialog).getByRole('checkbox', { name: 'I’ve saved these codes' }));
    await user.click(within(dialog).getByRole('button', { name: 'Done' }));

    // Turn off.
    await user.click(await within(section()).findByRole('button', { name: 'Turn off' }));
    dialog = await screen.findByRole('dialog', { name: 'Turn off two-step sign-in' });
    await user.type(within(dialog).getByLabelText('Master password'), PASSWORD);
    await user.click(within(dialog).getByRole('button', { name: 'Turn off' }));
    expect(await within(section()).findByRole('button', { name: 'Turn on' })).toBeInTheDocument();
    expect((await service.twoStep.getTwoStepStatus()).enabled).toBe(false);
  });

  it('changes the authenticator app without new recovery codes', async () => {
    const service = await createSignedInService();
    const setup = await service.twoStep.startTotpSetup(PASSWORD);
    await service.twoStep.confirmTotpSetup((await totpCode(setup.otpauthUri)).code);
    const { user } = renderApp(service, '/settings');

    await user.click(await within(await screen.findByRole('region', { name: 'Two-step sign-in' })).findByRole('button', { name: 'Change' }));
    const dialog = await screen.findByRole('dialog', { name: 'Change authenticator app' });
    await user.type(within(dialog).getByLabelText('Master password'), PASSWORD);
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }));
    await within(dialog).findByLabelText('Setup key');
    await user.type(within(dialog).getByLabelText('Authenticator code'), await codeFor(dialog));
    await user.click(within(dialog).getByRole('button', { name: 'Use this app' }));
    expect(await screen.findAllByText('Authenticator app changed')).not.toHaveLength(0);
    expect(screen.queryByRole('list', { name: 'Recovery codes' })).not.toBeInTheDocument();
  });

  it('adds and removes a security key where WebAuthn works', async () => {
    const id = new Uint8Array([4, 5, 6]);
    const create = vi.fn(async () => ({ rawId: id.buffer, response: { clientDataJSON: new ArrayBuffer(8), attestationObject: new ArrayBuffer(8) } }));
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create, get: vi.fn() } });
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
    const service = await createSignedInService();
    const setup = await service.twoStep.startTotpSetup(PASSWORD);
    await service.twoStep.confirmTotpSetup((await totpCode(setup.otpauthUri)).code);
    const { user } = renderApp(service, '/settings');

    await user.click(await within(await screen.findByRole('region', { name: 'Two-step sign-in' })).findByRole('button', { name: 'Add security key' }));
    let dialog = await screen.findByRole('dialog', { name: 'Add security key' });
    await user.clear(within(dialog).getByLabelText('Name'));
    await user.type(within(dialog).getByLabelText('Name'), 'Blue key');
    await user.type(within(dialog).getByLabelText('Master password'), PASSWORD);
    await user.click(within(dialog).getByRole('button', { name: 'Add security key' }));
    expect(await screen.findAllByText('Blue key added')).not.toHaveLength(0);
    const keys = await within(section()).findByRole('list', { name: 'Security keys' });
    expect(within(keys).getByText('Blue key')).toBeInTheDocument();

    await user.click(within(keys).getByRole('button', { name: 'Remove Blue key' }));
    dialog = await screen.findByRole('dialog', { name: 'Remove security key' });
    await user.type(within(dialog).getByLabelText('Master password'), PASSWORD);
    await user.click(within(dialog).getByRole('button', { name: 'Remove' }));
    expect(await screen.findAllByText('Blue key removed')).not.toHaveLength(0);
    await waitFor(() => expect(within(section()).queryByRole('list', { name: 'Security keys' })).not.toBeInTheDocument());
  });

  it('asks other devices for a code again', async () => {
    const service = await createSignedInService();
    const setup = await service.twoStep.startTotpSetup(PASSWORD);
    await service.twoStep.confirmTotpSetup((await totpCode(setup.otpauthUri)).code);
    const { user } = renderApp(service, '/settings');
    const row = await within(await screen.findByRole('region', { name: 'Two-step sign-in' })).findByRole('button', { name: 'Ask again' });
    await user.click(row);
    expect(await screen.findAllByText('Other devices will ask for a code at their next sign-in.')).not.toHaveLength(0);
    expect((await service.sharing!.getSecurityLog()).map((e) => e.type)).toContain('trusted-devices-forgotten');
  });

  it('labels the new events in the security log', async () => {
    const service = await createSignedInService();
    const setup = await service.twoStep.startTotpSetup(PASSWORD);
    await service.twoStep.confirmTotpSetup((await totpCode(setup.otpauthUri)).code);
    await service.twoStep.renewRecoveryCodes(PASSWORD);
    renderApp(service, '/settings/security-log');
    expect(await screen.findByText('You turned on two-step sign-in')).toBeInTheDocument();
    expect(screen.getByText('You made new recovery codes')).toBeInTheDocument();
  });
});
