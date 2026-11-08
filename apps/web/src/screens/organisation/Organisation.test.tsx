import { VaultError, type SsoRequired } from '@octapass/vault-client';
import { screen, waitFor, within } from '@testing-library/react';
import { createSignedInService, EMAIL, PASSWORD, renderApp } from '../../test/renderApp';

describe('organisations', { timeout: 30_000 }, () => {
  it('shows the rules that come with an invitation before anyone joins', async () => {
    const service = await createSignedInService();
    service.organisations.seedInvitation();
    const { user } = renderApp(service, '/organisation');

    expect(await screen.findByRole('heading', { name: 'Invitation to Acme' })).toBeInTheDocument();
    expect(screen.getByText(/Your personal vault stays private/)).toBeInTheDocument();
    expect(screen.getByText(/Organisation owners can get access to every organisation vault/)).toBeInTheDocument();
    expect(screen.getByText(/You sign in through your organisation’s identity provider/)).toBeInTheDocument();
    expect(screen.getByText(/You need two-step sign-in/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Join' }));
    await waitFor(async () => expect((await service.organisations.getOrganisation()).organisation?.name).toBe('Acme'));
    // Members get no admin sections.
    expect(await screen.findByText('Your role: Member')).toBeInTheDocument();
    expect(screen.queryByRole('radio', { name: 'Groups' })).not.toBeInTheDocument();
  });

  it('seals a vault only to the people a key holder confirmed', async () => {
    const service = await createSignedInService();
    const organisations = service.organisations;
    await organisations.createOrganisation('Acme');
    await organisations.createOrgVault('Finance');
    const group = await organisations.createOrgGroup('Accounts');
    const [vault] = await organisations.listOrgVaults();
    const sam = (await organisations.listOrgMembers()).members.find((member) => !member.isYou)!;
    await organisations.linkOrgVaultGroup(vault!.id, group.id, 'write');
    await organisations.addOrgGroupMember(group.id, sam.accountId);

    const apply = vi.spyOn(organisations, 'applyOrgAccess');
    const { user } = renderApp(service, '/organisation');
    expect(await screen.findByRole('heading', { name: 'Access to review' })).toBeInTheDocument();
    expect(await screen.findByRole('figure', { name: 'Fingerprint' })).toBeInTheDocument();

    const give = screen.getByRole('button', { name: /Give access/ });
    expect(give).toBeDisabled();
    await user.click(screen.getByRole('checkbox', { name: 'I recognise sam@example.com' }));
    await user.click(screen.getByRole('button', { name: 'Give access to 1 person' }));

    await waitFor(() => expect(apply).toHaveBeenCalledOnce());
    expect(apply.mock.calls[0]![0]).toBe(vault!.id);
    expect(apply.mock.calls[0]![1].map((grant) => grant.accountId)).toEqual([sam.accountId]);
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Access to review' })).not.toBeInTheDocument());
  });

  it('won’t seal to someone whose key changed since it was verified', async () => {
    const service = await createSignedInService();
    const organisations = service.organisations;
    await organisations.createOrganisation('Acme');
    await organisations.createOrgVault('Finance');
    vi.spyOn(organisations, 'getOrgAccess').mockResolvedValue([
      {
        vaultId: 'v',
        vaultName: 'Finance',
        shortId: 'abcd1234',
        canApply: true,
        rotate: false,
        grants: [{ accountId: 'a', email: 'sam@example.com', role: 'read', upgrade: false, fingerprint: { digits: '1111', emoji: [] }, verified: false, keyChanged: true }],
      },
    ]);
    renderApp(service, '/organisation');
    expect(await screen.findByRole('checkbox', { name: 'I recognise sam@example.com' })).toBeDisabled();
    expect(screen.getByText(/Their key changed since you verified it/)).toBeInTheDocument();
  });

  it('keeps server-enforced and app-applied policies apart, and won’t require SSO untested', async () => {
    const service = await createSignedInService();
    await service.organisations.createOrganisation('Acme');
    const { user } = renderApp(service, '/organisation');
    await user.click(await screen.findByRole('radio', { name: 'Policies' }));

    expect(await screen.findByRole('heading', { name: 'Enforced by the server' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Applied by the apps' })).toBeInTheDocument();
    expect(screen.getByText(/A modified app can ignore them/)).toBeInTheDocument();

    await user.click(screen.getByRole('switch', { name: 'Require single sign-on' }));
    await user.click(screen.getByRole('button', { name: 'Save policies' }));
    expect((await screen.findAllByText(/identity provider settings don’t work/)).length).toBeGreaterThan(0);
    expect((await service.organisations.getOrganisation()).organisation?.policies.requireSso).toBe(false);
  });

  it('says SSO is for signing in only', async () => {
    const service = await createSignedInService();
    await service.organisations.createOrganisation('Acme');
    const { user } = renderApp(service, '/organisation');
    await user.click(await screen.findByRole('radio', { name: 'Single sign-on' }));
    expect(await screen.findByText('Sign-in only')).toBeInTheDocument();
    expect(screen.getByText(/neither the provider nor this server can open a vault/)).toBeInTheDocument();
    expect(screen.getByText('https://vault.example.com/v1/sso/callback')).toBeInTheDocument();
  });

  it('takes SAML settings, with what to register at the provider', async () => {
    const service = await createSignedInService();
    await service.organisations.createOrganisation('Acme');
    const saveSaml = vi.spyOn(service.organisations, 'saveOrgSaml');
    const { user } = renderApp(service, '/organisation');
    await user.click(await screen.findByRole('radio', { name: 'Single sign-on' }));
    await user.click(await screen.findByRole('radio', { name: 'SAML 2.0' }));
    expect(screen.getByText('https://vault.example.com/v1/sso/saml/mock/acs')).toBeInTheDocument();
    expect(screen.getByText('https://vault.example.com/v1/sso/saml/mock/metadata')).toBeInTheDocument();

    await user.type(screen.getByLabelText('Identity provider entity ID'), 'https://idp.example.com/saml');
    await user.type(screen.getByLabelText('Single sign-on URL (HTTP-Redirect)'), 'https://idp.example.com/sso');
    await user.type(screen.getByLabelText('Signing certificate (PEM)'), 'MIIC');
    await user.click(screen.getByRole('button', { name: 'Save settings' }));
    await waitFor(() => expect(saveSaml).toHaveBeenCalledWith({ entityId: 'https://idp.example.com/saml', ssoUrl: 'https://idp.example.com/sso', certificates: ['MIIC'] }));
    expect(await screen.findByText('Saved: https://idp.example.com/saml')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Test sign-in' })).toBeInTheDocument();
  });

  it('makes a SCIM token, shows it once, and revokes it', async () => {
    const service = await createSignedInService();
    await service.organisations.createOrganisation('Acme');
    const { user } = renderApp(service, '/organisation');
    await user.click(await screen.findByRole('radio', { name: 'Provisioning' }));
    expect(await screen.findByText('https://vault.example.com/v1/scim/v2')).toBeInTheDocument();
    expect(screen.getByText(/It never removes an owner, and it can’t open a vault/)).toBeInTheDocument();

    await user.type(screen.getByLabelText('Token name'), 'Entra ID');
    await user.click(screen.getByRole('button', { name: 'Make a token' }));
    const shown = await screen.findByLabelText('New token');
    expect((shown as HTMLInputElement).value).toMatch(/^opscim_/);
    expect(await screen.findByText('Entra ID')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Done' }));
    expect(screen.queryByLabelText('New token')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Revoke' }));
    await waitFor(() => expect(screen.queryByText('Entra ID')).not.toBeInTheDocument());
  });

  it('asks again before leaving a vault with nobody to manage it', async () => {
    const service = await createSignedInService();
    const organisations = service.organisations;
    await organisations.createOrganisation('Acme');
    const remove = vi.spyOn(organisations, 'removeOrgMember').mockRejectedValueOnce(new VaultError('orgVaultOrphaned'));
    const { user } = renderApp(service, '/organisation');

    await user.click(await screen.findByRole('button', { name: 'Remove sam@example.com' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove sam@example.com?' });
    await user.click(within(dialog).getByRole('button', { name: 'Remove' }));
    expect(await within(dialog).findByText(/stay unreadable to everyone/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(remove).toHaveBeenLastCalledWith(expect.any(String), { orphanVaults: true }));
  });

  it('holds a new master password to the organisation’s length', async () => {
    const service = await createSignedInService();
    const organisations = service.organisations;
    await organisations.createOrganisation('Acme');
    const { organisation } = await organisations.getOrganisation();
    await organisations.setOrgPolicies({ ...organisation!.policies, minPasswordLength: 60 });
    const change = vi.spyOn(service, 'changeMasterPassword');
    const { user } = renderApp(service, '/settings');

    await user.click(await screen.findByRole('button', { name: 'Change' }));
    const dialog = await screen.findByRole('dialog', { name: 'Change your master password' });
    await user.type(within(dialog).getByLabelText('Current master password'), PASSWORD);
    const fresh = 'Marble otter violin thunder 77';
    const [next, again] = within(dialog)
      .getAllByLabelText(/password/i)
      .filter((field) => field.tagName === 'INPUT' && field !== within(dialog).getByLabelText('Current master password'));
    await user.type(next!, fresh);
    await user.type(again!, fresh);
    await user.click(within(dialog).getByRole('button', { name: 'Change password' }));
    expect(await within(dialog).findByText('Your organisation asks for at least 60 characters.')).toBeInTheDocument();
    expect(change).not.toHaveBeenCalled();
  });
});

describe('the SSO sign-in step', { timeout: 30_000 }, () => {
  const sso: SsoRequired = { status: 'ssoRequired', url: 'https://server.example/v1/sso/start/token', orgName: 'Acme' };

  async function waitingForSso() {
    const service = await createSignedInService();
    const secretKey = await service.getSecretKey();
    await service.signOut();
    vi.spyOn(service, 'signIn').mockResolvedValue(sso);
    const finishSso = vi.fn();
    Object.assign(service, { finishSso });
    const rendered = renderApp(service, '/welcome');
    await rendered.user.type(await screen.findByLabelText('Email'), EMAIL);
    await rendered.user.type(screen.getByLabelText('Master password'), PASSWORD);
    await rendered.user.type(screen.getByLabelText('Secret Key'), secretKey);
    await rendered.user.click(screen.getByRole('button', { name: 'Sign in' }));
    await screen.findByRole('heading', { name: 'Sign in with your organisation' });
    return { service, finishSso, ...rendered };
  }

  it('shows the sign-in page’s address and takes its code', async () => {
    const { user, finishSso } = await waitingForSso();
    expect(screen.getByText(/Acme asks you to confirm/)).toBeInTheDocument();
    expect(screen.getByLabelText('Or open this address yourself')).toHaveValue(sso.url);

    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByText('Type the 6-digit code from the sign-in page.')).toBeInTheDocument();
    expect(finishSso).not.toHaveBeenCalled();

    finishSso.mockRejectedValueOnce(new VaultError('ssoPending'));
    await user.type(screen.getByLabelText('Code from the sign-in page'), '123 456');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByText(/hasn’t finished yet/)).toBeInTheDocument();
    expect(finishSso).toHaveBeenCalledWith('123456');
  });

  it('goes on to two-step sign-in when the account has it', async () => {
    const { user, finishSso } = await waitingForSso();
    finishSso.mockResolvedValueOnce({ status: 'twoStepRequired', methods: ['totp'] });
    await user.type(screen.getByLabelText('Code from the sign-in page'), '123456');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Two-step sign-in' })).toBeInTheDocument();
  });

  it('starts over when the sign-in is gone', async () => {
    const { user, finishSso } = await waitingForSso();
    finishSso.mockRejectedValueOnce(new VaultError('twoStepExpired'));
    await user.type(screen.getByLabelText('Code from the sign-in page'), '123456');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument();
  });
});
