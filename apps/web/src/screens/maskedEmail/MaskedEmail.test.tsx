import { screen, waitFor, within } from '@testing-library/react';
import type { LoginDetails } from '@octapass/vault-client';
import { DEFAULT_SERVER_URL, MockVaultService } from '@octapass/vault-client/mock';
import { EMAIL, PASSWORD, renderApp } from '../../test/renderApp';

let db = 0;

/** A signed-in mock whose network answers like SimpleLogin; nothing leaves the test. */
async function serviceWithProvider() {
  const requests: { url: string; init?: RequestInit }[] = [];
  const fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    requests.push({ url, init });
    if (url.endsWith('/api/aliases/42') && init?.method === 'GET') return new Response(JSON.stringify({ enabled: true }));
    if (url.startsWith('https://app.simplelogin.io/api/alias/random/new')) {
      const host = new URL(url).searchParams.get('hostname');
      return new Response(JSON.stringify({ alias: `${host?.split('.')[0]}.x7k2@simplelogin.com`, id: 42 }), { status: 201 });
    }
    return new Response('');
  };
  const service = await MockVaultService.create({ dbName: `masked-web-${db++}`, latency: [0, 0], fetch });
  const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: EMAIL, password: PASSWORD });
  await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
  return { service, requests };
}

describe('masked email', () => {
  it('connects a provider, keeping the token out of the item list', async () => {
    const { service } = await serviceWithProvider();
    const { user } = renderApp(service, '/masked-email');
    const form = await screen.findByRole('form', { name: 'Connect a provider' });
    expect(within(form).getByRole('link', { name: 'Where to get a token' })).toHaveAttribute('href', 'https://app.simplelogin.io/dashboard/api_key');
    await user.type(within(form).getByLabelText('API token'), 'sl-token');
    await user.click(within(form).getByRole('button', { name: 'Connect' }));

    const providers = screen.getByRole('region', { name: 'Providers' });
    const disconnect = await within(providers).findByRole('button', { name: 'Disconnect' });
    expect(disconnect.parentElement?.parentElement).toHaveTextContent('SimpleLogin');
    expect((await service.listItems()).some((item) => item.type === 'maskedEmailProvider')).toBe(false);
    expect(await service.maskedEmail.listConnections()).toEqual([expect.objectContaining({ provider: 'simplelogin', usableHere: true })]);

    await user.click(disconnect);
    await user.click(within(await screen.findByRole('dialog', { name: 'Disconnect SimpleLogin?' })).getByRole('button', { name: 'Disconnect' }));
    expect(await within(providers).findByText('No provider connected yet.')).toBeInTheDocument();
  });

  it('explains that Firefox Relay and DuckDuckGo work in the extension and apps, not in a web page', async () => {
    const { service } = await serviceWithProvider();
    const { user } = renderApp(service, '/masked-email');
    const form = await screen.findByRole('form', { name: 'Connect a provider' });
    expect(within(form).queryByText(/doesn’t allow calls from web pages/)).not.toBeInTheDocument();
    await user.selectOptions(within(form).getByLabelText('Provider'), 'firefoxRelay');
    expect(within(form).getByText(/Firefox Relay doesn’t allow calls from web pages/)).toBeInTheDocument();
    await user.selectOptions(within(form).getByLabelText('Provider'), 'addy');
    expect(within(form).getByLabelText('Alias domain')).toBeRequired();
  });

  it('makes an alias in the generator', async () => {
    const { service, requests } = await serviceWithProvider();
    await service.maskedEmail.connect({ provider: 'simplelogin', token: 'sl-token' });
    const { user } = renderApp(service, '/generator');
    const maker = await screen.findByRole('form', { name: 'Make a masked email' });
    await user.type(within(maker).getByLabelText('For website'), 'https://www.shop.example/join');
    await user.click(within(maker).getByRole('button', { name: 'Use a masked email' }));
    expect(await within(maker).findByText('shop.x7k2@simplelogin.com')).toBeInTheDocument();
    const call = requests.find((r) => r.url.includes('simplelogin'))!;
    expect(call.url).toBe('https://app.simplelogin.io/api/alias/random/new?hostname=shop.example');
    expect(call.init?.headers).toMatchObject({ Authentication: 'sl-token' });
    expect(call.init?.credentials).toBe('omit');
  });

  it('fills the username and recovery email with a new alias, linked to the provider', async () => {
    const { service } = await serviceWithProvider();
    await service.maskedEmail.connect({ provider: 'simplelogin', token: 'sl-token' });
    const { user, router } = renderApp(service, '/items/all/new?type=login');
    await user.type(await screen.findByLabelText('Title'), 'Shop');
    await user.type(screen.getByLabelText('Website'), 'shop.example');
    const [fromUsername] = await screen.findAllByRole('button', { name: 'Use a masked email' });
    await user.click(fromUsername!);
    await waitFor(() => expect(screen.getByLabelText('Username')).toHaveValue('shop.x7k2@simplelogin.com'));
    expect(screen.getByLabelText('Recovery email')).toHaveValue('shop.x7k2@simplelogin.com');
    expect(screen.getByText('Masked email from SimpleLogin')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/items\/all\/[0-9a-f-]{36}$/));
    const id = router.state.location.pathname.split('/').pop()!;
    expect(((await service.getItem(id)).details as LoginDetails).recovery).toEqual({
      email: 'shop.x7k2@simplelogin.com',
      emailSource: { kind: 'alias', provider: 'simplelogin', aliasId: '42' },
    });
    expect(await screen.findByText('Masked email from SimpleLogin')).toBeInTheDocument();
  });

  it('lists aliases with the logins that use them', async () => {
    const { service } = await serviceWithProvider();
    const [personal] = await service.listVaults();
    await service.saveItem({
      vaultId: personal!.id,
      overview: { schemaVersion: 1, type: 'login', title: 'Shop', urls: ['https://shop.example'] },
      details: { schemaVersion: 1, username: 'shop.x7k2@simplelogin.com', recovery: { email: 'shop.x7k2@simplelogin.com', emailSource: { kind: 'alias', provider: 'simplelogin', aliasId: '42' } } },
    });
    renderApp(service, '/masked-email');
    const aliases = await screen.findByRole('region', { name: 'Aliases in use' });
    expect(await within(aliases).findByText('shop.x7k2@simplelogin.com', {}, { timeout: 5000 })).toBeInTheDocument();
    expect(within(aliases).getByText(/SimpleLogin · Used by 1 login/)).toBeInTheDocument();
    expect(within(aliases).getByRole('link', { name: 'Shop' })).toBeInTheDocument();
  });

  async function linkedLogin(service: MockVaultService) {
    const [personal] = await service.listVaults();
    return service.saveItem({
      vaultId: personal!.id,
      overview: { schemaVersion: 1, type: 'login', title: 'Shop', urls: ['https://shop.example'] },
      details: { schemaVersion: 1, username: 'shop.x7k2@simplelogin.com', recovery: { email: 'shop.x7k2@simplelogin.com', emailSource: { kind: 'alias', provider: 'simplelogin', aliasId: '42' } } },
    });
  }

  it('turns an alias off at its provider', async () => {
    const { service, requests } = await serviceWithProvider();
    await service.maskedEmail.connect({ provider: 'simplelogin', token: 'sl-token' });
    await linkedLogin(service);
    const { user } = renderApp(service, '/masked-email');
    const aliases = await screen.findByRole('region', { name: 'Aliases in use' });
    await user.click(await within(aliases).findByRole('button', { name: 'Turn off shop.x7k2@simplelogin.com' }, { timeout: 5000 }));
    await waitFor(() => expect(requests.map((r) => r.url)).toContain('https://app.simplelogin.io/api/aliases/42/toggle'));
    expect((await screen.findAllByText('Masked email turned off. Mail to it no longer reaches you.')).length).toBeGreaterThan(0);
  });

  it('deletes an alias after asking, and the login keeps the address without the link', async () => {
    const { service, requests } = await serviceWithProvider();
    await service.maskedEmail.connect({ provider: 'simplelogin', token: 'sl-token' });
    const login = await linkedLogin(service);
    const { user } = renderApp(service, '/masked-email');
    const aliases = await screen.findByRole('region', { name: 'Aliases in use' });
    await user.click(await within(aliases).findByRole('button', { name: 'Delete shop.x7k2@simplelogin.com' }, { timeout: 5000 }));
    const dialog = await screen.findByRole('dialog', { name: 'Delete this masked email?' });
    expect(requests.some((r) => r.init?.method === 'DELETE')).toBe(false);
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(requests.some((r) => r.init?.method === 'DELETE' && r.url.endsWith('/api/aliases/42'))).toBe(true));
    await waitFor(async () => expect(((await service.getItem(login.id)).details as LoginDetails).recovery).toEqual({ email: 'shop.x7k2@simplelogin.com' }));
    expect(((await service.getItem(login.id)).details as LoginDetails).username).toBe('shop.x7k2@simplelogin.com');
    await within(aliases).findByText('None of your logins use a masked email yet.', {}, { timeout: 5000 });
  });

  it('asks to connect the provider before an alias can be changed', async () => {
    const { service } = await serviceWithProvider();
    await linkedLogin(service);
    renderApp(service, '/masked-email');
    const aliases = await screen.findByRole('region', { name: 'Aliases in use' });
    expect(await within(aliases).findByText('Connect SimpleLogin above to turn this off or delete it.', {}, { timeout: 5000 })).toBeInTheDocument();
    expect(within(aliases).queryByRole('button', { name: /Turn off/ })).not.toBeInTheDocument();
  });

  it('links a recovery email to an identity and back', async () => {
    const { service } = await serviceWithProvider();
    const { user } = renderApp(service, '/items/all/new?type=login');
    await user.type(await screen.findByLabelText('Title'), 'Forum');
    await user.click(await screen.findByRole('button', { name: `Use ${EMAIL}` }));
    expect(screen.getByLabelText('Recovery email')).toHaveValue(EMAIL);
    expect(screen.getByText('From the identity “Personal details”')).toBeInTheDocument();
    await user.type(screen.getByLabelText('Recovery email'), 'x');
    expect(screen.queryByText('From the identity “Personal details”')).not.toBeInTheDocument();
  });
});
