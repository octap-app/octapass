import type { Item, LoginDetails, VaultService } from '@octapass/vault-client';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createSignedInService, renderApp } from '../../test/renderApp';

const TIMEOUT = { timeout: 8000 };

async function addLogin(service: VaultService, title: string, password: string, urls: string[]): Promise<Item> {
  const [vault] = await service.listVaults();
  return service.saveItem({
    vaultId: vault!.id,
    overview: { schemaVersion: 1, type: 'login', title, urls },
    details: { schemaVersion: 1, username: 'maya', password } as LoginDetails,
  });
}

describe('Health page', () => {
  it('lists the checks, and each opens a page with its items', async () => {
    const service = await createSignedInService();
    const [vault] = await service.listVaults();
    await addLogin(service, 'Old forum', 'Xq7!vP2#mK9$wL4@', ['http://forum.example/login']);
    await service.saveItem({
      vaultId: vault!.id,
      overview: { schemaVersion: 1, type: 'card', title: 'Travel card' },
      details: { schemaVersion: 1, expiry: '01/20' },
    });
    const user = userEvent.setup();
    renderApp(service, '/health');

    const checks = await screen.findByRole('navigation', { name: 'Checks' }, TIMEOUT);
    const insecureTile = within(checks).getByRole('link', { name: /Insecure websites/ });
    expect(insecureTile).toHaveAttribute('href', '/health/insecure');
    expect(within(checks).getByRole('link', { name: /Weak passwords/ })).toHaveAttribute('href', '/health/weak');
    expect(await within(checks).findByRole('link', { name: /Email breach alerts/ }, TIMEOUT)).toHaveTextContent('Off');
    // The overview lists no items, only the checks.
    expect(screen.queryByRole('link', { name: /Old forum/ })).not.toBeInTheDocument();

    await user.click(insecureTile);
    expect(await screen.findByRole('heading', { level: 1, name: 'Insecure websites' })).toBeInTheDocument();
    const insecure = screen.getByRole('list', { name: 'Insecure websites' });
    expect(within(insecure).getByRole('link', { name: /Old forum/ })).toHaveTextContent('http://forum.example/login');

    await user.click(screen.getByRole('button', { name: 'Health' }));
    await user.click(within(await screen.findByRole('navigation', { name: 'Checks' })).getByRole('link', { name: /Expiring soon/ }));
    const expiring = await screen.findByRole('list', { name: 'Expiring soon' });
    expect(within(expiring).getByRole('link', { name: /Travel card/ })).toHaveTextContent('Expired');
  });

  it('says so when a check has nothing to fix, and sends an unknown check back to Health', async () => {
    const service = await createSignedInService();
    const { router } = renderApp(service, '/health/backup-codes');
    expect(await screen.findByText('None found.', undefined, TIMEOUT)).toBeInTheDocument();
    await router.navigate('/health/nonsense');
    await waitFor(() => expect(router.state.location.pathname).toBe('/health'));
  });

  it('dismisses a warning, remembers it, and shows it again', async () => {
    const service = await createSignedInService();
    await addLogin(service, 'Plain site', 'password123', ['https://plain.example']);
    const user = userEvent.setup();
    renderApp(service, '/health/weak');

    const weak = await screen.findByRole('list', { name: 'Weak passwords' }, TIMEOUT);
    const line = within(weak).getByRole('link', { name: /Plain site/ }).closest('li')!;
    await user.click(within(line).getByRole('button', { name: 'Dismiss' }));
    await waitFor(() => expect(screen.queryByRole('link', { name: /Plain site/ })).not.toBeInTheDocument());

    await waitFor(async () => expect((await service.getHealthReport()).dismissed.map((e) => e.title)).toContain('Plain site'), TIMEOUT);
    await user.click(screen.getByRole('button', { name: 'Health' }));
    await user.click(await screen.findByRole('link', { name: /dismissed warnings?/ }, TIMEOUT));
    const dismissed = await screen.findByRole('list', { name: 'Dismissed warnings' }, TIMEOUT);
    const row = within(dismissed).getByText('Plain site').closest('li')!;
    await user.click(within(row).getByRole('button', { name: 'Show again' }));
    await waitFor(() => expect(screen.queryByText('Plain site')).not.toBeInTheDocument(), TIMEOUT);

    await user.click(screen.getByRole('button', { name: 'Health' }));
    await user.click(within(await screen.findByRole('navigation', { name: 'Checks' }, TIMEOUT)).getByRole('link', { name: /Weak passwords/ }));
    expect(await within(await screen.findByRole('list', { name: 'Weak passwords' }, TIMEOUT)).findByRole('link', { name: /Plain site/ }, TIMEOUT)).toBeInTheDocument();
  });

  it('opens the site’s change-password page and saves a generated password', async () => {
    const service = await createSignedInService();
    const item = await addLogin(service, 'Plain site', 'password123', ['https://www.plain.example/login']);
    const user = userEvent.setup();
    renderApp(service, '/health/weak');

    const weak = await screen.findByRole('list', { name: 'Weak passwords' }, TIMEOUT);
    const line = within(weak).getByRole('link', { name: /Plain site/ }).closest('li')!;
    const change = within(line).getByRole('link', { name: 'Change password' });
    expect(change).toHaveAttribute('href', 'https://www.plain.example/.well-known/change-password');
    expect(change).toHaveAttribute('target', '_blank');
    expect(change).toHaveAttribute('rel', 'noopener noreferrer');

    await user.click(change);
    const dialog = await screen.findByRole('dialog', { name: 'Change the password for Plain site', hidden: true });
    await user.click(within(dialog).getByRole('button', { name: 'Save new password', hidden: true }));

    await waitFor(async () => {
      const saved = (await service.getItem(item.id)).details as LoginDetails;
      expect(saved.password).not.toBe('password123');
      expect(saved.passwordHistory?.[0]?.password).toBe('password123');
    }, TIMEOUT);
  });

  it('sends no address until the user reads the disclosure and turns alerts on', async () => {
    const service = await createSignedInService();
    const lookup = vi.spyOn(service, 'lookupEmailBreaches');
    const user = userEvent.setup();
    renderApp(service, '/health/email-breaches');

    expect(await screen.findByRole('heading', { level: 1, name: 'Email breach alerts' }, TIMEOUT)).toBeInTheDocument();
    const toggle = await screen.findByRole('switch', { name: /Check my email addresses/ }, TIMEOUT);
    expect(toggle).not.toBeChecked();
    expect(lookup).not.toHaveBeenCalled();

    await user.click(toggle);
    const dialog = await screen.findByRole('dialog', { name: 'Send your addresses to check them?', hidden: true });
    expect(dialog).toHaveTextContent('Have I Been Pwned');
    expect(dialog).toHaveTextContent('masked email aliases');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel', hidden: true }));
    expect(lookup).not.toHaveBeenCalled();
    expect((await service.getHealthReport()).emailBreaches.enabled).toBe(false);

    await user.click(toggle);
    await user.click(within(dialog).getByRole('button', { name: 'Turn on', hidden: true }));
    await waitFor(() => expect(lookup).toHaveBeenCalledWith('maya@example.com'), TIMEOUT);
  });
});
