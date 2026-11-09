// Health's backup reminder for local vaults (plan 05) and "recovery email breached" with its own
// opt-in (plan 06).
import type { LocalVaultInfo, LocalVaultService, LoginDetails, SessionState, VaultService } from '@octapass/vault-client';
import { screen, waitFor, within } from '@testing-library/react';
import { vi } from 'vitest';
import { createSignedInService, renderApp } from '../../test/renderApp';

const TIMEOUT = { timeout: 15_000 };
const DAY = 86_400_000;
const LOCAL = { serverUrl: 'local:a', email: 'Home' };

function vault(overrides: Partial<LocalVaultInfo> = {}): LocalVaultInfo {
  return { id: 'a', name: 'Home', createdAt: '2026-01-01T00:00:00Z', backupDue: false, chipBound: false, current: true, ...overrides };
}

/** The mock service with these extra members, and a session on a local vault when `session` says so. */
function withExtras(service: VaultService, extras: Partial<Record<keyof VaultService, unknown>>, session?: Partial<SessionState>): VaultService {
  const shown = session && { ...service.getSession(), ...session };
  return new Proxy(service, {
    get(target, key) {
      if (key in extras) return extras[key as keyof VaultService];
      if (key === 'getSession' && shown) return () => shown;
      const value = Reflect.get(target, key);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

function localVaults(vaults: LocalVaultInfo[]): LocalVaultService {
  return { list: vi.fn(async () => vaults) } as unknown as LocalVaultService;
}

describe('the backup reminder in Health', () => {
  it('says how long ago the last backup was, and goes to the backup settings when one is due', async () => {
    const days = new Date(Date.now() - 34 * DAY).toISOString();
    const service = withExtras(await createSignedInService(), { local: localVaults([vault({ backupDue: true, lastBackupAt: days })]) }, LOCAL);
    const { router, user } = renderApp(service, '/health');
    const line = await screen.findByTestId('health-backup', undefined, TIMEOUT);
    expect(line).toHaveTextContent('Last backup 34 days ago');
    expect(line).toHaveTextContent('Back up this vault so you don’t lose it with this device.');
    await user.click(screen.getByRole('button', { name: 'Back up' }));
    await waitFor(() => expect(`${router.state.location.pathname}${router.state.location.hash}`).toBe('/settings#local'));
  });

  it('names the folder when automatic backups keep up, with no nudge', async () => {
    const today = new Date().toISOString();
    const service = withExtras(await createSignedInService(), { local: localVaults([vault({ lastBackupAt: today, backupFolder: '/Backups' })]) }, LOCAL);
    renderApp(service, '/health');
    const line = await screen.findByTestId('health-backup', undefined, TIMEOUT);
    expect(line).toHaveTextContent('Last backup today · Backed up automatically to /Backups');
    expect(line).not.toHaveTextContent('lose it');
  });

  it('works for the extension’s one local vault', async () => {
    const created = new Date(Date.now() - 40 * DAY).toISOString();
    const localBackupInfo = vi.fn(async () => ({ createdAt: created }));
    renderApp(withExtras(await createSignedInService(), { localBackupInfo }, LOCAL), '/health');
    const line = await screen.findByTestId('health-backup', undefined, TIMEOUT);
    expect(line).toHaveTextContent('Not backed up yet');
    expect(line).toHaveTextContent('lose it');
  });

  it('isn’t shown for an account: its server keeps the copy', async () => {
    const localBackupInfo = vi.fn(async () => ({ createdAt: '2020-01-01T00:00:00Z' }));
    renderApp(withExtras(await createSignedInService(), { localBackupInfo }), '/health');
    await screen.findByRole('navigation', { name: 'Checks' }, TIMEOUT);
    expect(screen.queryByTestId('health-backup')).not.toBeInTheDocument();
    expect(localBackupInfo).not.toHaveBeenCalled();
  });
});

describe('recovery email breached', () => {
  it('sends other recovery emails only after its own opt-in, then lists the breached ones', async () => {
    const service = await createSignedInService();
    const lookups: string[] = [];
    const lookupEmailBreaches = service.lookupEmailBreaches.bind(service);
    const spied = withExtras(service, {
      lookupEmailBreaches: async (address: string) => {
        lookups.push(address);
        return lookupEmailBreaches(address);
      },
    });
    const [personal] = await service.listVaults();
    await service.saveItem({
      vaultId: personal!.id,
      overview: { schemaVersion: 1, type: 'login', title: 'Shop', urls: ['https://shop.example'] },
      details: { schemaVersion: 1, username: 'shopper', password: 'Xq7!vP2#mK9$wL4@', recovery: { email: 'old@pwned.example' } } as LoginDetails,
    });

    const { user } = renderApp(spied, '/health/email-breaches');
    await user.click(await screen.findByRole('switch', { name: /Check my email addresses/ }, TIMEOUT));
    await user.click(await screen.findByRole('button', { name: 'Turn on' }));
    await waitFor(() => expect(lookups.length).toBeGreaterThan(0), TIMEOUT);
    expect(lookups).not.toContain('old@pwned.example');

    await user.click(await screen.findByRole('switch', { name: /Also check my other recovery emails/ }, TIMEOUT));
    const dialog = await screen.findByRole('dialog', { name: 'Send your recovery emails too?' });
    expect(dialog).toHaveTextContent('Some may not be yours');
    await user.click(within(dialog).getByRole('button', { name: 'Check them too' }));
    await waitFor(() => expect(lookups).toContain('old@pwned.example'), TIMEOUT);

    await user.click(await screen.findByRole('button', { name: 'Health' }));
    const checks = await screen.findByRole('navigation', { name: 'Checks' }, TIMEOUT);
    await user.click(await within(checks).findByRole('link', { name: /Recovery emails in a breach/ }, TIMEOUT));
    const list = await screen.findByRole('list', { name: 'Recovery emails in a breach' }, TIMEOUT);
    expect(list).toHaveTextContent('old@pwned.example');
    expect(list).toHaveTextContent('In Demo breach');
    expect(list).toHaveTextContent('Resets 1 login');
    // No login for that inbox in the vault, so the row opens nothing.
    expect(within(list).queryByRole('link')).not.toBeInTheDocument();
  });
});
