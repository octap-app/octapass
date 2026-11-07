import { screen } from '@testing-library/react';
import { VaultError, type LocalVaultInfo, type LocalVaultService, type SessionState, type VaultService } from '@octapass/vault-client';
import { vi } from 'vitest';
import { createService, createSignedInService, renderApp } from '../../test/renderApp';

const STRONG = 'vexed-kiwi-trumpet-galaxy-oboe';

function vault(overrides: Partial<LocalVaultInfo> = {}): LocalVaultInfo {
  return { id: 'a', name: 'Home', createdAt: '2026-01-01T00:00:00Z', backupDue: false, chipBound: false, current: true, ...overrides };
}

function localService(vaults: LocalVaultInfo[] = [], minScore = 4): LocalVaultService {
  return {
    capabilities: vi.fn(async () => ({ chip: minScore === 3, minScore })),
    list: vi.fn(async () => vaults),
    create: vi.fn(async () => 'AAAAA-BBBBB'),
    restore: vi.fn(async () => undefined),
    switchTo: vi.fn(async () => undefined),
    leave: vi.fn(async () => undefined),
    rename: vi.fn(async () => undefined),
    remove: vi.fn(async () => undefined),
    saveBackup: vi.fn(async () => '/backup'),
    recoveryCode: vi.fn(async () => 'AAAAA-BBBBB'),
    chooseBackupFolder: vi.fn(async () => undefined),
    clearBackupFolder: vi.fn(async () => undefined),
    startTurnOnSync: vi.fn(async () => ({ signupId: 's' })),
    finishTurnOnSync: vi.fn(),
  };
}

/** The mock service with `local`, and a session on a local vault when `session` says so. */
function withLocal(service: VaultService, local: LocalVaultService, session?: Partial<SessionState>): VaultService {
  // One object per session state: React compares what `getSession` returns.
  const shown = session && { ...service.getSession(), ...session };
  return new Proxy(service, {
    get(target, key) {
      if (key === 'local') return local;
      if (key === 'getSession' && shown) return () => shown;
      const value = Reflect.get(target, key);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

describe('local vaults', () => {
  it('stay out of the web vault', async () => {
    renderApp(await createService(), '/welcome');
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Use on this device only' })).not.toBeInTheDocument();
  });

  it('send the web vault back from their own addresses', async () => {
    const { router } = renderApp(await createService(), '/local/new');
    await vi.waitFor(() => expect(router.state.location.pathname).toBe('/welcome'));
  });

  it('are offered on the first screen, with the vaults already here', async () => {
    const local = localService([vault({ current: false })]);
    const { user } = renderApp(withLocal(await createService(), local), '/welcome');
    await user.click(await screen.findByRole('button', { name: 'Open' }));
    expect(local.switchTo).toHaveBeenCalledWith('a');
    expect(screen.getByRole('button', { name: 'Use on this device only' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Restore a backup' })).toBeInTheDocument();
  });

  it('refuse a weak password without a chip, then show the code and offer a first backup', async () => {
    const local = localService();
    const { user } = renderApp(withLocal(await createService(), local), '/local/new');
    await user.type(await screen.findByLabelText('Master password'), 'password123');
    await user.type(screen.getByLabelText('Confirm master password'), 'password123');
    await user.click(screen.getByRole('button', { name: 'Create vault' }));
    expect(await screen.findByText('Choose a stronger master password. Four or more random words work well.')).toBeInTheDocument();
    expect(local.create).not.toHaveBeenCalled();

    await user.clear(screen.getByLabelText('Master password'));
    await user.clear(screen.getByLabelText('Confirm master password'));
    await user.type(screen.getByLabelText('Master password'), STRONG);
    await user.type(screen.getByLabelText('Confirm master password'), STRONG);
    await user.click(screen.getByRole('button', { name: 'Create vault' }));
    expect(await screen.findByText('AAAAA-BBBBB')).toBeInTheDocument();
    expect(local.create).toHaveBeenCalledWith({ name: 'My vault', password: STRONG });

    expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
    await user.click(screen.getByRole('checkbox'));
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await user.click(await screen.findByRole('button', { name: 'Back up now' }));
    expect(local.saveBackup).toHaveBeenCalled();
  });

  it('show a restore that failed', async () => {
    const local = localService();
    vi.mocked(local.restore).mockRejectedValue(new VaultError('invalidBackup'));
    const { user } = renderApp(withLocal(await createService(), local), '/local/restore');
    await user.upload(await screen.findByLabelText('Backup file'), new File([new Uint8Array([1])], 'a.octapass-backup'));
    await user.type(screen.getByLabelText('The backup’s master password'), 'pw');
    await user.click(screen.getByRole('button', { name: 'Restore' }));
    expect(await screen.findByText('That file, password or code didn’t open a backup. Check them and try again.')).toBeInTheDocument();
    expect(local.restore).toHaveBeenCalledWith(expect.any(Uint8Array), { password: 'pw' });
  });

  it('remind about backups on the vault’s screens, until they’re done', async () => {
    const session = { serverUrl: 'local:a', email: 'Home' };
    const days = new Date(Date.now() - 34 * 86_400_000).toISOString();
    const due = localService([vault({ backupDue: true, lastBackupAt: days })]);
    const first = renderApp(withLocal(await createSignedInService(), due, session), '/items/all');
    expect(await screen.findByText(/Last backup 34 days ago/)).toBeInTheDocument();
    first.unmount();

    const folder = localService([vault({ backupDue: false, lastBackupAt: days, backupFolder: '/Backups' })]);
    renderApp(withLocal(await createSignedInService(), folder, session), '/items/all');
    await vi.waitFor(() => expect(folder.list).toHaveBeenCalled());
    expect(screen.queryByText(/Last backup 34 days ago/)).not.toBeInTheDocument();
  });

  it('show “Needs sync” in place of what takes an account', async () => {
    const session = { serverUrl: 'local:a', email: 'Home' };
    renderApp(withLocal(await createSignedInService(), localService([vault()]), session), '/sharing');
    expect(await screen.findByRole('heading', { name: 'Needs sync' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Turn on sync' })).toBeInTheDocument();
  });
});
