import type { SshAgentService, SshAgentStatus, SshHomeService } from '@octapass/vault-client';
import { screen, waitFor, within } from '@testing-library/react';
import { vi } from 'vitest';
import { PASSWORD, createSignedInService, renderApp } from '../../test/renderApp';

function fakeAgent(start: Partial<SshAgentStatus> = {}): SshAgentService {
  let status: SshAgentStatus = {
    enabled: false,
    running: false,
    endpoint: '/home/ada/.octapass/agent.sock',
    configConnected: false,
    keys: [],
    windows: false,
    ...start,
  };
  const change = (patch: Partial<SshAgentStatus>) => {
    status = { ...status, ...patch };
    return Promise.resolve(status);
  };
  return {
    status: () => Promise.resolve(status),
    setEnabled: (enabled) => change({ enabled, running: enabled, keys: enabled ? [{ title: 'Laptop', fingerprint: 'SHA256:abc', keyType: 'ssh-ed25519' }] : [] }),
    connectConfig: () => change({ configConnected: true }),
    disconnectConfig: () => change({ configConnected: false }),
  };
}

function withSsh<T extends object>(service: T, parts: { sshAgent?: SshAgentService; sshHome?: SshHomeService }): T {
  for (const [key, value] of Object.entries(parts)) Object.defineProperty(service, key, { value });
  return service;
}

describe('the SSH agent in Settings', { timeout: 30_000 }, () => {
  it('stays out of apps without one', async () => {
    const service = await createSignedInService();
    renderApp(service, '/settings');
    expect(await screen.findByRole('heading', { name: 'Security' }, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'SSH agent' })).not.toBeInTheDocument();
  });

  it('turns on, shows what it offers and connects ~/.ssh/config', async () => {
    const service = withSsh(await createSignedInService(), { sshAgent: fakeAgent() });
    const { user } = renderApp(service, '/settings');
    await screen.findByRole('heading', { name: 'SSH agent' }, { timeout: 10_000 });
    expect(screen.queryByText('Agent address')).not.toBeInTheDocument();
    await user.click(screen.getByRole('switch', { name: /Run the SSH agent/ }));
    expect(await screen.findByText('Agent address')).toBeInTheDocument();
    expect(screen.getByText('/home/ada/.octapass/agent.sock')).toBeInTheDocument();
    expect(screen.getByText('1 key offered')).toBeInTheDocument();
    expect(screen.getByText(/Laptop \(Ed25519\)/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Use it for SSH' }));
    expect(await screen.findByText('SSH uses Octa Pass (set in ~/.ssh/config)')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Stop using it' }));
    expect(await screen.findByRole('button', { name: 'Use it for SSH' })).toBeInTheDocument();
  });

  it('says why the agent could not start', async () => {
    const service = withSsh(await createSignedInService(), { sshAgent: fakeAgent({ enabled: true, error: 'pipe in use' }) });
    renderApp(service, '/settings');
    expect(await screen.findByText('The agent couldn’t start: pipe in use', undefined, { timeout: 10_000 })).toBeInTheDocument();
  });
});

describe('~/.ssh in the key editor and view', { timeout: 30_000 }, () => {
  it('reads a key from ~/.ssh, asking for its passphrase, and offers it to the agent', async () => {
    const base = await createSignedInService();
    const made = await base.sshKeys!.generate('ed25519', 'home@laptop');
    const home: SshHomeService = {
      scan: () => Promise.resolve([{ name: 'id_work', protected: true, fingerprint: made.fingerprint }]),
      read: vi.fn((_name: string, passphrase?: string) => (passphrase === 'secret' ? Promise.resolve(made) : Promise.reject(new Error('wrong')))),
      write: vi.fn(() => Promise.resolve('/home/ada/.ssh/id_work')),
    };
    const service = withSsh(base, { sshHome: home, sshAgent: fakeAgent() });
    const { user } = renderApp(service, '/items/all/new?type=sshKey');
    const chosen = await screen.findByRole('button', { name: 'id_work' }, { timeout: 10_000 });
    expect(screen.getByText(made.fingerprint)).toBeInTheDocument();
    await user.click(chosen);
    const dialog = await screen.findByRole('dialog', { name: 'Enter the key’s passphrase' });
    await user.type(within(dialog).getByLabelText('Passphrase'), 'secret');
    await user.click(within(dialog).getByRole('button', { name: 'Read key' }));
    await waitFor(() => expect(home.read).toHaveBeenCalledWith('id_work', 'secret'));
    expect(await screen.findByLabelText('Offer this key through the SSH agent')).toBeChecked();
  });

  it('writes a key to ~/.ssh only after confirming, and never replaces a file unasked', async () => {
    const base = await createSignedInService();
    const made = await base.sshKeys!.generate('ed25519', 'me@laptop');
    const vault = (await base.listVaults())[0]!;
    const { VaultError } = await import('@octapass/vault-client');
    const write = vi.fn((_id: string, _name: string, _passphrase?: string, replace?: boolean) => (replace ? Promise.resolve('/home/ada/.ssh/laptop') : Promise.reject(new VaultError('alreadyExists'))));
    const home: SshHomeService = { scan: () => Promise.resolve([]), read: () => Promise.reject(new Error('unused')), write };
    const service = withSsh(base, { sshHome: home });
    const item = await service.saveItem({
      vaultId: vault.id,
      overview: { schemaVersion: 1, type: 'sshKey', title: 'Laptop' },
      details: { schemaVersion: 1, privateKey: made.privateKey, publicKey: made.publicKey, keyType: made.keyType, fingerprint: made.fingerprint, comment: made.comment },
    } as never);
    const { user } = renderApp(service, `/items/all/${item.id}`);
    await user.click(await screen.findByRole('button', { name: 'Write to ~/.ssh' }, { timeout: 10_000 }));
    let dialog = await screen.findByRole('dialog', { name: 'Confirm it’s you' });
    expect(write).not.toHaveBeenCalled();
    await user.type(within(dialog).getByLabelText('Master password'), PASSWORD);
    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }));
    dialog = await screen.findByRole('dialog', { name: 'Write the key to ~/.ssh' });
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    const replace = await within(dialog).findByLabelText('Replace the file that’s already there');
    expect(write).toHaveBeenCalledTimes(1);
    await user.click(replace);
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(write).toHaveBeenLastCalledWith(item.id, expect.any(String), undefined, true));
    expect(screen.queryByText(made.privateKey)).not.toBeInTheDocument();
  });
});
