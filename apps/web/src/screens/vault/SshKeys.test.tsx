import { screen, waitFor, within } from '@testing-library/react';
import { vi } from 'vitest';
import { downloadBlob } from '../../lib/download';
import { PASSWORD, createSignedInService, renderApp } from '../../test/renderApp';

vi.mock('../../lib/download', () => ({ downloadBlob: vi.fn(() => 'downloaded') }));

const PASSPHRASE = 'correct horse';

function itemId(path: string): string {
  return path.split('/').pop()!;
}

describe('SSH keys', { timeout: 30_000 }, () => {
  it('generates a key, shows it, and saves it after confirming, with or without a passphrase', async () => {
    const service = await createSignedInService();
    const { user, router } = renderApp(service, '/items/all/new?type=sshKey');

    expect(await screen.findByRole('heading', { name: 'New SSH key' }, { timeout: 10_000 })).toBeInTheDocument();
    await user.type(screen.getByLabelText('Title'), 'Laptop key');
    await user.type(screen.getByLabelText('Comment'), 'me@laptop');
    await user.click(screen.getByRole('button', { name: 'Generate' }));
    expect(await screen.findByText('Ed25519')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/items\/all\/[0-9a-f-]{36}$/));
    const id = itemId(router.state.location.pathname);
    expect(await screen.findByRole('heading', { name: 'Laptop key' }, { timeout: 10_000 })).toBeInTheDocument();
    const item = await service.getItem(id);
    const details = item.details as { fingerprint: string; publicKey: string; privateKey: string };
    expect(screen.getAllByText(details.fingerprint).length).toBeGreaterThan(0);
    expect(screen.getByText(`${details.publicKey} me@laptop`)).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN OPENSSH PRIVATE KEY/)).not.toBeInTheDocument();

    // The vault is open, so showing the private key doesn't ask (maintainer decision, 2026-11-06).
    await user.click(screen.getByRole('button', { name: 'Show' }));
    expect(await screen.findByText(/BEGIN OPENSSH PRIVATE KEY/)).toBeInTheDocument();
    expect(screen.queryByRole('dialog', { name: 'Confirm it’s you' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Hide private key' }));
    expect(screen.queryByText(/BEGIN OPENSSH PRIVATE KEY/)).not.toBeInTheDocument();

    // Saving the private key to a file always asks for the master password (plan 16 §6), then
    // writes an OpenSSH file, protected by the passphrase chosen here.
    await user.click(screen.getByRole('button', { name: 'Save private key' }));
    let dialog = await screen.findByRole('dialog', { name: 'Confirm it’s you' });
    await user.type(within(dialog).getByLabelText('Master password'), 'not it');
    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }));
    expect(await within(dialog).findByText('That master password isn’t right.')).toBeInTheDocument();
    await user.clear(within(dialog).getByLabelText('Master password'));
    await user.type(within(dialog).getByLabelText('Master password'), PASSWORD);
    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }));
    dialog = await screen.findByRole('dialog', { name: 'Save the private key' });
    await user.type(within(dialog).getByLabelText('Passphrase for the file'), PASSPHRASE);
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(downloadBlob).toHaveBeenCalled());
    const [blob, name] = vi.mocked(downloadBlob).mock.calls.at(-1)!;
    expect(name).toBe('laptop_key');
    const text = await (blob as Blob).text();
    expect(text).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');
    await expect(service.sshKeys!.read(text)).rejects.toMatchObject({ code: 'sshPassphraseRequired' });
    expect((await service.sshKeys!.read(text, PASSPHRASE)).fingerprint).toBe(details.fingerprint);

    // A public key downloads as one authorized_keys line.
    await user.click(screen.getByRole('button', { name: 'Save public key' }));
    await waitFor(() => expect(downloadBlob).toHaveBeenCalledTimes(2));
    const [publicBlob, publicName] = vi.mocked(downloadBlob).mock.calls.at(-1)!;
    expect(publicName).toBe('laptop_key.pub');
    expect(await (publicBlob as Blob).text()).toBe(`${details.publicKey} me@laptop\n`);
  });

  it('imports a passphrase-protected key from pasted text, asking for the passphrase', async () => {
    const service = await createSignedInService();
    const made = await service.sshKeys!.generate('ed25519', 'locked@test');
    const locked = await service.sshKeys!.write(made.privateKey, 'locked@test', PASSPHRASE);
    const { user, router } = renderApp(service, '/items/all/new?type=sshKey');

    await user.type(await screen.findByLabelText('Title', undefined, { timeout: 10_000 }), 'Locked key');
    await user.click(screen.getByLabelText('Or paste a private key'));
    await user.paste(locked);
    await user.click(screen.getByRole('button', { name: 'Use this key' }));

    let dialog = await screen.findByRole('dialog', { name: 'Enter the key’s passphrase' });
    await user.type(within(dialog).getByLabelText('Passphrase'), 'nope');
    await user.click(within(dialog).getByRole('button', { name: 'Read key' }));
    expect(await within(dialog).findByText('That passphrase doesn’t open this key.')).toBeInTheDocument();
    await user.clear(within(dialog).getByLabelText('Passphrase'));
    await user.type(within(dialog).getByLabelText('Passphrase'), PASSPHRASE);
    await user.click(within(dialog).getByRole('button', { name: 'Read key' }));
    expect(await screen.findByText(made.fingerprint)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/items\/all\/[0-9a-f-]{36}$/));
    expect(await screen.findByRole('heading', { name: 'Locked key' }, { timeout: 10_000 })).toBeInTheDocument();
    // The passphrase is kept for exports, not used to store the key.
    const item = await service.getItem(itemId(router.state.location.pathname));
    const details = item.details as { passphrase: string; privateKey: string };
    expect(details.passphrase).toBe(PASSPHRASE);
    expect(await service.sshKeys!.read(details.privateKey)).toMatchObject({ fingerprint: made.fingerprint });
  });

  it('shows DSA keys but says they can not be used yet', async () => {
    const service = await createSignedInService();
    const [vault] = await service.listVaults();
    const item = await service.saveItem({
      vaultId: vault!.id,
      overview: { schemaVersion: 1, type: 'sshKey', title: 'Old key', subtitle: 'SHA256:old' },
      details: { schemaVersion: 1, publicKey: 'ssh-dss AAAA', keyType: 'ssh-dss', fingerprint: 'SHA256:old', comment: 'old@host' },
    });
    renderApp(service, `/items/all/${item.id}`);
    expect(await screen.findByRole('heading', { name: 'Old key' }, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.getByText(/Octa Pass keeps this key, but can’t use or convert DSA keys yet/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Show' })).not.toBeInTheDocument();
  });
});
