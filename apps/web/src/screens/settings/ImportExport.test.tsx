import { screen, waitFor, within } from '@testing-library/react';
import { vi } from 'vitest';
import { downloadBlob } from '../../lib/download';
import { createSignedInService, PASSWORD, renderApp } from '../../test/renderApp';
import { exportFilename, MIN_EXPORT_PASSWORD } from './ExportDialog';

vi.mock('../../lib/download', () => ({ downloadBlob: vi.fn() }));

describe('Settings → Export', () => {
  it('asks for a fresh confirmation, and a long confirmed password for the encrypted export', async () => {
    const service = await createSignedInService();
    const exportVault = vi.spyOn(service, 'exportVault').mockResolvedValue(new Blob(['OPEX']));
    const { user } = renderApp(service, '/settings');
    await user.click(await screen.findByRole('button', { name: 'Export' }));
    const dialog = await screen.findByRole('dialog', { name: 'Export your vault' });
    expect(within(dialog).getByRole('radio', { name: 'Encrypted' })).toBeChecked();
    const go = () => user.click(within(dialog).getByRole('button', { name: 'Export' }));

    await go();
    expect(await within(dialog).findByText(`Use at least ${MIN_EXPORT_PASSWORD} characters for the file’s password.`)).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText('Password for the file'), 'a long file password');
    await user.type(within(dialog).getByLabelText('Confirm the password'), 'a different one');
    await go();
    expect(await within(dialog).findByText('The two passwords don’t match.')).toBeInTheDocument();
    expect(exportVault).not.toHaveBeenCalled();

    await user.clear(within(dialog).getByLabelText('Confirm the password'));
    await user.type(within(dialog).getByLabelText('Confirm the password'), 'a long file password');
    await go();
    const gate = await screen.findByRole('dialog', { name: 'Confirm it’s you' });
    await user.type(within(gate).getByLabelText('Master password'), PASSWORD);
    await user.click(within(gate).getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(exportVault).toHaveBeenCalledWith('encrypted', { password: 'a long file password' }));
    expect(downloadBlob).toHaveBeenCalledWith(expect.any(Blob), expect.stringMatching(/^octapass-export-\d{4}-\d\d-\d\d\.octapass$/));
    expect(await screen.findAllByText('Export downloaded')).not.toHaveLength(0);
  });

  it('checks the master password before an export when the device has no unlock', async () => {
    const service = await createSignedInService();
    const { user } = renderApp(service, '/settings');
    await user.click(await screen.findByRole('button', { name: 'Export' }));
    const dialog = await screen.findByRole('dialog', { name: 'Export your vault' });
    await user.click(within(dialog).getByRole('radio', { name: 'JSON' }));
    expect(within(dialog).getByText(/This file isn’t encrypted/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Export' }));
    const gate = await screen.findByRole('dialog', { name: 'Confirm it’s you' });
    await user.type(within(gate).getByLabelText('Master password'), 'wrong password');
    await user.click(within(gate).getByRole('button', { name: 'Confirm' }));
    expect(await within(gate).findByText('That master password is wrong.')).toBeInTheDocument();
    expect(downloadBlob).not.toHaveBeenCalledWith(expect.anything(), expect.stringMatching(/\.json$/));
  });

  it('names files by format', () => {
    const day = new Date('2026-10-24T12:00:00Z');
    expect(exportFilename('encrypted', day)).toBe('octapass-export-2026-10-24.octapass');
    expect(exportFilename('cxf', day)).toBe('octapass-export-2026-10-24.cxf.json');
    expect(exportFilename('csv', day)).toBe('octapass-export-2026-10-24.csv');
  });
});

describe('Settings → Import', () => {
  it('offers every source, asks for a password where a file can have one, and imports', async () => {
    const service = await createSignedInService();
    const json = await (await service.exportVault('json')).text();
    const before = (await service.listItems()).length;
    const importFile = vi.spyOn(service, 'importFile');
    const { user } = renderApp(service, '/settings');
    const from = await screen.findByLabelText('Import from');
    expect(within(from).getByRole('option', { name: 'KeePass, KeePassXC' })).toBeInTheDocument();
    expect(within(from).getByRole('option', { name: 'Credential Exchange (CXF)' })).toBeInTheDocument();
    expect(within(from).getByRole('option', { name: '2FAS' })).toBeInTheDocument();
    expect(screen.queryByLabelText('File password')).not.toBeInTheDocument();

    await user.selectOptions(from, 'keepass');
    expect(screen.getByLabelText('File password')).toBeInTheDocument();
    expect(screen.getByLabelText('Key file (optional)')).toBeInTheDocument();

    await user.selectOptions(from, 'octapass');
    expect(screen.queryByLabelText('Key file (optional)')).not.toBeInTheDocument();
    await user.upload(screen.getByLabelText('File'), new File([json], 'octapass-export.json', { type: 'application/json' }));
    await user.click(screen.getByRole('button', { name: 'Import' }));
    const imported = (await service.listItems()).length - before;
    expect(await screen.findByText(`Imported ${imported} items.`)).toBeInTheDocument();
    expect(imported).toBeGreaterThan(0);
    expect(importFile).toHaveBeenCalledWith('octapass', expect.any(File), { password: undefined, keyFile: undefined });
    expect(screen.getByText(/Delete the file you imported/)).toBeInTheDocument();
  });

  it('says what an import of the same file again updated', async () => {
    const service = await createSignedInService();
    vi.spyOn(service, 'importFile').mockResolvedValue({ imported: 1, updated: 2, unchanged: 3, skipped: 0, warnings: [] });
    const { user } = renderApp(service, '/settings');
    await user.selectOptions(await screen.findByLabelText('Import from'), 'firefox');
    await user.upload(screen.getByLabelText('File'), new File(['url,username,password,httpRealm'], 'passwords.csv', { type: 'text/csv' }));
    await user.click(screen.getByRole('button', { name: 'Import' }));
    expect(await screen.findByText('1 new, 2 updated, 3 unchanged.')).toBeInTheDocument();
  });

  it('says so when everything in the file is already in the vaults', async () => {
    const service = await createSignedInService();
    vi.spyOn(service, 'importFile').mockResolvedValue({ imported: 0, unchanged: 25, skipped: 0, warnings: [] });
    const { user } = renderApp(service, '/settings');
    await user.selectOptions(await screen.findByLabelText('Import from'), 'octapass');
    await user.upload(screen.getByLabelText('File'), new File(['{}'], 'octapass-export.json', { type: 'application/json' }));
    await user.click(screen.getByRole('button', { name: 'Import' }));
    expect(await screen.findByText('All 25 items are already in your vaults, so nothing was added.')).toBeInTheDocument();
  });
});
