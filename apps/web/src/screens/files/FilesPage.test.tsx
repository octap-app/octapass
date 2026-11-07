import { fireEvent, screen, waitFor } from '@testing-library/react';
import { SAFE_ROOT, type FilesService, type LocalFile, type SafeEntry, type SafeSummary } from '@octapass/vault-client';
import type { MockVaultService } from '@octapass/vault-client/mock';
import { createSignedInService, renderApp } from '../../test/renderApp';

function local(name: string, more: Partial<LocalFile> = {}): LocalFile {
  return { path: `/home/ada/${name}`, name, size: 2048, folder: false, encrypted: false, storage: 'copyOnWrite', guarantee: 'bestEffort', ...more };
}

const safe: SafeSummary = { itemId: 's1', vaultId: 'v', safeId: 'x', name: 'Taxes', sync: true, open: false, mounted: false, canMount: false, warnings: [] };
const entry: SafeEntry = { id: 'e1', parent: SAFE_ROOT, name: 'return.pdf', folder: false, size: 4096, modified: 0 };

/** The Rust side, faked: what the page sends, and paths dropped from outside. */
function fakeFiles(service: MockVaultService, overrides: Partial<FilesService> = {}) {
  let drop: (paths: string[]) => void = () => {};
  let request: (r: { action: 'encrypt' | 'decrypt'; paths: string[] }) => void = () => {};
  const files = {
    describe: vi.fn(async (paths: string[]) => paths.map((path) => local(path.split('/').pop()!, { encrypted: path.endsWith('.age') }))),
    choose: vi.fn(async () => ['/home/ada/picked.txt']),
    onDrop: vi.fn(async (handler: (paths: string[]) => void) => {
      drop = handler;
      return () => {};
    }),
    onRequest: vi.fn(async (handler: typeof request) => {
      request = handler;
      return () => {};
    }),
    encrypt: vi.fn(async (input: Parameters<FilesService['encrypt']>[0]) => input.paths.map((path) => ({ source: path, output: `${path}.age`, bytes: 1, skipped: [], ...(input.shredOriginals ? { shredded: 'bestEffort' as const, storage: 'copyOnWrite' as const } : {}) }))),
    decrypt: vi.fn(async (input: { paths: string[] }) => input.paths.map((path) => ({ source: path, output: path.replace(/\.age$/, ''), bytes: 1, skipped: [] }))),
    findRecipient: vi.fn(async (email: string) => ({ email, recipient: 'age1abc', fingerprint: '1234 5678', verified: false })),
    ownRecipient: vi.fn(async () => 'age1mine'),
    menuStatus: vi.fn(async () => [{ surface: 'finder' as const, installed: false }]),
    installMenu: vi.fn(async () => {}),
    removeMenu: vi.fn(async () => {}),
    listSafes: vi.fn(async () => [safe]),
    createSafe: vi.fn(async (input: { name: string; sync: boolean }) => ({ ...safe, name: input.name, sync: input.sync })),
    setSafeSync: vi.fn(async () => safe),
    syncSafe: vi.fn(async () => ({ downloaded: 0, uploaded: 0, deleted: 0, conflicts: ['a (conflict).pdf'], tooBig: [] })),
    safeEntries: vi.fn(async () => [entry]),
    safeAddFiles: vi.fn(async () => {}),
    safeCreateFolder: vi.fn(async () => entry),
    safeRename: vi.fn(async () => {}),
    safeDelete: vi.fn(async () => {}),
    safeSaveFile: vi.fn(async () => true),
    safeLock: vi.fn(async () => {}),
    safeMount: vi.fn(async () => '/home/ada/Octa Pass Safe/Taxes'),
    deleteSafe: vi.fn(async () => {}),
    lockProblems: vi.fn(async (): Promise<string[]> => []),
    ...overrides,
  } satisfies FilesService;
  Object.defineProperty(service, 'files', { value: files });
  return { files, drop: (paths: string[]) => drop(paths), request: (r: Parameters<typeof request>[0]) => request(r) };
}

async function open(service: MockVaultService) {
  renderApp(service, '/files');
  await screen.findByText('Drop files or folders here');
}

vi.setConfig({ testTimeout: 30_000 });

describe('FilesPage', () => {
  it('encrypts dropped files for yourself', async () => {
    const service = await createSignedInService();
    const { files, drop } = fakeFiles(service);
    await open(service);
    await waitFor(() => expect(files.onDrop).toHaveBeenCalled());
    drop(['/home/ada/plan.txt']);
    expect(await screen.findByText('plan.txt')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Encrypt' }));
    await waitFor(() => expect(files.encrypt).toHaveBeenCalledWith({ paths: ['/home/ada/plan.txt'], target: { kind: 'yourself' }, armor: false, shredOriginals: false }));
    expect(await screen.findByText(/plan\.txt → plan\.txt\.age/)).toBeInTheDocument();
  });

  it('takes paths from a right-click menu', async () => {
    const service = await createSignedInService();
    const { files, request } = fakeFiles(service);
    await open(service);
    await waitFor(() => expect(files.onRequest).toHaveBeenCalled());
    request({ action: 'decrypt', paths: ['/home/ada/plan.txt.age'] });
    expect(await screen.findByText('plan.txt.age')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Decrypt' }));
    await waitFor(() => expect(files.decrypt).toHaveBeenCalled());
  });

  it('warns before encrypting for an unverified key', async () => {
    const service = await createSignedInService();
    const { files, drop } = fakeFiles(service);
    await open(service);
    await waitFor(() => expect(files.onDrop).toHaveBeenCalled());
    drop(['/home/ada/plan.txt']);
    await screen.findByText('plan.txt');
    fireEvent.click(screen.getByRole('radio', { name: 'People' }));
    expect(screen.getByRole('button', { name: 'Encrypt' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Octa Pass email or age1… key'), { target: { value: 'grace@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(await screen.findByText(/hasn’t been compared.*1234 5678/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Encrypt' }));
    await waitFor(() => expect(files.encrypt).toHaveBeenCalledWith(expect.objectContaining({ target: { kind: 'people', to: ['grace@example.com'], yourself: true } })));
  });

  it('wants a passphrase twice, the same', async () => {
    const service = await createSignedInService();
    const { files, drop } = fakeFiles(service);
    await open(service);
    await waitFor(() => expect(files.onDrop).toHaveBeenCalled());
    drop(['/home/ada/plan.txt']);
    await screen.findByText('plan.txt');
    fireEvent.click(screen.getByRole('radio', { name: 'Passphrase' }));
    fireEvent.change(screen.getByLabelText('Passphrase', { selector: 'input[type=password]' }), { target: { value: 'one' } });
    fireEvent.change(screen.getByLabelText('Passphrase again'), { target: { value: 'two' } });
    expect(screen.getByText('The two passphrases don’t match.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Encrypt' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Passphrase again'), { target: { value: 'one' } });
    fireEvent.click(screen.getByRole('button', { name: 'Encrypt' }));
    await waitFor(() => expect(files.encrypt).toHaveBeenCalledWith(expect.objectContaining({ target: { kind: 'passphrase', passphrase: 'one' } })));
  });

  it('is honest about deleting originals on copy-on-write and solid-state drives', async () => {
    const service = await createSignedInService();
    const { files, drop } = fakeFiles(service);
    await open(service);
    await waitFor(() => expect(files.onDrop).toHaveBeenCalled());
    drop(['/home/ada/plan.txt']);
    await screen.findByText('plan.txt');
    fireEvent.click(screen.getByRole('switch', { name: 'Delete the originals' }));
    expect(screen.getByText(/copy-on-write/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Encrypt' }));
    await waitFor(() => expect(files.encrypt).toHaveBeenCalledWith(expect.objectContaining({ shredOriginals: true })));
    expect(await screen.findByText(/Original deleted\..*copy-on-write/)).toBeInTheDocument();
    expect(screen.queryByText('Original overwritten and deleted.')).not.toBeInTheDocument();
  });

  it('asks for a passphrase only when a file needs one', async () => {
    const service = await createSignedInService();
    const { VaultError } = await import('@octapass/vault-client');
    const decrypt = vi.fn(async (input: { paths: string[]; passphrase?: string }) => {
      if (!input.passphrase) throw new VaultError('passwordRequired');
      return [{ source: input.paths[0]!, output: '/home/ada/plan.txt', bytes: 1, skipped: [] }];
    });
    const { files, drop } = fakeFiles(service, { decrypt });
    await open(service);
    await waitFor(() => expect(files.onDrop).toHaveBeenCalled());
    drop(['/home/ada/plan.txt.age']);
    await screen.findByText('plan.txt.age');
    fireEvent.click(screen.getByRole('button', { name: 'Decrypt' }));
    const field = await screen.findByLabelText('These files need their passphrase');
    fireEvent.change(field, { target: { value: 'secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'Decrypt' }));
    await waitFor(() => expect(decrypt).toHaveBeenLastCalledWith({ paths: ['/home/ada/plan.txt.age'], passphrase: 'secret' }));
  });

  it('browses a Safe, and drops go into it', async () => {
    const service = await createSignedInService();
    const { files, drop } = fakeFiles(service);
    await open(service);
    await waitFor(() => expect(files.onDrop).toHaveBeenCalled());
    fireEvent.click(await screen.findByRole('button', { name: 'Open' }));
    expect(await screen.findByText('return.pdf')).toBeInTheDocument();
    expect(files.safeEntries).toHaveBeenCalledWith({ itemId: 's1', folder: SAFE_ROOT });

    drop(['/home/ada/new.pdf']);
    await waitFor(() => expect(files.safeAddFiles).toHaveBeenCalledWith({ itemId: 's1', folder: SAFE_ROOT, paths: ['/home/ada/new.pdf'] }));

    // Fetched on opening, and on asking.
    await waitFor(() => expect(files.syncSafe).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole('button', { name: 'Sync now' }));
    await waitFor(() => expect(files.syncSafe).toHaveBeenCalledTimes(2));
    expect(files.syncSafe).toHaveBeenLastCalledWith('s1');

    fireEvent.click(screen.getByRole('button', { name: 'Save a decrypted copy' }));
    await waitFor(() => expect(files.safeSaveFile).toHaveBeenCalledWith({ itemId: 's1', id: 'e1' }));

    fireEvent.click(screen.getByRole('button', { name: 'Lock' }));
    await waitFor(() => expect(files.safeLock).toHaveBeenCalledWith('s1'));
    expect(await screen.findByText('Drop files or folders here')).toBeInTheDocument();
  });

  it('deletes a Safe only after its name is typed', async () => {
    const service = await createSignedInService();
    const { files } = fakeFiles(service);
    await open(service);
    fireEvent.click(await screen.findByRole('button', { name: 'Open' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Delete Safe' }));
    const confirm = screen.getAllByRole('button', { name: 'Delete Safe' }).at(-1)!;
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Type Taxes to confirm'), { target: { value: 'Taxes' } });
    fireEvent.click(confirm);
    await waitFor(() => expect(files.deleteSafe).toHaveBeenCalledWith('s1'));
    expect(await screen.findByText('Drop files or folders here')).toBeInTheDocument();
  });

  it('shows a Safe as a folder where the system can', async () => {
    const service = await createSignedInService();
    const { files } = fakeFiles(service, { listSafes: vi.fn(async () => [{ ...safe, canMount: true }]) });
    await open(service);
    fireEvent.click(await screen.findByRole('button', { name: 'Open' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Show as a folder' }));
    await waitFor(() => expect(files.safeMount).toHaveBeenCalledWith('s1'));
    expect((await screen.findAllByText(/Octa Pass Safe\/Taxes until it locks/)).length).toBeGreaterThan(0);
  });

  it('says what went wrong at the last lock', async () => {
    const service = await createSignedInService();
    fakeFiles(service, { lockProblems: vi.fn(async () => ['report.docx is open in Word, so it stayed']) });
    await open(service);
    expect(await screen.findByText('report.docx is open in Word, so it stayed')).toBeInTheDocument();
  });

  it('shows a Safe’s warnings', async () => {
    const service = await createSignedInService();
    const { files } = fakeFiles(service, { listSafes: vi.fn(async () => [{ ...safe, warnings: [{ kind: 'rolledBack' as const, object: 'x' }] }]) });
    await open(service);
    await waitFor(() => expect(files.listSafes).toHaveBeenCalled());
    fireEvent.click(await screen.findByRole('button', { name: 'Open' }));
    expect(await screen.findByText(/may have been rolled back/)).toBeInTheDocument();
  });

  it('makes a Safe with sync off unless asked', async () => {
    const service = await createSignedInService();
    const { files } = fakeFiles(service);
    await open(service);
    fireEvent.click(await screen.findByRole('button', { name: 'New Safe' }));
    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'Photos' } });
    fireEvent.click(screen.getByRole('button', { name: 'Make Safe' }));
    await waitFor(() => expect(files.createSafe).toHaveBeenCalledWith({ name: 'Photos', sync: false }));
  });

  it('adds the right-click menu', async () => {
    const service = await createSignedInService();
    const { files } = fakeFiles(service);
    await open(service);
    fireEvent.click(await screen.findByRole('switch', { name: 'In the right-click menu' }));
    await waitFor(() => expect(files.installMenu).toHaveBeenCalled());
  });

  it('is left out of the sidebar where the host has no files', async () => {
    const service = await createSignedInService();
    renderApp(service, '/');
    await screen.findAllByRole('link', { name: /Generator/ });
    expect(screen.queryByRole('link', { name: 'Files' })).not.toBeInTheDocument();
  });
});
