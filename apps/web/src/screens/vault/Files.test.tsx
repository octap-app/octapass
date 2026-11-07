import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import type { AttachmentService, DocumentDetails, NativeFiles, PickedFile } from '@octapass/vault-client';
import type { MockVaultService } from '@octapass/vault-client/mock';
import { createSignedInService, renderApp } from '../../test/renderApp';

/**
 * The phone apps' file handling, faked over the mock: picked files are only descriptions, and
 * attaching one adds what the "phone" holds for it.
 */
function phoneFiles(service: MockVaultService, contents: Record<string, string>) {
  const native = {
    sources: ['files', 'photos'],
    pick: vi.fn(async (): Promise<PickedFile[]> => Object.entries(contents).map(([name, text], i) => ({ id: `p${i}`, name, type: 'application/pdf', size: text.length }))),
    attachPicked: vi.fn((itemId: string, file: PickedFile) => service.addAttachment(itemId, new Blob([contents[file.name]!], { type: file.type }), file.name)),
    discardPicked: vi.fn(async () => {}),
    open: vi.fn(async () => {}),
  } satisfies NativeFiles;
  const attachments: AttachmentService = {
    addAttachment: () => Promise.reject(new Error('phones never send file bytes')),
    getAttachment: () => Promise.reject(new Error('phones never receive file bytes')),
    removeAttachment: (itemId, attachmentId) => service.removeAttachment(itemId, attachmentId),
    getStorageUsage: () => service.getStorageUsage(),
    native,
  };
  Object.defineProperty(service, 'attachments', { value: attachments });
  return native;
}

/** Captures what the page hands to the browser's download. */
function captureDownloads() {
  const blobs: Blob[] = [];
  const names: string[] = [];
  URL.createObjectURL = vi.fn((blob: Blob) => {
    blobs.push(blob);
    return 'blob:test';
  });
  URL.revokeObjectURL = vi.fn();
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    names.push(this.download);
  });
  return { blobs, names };
}

/**
 * Saving an item and then uploading its files takes several seconds on a busy machine (a CI runner,
 * or a Mac building in parallel): the lookups that wait for it, and those tests, get room for it.
 */
const SLOW = 15_000;

describe('files', () => {
  afterEach(() => vi.restoreAllMocks());

  it('creates a document with its file, downloads it decrypted and removes it', async () => {
    const service = await createSignedInService();
    const { user, router } = renderApp(service, '/items/all/new?type=document');

    await user.type(await screen.findByLabelText('Title'), 'Lease');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Choose the file for this document.')).toBeInTheDocument();

    await user.upload(screen.getByTestId('file-input'), new File(['contract'], 'lease.pdf', { type: 'application/pdf' }));
    expect(screen.getByText('lease.pdf')).toBeInTheDocument();
    expect(screen.getByText('8 bytes · PDF · Uploaded when you save')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/items\/all\/[0-9a-f-]{36}$/));
    expect(await screen.findByRole('heading', { name: 'Lease' }, { timeout: SLOW })).toBeInTheDocument();
    expect(await screen.findByText('8 bytes · PDF')).toBeInTheDocument();

    const downloads = captureDownloads();
    await user.click(screen.getByRole('button', { name: 'Download lease.pdf' }));
    await waitFor(() => expect(downloads.names).toEqual(['lease.pdf']));
    expect(await downloads.blobs[0]!.text()).toBe('contract');

    await user.click(screen.getByRole('button', { name: 'Remove lease.pdf' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove “lease.pdf”?' });
    await user.click(within(dialog).getByRole('button', { name: 'Remove file' }));
    expect(await screen.findByText('No files attached.')).toBeInTheDocument();
  }, 3 * SLOW);

  it('attaches dropped files to any item at once', async () => {
    const service = await createSignedInService();
    const [login] = await service.listItems({ type: 'login' });
    renderApp(service, `/items/all/${login!.id}`);

    const section = (await screen.findByRole('heading', { name: 'Files' })).closest('section')!;
    expect(within(section).getByText('No files attached.')).toBeInTheDocument();
    const file = new File(['png'], 'scan.png', { type: 'image/png' });
    fireEvent.dragEnter(section, { dataTransfer: { types: ['Files'], files: [file] } });
    expect(within(section).getByText('Drop to attach')).toBeInTheDocument();
    fireEvent.drop(section, { dataTransfer: { types: ['Files'], files: [file] } });

    // The row shows while it uploads; the download button once it's attached.
    expect(await within(section).findByRole('button', { name: 'Download scan.png' }, { timeout: SLOW })).toBeInTheDocument();
    expect(((await service.getItem(login!.id)).details as DocumentDetails).attachments).toMatchObject([{ name: 'scan.png', type: 'image/png', size: 3 }]);
  }, 3 * SLOW);

  it('shows the storage used in Settings', async () => {
    const service = await createSignedInService();
    const [login] = await service.listItems({ type: 'login' });
    await service.addAttachment(login!.id, new Blob(['0123456789']), 'notes.txt');
    renderApp(service, '/settings');
    expect(await screen.findByText(/10 bytes of 1 GB used\. Each file can be up to 100 MB\./)).toBeInTheDocument();
  });

  it('leaves files and documents out where the host has no file storage', async () => {
    const service = await createSignedInService();
    Object.defineProperty(service, 'attachments', { value: undefined });
    const [login] = await service.listItems({ type: 'login' });
    const { user } = renderApp(service, `/items/all/${login!.id}`);

    expect(await screen.findByRole('heading', { name: login!.title })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Files' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'New item' }));
    expect(await screen.findByRole('menuitem', { name: 'Secure note' })).toBeInTheDocument();
    expect(screen.queryByRole('menuitem', { name: 'Document' })).not.toBeInTheDocument();
  });

  it('on a phone, picks with the system pickers and opens files in the system viewer', async () => {
    const service = await createSignedInService();
    const native = phoneFiles(service, { 'lease.pdf': 'contract', 'draft.pdf': 'draft' });
    const downloads = captureDownloads();
    const { user, router } = renderApp(service, '/items/all/new?type=document');

    await user.type(await screen.findByLabelText('Title'), 'Lease');
    expect(screen.queryByTestId('file-input')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Photos' }));
    expect(native.pick).toHaveBeenCalledWith('photos');
    expect(await screen.findByText('lease.pdf')).toBeInTheDocument();
    // Taken off the list before saving: the phone deletes its copy.
    await user.click(screen.getByRole('button', { name: 'Remove draft.pdf' }));
    expect(native.discardPicked).toHaveBeenCalledWith([expect.objectContaining({ name: 'draft.pdf' })]);
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/items\/all\/[0-9a-f-]{36}$/));
    expect(native.attachPicked).toHaveBeenCalledOnce();
    const itemId = router.state.location.pathname.split('/').at(-1)!;
    const open = await screen.findByRole('button', { name: 'Open lease.pdf' }, { timeout: SLOW });
    expect(screen.queryByRole('button', { name: 'Download lease.pdf' })).not.toBeInTheDocument();
    await user.click(open);
    const [file] = ((await service.getItem(itemId)).details as DocumentDetails).attachments!;
    expect(native.open).toHaveBeenCalledWith(itemId, file!.id);
    expect(downloads.names).toEqual([]);

    // Picked from the item view: attached at once.
    native.pick.mockResolvedValueOnce([{ id: 'p9', name: 'draft.pdf', type: 'application/pdf', size: 5 }]);
    await user.click(screen.getByRole('button', { name: 'Choose files' }));
    expect(await screen.findByRole('button', { name: 'Open draft.pdf' }, { timeout: SLOW })).toBeInTheDocument();
    expect(native.pick).toHaveBeenLastCalledWith('files');
  }, 3 * SLOW);

  it('on a phone, says which files are still waiting to upload and why a pick failed', async () => {
    const service = await createSignedInService();
    const native = phoneFiles(service, {});
    const [login] = await service.listItems({ type: 'login' });
    await service.addAttachment(login!.id, new Blob(['scan']), 'scan.pdf');
    const getItem = service.getItem.bind(service);
    service.getItem = async (id) => {
      const item = await getItem(id);
      return { ...item, details: { ...item.details, attachments: (item.details as DocumentDetails).attachments?.map((file) => ({ ...file, pending: true })) } };
    };
    native.pick.mockRejectedValueOnce(new (await import('@octapass/vault-client')).VaultError('cameraUnavailable'));
    const { user } = renderApp(service, `/items/all/${login!.id}`);

    expect(await screen.findByText(/Waiting to upload/)).toBeInTheDocument();
    expect(screen.getByText(/Offline, it uploads when you’re back online/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Photos' }));
    expect((await screen.findAllByText(/can’t use the camera/)).length).toBeGreaterThan(0);
  });
});
