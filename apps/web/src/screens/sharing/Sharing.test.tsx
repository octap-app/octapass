import { cleanup, screen, waitFor, within } from '@testing-library/react';
import { createSignedInService, renderApp } from '../../test/renderApp';

// Every mock write re-seals the vault with PBKDF2, which is slow under jsdom.
const slow = { timeout: 5000 };

describe('sharing', { timeout: 30_000 }, () => {
  it('creates a shared vault, adds someone after showing their fingerprint, changes their role and removes them', async () => {
    const service = await createSignedInService();
    const { user, router } = renderApp(service, '/sharing');

    expect(await screen.findByRole('figure', { name: 'Your fingerprint' })).toBeInTheDocument();
    await user.click(within(screen.getByRole('main')).getByRole('button', { name: 'New shared vault' }));
    const dialog = await screen.findByRole('dialog', { name: 'New shared vault' });
    await user.type(within(dialog).getByLabelText('Name'), 'Lisbon trip');
    await user.click(within(dialog).getByRole('button', { name: 'Create vault' }));
    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/sharing\/vaults\//), slow);
    expect(await screen.findByRole('heading', { name: 'Lisbon trip', level: 1 }, slow)).toBeInTheDocument();

    await user.type(screen.getByLabelText('Their email'), 'omar@example.com');
    await user.click(screen.getByRole('button', { name: 'Find' }));
    const omar = await service.sharing.lookupAccount('omar@example.com');
    expect(await screen.findByRole('figure', { name: 'Fingerprint' })).toHaveTextContent(omar.fingerprint.digits.replace(/ /g, ''));
    await user.click(screen.getByRole('checkbox', { name: 'It matches what omar@example.com sees' }));
    await user.selectOptions(screen.getByLabelText('Role'), 'read');
    await user.click(screen.getByRole('button', { name: 'Add to vault' }));

    const row = await waitFor(() => {
      const found = screen.getAllByRole('listitem').find((li) => li.textContent?.includes('omar@example.com'));
      if (!found) throw new Error('omar is not listed yet');
      return found;
    }, slow);
    expect(within(row).getByText('Verified')).toBeInTheDocument();
    await user.selectOptions(within(row).getByLabelText('Role'), 'write');
    await waitFor(async () => expect((await service.sharing.listMembers(router.state.location.pathname.split('/').pop()!)).find((m) => m.email === 'omar@example.com')?.role).toBe('write'));

    await user.click(within(row).getByRole('button', { name: 'Remove omar@example.com' }));
    const confirm = await screen.findByRole('dialog', { name: 'Remove omar@example.com?' });
    expect(within(confirm).getByText(/gives Lisbon trip a new key/)).toBeInTheDocument();
    await user.click(within(confirm).getByRole('button', { name: 'Remove and change key' }));
    await waitFor(() => expect(screen.queryByText('omar@example.com')).not.toBeInTheDocument(), slow);
  });

  it('makes a service account, shows its token once, and revokes it', async () => {
    const service = await createSignedInService();
    const vault = await service.sharing.createVault('CI');
    const { user } = renderApp(service, `/sharing/vaults/${vault.id}`);

    expect(await screen.findByRole('heading', { name: 'Service accounts' }, slow)).toBeInTheDocument();
    await user.type(await screen.findByLabelText('Name', { selector: '#service-accounts input' }), 'Deploy job');
    await user.click(screen.getByRole('button', { name: 'New service account' }));
    const dialog = await screen.findByRole('dialog', { name: 'Copy this token now' }, slow);
    expect(((await within(dialog).findByLabelText('Token')) as HTMLInputElement).value).toMatch(/^opsa1_/);
    await user.click(within(dialog).getByRole('button', { name: 'Done' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    const [account] = await service.sharing.listServiceAccounts(vault.id);
    expect(account).toMatchObject({ name: 'Deploy job', role: 'read' });
    await user.click(await screen.findByRole('button', { name: 'Revoke Deploy job' }, slow));
    const confirm = await screen.findByRole('dialog', { name: 'Revoke this service account?' });
    await user.click(within(confirm).getByRole('button', { name: 'Revoke' }));
    await waitFor(async () => expect((await service.sharing.listServiceAccounts(vault.id))[0]?.revokedAt).toBeDefined(), slow);
  });

  it('shares a copy of an item, which opens on the public link page with its passphrase', async () => {
    const service = await createSignedInService();
    const github = (await service.listItems()).find((s) => s.title === 'GitHub')!;
    const { user } = renderApp(service, `/items/all/${github.id}`);

    await user.click(await screen.findByRole('button', { name: 'More actions' }));
    await user.click(screen.getByRole('menuitem', { name: 'Share a copy' }));
    const dialog = await screen.findByRole('dialog', { name: 'Share a copy of GitHub' });
    await user.clear(within(dialog).getByLabelText('Number of views'));
    await user.type(within(dialog).getByLabelText('Number of views'), '2');
    await user.type(within(dialog).getByLabelText('Passphrase (optional)'), 'blue heron');
    await user.click(within(dialog).getByRole('button', { name: 'Create link' }));
    const link = (await screen.findByRole('textbox', { name: 'Link' })) as HTMLInputElement;
    expect(screen.getByText('Remember to send the passphrase separately.')).toBeInTheDocument();
    const url = new URL(link.value);
    expect(url.pathname).toMatch(/^\/s\//);
    expect(url.hash.length).toBeGreaterThan(20);

    // Someone else opens the link: only the viewer is on screen.
    cleanup();
    const viewer = renderApp(service, `${url.pathname}${url.search}${url.hash}`);
    await viewer.user.click(await screen.findByRole('button', { name: 'Show the item' }));
    await viewer.user.type(await screen.findByLabelText('Passphrase'), 'blue heron');
    await viewer.user.click(screen.getByRole('button', { name: 'Unlock' }));
    expect(await screen.findByText(/A copy, as it was when it was shared/)).toBeInTheDocument();
    const [info] = await service.sharing.listShareLinks();
    expect(info).toMatchObject({ itemTitle: 'GitHub', maxViews: 2, views: 1 });
    expect(await screen.findByText(/This link can be opened 1 more time, until/)).toBeInTheDocument();
    expect(screen.queryByText(/previous password/)).not.toBeInTheDocument();
  });

  it('shows the address the host made for a link (the apps, whose pages are elsewhere)', async () => {
    const service = await createSignedInService();
    const github = (await service.listItems()).find((s) => s.title === 'GitHub')!;
    const create = service.sharing.createShareLink.bind(service.sharing);
    vi.spyOn(service.sharing, 'createShareLink').mockImplementation(async (itemId, options) => ({
      ...(await create(itemId, options)),
      url: 'https://vault.octap.app/s/made-by-the-app#key',
    }));
    const { user } = renderApp(service, `/items/all/${github.id}`);

    await user.click(await screen.findByRole('button', { name: 'More actions' }));
    await user.click(screen.getByRole('menuitem', { name: 'Share a copy' }));
    const dialog = await screen.findByRole('dialog', { name: 'Share a copy of GitHub' });
    await user.click(within(dialog).getByRole('button', { name: 'Create link' }));
    expect(await screen.findByRole('textbox', { name: 'Link' }, slow)).toHaveValue('https://vault.octap.app/s/made-by-the-app#key');
  });

  it('says when a link is incomplete, without using up a view', async () => {
    const service = await createSignedInService();
    renderApp(service, '/s/some-link-id');
    expect(await screen.findByRole('heading', { name: 'This link is incomplete' })).toBeInTheDocument();
  });

  it('moves an item into another vault', async () => {
    const service = await createSignedInService();
    const figma = (await service.listItems()).find((s) => s.title === 'Figma')!;
    const { user, router } = renderApp(service, `/items/all/${figma.id}`);
    await user.click(await screen.findByRole('button', { name: 'More actions' }));
    await user.click(screen.getByRole('menuitem', { name: 'Move to…' }));
    const dialog = await screen.findByRole('dialog', { name: 'Move Figma' });
    await user.click(within(dialog).getByRole('radio', { name: 'Studio' }));
    await user.click(within(dialog).getByRole('button', { name: 'Move' }));
    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/items\/v-/), slow);
    const studio = (await service.listVaults()).find((v) => v.name === 'Studio')!;
    expect((await service.listItems({ vaultId: studio.id })).map((s) => s.title)).toContain('Figma');
    expect((await service.getItem(figma.id)).deletedAt).toBeDefined();
  });
});
