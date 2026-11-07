import { screen, waitFor, within } from '@testing-library/react';
import type { LoginDetails, VaultService } from '@octapass/vault-client';
import { createSignedInService, renderApp } from '../../../test/renderApp';

// The demo service reads an "image" whose bytes are text lines as the QR codes it holds.
const image = (...lines: string[]) => new File([lines.join('\n')], 'qr.png', { type: 'image/png' });
const DROPBOX = 'otpauth://totp/Dropbox:maya%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Dropbox';
const DUO = 'otpauth://totp/Duo:maya?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Duo';

async function itemId(service: VaultService, title: string): Promise<string> {
  return (await service.listItems()).find((item) => item.title === title)!.id;
}

async function totpOf(service: VaultService, title: string): Promise<string | undefined> {
  return ((await service.getItem(await itemId(service, title))).details as LoginDetails).totp;
}

function fileInput(dialog: HTMLElement): HTMLInputElement {
  return dialog.querySelector('input[type="file"]')!;
}

describe('One-time codes', () => {
  it('adds a code to a login from its page, from an image', async () => {
    const service = await createSignedInService();
    const { user } = renderApp(service, `/items/all/${await itemId(service, 'Dropbox')}`);
    // The file's first render loads the vault screens, which takes a few seconds on a busy machine.
    await user.click(await screen.findByRole('button', { name: 'Add one-time code' }, { timeout: 15_000 }));
    const dialog = await screen.findByRole('dialog', { name: 'Add one-time code' });
    expect(within(dialog).getByRole('button', { name: 'Add code' })).toBeDisabled();

    await user.upload(fileInput(dialog), image('https://example.com'));
    expect(await within(dialog).findByText('That QR code isn’t a one-time code.')).toBeInTheDocument();
    await user.upload(fileInput(dialog), image(DROPBOX));
    expect(await within(dialog).findByText('Found this one-time code:')).toBeInTheDocument();
    expect(within(dialog).getByRole('radio', { name: 'Dropbox (maya@example.com)' })).toBeChecked();
    await user.click(within(dialog).getByRole('button', { name: 'Add code' }));

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(await totpOf(service, 'Dropbox')).toBe(DROPBOX);
    expect((await screen.findAllByText('One-time code added.')).length).toBeGreaterThan(0);
    expect(screen.queryByRole('button', { name: 'Add one-time code' })).not.toBeInTheDocument();
  });

  it('adds a pasted setup key, and refuses one that isn’t', async () => {
    const service = await createSignedInService();
    const { user } = renderApp(service, `/items/all/${await itemId(service, 'Etsy')}`);
    await user.click(await screen.findByRole('button', { name: 'Add one-time code' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add one-time code' });
    const field = within(dialog).getByLabelText('Setup link or key');
    await user.type(field, 'not a key!');
    await user.click(within(dialog).getByRole('button', { name: 'Add' }));
    expect(await within(dialog).findByText('That isn’t a one-time code setup link or key.')).toBeInTheDocument();
    await user.clear(field);
    await user.type(field, 'JBSW Y3DP EHPK 3PXP');
    await user.click(within(dialog).getByRole('button', { name: 'Add' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(await totpOf(service, 'Etsy')).toBe('JBSWY3DPEHPK3PXP');
  });

  it('scans new codes, and the review links one to a login picked by search', async () => {
    const service = await createSignedInService();
    const { user } = renderApp(service, '/items/all');
    await user.click(await screen.findByRole('button', { name: 'New item' }));
    await user.click(await screen.findByRole('menuitem', { name: 'One-time codes from a QR code' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add one-time codes from a QR code' });
    await user.upload(fileInput(dialog), image(DROPBOX, DUO));
    expect(await within(dialog).findByText('Found 2 one-time codes:')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }));

    const review = await screen.findByRole('dialog', { name: 'Choose where each code goes' });
    const rows = within(review).getAllByRole('listitem');
    // Dropbox matched the Dropbox login; Duo matched nothing.
    expect(within(rows[0]!).getByText('Joins Dropbox')).toBeInTheDocument();
    expect(within(rows[1]!).getByText('Keep as a separate item')).toBeInTheDocument();
    await user.click(within(rows[1]!).getByRole('button', { name: 'Change' }));
    const search = within(rows[1]!).getByRole('searchbox', { name: 'Login for Duo (maya)' });
    // Logins that already have a code can't take another.
    await user.type(search, 'github');
    expect(within(rows[1]!).getByRole('radio', { name: /GitHub/ })).toBeDisabled();
    await user.clear(search);
    await user.type(search, 'duolingo');
    await user.click(within(rows[1]!).getByRole('radio', { name: /Duolingo/ }));
    expect(within(rows[1]!).getByText('Joins Duolingo')).toBeInTheDocument();
    await user.click(within(review).getByRole('button', { name: 'Save 2 items' }));

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect((await screen.findAllByText('Saved 2 one-time codes.')).length).toBeGreaterThan(0);
    expect(await totpOf(service, 'Dropbox')).toBe(DROPBOX);
    expect(await totpOf(service, 'Duolingo')).toBe(DUO);
  });

  it('moves a code on an item of its own into a login, and trashes the item', async () => {
    const service = await createSignedInService();
    const vault = (await service.listVaults()).find((v) => v.type === 'personal')!;
    const code = await service.saveItem({
      vaultId: vault.id,
      overview: { schemaVersion: 1, type: 'login', title: 'LinkedIn code' },
      details: { schemaVersion: 1, totp: DUO },
    });
    const { user } = renderApp(service, `/items/all/${code.id}`);
    // A code-only item can't take a second code, but it can join a login.
    expect(await screen.findByRole('button', { name: 'Link to a login' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add one-time code' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Link to a login' }));
    const dialog = await screen.findByRole('dialog', { name: 'Move this code to a login' });
    await user.type(within(dialog).getByRole('searchbox'), 'linkedin.com');
    await user.click(within(dialog).getByRole('radio', { name: /^LinkedIn/ }));
    await user.click(within(dialog).getByRole('button', { name: 'Link to a login' }));

    expect((await screen.findAllByText('Moved the code to LinkedIn. The old item is in the trash.')).length).toBeGreaterThan(0);
    expect(await totpOf(service, 'LinkedIn')).toBe(DUO);
    expect((await service.getItem(code.id)).deletedAt).toBeDefined();
  });
});

describe('Settings → Import, authenticator apps', () => {
  it('reviews where each code goes before saving', async () => {
    const service = await createSignedInService();
    const { user } = renderApp(service, '/settings');
    await user.selectOptions(await screen.findByLabelText('Import from'), 'otpauth');
    await user.upload(screen.getByLabelText('File'), new File([`${DROPBOX}\n${DUO}\n`], 'codes.txt', { type: 'text/plain' }));
    await user.click(screen.getByRole('button', { name: 'Import' }));
    const review = await screen.findByRole('list', { name: 'Choose where each code goes' });
    expect(within(review).getAllByRole('listitem')).toHaveLength(2);
    expect(await totpOf(service, 'Dropbox')).toBeUndefined();
    await user.click(screen.getByRole('button', { name: 'Save 2 items' }));
    expect(await screen.findByText('Imported 2 items.')).toBeInTheDocument();
    expect(await totpOf(service, 'Dropbox')).toBe(DROPBOX);
    expect((await service.listItems({ query: 'Duo' })).map((item) => item.title)).toContain('Duo');
  });
});
