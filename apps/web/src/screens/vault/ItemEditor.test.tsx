import { screen, waitFor, within } from '@testing-library/react';
import type { ItemDraft } from '@octapass/vault-client';
import { createSignedInService, renderApp } from '../../test/renderApp';

// Each test renders the whole app; after saving, the list and the item page render again at once,
// which takes a few seconds in jsdom on a busy machine.
describe('item editor', { timeout: 30_000 }, () => {
  it('validates, saves a new login and shows it', async () => {
    const service = await createSignedInService();
    const { user, router } = renderApp(service, '/items/all/new?type=login');

    await user.click(await screen.findByRole('button', { name: 'Save' }, { timeout: 10_000 }));
    expect(screen.getByLabelText('Title')).toHaveAccessibleDescription(/Give the item a title/);

    await user.type(screen.getByLabelText('Title'), 'Kagi');
    await user.type(screen.getByLabelText('Username'), 'maya');
    await user.type(screen.getByLabelText('Password'), 'correct-horse-battery-staple');
    await user.type(screen.getByLabelText('Website'), 'kagi.com');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/items\/all\/[0-9a-f-]{36}$/));
    expect(await screen.findByRole('heading', { name: 'Kagi' }, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.getAllByRole('status').some((region) => region.textContent === '“Kagi” saved')).toBe(true);
  });

  it('says when the vault already has the login, and adds a copy only when asked', async () => {
    const service = await createSignedInService();
    const personal = (await service.listVaults()).find((vault) => vault.type === 'personal')!;
    const existing = await service.saveItem({
      vaultId: personal.id,
      overview: { schemaVersion: 1, title: 'GitHub', type: 'login', urls: ['https://github.com'], subtitle: 'octocat' },
      details: { schemaVersion: 1, username: 'octocat', password: 'an-older-password-1' },
    } as ItemDraft);
    const before = (await service.listItems()).length;
    const { user, router } = renderApp(service, '/items/all/new?type=login');

    await user.type(await screen.findByLabelText('Title', {}, { timeout: 10_000 }), 'GitHub again');
    await user.type(screen.getByLabelText('Username'), 'Octocat');
    await user.type(screen.getByLabelText('Password'), 'a-newer-password-2');
    await user.type(screen.getByLabelText('Website'), 'www.github.com/login');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    let dialog = await screen.findByRole('dialog', { name: 'You already have this login' });
    expect(dialog).toHaveTextContent('“GitHub” in Personal is for the same website, with the same username.');
    expect(await service.listItems()).toHaveLength(before);

    // Keep editing leaves the form as it was.
    await user.click(within(dialog).getByRole('button', { name: 'Keep editing' }));
    expect(screen.getByLabelText('Title')).toHaveValue('GitHub again');

    // Open it still asks about the unsaved changes first.
    await user.click(screen.getByRole('button', { name: 'Save' }));
    dialog = await screen.findByRole('dialog', { name: 'You already have this login' });
    await user.click(within(dialog).getByRole('button', { name: 'Open it' }));
    await user.click(within(await screen.findByRole('dialog', { name: 'Discard your changes?' })).getByRole('button', { name: 'Keep editing' }));
    expect(router.state.location.pathname).toBe('/items/all/new');

    // Save a copy saves it after all.
    await user.click(screen.getByRole('button', { name: 'Save' }));
    dialog = await screen.findByRole('dialog', { name: 'You already have this login' });
    await user.click(within(dialog).getByRole('button', { name: 'Save a copy' }));
    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/items\/all\/[0-9a-f-]{36}$/));
    expect(router.state.location.pathname).not.toContain(existing.id);
    expect(await service.listItems()).toHaveLength(before + 1);
  });

  it('lists the match rules with "this site and its subdomains" as the default, and saves another one', async () => {
    const service = await createSignedInService();
    const { user, router } = renderApp(service, '/items/all/new?type=login');

    await user.type(await screen.findByLabelText('Title', {}, { timeout: 10_000 }), 'Shop');
    await user.type(screen.getByLabelText('Website'), 'login.example.com');
    const rule = screen.getByRole('combobox', { name: 'Fill on' });
    expect(within(rule).getAllByRole('option').map((option) => option.textContent)).toEqual([
      'This site and its subdomains',
      'Every part of this domain',
      'This exact host',
      'Pages that start with this address',
      'Regular expression',
      'Never fill here',
    ]);
    expect(rule).toHaveValue('subdomains');
    expect(screen.getByText(/Not on other parts like shop\.example\.com/)).toBeInTheDocument();

    await user.selectOptions(rule, 'baseDomain');
    expect(screen.getByText(/including other parts like shop\.example\.com/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/items\/all\/[0-9a-f-]{36}$/));
    const saved = (await service.listItems()).find((item) => item.title === 'Shop')!;
    expect(saved.urlMatch).toEqual({ 'login.example.com': 'baseDomain' });
  });

  it('asks before throwing away unsaved changes', async () => {
    const service = await createSignedInService();
    const { user, router } = renderApp(service, '/items/all/new?type=secureNote');

    await user.type(await screen.findByLabelText('Title'), 'Draft');
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    const dialog = await screen.findByRole('dialog', { name: 'Discard your changes?' });
    await user.click(within(dialog).getByRole('button', { name: 'Keep editing' }));
    expect(screen.getByLabelText('Title')).toHaveValue('Draft');

    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Discard changes' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/items/all'));
  });

  it('edits auto-type settings where the app can auto-type', async () => {
    const service = await createSignedInService();
    const { unmount } = renderApp(service, '/items/all/new?type=login');
    expect(await screen.findByLabelText('Title')).toBeInTheDocument();
    expect(screen.queryByText('Auto-type')).not.toBeInTheDocument();
    unmount();

    Object.defineProperty(service, 'autoType', { value: { shortcut: '⌘⇧\\' } });
    const view = renderApp(service, '/items/all/new?type=login');
    await view.user.type(await screen.findByLabelText('Title'), 'Slack');
    expect(screen.getByText(/In another app, press ⌘⇧\\ and Octa Pass types this login there/)).toBeInTheDocument();
    const sequence = screen.getByLabelText('What to type');
    expect(sequence).toHaveAttribute('placeholder', '{USERNAME}{TAB}{PASSWORD}{ENTER}');
    await view.user.click(sequence);
    await view.user.paste('{PASSWROD}');
    await view.user.click(screen.getByRole('button', { name: 'Save' }));
    expect(sequence).toHaveAccessibleDescription(/Octa Pass can’t type this/);

    await view.user.clear(sequence);
    await view.user.paste('{PASSWORD}{ENTER}');
    await view.user.type(screen.getByLabelText('Windows'), 'Slack');
    await view.user.click(screen.getByRole('button', { name: 'Add a window' }));
    await view.user.type(screen.getByLabelText('Window 2'), '  ');
    await view.user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(view.router.state.location.pathname).toMatch(/^\/items\/all\/[0-9a-f-]{36}$/));
    const id = view.router.state.location.pathname.split('/').pop()!;
    expect((await service.getItem(id)).details).toMatchObject({ autoType: { sequence: '{PASSWORD}{ENTER}', windowTitles: ['Slack'] } });
  });
});

describe('environment editor', { timeout: 30_000 }, () => {
  it('saves a project, a stage and ordered variables, then shows them hidden', async () => {
    const service = await createSignedInService();
    const { user, router } = renderApp(service, '/items/all/new?type=environment');

    await user.type(await screen.findByLabelText('Title'), 'Shop API (production)');
    await user.type(screen.getByLabelText('Project'), 'shop-api');
    await user.type(screen.getByLabelText('Stage'), 'production');
    await user.click(screen.getByRole('button', { name: 'Add a variable' }));
    await user.type(screen.getByLabelText('Name'), 'DATABASE_URL');
    await user.type(screen.getByLabelText('Value'), 'postgres://db');
    await user.click(screen.getByRole('button', { name: 'Add a variable' }));
    await user.type(screen.getAllByLabelText('Name')[1]!, 'PORT');
    await user.type(screen.getAllByLabelText('Value')[1]!, '8080');

    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/items\/all\/[0-9a-f-]{36}$/));
    const id = router.state.location.pathname.split('/').pop()!;
    expect((await service.getItem(id)).details).toMatchObject({
      project: 'shop-api',
      stage: 'production',
      variables: [
        { key: 'DATABASE_URL', value: 'postgres://db', concealed: true },
        { key: 'PORT', value: '8080', concealed: true },
      ],
    });
    expect(await screen.findByRole('heading', { name: 'Shop API (production)' }, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.queryByText('postgres://db')).not.toBeInTheDocument();
    expect(screen.getAllByText('Production').length).toBeGreaterThan(0);
  });

  it('adds pasted .env text and rejects a bad name', async () => {
    const service = await createSignedInService();
    const { user } = renderApp(service, '/items/all/new?type=environment');
    await user.type(await screen.findByLabelText('Title'), 'Pasted');
    await user.click(screen.getByRole('button', { name: 'Paste .env text' }));
    await user.type(screen.getByLabelText('Paste .env text'), 'A=1\nB="two words"');
    await user.click(screen.getByRole('button', { name: 'Add these variables' }));
    expect(screen.getByDisplayValue('A')).toBeInTheDocument();
    expect(screen.getByDisplayValue('two words')).toBeInTheDocument();

    await user.clear(screen.getAllByLabelText('Name')[0]!);
    await user.type(screen.getAllByLabelText('Name')[0]!, '1BAD');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(screen.getByText(/Fix the highlighted field/)).toBeInTheDocument();
  });
});
