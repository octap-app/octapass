import type { ItemSummary } from '@octapass/vault-client';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { FakeTransport } from '../test/fakeTransport';
import { TauriVaultService, type SessionSnapshot } from '../TauriVaultService';
import { QuickAccess, type AutoTypeOutcome, type QuickActions, type QuickOpened } from './QuickAccess';

const session = (status: 'locked' | 'unlocked'): SessionSnapshot => ({
  session: { status, email: 'ada@example.com', serverUrl: 'http://localhost:8080' },
  rememberedAccounts: [],
});

const rows: ItemSummary[] = [
  { id: 'gh', vaultId: 'v', type: 'login', title: 'GitHub', subtitle: 'ada', favorite: false, hasTotp: true, hasPasskey: false, createdAt: 't', updatedAt: 't' },
  { id: 'bank', vaultId: 'v', type: 'login', title: 'Bank', subtitle: 'ada.l', favorite: false, hasTotp: false, hasPasskey: false, createdAt: 't', updatedAt: 't' },
  { id: 'note', vaultId: 'v', type: 'secureNote', title: 'Notes', favorite: false, hasTotp: false, hasPasskey: false, createdAt: 't', updatedAt: 't' },
  { id: 'db', vaultId: 'v', type: 'database', title: 'Warehouse', subtitle: 'db.internal', favorite: false, hasTotp: false, hasPasskey: false, createdAt: 't', updatedAt: 't' },
];

async function setup(status: 'locked' | 'unlocked', transport = new FakeTransport()) {
  transport.on('session_snapshot', () => session(status)).on('list_items', () => rows);
  const service = await TauriVaultService.create(transport);
  let opened: (opened: QuickOpened) => void = () => {};
  const actions = {
    copy: vi.fn(async () => 30),
    autoType: vi.fn(async (): Promise<AutoTypeOutcome> => ({ status: 'typed', window: 'GitHub — Safari' })),
    openAccessibilitySettings: vi.fn(),
    hide: vi.fn(),
    openVault: vi.fn(),
    onOpened: (cb: (opened: QuickOpened) => void) => {
      opened = cb;
      return () => {};
    },
  } satisfies QuickActions;
  render(<QuickAccess service={service} actions={actions} />);
  return { actions, transport, open: (payload: QuickOpened) => act(() => opened(payload)) };
}

describe('QuickAccess', () => {
  it('runs tool commands from the search box, in the core', async () => {
    const user = userEvent.setup();
    const transport = new FakeTransport().on('toolkit_run', (args) => JSON.stringify(args?.op === 'random.uuid' ? { values: ['0192-uuid'] } : { payload: { sub: 'ada' } }));
    await setup('unlocked', transport);
    const search = await screen.findByRole('searchbox', { name: 'Search logins' });
    await user.type(search, 'uuid');
    expect(await screen.findByTestId('quick-tool')).toHaveTextContent('0192-uuid');
    await user.clear(search);
    await user.type(search, 'decode jwt eyJhbGciOiJub25lIn0.e30.');
    await waitFor(() => expect(screen.getByTestId('quick-tool')).toHaveTextContent('"sub": "ada"'));
  });

  it('lists logins and copies with the keyboard', async () => {
    const user = userEvent.setup();
    const { actions } = await setup('unlocked');
    expect(await screen.findByRole('option', { name: /Bank/ })).toBeInTheDocument();
    expect(screen.queryByText('Notes')).not.toBeInTheDocument();

    const search = screen.getByRole('searchbox', { name: 'Search logins' });
    await user.keyboard('{Enter}');
    expect(actions.copy).toHaveBeenLastCalledWith('bank', 'password');
    expect(await screen.findByRole('status')).toHaveTextContent('Password for Bank copied. The clipboard clears in 30 s.');

    await user.keyboard('{ArrowDown}{Shift>}{Enter}{/Shift}');
    expect(actions.copy).toHaveBeenLastCalledWith('gh', 'username');
    await user.keyboard('{Alt>}{Enter}{/Alt}');
    expect(actions.copy).toHaveBeenLastCalledWith('gh', 'code');

    await user.type(search, 'git');
    await waitFor(() => expect(screen.queryByText('Bank')).not.toBeInTheDocument());
    await user.keyboard('{Escape}');
    expect(actions.hide).toHaveBeenCalled();
  });

  it('lists databases with logins, to copy or type their user name and password', async () => {
    const user = userEvent.setup();
    const { actions } = await setup('unlocked');
    const search = await screen.findByRole('searchbox', { name: 'Search logins' });
    await user.type(search, 'ware');
    await waitFor(() => expect(screen.queryByText('Bank')).not.toBeInTheDocument());
    expect(screen.getByRole('option', { name: /Warehouse/ })).toBeInTheDocument();
    await user.keyboard('{Enter}');
    expect(actions.copy).toHaveBeenLastCalledWith('db', 'password');
    await user.keyboard('{Shift>}{Enter}{/Shift}');
    expect(actions.copy).toHaveBeenLastCalledWith('db', 'username');
    await user.keyboard('{Alt>}{Enter}{/Alt}');
    expect(actions.copy).toHaveBeenCalledTimes(2);
  });

  it('offers no code for a login without one', async () => {
    const user = userEvent.setup();
    const { actions } = await setup('unlocked');
    await screen.findByText('Bank');
    await user.keyboard('{Alt>}{Enter}{/Alt}');
    expect(actions.copy).not.toHaveBeenCalled();
  });

  it('unlocks with the device when locked', async () => {
    const user = userEvent.setup();
    const transport = new FakeTransport()
      .on('unlock_methods', () => ({ deviceUnlockSupported: true, deviceUnlockEnabled: true, label: 'Touch ID', platform: 'mac', passwordRequired: false }))
      .on('unlock_with_device', () => {
        transport.emit('vault://session', session('unlocked'));
      });
    const { actions } = await setup('locked', transport);
    expect(screen.getByRole('heading', { name: 'Octa Pass is locked' })).toBeInTheDocument();
    await user.click(await screen.findByRole('button', { name: 'Unlock with Touch ID' }));
    expect(await screen.findByRole('searchbox')).toBeInTheDocument();

    transport.emit('vault://session', session('locked'));
    await user.click(await screen.findByRole('button', { name: 'Open Octa Pass' }));
    expect(actions.openVault).toHaveBeenCalled();
  });

  it('auto-types the selected login with Ctrl+Enter or its button, and explains refusals', async () => {
    const user = userEvent.setup();
    const { actions } = await setup('unlocked');
    const status = (text: string) => waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(text));
    await screen.findByText('Bank');
    await user.keyboard('{Control>}{Enter}{/Control}');
    expect(actions.autoType).toHaveBeenLastCalledWith('bank');
    expect(actions.copy).not.toHaveBeenCalled();

    actions.autoType.mockRejectedValueOnce({ code: 'noMatch', window: 'Untitled — TextEdit' });
    await user.click(screen.getAllByRole('button', { name: 'Type into the window' })[0]!);
    expect(actions.autoType).toHaveBeenLastCalledWith('bank');
    await status('Untitled — TextEdit isn’t a window for Bank. Add its title to the login’s auto-type windows in Octa Pass.');
    await user.click(screen.getByRole('searchbox'));

    actions.autoType.mockRejectedValueOnce({ code: 'permissionRequired', settingsUrl: 'x-apple.systempreferences:' });
    await user.keyboard('{Control>}{Enter}{/Control}');
    await status('Octa Pass needs the Accessibility permission');
    await user.click(screen.getByRole('button', { name: 'Open System Settings' }));
    expect(actions.openAccessibilitySettings).toHaveBeenCalled();
    await user.click(screen.getByRole('searchbox'));

    actions.autoType.mockRejectedValueOnce({ code: 'missingField', field: 'totp' });
    await user.keyboard('{Control>}{Enter}{/Control}');
    await status('Bank has no one-time code to type.');

    actions.autoType.mockResolvedValueOnce({ status: 'copied', clearsIn: 30 });
    await user.keyboard('{Control>}{Enter}{/Control}');
    await status('so the password for Bank was copied. The clipboard clears in 30 s.');
  });

  it('lists the logins for the window when the auto-type shortcut opens it, and Enter types', async () => {
    const user = userEvent.setup();
    const { actions, open } = await setup('unlocked');
    await screen.findByText('Bank');
    open({ autoType: { window: 'GitHub — Safari', matches: ['gh'] } });
    expect(await screen.findByText('Type into GitHub — Safari')).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText('Bank')).not.toBeInTheDocument());
    await user.keyboard('{Enter}');
    expect(actions.autoType).toHaveBeenLastCalledWith('gh');
    // Shift+Enter still copies.
    await user.keyboard('{Shift>}{Enter}{/Shift}');
    expect(actions.copy).toHaveBeenLastCalledWith('gh', 'username');

    // A search shows every login again.
    await user.type(screen.getByRole('searchbox'), 'ban');
    expect(await screen.findByText('Bank')).toBeInTheDocument();

    open({ autoType: { window: 'Slack', matches: [] } });
    expect(await screen.findByText('No login is set up for Slack. Pick one, or add the window to a login’s auto-type windows.')).toBeInTheDocument();
    expect(screen.getByRole('searchbox')).toHaveValue('');

    open({ autoType: { window: 'GitHub — Safari', matches: ['gh'], failure: { code: 'focusChanged', window: 'Software Update' }, title: 'GitHub' } });
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Software Update took focus, so typing stopped.'));

    // The quick-access shortcut opens the plain search again.
    open({});
    expect(await screen.findByText('Bank')).toBeInTheDocument();
    expect(screen.queryByText(/Type into/)).not.toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('');
  });
});
