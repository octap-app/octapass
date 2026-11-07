import type { PasskeyMatch } from '@octapass/core';
import { VaultError } from '@octapass/vault-client';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { PasskeyPrompt } from '../shared/passkey';
import type { PasskeyClient, SessionStatus } from './client';
import type { FrameLink } from './frame';
import { Prompt } from './Prompt';

const GET: PasskeyPrompt = { kind: 'get', origin: 'https://login.example.com', rpId: 'example.com', rpName: 'Totally your bank' };
const CREATE: PasskeyPrompt = { kind: 'create', origin: 'https://example.com', rpId: 'example.com', rpName: 'Example', userName: 'maya@example.com' };

const match = (id: string, userName: string, extra: Partial<PasskeyMatch> = {}): PasskeyMatch => ({
  vaultId: 'v1',
  itemId: `item-${id}`,
  credentialId: id,
  rpId: 'example.com',
  userName,
  createdAt: '2026-10-01T00:00:00Z',
  ...extra,
});

function fake(status: SessionStatus | undefined, overrides: Partial<PasskeyClient> = {}) {
  const listeners = new Set<() => void>();
  let current = status;
  const client: PasskeyClient = {
    status: () => current,
    onStatus: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    unlock: vi.fn(async () => undefined),
    prompt: vi.fn(async () => GET),
    matches: vi.fn(async () => [match('c1', 'maya@example.com', { userDisplayName: 'Maya Haddad' }), match('c2', 'work@example.com')]),
    titles: vi.fn(async () => new Map([['item-c2', 'Example (work)']])),
    approve: vi.fn(() => new Promise<void>(() => undefined)),
    fallback: vi.fn(async () => undefined),
    cancel: vi.fn(async () => undefined),
    ...overrides,
  };
  const setStatus = (next: SessionStatus) => {
    current = next;
    act(() => listeners.forEach((listener) => listener()));
  };
  return { client, setStatus };
}

const frameLink = (): FrameLink => ({ height: vi.fn(), close: vi.fn() });

describe('the passkey prompt', () => {
  it('shows its shape at once, then the passkeys for the real site', async () => {
    const { client, setStatus } = fake(undefined);
    render(<Prompt client={client} requestId="r1" />);
    expect(screen.getByRole('main')).toHaveAttribute('aria-busy', 'true');
    setStatus('unlocked');

    // Named by rpId, never by the page's rp.name.
    expect(await screen.findByRole('heading', { name: 'Sign in to example.com with a passkey' })).toBeVisible();
    expect(screen.queryByText(/Totally your bank/)).toBeNull();
    const list = await screen.findByRole('list', { name: 'Choose a passkey saved in Octa Pass.' });
    const rows = within(list).getAllByRole('button');
    expect(rows.map((row) => row.textContent)).toEqual(['MMaya Haddadmaya@example.com', 'Wwork@example.comExample (work)']);
    expect(client.titles).toHaveBeenCalledWith('https://login.example.com');
  });

  it('moves with the arrow keys, and picks with Enter', async () => {
    const user = userEvent.setup();
    const { client } = fake('unlocked');
    render(<Prompt client={client} requestId="r1" />);
    const rows = within(await screen.findByRole('list')).getAllByRole('button');
    await waitFor(() => expect(rows[0]).toHaveFocus());
    await user.keyboard('{ArrowDown}');
    expect(rows[1]).toHaveFocus();
    await user.keyboard('{ArrowDown}');
    expect(rows[0]).toHaveFocus();
    await user.keyboard('{End}');
    expect(rows[1]).toHaveFocus();
    await user.keyboard('{Enter}');

    expect(client.approve).toHaveBeenCalledWith('r1', expect.objectContaining({ itemId: 'item-c2', credentialId: 'c2' }));
    expect(rows[1]).toHaveAttribute('aria-busy', 'true');
    expect(rows[0]).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Use another device or security key' })).toBeDisabled();
  });

  it('says so when there are no passkeys for the site', async () => {
    const { client } = fake('unlocked', { matches: vi.fn(async () => []) });
    render(<Prompt client={client} requestId="r1" />);
    expect(await screen.findByText('No passkeys for example.com in Octa Pass.')).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'Use another device or security key' }));
    expect(client.fallback).toHaveBeenCalledWith('r1');
  });

  it('unlocks first, then lists the passkeys', async () => {
    const user = userEvent.setup();
    const { client, setStatus } = fake('locked');
    render(<Prompt client={client} requestId="r1" />);
    await user.click(await screen.findByRole('button', { name: 'Unlock' }));
    expect(await screen.findByText('Enter your master password.')).toBeVisible();
    expect(client.unlock).not.toHaveBeenCalled();

    await user.type(screen.getByLabelText('Master password'), 'correct horse');
    await user.click(screen.getByRole('button', { name: 'Unlock' }));
    expect(client.unlock).toHaveBeenCalledWith('correct horse');
    setStatus('unlocked');
    expect(await screen.findByRole('list')).toBeVisible();
  });

  it('shows the vault’s own message for a wrong master password', async () => {
    const user = userEvent.setup();
    const { client } = fake('locked', { unlock: vi.fn(async () => Promise.reject(new VaultError('invalidCredentials'))) });
    render(<Prompt client={client} requestId="r1" />);
    await user.type(await screen.findByLabelText('Master password'), 'wrong');
    await user.click(screen.getByRole('button', { name: 'Unlock' }));
    expect(await screen.findByText(/password/i, { selector: 'p' })).toBeVisible();
    expect(screen.getByLabelText('Master password')).toHaveValue('');
  });

  it('asks to sign in when signed out, and cancels from the close button', async () => {
    const { client } = fake('signedOut');
    render(<Prompt client={client} requestId="r1" />);
    expect(await screen.findByText('Sign in to Octa Pass from the toolbar button to use your passkeys.')).toBeVisible();
    await userEvent.click(screen.getAllByRole('button', { name: 'Cancel' })[0]!);
    expect(client.cancel).toHaveBeenCalledWith('r1');
  });

  it('saves a new passkey for the account the site named', async () => {
    const { client } = fake('unlocked', { prompt: vi.fn(async () => CREATE) });
    render(<Prompt client={client} requestId="r1" />);
    expect(await screen.findByRole('heading', { name: 'Save a passkey for example.com?' })).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'Save in Octa Pass' }));
    expect(client.approve).toHaveBeenCalledWith('r1');
  });

  it('closes through the content script when the request has ended', async () => {
    const frame = frameLink();
    const { client } = fake('unlocked', { prompt: vi.fn(async () => Promise.reject(new Error('ended'))) });
    render(<Prompt client={client} requestId="r1" frame={frame} />);
    expect(await screen.findByText('This request has ended. Try again on the website.')).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(frame.close).toHaveBeenCalled();
  });

  it('closes through the content script when the service worker no longer knows the request', async () => {
    const frame = frameLink();
    const { client } = fake('signedOut', { cancel: vi.fn(async () => Promise.reject(new Error('This request has ended.'))) });
    render(<Prompt client={client} requestId="r1" frame={frame} />);
    await screen.findByText('Sign in to Octa Pass from the toolbar button to use your passkeys.');
    // The footer's Cancel; the close button in the header does the same.
    await userEvent.click(screen.getAllByRole('button', { name: 'Cancel' })[1]!);
    await waitFor(() => expect(frame.close).toHaveBeenCalled());
  });

  it('tells the content script how tall it is', async () => {
    const observed: Element[] = [];
    vi.stubGlobal(
      'ResizeObserver',
      class {
        observe(element: Element) {
          observed.push(element);
        }
        disconnect() {}
      },
    );
    const frame = frameLink();
    const { client } = fake('unlocked');
    render(<Prompt client={client} requestId="r1" frame={frame} />);
    expect(frame.height).toHaveBeenCalled();
    expect(observed).toHaveLength(2);
    vi.unstubAllGlobals();
  });
});
