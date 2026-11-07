import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router';
import type { HttpAuthApproval, HttpAuthPrompt as Prompt } from '../background/httpAuth';
import { ExtensionProvider } from './ExtensionContext';
import { HttpAuthPrompt } from './HttpAuthPrompt';
import { HttpAuthSites } from './HttpAuthSites';
import type { ExtensionApi } from './service';

describe('HttpAuthSites', () => {
  it('lists the sites the user allowed and removes one', async () => {
    let approvals: HttpAuthApproval[] = [
      { origin: 'http://192.168.1.1', itemId: 'router', approvedAt: '2026-10-25T09:00:00Z' },
      { origin: 'https://nas.example:5001', itemId: 'nas', approvedAt: '2026-10-25T09:00:00Z' },
    ];
    const api = {
      httpAuthApprovals: async () => approvals,
      removeHttpAuthApproval: vi.fn(async (origin: string) => {
        approvals = approvals.filter((a) => a.origin !== origin);
      }),
    } as unknown as ExtensionApi;
    render(
      <ExtensionProvider value={{ api, view: 'tab' }}>
        <HttpAuthSites />
      </ExtensionProvider>,
    );
    const section = screen.getByRole('region', { name: 'HTTP sign-in prompts' });
    expect(await within(section).findByText('192.168.1.1')).toBeInTheDocument();
    expect(within(section).getByText('nas.example:5001')).toBeInTheDocument();
    await userEvent.click(within(section).getByRole('button', { name: 'Remove 192.168.1.1' }));
    expect(api.removeHttpAuthApproval).toHaveBeenCalledWith('http://192.168.1.1');
    await vi.waitFor(() => expect(within(section).queryByText('192.168.1.1')).not.toBeInTheDocument());
  });

  it('says when there are none', async () => {
    const api = { httpAuthApprovals: async () => [] } as unknown as ExtensionApi;
    render(
      <ExtensionProvider value={{ api, view: 'tab' }}>
        <HttpAuthSites />
      </ExtensionProvider>,
    );
    expect(await screen.findByText('None yet. Octa Pass asks the first time a site’s prompt matches a login.')).toBeInTheDocument();
  });
});

describe('HttpAuthPrompt', () => {
  function renderPrompt(api: Partial<ExtensionApi>) {
    const router = createMemoryRouter([{ path: '/http-auth/:id', element: <HttpAuthPrompt /> }], { initialEntries: ['/http-auth/p1'] });
    render(
      <ExtensionProvider value={{ api: api as ExtensionApi, view: 'window' }}>
        <RouterProvider router={router} />
      </ExtensionProvider>,
    );
  }
  const prompt: Prompt = { origin: 'http://192.168.1.1', realm: 'Router admin', logins: [{ itemId: 'router', title: 'Home router', username: 'admin' }] };

  it('names the site and realm, warns about http, and signs in with the login picked', async () => {
    const close = vi.spyOn(window, 'close').mockImplementation(() => {});
    const api = { httpAuthPrompt: vi.fn(async () => prompt), httpAuthApprove: vi.fn(async () => {}), httpAuthDecline: vi.fn(async () => {}) };
    renderPrompt(api);
    expect(await screen.findByRole('heading', { name: 'Sign in to 192.168.1.1?' })).toBeInTheDocument();
    expect(screen.getByText(/for “Router admin”/)).toBeInTheDocument();
    expect(screen.getByText(/isn’t encrypted/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Home router/ }));
    expect(api.httpAuthApprove).toHaveBeenCalledWith('p1', 'router');
    expect(close).toHaveBeenCalled();
  });

  it('“Not now” declines, and an ended request says so', async () => {
    vi.spyOn(window, 'close').mockImplementation(() => {});
    const api = { httpAuthPrompt: vi.fn(async () => ({ ...prompt, origin: 'https://nas.example' })), httpAuthDecline: vi.fn(async () => {}) };
    renderPrompt(api);
    await userEvent.click(await screen.findByRole('button', { name: 'Not now' }));
    expect(api.httpAuthDecline).toHaveBeenCalledWith('p1');
    expect(screen.queryByText(/isn’t encrypted/)).not.toBeInTheDocument();
  });

  it('shows when the request is gone', async () => {
    renderPrompt({ httpAuthPrompt: async () => Promise.reject(new Error('ended')) });
    expect(await screen.findByText('This sign-in request has ended. Reload the page to try again.')).toBeInTheDocument();
  });
});
