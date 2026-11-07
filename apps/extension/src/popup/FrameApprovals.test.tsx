import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { FrameApproval } from '../background/frames';
import { ExtensionProvider } from './ExtensionContext';
import { FrameApprovals } from './FrameApprovals';
import type { ExtensionApi } from './service';

describe('FrameApprovals', () => {
  it('lists the frames the user allowed and removes one', async () => {
    let approvals: FrameApproval[] = [
      { site: 'shop.example', origin: 'https://accounts.idp.example', approvedAt: '2026-10-24T09:00:00Z' },
      { site: 'blog.example', origin: 'https://pay.example:8443', approvedAt: '2026-10-24T09:00:00Z' },
    ];
    const api = {
      frameApprovals: async () => approvals,
      removeFrameApproval: vi.fn(async (site: string, origin: string) => {
        approvals = approvals.filter((a) => a.site !== site || a.origin !== origin);
      }),
    } as unknown as ExtensionApi;
    render(
      <ExtensionProvider value={{ api, view: 'tab' }}>
        <FrameApprovals />
      </ExtensionProvider>,
    );
    const section = screen.getByRole('region', { name: 'Frames from other sites' });
    expect(await within(section).findByText('accounts.idp.example')).toBeInTheDocument();
    expect(within(section).getByText('Inside shop.example')).toBeInTheDocument();
    expect(within(section).getByText('pay.example:8443')).toBeInTheDocument();

    await userEvent.click(within(section).getByRole('button', { name: 'Remove accounts.idp.example inside shop.example' }));
    expect(api.removeFrameApproval).toHaveBeenCalledWith('shop.example', 'https://accounts.idp.example');
    await vi.waitFor(() => expect(within(section).queryByText('accounts.idp.example')).not.toBeInTheDocument());
    expect(within(section).getByText('pay.example:8443')).toBeInTheDocument();
  });

  it('says when there are none', async () => {
    const api = { frameApprovals: async () => [] } as unknown as ExtensionApi;
    render(
      <ExtensionProvider value={{ api, view: 'tab' }}>
        <FrameApprovals />
      </ExtensionProvider>,
    );
    expect(await screen.findByText('None yet. Octa Pass asks the first time you use one.')).toBeInTheDocument();
  });
});
