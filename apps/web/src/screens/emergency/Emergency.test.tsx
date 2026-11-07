import { screen, waitFor, within } from '@testing-library/react';
import { createSignedInService, renderApp } from '../../test/renderApp';

const slow = { timeout: 5000 };

describe('emergency access', { timeout: 30_000 }, () => {
  it('gives a waiting contact access now, then takes it back', async () => {
    const service = await createSignedInService();
    const { user } = renderApp(service, '/emergency');
    const leila = (await screen.findByText('leila.rahman@example.com')).closest('li')!;
    expect(within(leila).getByText(/Asked for access/)).toBeInTheDocument();
    await user.click(within(leila).getByRole('button', { name: 'Give access now' }));
    await waitFor(() => expect(within(leila).getByText(/Has access since/)).toBeInTheDocument(), slow);
    await user.click(within(leila).getByRole('button', { name: 'Take back access' }));
    await waitFor(() => expect(within(leila).getByText('No request')).toBeInTheDocument(), slow);
    expect((await service.sharing.getSecurityLog()).map((e) => e.type)).toContain('emergency-access-approved');
  });

  it('adds a trusted contact after showing their fingerprint', async () => {
    const service = await createSignedInService();
    const { user } = renderApp(service, '/emergency');
    await user.type(await screen.findByLabelText('Their email'), 'omar@example.com');
    await user.click(screen.getByRole('button', { name: 'Find' }));
    await screen.findByRole('figure', { name: 'Fingerprint' });
    await user.selectOptions(screen.getByLabelText('Waiting period'), '14');
    await user.click(screen.getByRole('radio', { name: 'Take over' }));
    await user.click(screen.getByRole('button', { name: 'Add contact' }));
    await waitFor(async () => expect((await service.sharing.listEmergencyContacts()).granted.find((c) => c.contactEmail === 'omar@example.com')).toMatchObject({ waitDays: 14, accessLevel: 'takeover', scope: { type: 'account' } }), slow);
  });

  it('opens a released grantor’s vault read-only', async () => {
    const service = await createSignedInService();
    const { user, router } = renderApp(service, '/emergency');
    await user.click(await screen.findByRole('button', { name: 'Open vault' }));
    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/emergency\//));
    expect(await screen.findByRole('heading', { name: 'sam.rahman@example.com’s vault', level: 1 }, slow)).toBeInTheDocument();
    expect(screen.getByText(/Read-only emergency access/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Northwind Bank/ }));
    expect(await screen.findByText('Username')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Files' })).not.toBeInTheDocument();
  });

  it('downloads a released grantor’s file, decrypted on this device', async () => {
    const service = await createSignedInService();
    const blobs: Blob[] = [];
    const names: string[] = [];
    URL.createObjectURL = vi.fn((blob: Blob) => (blobs.push(blob), 'blob:test'));
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      names.push(this.download);
    });
    const { user } = renderApp(service, '/emergency');
    await user.click(await screen.findByRole('button', { name: 'Open vault' }));
    await user.click(await screen.findByRole('button', { name: /Pension/ }, slow));
    expect(await screen.findByRole('heading', { name: 'Files' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Download Pension statement.txt' }));
    await waitFor(() => expect(names).toEqual(['Pension statement.txt']), slow);
    expect(await blobs[0]!.text()).toContain('Pension statement');
    vi.restoreAllMocks();
  });
});
