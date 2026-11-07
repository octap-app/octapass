import { screen } from '@testing-library/react';
import { createSignedInService, PASSWORD, renderApp } from '../../test/renderApp';

describe('Settings → Security log', () => {
  it('shows each export with the device and the format', async () => {
    const service = await createSignedInService();
    await service.exportVault('csv', { masterPassword: PASSWORD });
    renderApp(service, '/settings/security-log');
    expect(await screen.findByText('Your vault was exported on This browser')).toBeInTheDocument();
    expect(screen.getByText(/CSV, not encrypted/)).toBeInTheDocument();
  });

  it('says what an encrypted export held, and copes with an unnamed device', async () => {
    const service = await createSignedInService();
    vi.spyOn(service.sharing, 'getSecurityLog').mockResolvedValue([
      { type: 'vault-exported', createdAt: '2026-10-25T09:00:00Z', exportFormat: 'encrypted', exportAttachments: true, deviceName: 'Ada’s Mac', devicePlatform: 'mac' },
      { type: 'vault-exported', createdAt: '2026-10-24T09:00:00Z', exportFormat: 'cxf', exportAttachments: false },
    ]);
    renderApp(service, '/settings/security-log');
    expect(await screen.findByText('Your vault was exported on Ada’s Mac')).toBeInTheDocument();
    expect(screen.getByText(/Encrypted, with attached files/)).toBeInTheDocument();
    expect(screen.getByText('Your vault was exported on a device')).toBeInTheDocument();
    expect(screen.getByText(/CXF, not encrypted/)).toBeInTheDocument();
  });
});
