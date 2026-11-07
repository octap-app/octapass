import { screen, within } from '@testing-library/react';
import { createSignedInService, renderApp } from '../../test/renderApp';

describe('recovery map', () => {
  it('flags the demo mailbox, which resets many logins without two-step sign-in', async () => {
    const service = await createSignedInService();
    renderApp(service, '/health/recovery-emails');
    const group = await screen.findByRole('list', { name: 'Recovery emails without two-step sign-in' }, { timeout: 5000 });
    const row = within(group).getByRole('link', { name: /Email/ });
    expect(row).toHaveTextContent('maya@example.com');
    expect(row).toHaveTextContent(/Resets \d+ logins/);
    expect(screen.getByRole('link', { name: 'View the recovery map' })).toHaveAttribute('href', '/health/recovery');
  });

  it('groups logins by recovery email and phone', async () => {
    const service = await createSignedInService();
    renderApp(service, '/health/recovery');
    const mailbox = await screen.findByRole('region', { name: 'maya@example.com' }, { timeout: 5000 });
    expect(within(mailbox).getByRole('heading')).toHaveTextContent(/^\d+ accounts can be reset through maya@example.com$/);
    expect(within(mailbox).getByRole('link', { name: 'Its own login has no two-step sign-in' })).toBeInTheDocument();
    expect(within(mailbox).getByRole('link', { name: /GitHub/ })).toBeInTheDocument();
    const phone = screen.getByRole('region', { name: '+44 7700 900123' });
    expect(within(phone).getByRole('link', { name: /Northwind Bank/ })).toBeInTheDocument();
    expect(screen.getByText(/doesn’t check recovery emails against data breaches yet/)).toBeInTheDocument();
  });
});
