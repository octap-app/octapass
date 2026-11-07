import { screen, waitFor } from '@testing-library/react';
import { createSignedInService, renderApp } from '../../test/renderApp';

describe('vault layout on a narrow screen', () => {
  beforeEach(() => {
    vi.stubGlobal('matchMedia', (query: string) => ({ matches: true, media: query, addEventListener: () => {}, removeEventListener: () => {} }));
  });
  afterEach(() => vi.unstubAllGlobals());

  it('keeps the closed drawer out of reach, and handles focus like a dialog when open', async () => {
    const service = await createSignedInService();
    const { user } = renderApp(service, '/items/all');

    await screen.findByRole('heading', { name: 'All items' });
    const vaultNav = document.querySelector('nav[aria-label="Vault"]')!;
    expect(vaultNav.parentElement).toHaveAttribute('inert');

    const menu = screen.getByRole('button', { name: 'Open menu' });
    await user.click(menu);
    expect(vaultNav.parentElement).not.toHaveAttribute('inert');
    await waitFor(() => expect(vaultNav.contains(document.activeElement)).toBe(true));

    await user.keyboard('{Escape}');
    expect(vaultNav.parentElement).toHaveAttribute('inert');
    expect(menu).toHaveFocus();
  });
});
