import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Menu } from './Menu';

function renderMenu(onSelect = vi.fn(), behind = vi.fn()) {
  render(
    <>
      <button onClick={behind}>Behind</button>
      <Menu label="More" items={[{ key: 'share', label: 'Share', onSelect }]} trigger={(props) => <button {...props}>More</button>} />
    </>,
  );
  return { onSelect, behind };
}

describe('Menu', () => {
  const desktop = window.matchMedia;
  afterEach(() => {
    window.matchMedia = desktop;
  });

  it('opens next to its button on wide screens', async () => {
    const { onSelect } = renderMenu();
    await userEvent.click(screen.getByRole('button', { name: 'More' }));
    expect(screen.getByRole('menu').parentElement?.contains(screen.getByRole('button', { name: 'More' }))).toBe(true);
    await userEvent.click(screen.getByRole('menuitem', { name: 'Share' }));
    expect(onSelect).toHaveBeenCalled();
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
  });

  it('opens as a sheet on phones, and the scrim closes it without reaching what’s behind', async () => {
    window.matchMedia = ((query: string) => ({ matches: query.includes('max-width'), media: query, addEventListener: () => {}, removeEventListener: () => {} })) as unknown as typeof window.matchMedia;
    const { onSelect, behind } = renderMenu();
    await userEvent.click(screen.getByRole('button', { name: 'More' }));
    const menu = screen.getByRole('menu');
    expect(menu.parentElement).toBe(document.body);
    expect(screen.getByRole('menuitem', { name: 'Share' })).toHaveFocus();
    await userEvent.click(document.body.querySelector('[aria-hidden="true"]')!);
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    expect(behind).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'More' })).toHaveFocus();

    await userEvent.click(screen.getByRole('button', { name: 'More' }));
    await userEvent.click(screen.getByRole('menuitem', { name: 'Share' }));
    expect(onSelect).toHaveBeenCalled();
  });
});
