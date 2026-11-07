import { emptyDraft, type LoginDetails } from '@octapass/vault-client';
import { DEFAULT_SERVER_URL, MockVaultService } from '@octapass/vault-client/mock';
import { screen, waitFor, within } from '@testing-library/react';
import { usageTrackerFor } from '../../lib/usage';
import { EMAIL, PASSWORD, renderApp } from '../../test/renderApp';

let db = 0;

/** A signed-in account with these logins, saved in this order, instead of the demo vault. */
async function withLogins(titles: string[]): Promise<MockVaultService> {
  const service = await MockVaultService.create({ dbName: `quick-lists-${db++}`, latency: [0, 0], seed: false, fetch: async () => new Response('') });
  const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: EMAIL, password: PASSWORD });
  await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
  const [vault] = await service.listVaults();
  for (const title of titles) {
    const draft = emptyDraft('login', vault!.id);
    await service.saveItem({ ...draft, overview: { ...draft.overview, title }, details: { ...(draft.details as LoginDetails), username: `${title.toLowerCase()}@example.com`, password: 'pw' } });
    // Each one a moment after the last, so their dates differ.
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  return service;
}

/** Waits for the list to show these titles, in this order. */
async function expectRows(titles: string[]) {
  await waitFor(() => expect(Array.from(document.querySelectorAll('a[data-item-id]')).map((row) => row.querySelector('bdi')!.textContent)).toEqual(titles), { timeout: 5000 });
}

// Each test signs up a fresh account, which derives keys: slower than most component tests.
describe('the lists above the vaults', { timeout: 20_000 }, () => {
  it('come in order between All items and the vaults, with Nearby marked as coming soon', async () => {
    renderApp(await withLogins(['GitHub']), '/items/all');
    const nav = await screen.findByRole('navigation', { name: 'Vault' });
    await within(nav).findByRole('link', { name: /Personal/ }, { timeout: 5000 });
    const list = within(nav).getByRole('heading', { name: 'Vaults' }).nextElementSibling as HTMLElement;
    // Each row's own label, without its count or badge.
    const labels = Array.from(list.querySelectorAll('li')).map((row) => row.querySelector('svg + span')?.firstChild?.textContent);
    expect(labels).toEqual(['All items', 'Recently created', 'Nearby', 'Pinned', 'Favourites', 'Frequently used', 'Recently used', 'Recently modified', 'Personal', 'New shared vault']);
    expect(within(nav).queryByRole('link', { name: /Nearby/ })).not.toBeInTheDocument();
    expect(within(list).getByText('Soon')).toBeInTheDocument();
  });

  it('pins from the item, and lists pinned items under Pinned with a count', async () => {
    const service = await withLogins(['GitHub', 'Bank']);
    const { user } = renderApp(service, '/items/pinned');
    expect(await screen.findByText('Nothing pinned yet', {}, { timeout: 5000 })).toBeInTheDocument();

    const item = (await service.listItems()).find((one) => one.title === 'Bank')!;
    renderApp(service, `/items/all/${item.id}`);
    const pin = await screen.findByRole('button', { name: 'Pin' });
    expect(pin).toHaveAttribute('aria-pressed', 'false');
    await user.click(pin);
    expect(await screen.findByRole('button', { name: 'Unpin' })).toHaveAttribute('aria-pressed', 'true');
    expect((await service.listItems({ pinned: true })).map((one) => one.title)).toEqual(['Bank']);
    await waitFor(() => expect(screen.getAllByRole('link', { name: /Pinned/ })[0]).toHaveTextContent('1'));
  });

  it('orders Recently created newest first, and Recently modified by the latest change', async () => {
    const service = await withLogins(['First', 'Second', 'Third']);
    const { unmount } = renderApp(service, '/items/created');
    await expectRows(['Third', 'Second', 'First']);
    expect(screen.queryByRole('button', { name: 'Sort and group' })).not.toBeInTheDocument();
    unmount();

    const first = (await service.listItems()).find((one) => one.title === 'First')!;
    await service.saveItem({ ...(await service.getItem(first.id)), overview: { ...(await service.getItem(first.id)).overview, subtitle: 'changed' } });
    renderApp(service, '/items/changed');
    await expectRows(['First', 'Third', 'Second']);
  });

  it('counts copying a field as a use, for Recently used and Frequently used', async () => {
    const service = await withLogins(['GitHub', 'Bank', 'Mail']);
    const items = await service.listItems();
    const id = (title: string) => items.find((one) => one.title === title)!.id;

    const { user, unmount } = renderApp(service, '/items/used');
    expect(await screen.findByText('Nothing used yet', {}, { timeout: 5000 })).toBeInTheDocument();
    unmount();

    // Bank twice, then GitHub once.
    const bank = renderApp(service, `/items/all/${id('Bank')}`);
    await user.click(await screen.findByRole('button', { name: 'Copy Username' }));
    await user.click(screen.getByRole('button', { name: 'Copy Username' }));
    bank.unmount();
    const github = renderApp(service, `/items/all/${id('GitHub')}`);
    await user.click(await screen.findByRole('button', { name: 'Copy Username' }));
    github.unmount();

    // Shown at once, before the uses are saved.
    const used = renderApp(service, '/items/used');
    await expectRows(['GitHub', 'Bank']);
    used.unmount();

    // Then saved in one hidden item, which no list shows.
    await usageTrackerFor(service).flush();
    const hidden = await service.listItems({ type: 'usageStats' });
    expect(hidden).toHaveLength(1);
    expect((await service.listItems()).map((one) => one.title).sort()).toEqual(['Bank', 'GitHub', 'Mail']);

    renderApp(service, '/items/frequent');
    await expectRows(['Bank', 'GitHub']);
  });
});
