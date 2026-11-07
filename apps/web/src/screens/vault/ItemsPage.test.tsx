import { emptyDraft, type ItemType } from '@octapass/vault-client';
import { DEFAULT_SERVER_URL, MockVaultService } from '@octapass/vault-client/mock';
import { screen, waitFor, within } from '@testing-library/react';
import { COMBINE_SITES_STORAGE_KEY, LIST_STORAGE_KEY } from '../../lib/listArrangement';
import { EMAIL, PASSWORD, renderApp } from '../../test/renderApp';

let db = 0;

/** A signed-in account with only these items, instead of the demo vault. */
async function withItems(items: [ItemType, string, string?][]): Promise<MockVaultService> {
  const service = await MockVaultService.create({ dbName: `items-page-${db++}`, latency: [0, 0], seed: false, fetch: async () => new Response('') });
  const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: EMAIL, password: PASSWORD });
  await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
  const [vault] = await service.listVaults();
  for (const [type, title, url] of items) {
    const draft = emptyDraft(type, vault!.id);
    await service.saveItem({ ...draft, overview: { ...draft.overview, title, ...(url ? { urls: [url] } : {}) } });
  }
  return service;
}

const SAMPLE: [ItemType, string][] = [
  ['login', 'Zoom'],
  ['card', 'Visa'],
  ['login', 'amazon'],
  ['secureNote', 'Wi-Fi at home'],
  ['login', 'بنك الخليج'],
  ['login', '2FA backup'],
];

/** Each section's name and the titles of its rows, in order. */
function sections() {
  return Array.from(document.querySelectorAll('section[data-section]')).map((section) => [
    section.querySelector('h2 bdi')!.textContent,
    Array.from(section.querySelectorAll('li')).map((row) => row.querySelector('bdi')!.textContent),
  ]);
}

async function rows() {
  await screen.findAllByRole('link', { name: /./ });
  return Array.from(document.querySelectorAll('a[data-item-id]')).map((row) => row.querySelector('bdi')!.textContent);
}

// Each test signs up a fresh account, which derives keys: slower than most component tests.
describe('item list sorting and grouping', { timeout: 20_000 }, () => {
  it('groups all items by type, in a fixed order, each section in name order with a count', async () => {
    renderApp(await withItems(SAMPLE), '/items/all');
    await screen.findByRole('heading', { name: /Logins/ }, { timeout: 5000 });
    expect(sections()).toEqual([
      ['Logins', ['2FA backup', 'amazon', 'Zoom', 'بنك الخليج']],
      ['Cards', ['Visa']],
      ['Secure notes', ['Wi-Fi at home']],
    ]);
    expect(screen.getByRole('heading', { name: 'Logins 4 items' })).toBeInTheDocument();
  });

  it('changes the order and grouping from the menu, and remembers them for that list', async () => {
    const service = await withItems(SAMPLE);
    const { user, unmount } = renderApp(service, '/items/all');
    await screen.findByRole('heading', { name: /Logins/ }, { timeout: 5000 });

    await user.click(screen.getByRole('button', { name: 'Sort and group' }));
    await user.click(screen.getByRole('menuitemradio', { name: 'Name, Z to A' }));
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    expect(sections()[0]).toEqual(['Logins', ['بنك الخليج', 'Zoom', 'amazon', '2FA backup']]);

    await user.click(screen.getByRole('button', { name: 'Sort and group' }));
    expect(screen.getByRole('menuitemradio', { name: 'Name, Z to A' })).toHaveAttribute('aria-checked', 'true');
    await user.click(screen.getByRole('menuitemradio', { name: 'None' }));
    expect(document.querySelector('section[data-section]')).toBeNull();
    expect(await rows()).toEqual(['بنك الخليج', 'Zoom', 'Wi-Fi at home', 'Visa', 'amazon', '2FA backup']);

    expect(JSON.parse(localStorage.getItem(LIST_STORAGE_KEY)!)).toEqual({ all: { sort: 'nameDesc', grouping: 'none' } });
    unmount();
    renderApp(service, '/items/all');
    expect(await rows()).toEqual(['بنك الخليج', 'Zoom', 'Wi-Fi at home', 'Visa', 'amazon', '2FA backup']);
  });

  it('groups by first letter: Latin letters, Arabic letters, then #', async () => {
    const { user } = renderApp(await withItems(SAMPLE), '/items/all');
    await user.click(await screen.findByRole('button', { name: 'Sort and group' }));
    await user.click(screen.getByRole('menuitemradio', { name: 'First letter' }));
    expect(sections()).toEqual([
      ['A', ['amazon']],
      ['V', ['Visa']],
      ['W', ['Wi-Fi at home']],
      ['Z', ['Zoom']],
      ['ب', ['بنك الخليج']],
      ['#', ['2FA backup']],
    ]);
  });

  it('starts a list of one type by first letter, and doesn’t offer grouping by type there', async () => {
    const { user } = renderApp(await withItems(SAMPLE), '/items/login');
    await screen.findByRole('heading', { name: 'A 1 item' }, { timeout: 5000 });
    expect(sections().map(([name]) => name)).toEqual(['A', 'Z', 'ب', '#']);
    await user.click(screen.getByRole('button', { name: 'Sort and group' }));
    const groupBy = within(screen.getByRole('group', { name: 'Group by' }));
    expect(groupBy.getAllByRole('menuitemradio').map((item) => item.textContent)).toEqual(['First letter', 'None']);
    expect(groupBy.getByRole('menuitemradio', { name: 'First letter' })).toHaveAttribute('aria-checked', 'true');
  });

  it('works from the keyboard: focus starts on the current choice, arrows move, Escape returns', async () => {
    const { user } = renderApp(await withItems(SAMPLE), '/items/all');
    const button = await screen.findByRole('button', { name: 'Sort and group' });
    button.focus();
    await user.keyboard('{Enter}');
    await waitFor(() => expect(screen.getByRole('menuitemradio', { name: 'Name, A to Z' })).toHaveFocus());
    await user.keyboard('{ArrowDown}');
    expect(screen.getByRole('menuitemradio', { name: 'Name, Z to A' })).toHaveFocus();
    await user.keyboard('{End}');
    expect(screen.getByRole('menuitemcheckbox', { name: 'Combine accounts for the same website' })).toHaveFocus();
    await user.keyboard('{ArrowUp}');
    expect(screen.getByRole('menuitemradio', { name: 'None' })).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    expect(button).toHaveFocus();
  });

  it('shows search results without groups, in name order, with a note', async () => {
    const { user } = renderApp(await withItems(SAMPLE), '/items/all');
    await screen.findByRole('heading', { name: /Logins/ }, { timeout: 5000 });
    await user.type(screen.getByRole('searchbox', { name: 'Search' }), 'a');
    await screen.findByText('Search results are in name order, without groups.');
    expect(document.querySelector('section[data-section]')).toBeNull();
    expect(await rows()).toEqual(['2FA backup', 'amazon', 'Visa', 'Wi-Fi at home']);
  });

  it('keeps the trash in deletion order, without the menu', async () => {
    const service = await withItems(SAMPLE.slice(0, 2));
    for (const item of await service.listItems()) await service.deleteItem(item.id);
    renderApp(service, '/items/trash');
    await screen.findByRole('heading', { name: 'Trash' });
    await rows();
    expect(screen.queryByRole('button', { name: 'Sort and group' })).not.toBeInTheDocument();
    expect(document.querySelector('section[data-section]')).toBeNull();
  });

  it('labels sections and choices in Arabic, with Arabic letters first', async () => {
    localStorage.setItem('octapass:settings', JSON.stringify({ language: 'ar' }));
    const { user } = renderApp(await withItems(SAMPLE), '/items/all');
    await screen.findByRole('heading', { name: /بيانات الدخول/ }, { timeout: 5000 });
    expect(sections().map(([name]) => name)).toEqual(['بيانات الدخول', 'البطاقات', 'الملاحظات الآمنة']);
    await user.click(screen.getByRole('button', { name: 'الترتيب والتجميع' }));
    await user.click(screen.getByRole('menuitemradio', { name: 'الحرف الأول' }));
    expect(sections().map(([name]) => name)).toEqual(['ب', 'A', 'V', 'W', 'Z', '#']);
  });
});

const SITES: [ItemType, string, string?][] = [
  ['login', 'Work', 'https://a.xxx.com/login'],
  ['login', 'Personal', 'a.xxx.com'],
  ['login', 'Shared inbox', 'https://www.a.xxx.com'],
  ['login', 'Billing', 'https://b.xxx.com'],
  ['login', 'Zoom', 'https://zoom.us'],
  ['card', 'Visa'],
];

/** The rows of the list as shown: titles, and `[host, count text, open]` for a website's row. */
function visibleRows() {
  return Array.from(document.querySelectorAll<HTMLElement>('a[data-item-id], button[data-site]')).map((row) =>
    row.dataset.site ? [row.dataset.site, row.querySelectorAll('span span')[1]!.textContent, row.getAttribute('aria-expanded')] : row.querySelector('bdi')!.textContent,
  );
}

describe('logins for the same website', { timeout: 20_000 }, () => {
  it('share one row, by host, inside the Logins section; a site with one login stays a normal row', async () => {
    renderApp(await withItems(SITES), '/items/all');
    await screen.findByRole('button', { name: /a\.xxx\.com/ }, { timeout: 5000 });
    expect(visibleRows()).toEqual([['a.xxx.com', '3 accounts', 'false'], 'Billing', 'Zoom', 'Visa']);
    expect(screen.getByRole('heading', { name: 'Logins 5 items' })).toBeInTheDocument();
  });

  it('opens in place with the logins under it, closes again, and stays open across lists', async () => {
    const { user } = renderApp(await withItems(SITES), '/items/all');
    const site = await screen.findByRole('button', { name: /a\.xxx\.com/ }, { timeout: 5000 });
    await user.click(site);
    expect(site).toHaveAttribute('aria-expanded', 'true');
    const logins = screen.getByRole('list', { name: 'a.xxx.com' });
    expect(site).toHaveAttribute('aria-controls', logins.id);
    expect(within(logins).getAllByRole('link').map((link) => link.querySelector('bdi')!.textContent)).toEqual(['Personal', 'Shared inbox', 'Work']);
    expect(visibleRows()).toEqual([['a.xxx.com', '3 accounts', 'true'], 'Personal', 'Shared inbox', 'Work', 'Billing', 'Zoom', 'Visa']);

    await user.click(within(logins).getByRole('link', { name: 'Work' }));
    await user.click(screen.getByRole('link', { name: /^Logins/ }));
    expect(await screen.findByRole('button', { name: /a\.xxx\.com/ })).toHaveAttribute('aria-expanded', 'true');

    await user.click(screen.getByRole('button', { name: /a\.xxx\.com/ }));
    expect(screen.getByRole('button', { name: /a\.xxx\.com/ })).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('list', { name: 'a.xxx.com' })).not.toBeInTheDocument();
  });

  it('works from the keyboard: arrows reach the site row, Enter opens it, arrows go on into its logins', async () => {
    const { user } = renderApp(await withItems(SITES), '/items/all');
    await screen.findByRole('button', { name: /a\.xxx\.com/ }, { timeout: 5000 });
    await user.click(screen.getByRole('searchbox', { name: 'Search' }));
    await user.keyboard('{ArrowDown}');
    expect(screen.getByRole('button', { name: /a\.xxx\.com/ })).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(screen.getByRole('button', { name: /a\.xxx\.com/ })).toHaveAttribute('aria-expanded', 'true');
    await user.keyboard('{ArrowDown}');
    expect(screen.getByRole('link', { name: 'Personal' })).toHaveFocus();
  });

  it('opens by itself when one of its logins is the item showing', async () => {
    const service = await withItems(SITES);
    const work = (await service.listItems()).find((item) => item.title === 'Work')!;
    renderApp(service, `/items/all/${work.id}`);
    expect(await screen.findByRole('button', { name: /a\.xxx\.com/ }, { timeout: 5000 })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('link', { name: 'Work' })).toHaveAttribute('aria-current', 'page');
  });

  it('can be turned off from the menu, which this device remembers', async () => {
    const service = await withItems(SITES);
    const { user, unmount } = renderApp(service, '/items/all');
    await screen.findByRole('button', { name: /a\.xxx\.com/ }, { timeout: 5000 });
    await user.click(screen.getByRole('button', { name: 'Sort and group' }));
    const toggle = screen.getByRole('menuitemcheckbox', { name: 'Combine accounts for the same website' });
    expect(toggle).toHaveAttribute('aria-checked', 'true');
    await user.click(toggle);
    expect(visibleRows()).toEqual(['Billing', 'Personal', 'Shared inbox', 'Work', 'Zoom', 'Visa']);
    expect(localStorage.getItem(COMBINE_SITES_STORAGE_KEY)).toBe('off');
    unmount();
    renderApp(service, '/items/login');
    await screen.findByRole('link', { name: 'Work' }, { timeout: 5000 });
    expect(document.querySelector('button[data-site]')).toBeNull();
  });

  it('sits with its host’s first letter, and isn’t offered in a list without logins', async () => {
    const { user } = renderApp(await withItems(SITES), '/items/login');
    await screen.findByRole('button', { name: /a\.xxx\.com/ }, { timeout: 5000 });
    expect(sections().map(([name]) => name)).toEqual(['A', 'B', 'Z']);
    await user.click(screen.getByRole('link', { name: /^Cards/ }));
    await screen.findByRole('link', { name: 'Visa' });
    await user.click(screen.getByRole('button', { name: 'Sort and group' }));
    expect(screen.queryByRole('menuitemcheckbox')).not.toBeInTheDocument();
  });

  it('lists every login on its own in search results', async () => {
    const { user } = renderApp(await withItems(SITES), '/items/all');
    await screen.findByRole('button', { name: /a\.xxx\.com/ }, { timeout: 5000 });
    await user.type(screen.getByRole('searchbox', { name: 'Search' }), 'xxx');
    await waitFor(() => expect(document.querySelector('button[data-site]')).toBeNull());
    expect(await rows()).toEqual(['Billing', 'Personal', 'Shared inbox', 'Work']);
  });

  it('counts accounts in Arabic', async () => {
    localStorage.setItem('octapass:settings', JSON.stringify({ language: 'ar' }));
    const { user } = renderApp(await withItems(SITES), '/items/all');
    await screen.findByRole('button', { name: /a\.xxx\.com/ }, { timeout: 5000 });
    expect(visibleRows()[0]).toEqual(['a.xxx.com', '3 حسابات', 'false']);
    await user.click(screen.getByRole('button', { name: 'الترتيب والتجميع' }));
    expect(screen.getByRole('menuitemcheckbox', { name: 'جمع حسابات الموقع نفسه في صف واحد' })).toBeInTheDocument();
  });
});

const SECRET = 'JBSWY3DPEHPK3PXP';

/** A login with a one-time code, a code saved on its own, and a login without one. */
async function withCodes(): Promise<MockVaultService> {
  const service = await withItems([['login', 'No code', 'https://plain.example']]);
  const [vault] = await service.listVaults();
  await service.saveItem({
    vaultId: vault!.id,
    overview: { schemaVersion: 1, type: 'login', title: 'GitHub', subtitle: 'maya', urls: ['https://github.com'] },
    details: { schemaVersion: 1, username: 'maya', password: 'x', totp: SECRET },
  });
  await service.saveItem({
    vaultId: vault!.id,
    overview: { schemaVersion: 1, type: 'password', title: 'Bank code' },
    details: { schemaVersion: 1, totp: `otpauth://totp/Bank:maya?secret=${SECRET}` },
  });
  return service;
}

describe('the one-time codes list', { timeout: 20_000 }, () => {
  it('is a category next to Passkeys, with a count of the items that have a code', async () => {
    renderApp(await withCodes(), '/items/all');
    const categories = await screen.findByRole('link', { name: /^One-time codes/ }, { timeout: 5000 });
    await waitFor(() => expect(categories).toHaveTextContent('One-time codes2'));
    const names = Array.from(categories.closest('ul')!.querySelectorAll('a')).map((link) => link.textContent!.replace(/\d+$/, ''));
    expect(names.slice(0, 3)).toEqual(['Logins', 'Passkeys', 'One-time codes']);
  });

  it('lists logins with a code and codes on their own, each with its live code that copies', async () => {
    const service = await withCodes();
    const { user } = renderApp(service, '/items/codes');
    await screen.findByRole('heading', { name: 'One-time codes', level: 1 }, { timeout: 5000 });
    expect(await rows()).toEqual(['Bank code', 'GitHub']);
    const copy = await screen.findByRole('button', { name: 'Copy the one-time code for GitHub' });
    await waitFor(() => expect(copy).toBeEnabled());
    expect(copy.textContent).toMatch(/^\d{3} \d{3}$/);
    // Logins for one website aren't combined here, so every code stays in view.
    await user.click(screen.getByRole('button', { name: 'Sort and group' }));
    expect(screen.queryByRole('menuitemcheckbox')).not.toBeInTheDocument();
    await user.keyboard('{Escape}');

    await user.click(copy);
    const expected = (await service.totpCode(SECRET)).code;
    expect(await navigator.clipboard.readText()).toBe(expected);
    expect((await screen.findAllByText('One-time code copied. Clears in 30 seconds'))[0]).toBeInTheDocument();
  });

  it('says what goes there when nothing has a code', async () => {
    renderApp(await withItems([['login', 'No code']]), '/items/codes');
    expect(await screen.findByRole('heading', { name: 'No one-time codes yet' }, { timeout: 5000 })).toBeInTheDocument();
  });

  it('is named in Arabic', async () => {
    localStorage.setItem('octapass:settings', JSON.stringify({ language: 'ar' }));
    renderApp(await withCodes(), '/items/codes');
    expect(await screen.findByRole('heading', { name: 'الرموز لمرة واحدة', level: 1 }, { timeout: 5000 })).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: /^نسخ الرمز لمرة واحدة لـ \u2068?GitHub\u2069?$/ })).toBeInTheDocument();
  });
});
