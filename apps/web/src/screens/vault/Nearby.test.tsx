import { screen, waitFor, within } from '@testing-library/react';
import type { ItemDraft, LocationService, PlaceData } from '@octapass/vault-client';
import { DEFAULT_SERVER_URL, type MockVaultService } from '@octapass/vault-client/mock';
import { createService, EMAIL, PASSWORD, renderApp } from '../../test/renderApp';
import { placeFromForm } from './Nearby';

const OFFICE = { latitude: 51.507351, longitude: -0.127758 };
/** A point `metres` north of the office. */
const north = (metres: number) => ({ latitude: OFFICE.latitude + metres / 111_195, longitude: OFFICE.longitude });

/** A signed-in account without the demo vault. */
async function account(): Promise<{ service: MockVaultService; vaultId: string }> {
  const service = await createService();
  const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: EMAIL, password: PASSWORD });
  await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
  for (const item of await service.listItems()) await service.deleteItem(item.id);
  const [vault] = await service.listVaults();
  return { service, vaultId: vault!.id };
}

async function place(service: MockVaultService, vaultId: string, title: string, data: PlaceData): Promise<string> {
  return (await service.saveItem({ vaultId, overview: { schemaVersion: 1, type: 'place', title, place: data }, details: { schemaVersion: 1 } } as ItemDraft)).id;
}

async function item(service: MockVaultService, vaultId: string, type: 'login' | 'secureNote', title: string, places: string[]): Promise<string> {
  const details = type === 'secureNote' ? { schemaVersion: 1, notes: 'n' } : { schemaVersion: 1, username: 'u' };
  return (await service.saveItem({ vaultId, overview: { schemaVersion: 1, type, title, ...(places.length && { places }) }, details } as ItemDraft)).id;
}

/** Location on, read from `at` (or refused). */
function locate(service: MockVaultService, at: { latitude: number; longitude: number } | 'denied') {
  localStorage.setItem('octapass:nearby-location', 'on');
  const location: LocationService = {
    permission: async () => (at === 'denied' ? 'denied' : 'granted'),
    current: async () => (at === 'denied' ? Promise.reject(new Error('denied')) : { ...at, accuracy: 15 }),
  };
  Object.assign(service, { location });
}

/** The places as listed, top to bottom: their headings. */
function placeHeadings(): string[] {
  return Array.from(document.querySelectorAll('[data-testid^="place-"] > header h2')).map((heading) => heading.textContent ?? '');
}

beforeEach(() => localStorage.clear());

describe('Nearby', { timeout: 30_000 }, () => {
  it('lists the place you’re at first, its items by type, then the others nearest first', async () => {
    const { service, vaultId } = await account();
    const office = await place(service, vaultId, 'Office', { ...OFFICE, radius: 100 });
    const cafe = await place(service, vaultId, 'Café', north(900));
    await place(service, vaultId, 'Attic', { networks: ['Attic'] });
    const cabin = await place(service, vaultId, 'Cabin', north(40_000));
    await item(service, vaultId, 'secureNote', 'Door code', [office]);
    await item(service, vaultId, 'login', 'Printer', [office]);
    await item(service, vaultId, 'secureNote', 'Alarm code', [office, cabin]);
    await item(service, vaultId, 'login', 'Coffee club', [cafe]);
    locate(service, north(30));

    renderApp(service, '/items/nearby');
    await waitFor(() => expect(placeHeadings()).toEqual(['Now nearby: Office', 'Café', 'Cabin', 'Attic']), { timeout: 10_000 });
    const here = screen.getByTestId(`place-${office}`);
    expect(within(here).getByText('By your location')).toBeInTheDocument();
    const sections = Array.from(here.querySelectorAll('section')).map((section) => [section.querySelector('h2 bdi')!.textContent, Array.from(section.querySelectorAll('a[data-item-id]')).map((row) => row.querySelector('bdi')!.textContent)]);
    expect(sections).toEqual([
      ['Logins', ['Printer']],
      ['Secure notes', ['Alarm code', 'Door code']],
    ]);
    expect(screen.getByText('Your other places')).toBeInTheDocument();
    expect(within(screen.getByTestId(`place-${cafe}`)).getByText('870 m away')).toBeInTheDocument();
    expect(within(screen.getByTestId(`place-${cabin}`)).getByText('40 km away')).toBeInTheDocument();
  });

  it('lists every place by name, none nearby, and says why when the location is off or refused', async () => {
    const { service, vaultId } = await account();
    await place(service, vaultId, 'Office', OFFICE);
    await place(service, vaultId, 'Attic', {});
    const { unmount } = renderApp(service, '/items/nearby');
    await waitFor(() => expect(placeHeadings()).toEqual(['Attic', 'Office']), { timeout: 10_000 });
    expect(await screen.findByText(/doesn’t use your location here/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Use my location' })).toBeInTheDocument();
    unmount();

    locate(service, 'denied');
    renderApp(service, '/items/nearby');
    expect(await screen.findByText(/Location is blocked for Octa Pass/, {}, { timeout: 10_000 })).toBeInTheDocument();
    expect(placeHeadings()).toEqual(['Attic', 'Office']);
  });

  it('saves a new place from the form, with the location read on the device', async () => {
    const { service } = await account();
    locate(service, OFFICE);
    const { user } = renderApp(service, '/items/nearby');
    expect(await screen.findByText('Save your first place', {}, { timeout: 10_000 })).toBeInTheDocument();
    await user.click(screen.getAllByRole('button', { name: 'New place' })[0]!);
    const dialog = await screen.findByRole('dialog', { name: 'New place' });
    await user.type(within(dialog).getByLabelText('Name'), 'Office');
    await user.click(within(dialog).getByRole('button', { name: 'Use my current location' }));
    await waitFor(() => expect(within(dialog).getByLabelText('Latitude')).toHaveValue(OFFICE.latitude.toFixed(6)));
    await user.type(within(dialog).getByPlaceholderText('Network name'), 'Office 5G');
    await user.click(within(dialog).getByRole('button', { name: 'Add network' }));
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(async () => expect((await service.listItems({ type: 'place' })).map((one) => [one.title, one.place])).toEqual([['Office', { ...OFFICE, networks: ['Office 5G'] }]]));
    await waitFor(() => expect(placeHeadings()).toEqual(['Now nearby: Office']), { timeout: 10_000 });
  });

  it('adds an item to a place from its page, and takes it off again', async () => {
    const { service, vaultId } = await account();
    const office = await place(service, vaultId, 'Office', OFFICE);
    const printer = await item(service, vaultId, 'login', 'Printer', []);
    const { user } = renderApp(service, `/items/all/${printer}`);
    await user.click(await screen.findByRole('button', { name: 'Add to a place' }, { timeout: 10_000 }));
    await user.click(await screen.findByRole('menuitem', { name: 'Office' }));
    await waitFor(async () => expect((await service.getItem(printer)).overview.places).toEqual([office]));
    await user.click(await screen.findByRole('button', { name: 'Remove from Office' }));
    await waitFor(async () => expect((await service.getItem(printer)).overview.places).toBeUndefined());
  });

  it('offers a new item the place you’re at once, and never when turned off', async () => {
    const { service, vaultId } = await account();
    const office = await place(service, vaultId, 'Office', OFFICE);
    locate(service, north(20));
    const { user } = renderApp(service, '/items/all/new?type=secureNote');
    await user.type(await screen.findByLabelText('Title', {}, { timeout: 10_000 }), 'Door code');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    const offer = await screen.findByText('You’re at Office. Add this item to it?', {}, { timeout: 10_000 });
    await user.click(within(offer.parentElement!).getByRole('button', { name: 'Add' }));
    const door = (await service.listItems()).find((one) => one.title === 'Door code')!;
    await waitFor(async () => expect((await service.getItem(door.id)).overview.places).toEqual([office]));
    expect(screen.queryByText('You’re at Office. Add this item to it?')).not.toBeInTheDocument();
  });

  it('doesn’t offer a place when the suggestion is turned off', async () => {
    const { service, vaultId } = await account();
    await place(service, vaultId, 'Office', OFFICE);
    locate(service, OFFICE);
    localStorage.setItem('octapass:nearby-suggest', 'off');
    const { user } = renderApp(service, '/items/all/new?type=secureNote');
    await user.type(await screen.findByLabelText('Title', {}, { timeout: 10_000 }), 'Alarm');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByRole('heading', { name: 'Alarm' }, { timeout: 10_000 })).toBeInTheDocument();
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(screen.queryByText(/Add this item to it\?/)).not.toBeInTheDocument();
  });
});

describe('the place form', () => {
  it('keeps both coordinates or neither, and the radius and networks in bounds', () => {
    expect(placeFromForm({ latitude: '51.5073519', longitude: '-0,1277', radius: '150', networks: ['A', 'A', ''] })).toEqual({ latitude: 51.507352, longitude: -0.1277, networks: ['A'] });
    expect(placeFromForm({ latitude: '', longitude: '', radius: '3', networks: [] })).toEqual({ radius: 25 });
    expect(placeFromForm({ latitude: '91', longitude: '0', radius: '', networks: [] })).toBeUndefined();
    expect(placeFromForm({ latitude: '10', longitude: '', radius: '', networks: [] })).toBeUndefined();
    expect(placeFromForm({ latitude: '', longitude: '', radius: '20000', networks: ['x'.repeat(33)] })).toEqual({ radius: 10_000 });
  });
});
