import { apply, browserName, readStates, requestPermission, restore, supportedFeatures, type BrowserApis, type PrivacySetting } from './browserSettings';

/** A `chrome.privacy` setting: the browser's value, ours on top of it, and who else may hold it. */
function setting(level = 'controllable_by_this_extension') {
  const state = { browser: true as boolean, ours: undefined as boolean | undefined, level };
  const api: PrivacySetting = {
    get: async () => ({
      value: state.level === 'controlled_by_other_extensions' || state.level === 'not_controllable' ? false : (state.ours ?? state.browser),
      levelOfControl: state.ours !== undefined ? 'controlled_by_this_extension' : state.level,
    }),
    set: vi.fn(async ({ value }: { value: boolean }) => void (state.ours = value)),
    clear: vi.fn(async () => void (state.ours = undefined)),
  };
  return { state, api };
}

function fakeBrowser({ firefox = false, granted = false, levels = {} as Record<string, string> } = {}) {
  const passwords = setting(levels.passwords);
  const addresses = setting(levels.addresses);
  const cards = setting(levels.cards);
  const permission = { granted, answer: true };
  const services: Record<string, PrivacySetting> = firefox
    ? { passwordSavingEnabled: passwords.api }
    : { passwordSavingEnabled: passwords.api, autofillAddressEnabled: addresses.api, autofillCreditCardEnabled: cards.api };
  const apis: BrowserApis = {
    // Like Chrome: `chrome.privacy` only exists once the permission is granted.
    privacy: () => (permission.granted ? { services } : undefined),
    permissions: {
      contains: async () => permission.granted,
      request: vi.fn(async () => (permission.granted = permission.granted || permission.answer)),
      remove: vi.fn(async () => !(permission.granted = false)),
    },
    optional: true,
    firefox,
  };
  return { apis, permission, passwords, addresses, cards };
}

describe('Octa Pass instead of the browser’s password manager', () => {
  it('turns off passwords, addresses and cards in Chrome after asking for the permission', async () => {
    const { apis, passwords, addresses, cards } = fakeBrowser();
    expect(await readStates(apis)).toEqual({ passwords: 'browser', addresses: 'browser', cards: 'browser' });
    expect(await requestPermission(apis)).toBe(true);
    expect(apis.permissions.request).toHaveBeenCalledWith({ permissions: ['privacy'] });
    expect(await apply(apis, ['passwords', 'addresses', 'cards'])).toEqual({ passwords: 'off', addresses: 'off', cards: 'off' });
    for (const s of [passwords, addresses, cards]) expect(s.state.ours).toBe(false);
  });

  it('gives back the features the user unticks, and everything when turned off', async () => {
    const { apis, permission, passwords, addresses, cards } = fakeBrowser({ granted: true });
    await apply(apis, ['passwords', 'addresses', 'cards']);
    expect(await apply(apis, ['passwords'])).toEqual({ passwords: 'off', addresses: 'browser', cards: 'browser' });
    expect(addresses.api.clear).toHaveBeenCalled();
    await restore(apis);
    expect([passwords.state.ours, addresses.state.ours, cards.state.ours]).toEqual([undefined, undefined, undefined]);
    expect(permission.granted).toBe(false);
  });

  it('says so when another extension or a policy holds a setting, and leaves it alone', async () => {
    const { apis, passwords, cards } = fakeBrowser({ granted: true, levels: { passwords: 'controlled_by_other_extensions', cards: 'not_controllable' } });
    expect(await apply(apis, ['passwords', 'addresses', 'cards'])).toEqual({ passwords: 'otherExtension', addresses: 'off', cards: 'policy' });
    expect(passwords.api.set).not.toHaveBeenCalled();
    expect(cards.api.set).not.toHaveBeenCalled();
  });

  it('does nothing when the user declines the permission', async () => {
    const { apis, permission, passwords } = fakeBrowser();
    permission.answer = false;
    expect(await requestPermission(apis)).toBe(false);
    expect(await apply(apis, ['passwords'])).toEqual({ passwords: 'browser', addresses: 'browser', cards: 'browser' });
    expect(passwords.api.set).not.toHaveBeenCalled();
  });

  it('only has passwords in Firefox, and nothing in Safari', async () => {
    const firefox = fakeBrowser({ firefox: true });
    expect(supportedFeatures(firefox.apis)).toEqual(['passwords']);
    firefox.permission.granted = true;
    expect(await apply(firefox.apis, ['passwords', 'addresses', 'cards'])).toEqual({ passwords: 'off', addresses: 'unsupported', cards: 'unsupported' });

    const safari = fakeBrowser();
    safari.apis.optional = false;
    expect(supportedFeatures(safari.apis)).toEqual([]);
    expect(await readStates(safari.apis)).toEqual({ passwords: 'unsupported', addresses: 'unsupported', cards: 'unsupported' });
  });

  it('names the browser', () => {
    expect(browserName('Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36')).toBe('Chrome');
    expect(browserName('Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 Edg/140.0')).toBe('Edge');
    expect(browserName('Mozilla/5.0 (Macintosh; rv:140.0) Gecko/20100101 Firefox/140.0')).toBe('Firefox');
    expect(browserName('Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15')).toBe('Safari');
  });
});
