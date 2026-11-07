import { appUrl, isAppTabUrl, openApp, type AppTabApis } from './appTab';

const BASE = 'chrome-extension://abc/';
const getURL = (path: string) => `${BASE}${path}`;

function apis(open: { tabId: number; windowId: number }[] = [], tabs: Record<number, { index: number; windowId: number }> = { 5: { index: 2, windowId: 1 } }) {
  const fake = {
    getURL,
    tabs: {
      get: vi.fn(async (id: number) => {
        const tab = tabs[id];
        if (!tab) throw new Error('No tab');
        return { id, ...tab };
      }),
      create: vi.fn(async () => undefined),
      update: vi.fn(async () => undefined),
    },
    focusWindow: vi.fn(async () => undefined),
    appTabs: vi.fn(async () => open),
  } satisfies AppTabApis;
  return fake;
}

describe('the app tab', () => {
  it('opens next to the page the button was clicked on, for that page', async () => {
    const fake = apis();
    await openApp(fake, { from: 5 });
    expect(fake.tabs.create).toHaveBeenCalledWith({ url: `${BASE}app.html?tab=5`, active: true, windowId: 1, index: 3, openerTabId: 5 });
  });

  it('brings back the one already open in that window instead of opening another', async () => {
    const fake = apis([
      { tabId: 8, windowId: 2 },
      { tabId: 9, windowId: 1 },
    ]);
    await openApp(fake, { from: 5 });
    expect(fake.tabs.create).not.toHaveBeenCalled();
    expect(fake.tabs.update).toHaveBeenCalledWith(9, { active: true });
    expect(fake.focusWindow).toHaveBeenCalledWith(1);
  });

  it('takes an open one to a path, such as a scan or an unlock to come back from', async () => {
    const fake = apis([{ tabId: 9, windowId: 1 }]);
    await openApp(fake, { from: 5, back: true });
    expect(fake.tabs.update).toHaveBeenCalledWith(9, { active: true, url: `${BASE}app.html?tab=5&back=1` });
    await openApp(fake, { from: 5, path: '/scan' });
    expect(fake.tabs.update).toHaveBeenLastCalledWith(9, { active: true, url: `${BASE}app.html?tab=5&path=%2Fscan` });
  });

  it('does nothing when clicked on the app tab itself', async () => {
    const fake = apis([{ tabId: 5, windowId: 1 }]);
    await openApp(fake, { from: 5 });
    expect(fake.tabs.create).not.toHaveBeenCalled();
    expect(fake.tabs.update).not.toHaveBeenCalled();
  });

  it('opens on its own when the page is gone', async () => {
    const fake = apis([], {});
    await openApp(fake, { from: 5 });
    expect(fake.tabs.create).toHaveBeenCalledWith({ url: `${BASE}app.html?tab=5`, active: true });
  });

  it('tells the app tab from the prompt windows, which load the same page', () => {
    expect(isAppTabUrl(getURL, `${BASE}app.html?tab=5`)).toBe(true);
    expect(isAppTabUrl(getURL, `${BASE}app.html`)).toBe(true);
    expect(isAppTabUrl(getURL, `${BASE}app.html?view=window&path=%2Fhttp-auth%2F1`)).toBe(false);
    expect(isAppTabUrl(getURL, `${BASE}passkey.html#1`)).toBe(false);
    expect(isAppTabUrl(getURL, undefined)).toBe(false);
    expect(appUrl(getURL, { back: true })).toBe(`${BASE}app.html`);
  });
});
