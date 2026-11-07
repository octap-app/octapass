import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserAutofillOffer, BrowserAutofillSection } from './BrowserAutofill';
import { BROWSER_AUTOFILL_KEY, type BrowserApis, type PrivacySetting } from './browserSettings';

let stored: Record<string, unknown>;

beforeEach(() => {
  stored = {};
  chrome.storage = {
    local: {
      get: async (key: string) => (key in stored ? { [key]: stored[key] } : {}),
      set: async (items: Record<string, unknown>) => void Object.assign(stored, items),
    },
  } as unknown as typeof chrome.storage;
});

function fake({ level = 'controllable_by_this_extension', answer = true } = {}) {
  const values: Record<string, boolean | undefined> = {};
  const setting = (name: string): PrivacySetting => ({
    get: async () => ({ value: values[name] ?? true, levelOfControl: values[name] === undefined ? level : 'controlled_by_this_extension' }),
    set: async ({ value }) => void (values[name] = value),
    clear: async () => void (values[name] = undefined),
  });
  let granted = false;
  const services = { passwordSavingEnabled: setting('passwords'), autofillAddressEnabled: setting('addresses'), autofillCreditCardEnabled: setting('cards') };
  const apis: BrowserApis = {
    privacy: () => (granted ? { services } : undefined),
    permissions: {
      contains: async () => granted,
      request: vi.fn(async () => (granted = answer)),
      remove: async () => !(granted = false),
    },
    optional: true,
    firefox: false,
  };
  return { apis, values };
}

describe('BrowserAutofillSection', () => {
  it('turns the browser’s password manager off, then gives one feature back', async () => {
    const { apis, values } = fake();
    render(<BrowserAutofillSection apis={apis} />);
    await userEvent.click(await screen.findByRole('switch', { name: 'Use Octa Pass instead of Chrome’s password manager' }));
    expect(apis.permissions.request).toHaveBeenCalledWith({ permissions: ['privacy'] });
    await vi.waitFor(() => expect(values).toEqual({ passwords: false, addresses: false, cards: false }));
    expect(screen.getByRole('switch', { name: 'Payment cards' })).toHaveAttribute('aria-checked', 'true');

    await userEvent.click(screen.getByRole('switch', { name: 'Addresses' }));
    await vi.waitFor(() => expect(values.addresses).toBeUndefined());
    expect(stored[BROWSER_AUTOFILL_KEY]).toEqual({ on: true, offered: true, features: ['passwords', 'cards'] });

    await userEvent.click(screen.getByRole('switch', { name: 'Use Octa Pass instead of Chrome’s password manager' }));
    await vi.waitFor(() => expect(values).toEqual({ passwords: undefined, addresses: undefined, cards: undefined }));
    expect(screen.queryByRole('switch', { name: 'Passwords' })).not.toBeInTheDocument();
  });

  it('says why when another extension holds the setting', async () => {
    const { apis } = fake({ level: 'controlled_by_other_extensions' });
    render(<BrowserAutofillSection apis={apis} />);
    await userEvent.click(await screen.findByRole('switch', { name: /Use Octa Pass instead/ }));
    expect((await screen.findAllByText('Another extension controls this in Chrome.')).length).toBe(3);
  });

  it('stays off when the permission is declined', async () => {
    const { apis } = fake({ answer: false });
    render(<BrowserAutofillSection apis={apis} />);
    const toggle = await screen.findByRole('switch', { name: /Use Octa Pass instead/ });
    await userEvent.click(toggle);
    expect(await screen.findByText('Octa Pass needs permission to change Chrome’s privacy settings to do this.')).toBeInTheDocument();
    expect(toggle).toHaveAttribute('aria-checked', 'false');
  });

  it('shows the steps where the browser doesn’t let extensions change it', async () => {
    const { apis } = fake();
    render(<BrowserAutofillSection apis={{ ...apis, optional: false }} />);
    expect(screen.getByText(/Safari doesn’t let extensions change this/)).toBeInTheDocument();
    expect(screen.queryByRole('switch')).not.toBeInTheDocument();
  });
});

describe('BrowserAutofillOffer', () => {
  it('asks once, and turns it on from the banner', async () => {
    const { apis, values } = fake();
    const { unmount } = render(<BrowserAutofillOffer apis={apis} />);
    await userEvent.click(await screen.findByRole('button', { name: 'Turn on' }));
    await vi.waitFor(() => expect(values.passwords).toBe(false));
    expect(screen.queryByRole('button', { name: 'Turn on' })).not.toBeInTheDocument();
    unmount();
    render(<BrowserAutofillOffer apis={apis} />);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(screen.queryByRole('button', { name: 'Turn on' })).not.toBeInTheDocument();
  });

  it('goes away for good after Not now', async () => {
    const { apis } = fake();
    render(<BrowserAutofillOffer apis={apis} />);
    await userEvent.click(await screen.findByRole('button', { name: 'Not now' }));
    expect(stored[BROWSER_AUTOFILL_KEY]).toMatchObject({ on: false, offered: true });
    expect(apis.permissions.request).not.toHaveBeenCalled();
  });
});
