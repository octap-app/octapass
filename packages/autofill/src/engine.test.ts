import { createAutofill, filterSuggestions, type Autofill, type AutofillOptions } from './engine';
import { captureShadowRoots, html, stubLayout } from './test/layout';
import type { ApiKeyPaste, AutofillHost, BlockReason, SaveReport, Suggestion } from './types';

const LOGIN: Suggestion = { kind: 'login', id: 'l1', title: 'Example', username: 'alex' };
const GENERATED: Suggestion = { kind: 'generated-password', id: 'g1', password: 'Lantern-ruby-T7#qv-42' };

const flush = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms));

let restoreLayout: () => void;
let shadow: ReturnType<typeof captureShadowRoots>;
let engine: Autofill | undefined;
let blocked: BlockReason[];
let saves: SaveReport[];

beforeEach(() => {
  restoreLayout = stubLayout();
  shadow = captureShadowRoots();
  blocked = [];
  saves = [];
});

afterEach(() => {
  engine?.stop();
  engine = undefined;
  shadow.restore();
  restoreLayout();
});

function start(suggestions: Suggestion[], options: Partial<AutofillOptions> = {}): AutofillHost {
  const host: AutofillHost = {
    getSuggestions: vi.fn(async () => suggestions),
    resolve: vi.fn(async () => ({ username: 'alex', 'current-password': 'pw' })),
    onBlocked: (reason) => blocked.push(reason),
    onSave: (report) => saves.push(report),
  };
  engine = createAutofill({ host, testing: { trustAllEvents: true, pickDelayMs: 0 }, ...options });
  return host;
}

const field = (id: string) => document.getElementById(id) as HTMLInputElement;

function menuHost(): HTMLElement | undefined {
  return [...shadow.roots.keys()].find((e) => e.localName === 'octapass-menu' && e.isConnected) as HTMLElement | undefined;
}

/** The menu's options, placed at y 300–400 and reported on top there, as a browser would. */
function options(): HTMLElement[] {
  const host = menuHost();
  if (!host) return [];
  const items = [...shadow.roots.get(host)!.querySelectorAll<HTMLElement>('[role=option]')];
  items.forEach((item, i) => item.setAttribute('data-rect', `0 ${300 + i * 40} 260 36`));
  const stubbed = Document.prototype.elementsFromPoint;
  document.elementsFromPoint = function (x: number, y: number) {
    return y >= 300 && y < 400 ? [host] : stubbed.call(this, x, y);
  };
  return items;
}

async function openMenu(id: string): Promise<HTMLElement[]> {
  field(id).focus();
  field(id).dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, composed: true }));
  await flush();
  return options();
}

function press(element: HTMLElement, key: string) {
  element.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, composed: true }));
}

const LOGIN_FORM = `<form><input id="u" autocomplete="username"><input id="p" type="password"><button>Log in</button></form>`;

// A made-up value in the shape of a GitHub token.
const FAKE_KEY = `ghp_${'FAKE0fake1'.repeat(4)}`.slice(0, 40);
const KEY_FORM = '<form><label>API key <input id="k"></label><label>API secret <input id="s"></label><button>Save</button></form>';

let pasted: ApiKeyPaste[] = [];

function paste(id: string, text: string): ApiKeyPaste[] {
  pasted = [];
  const event = new Event('paste', { bubbles: true, composed: true, cancelable: true });
  Object.defineProperty(event, 'clipboardData', { value: { getData: (type: string) => (type === 'text/plain' ? text : '') } });
  field(id).dispatchEvent(event);
  return pasted;
}

describe('pasted API keys', () => {
  const startPaste = (trusted = true) =>
    start([], {
      testing: { trustAllEvents: trusted, pickDelayMs: 0 },
      host: {
        getSuggestions: async () => [],
        resolve: async () => null,
        onApiKey: (offer) => pasted.push(offer),
      },
    });

  it('reports a key pasted into a key field, or anywhere plain, with the value for the host alone', () => {
    html(`${KEY_FORM}<form><label>Value <textarea id="v"></textarea></label><button>Add</button></form>`);
    startPaste();
    expect(paste('k', FAKE_KEY)).toEqual([{ kind: 'github', value: FAKE_KEY }]);
    expect(paste('v', ` Bearer ${FAKE_KEY}\n`)).toEqual([{ kind: 'github', value: FAKE_KEY }]);
    expect(field('k').getAttribute('value')).toBeNull();
  });

  it('takes a random value only in a field named as a key', () => {
    html(`${KEY_FORM}<form><label>Value <input id="v"></label><button>Add</button></form>`);
    startPaste();
    const value = 'FAKE0TEST1VALUE2NOT3REAL4TOKEN5XYZ';
    expect(paste('k', value)).toEqual([{ kind: 'generic', value }]);
    expect(paste('v', value)).toEqual([]);
  });

  it('never reacts to a password field of a sign-in, sign-up or change-password form', () => {
    html(`${LOGIN_FORM}
      <form><input type="email" name="email" autocomplete="email"><input id="new1" type="password" autocomplete="new-password"><input id="new2" type="password" autocomplete="new-password"><button>Sign up</button></form>`);
    startPaste();
    expect(paste('p', FAKE_KEY)).toEqual([]);
    expect(paste('u', FAKE_KEY)).toEqual([]);
    expect(paste('new1', FAKE_KEY)).toEqual([]);
    expect(paste('new2', FAKE_KEY)).toEqual([]);
  });

  it('stays out of searches, cards, addresses and prose', () => {
    html(`<form role="search"><input id="q" type="search"></form>
      <form><label>Card number <input id="c" autocomplete="cc-number"></label><button>Pay</button></form>
      <form><label>Message <textarea id="m"></textarea></label><button>Send</button></form>
      <form><label>Street <input id="a" autocomplete="street-address"></label><button>Save</button></form>`);
    startPaste();
    expect(paste('q', FAKE_KEY)).toEqual([]);
    expect(paste('c', FAKE_KEY)).toEqual([]);
    expect(paste('a', FAKE_KEY)).toEqual([]);
    expect(paste('m', `my key is ${FAKE_KEY}, please keep it safe`)).toEqual([]);
  });

  it('ignores a paste the page made up', () => {
    html(KEY_FORM);
    startPaste(false);
    expect(paste('k', FAKE_KEY)).toEqual([]);
  });

  it('ignores a hidden field', () => {
    html('<form><label>API key <input id="k" style="display:none"></label></form>');
    startPaste();
    expect(paste('k', FAKE_KEY)).toEqual([]);
  });
});

describe('createAutofill', () => {
  it('fills a login the user picks', async () => {
    html(LOGIN_FORM);
    const host = start([LOGIN]);
    const [item] = await openMenu('u');
    expect(host.getSuggestions).toHaveBeenCalledWith(expect.objectContaining({ fieldType: 'username', formType: 'login' }));
    press(item!, 'Enter');
    await flush();
    expect([field('u').value, field('p').value]).toEqual(['alex', 'pw']);
    expect(blocked).toEqual([]);
    expect(menuHost()).toBeUndefined();
  });

  it('draws website icons for logins inside the closed menu, without a request the page could see', async () => {
    html(LOGIN_FORM);
    const bitmap = { width: 64, height: 64, close: () => {} } as ImageBitmap;
    const decode = vi.fn(async () => bitmap);
    vi.stubGlobal('createImageBitmap', decode);
    const icon = new Blob([new Uint8Array([0x89, 0x50, 0x4e, 0x47])], { type: 'image/png' });
    const host = start([LOGIN, GENERATED]);
    host.siteIcon = vi.fn(async () => icon);
    const before = performance.getEntriesByType('resource').length;
    const [item] = await openMenu('u');
    await flush();
    expect(host.siteIcon).toHaveBeenCalledTimes(1);
    expect(host.siteIcon).toHaveBeenCalledWith(LOGIN);
    expect(decode).toHaveBeenCalledWith(icon);
    const glyph = item!.querySelector('.glyph')!;
    expect(glyph.classList.contains('site')).toBe(true);
    expect(glyph.querySelector('canvas')).not.toBeNull();
    expect(item!.querySelector('img')).toBeNull();
    expect(performance.getEntriesByType('resource')).toHaveLength(before);
    vi.unstubAllGlobals();
  });

  it('keeps the letter tile when a login has no icon, and asks again on a later open, not on every key', async () => {
    html(LOGIN_FORM);
    vi.stubGlobal('createImageBitmap', vi.fn());
    const host = start([LOGIN, { kind: 'login', id: 'l2', title: 'Example two', username: 'alexis' }]);
    host.siteIcon = vi.fn(async () => null);
    const [item] = await openMenu('u');
    await flush();
    const glyph = item!.querySelector<HTMLElement>('.glyph')!;
    expect(glyph.classList.contains('letter')).toBe(true);
    expect(glyph.dataset.letter).toBe('E');
    // Drawn by CSS: the letter isn't part of the entry's text.
    expect(item!.textContent).toBe('Examplealex');
    expect(createImageBitmap).not.toHaveBeenCalled();
    expect(host.siteIcon).toHaveBeenCalledTimes(2);
    type(field('u'), 'al');
    await flush();
    expect(host.siteIcon).toHaveBeenCalledTimes(2);
    vi.unstubAllGlobals();
  });

  it('shows the unlock entry with a lock, no account line and no website icon', async () => {
    html(LOGIN_FORM);
    const host = start([{ kind: 'login', id: 'unlock', title: 'Unlock Octa Pass', pinned: true }]);
    host.siteIcon = vi.fn(async () => null);
    vi.stubGlobal('createImageBitmap', vi.fn());
    const [item] = await openMenu('u');
    expect(item!.textContent).toBe('Unlock Octa Pass');
    expect(item!.querySelector('.glyph.lock svg')).not.toBeNull();
    expect(host.siteIcon).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it('names the site in the header and keeps the header and hints out of the listbox', async () => {
    html(LOGIN_FORM);
    start([LOGIN]);
    await openMenu('u');
    const root = shadow.roots.get(menuHost()!)!;
    expect(root.querySelector('.site')!.textContent).toBe(location.hostname.replace(/^www\./, ''));
    expect(root.querySelector('.head')!.getAttribute('aria-hidden')).toBe('true');
    expect(root.querySelector('.foot')!.textContent).toBe('↑↓Move↵Choose');
    expect(root.querySelector('[role=listbox] .head, [role=listbox] .foot')).toBeNull();
  });

  it('puts a hairline between kinds of suggestion, and shows a suggested password as the password', async () => {
    html(`<form><input id="e" type="email" autocomplete="email"><input id="n" type="password" autocomplete="new-password"><button>Sign up</button></form>`);
    start([{ kind: 'masked-email', id: 'm1' }, { kind: 'identity', id: 'i1', title: 'Home', subtitle: 'Sam' }, { kind: 'identity', id: 'i2', title: 'Work' }, GENERATED]);
    await openMenu('e');
    const list = shadow.roots.get(menuHost()!)!.querySelector('[role=listbox]')!;
    expect([...list.children].map((c) => (c.classList.contains('sep') ? '|' : c.querySelector('.title')!.textContent))).toEqual(['Use a masked email', '|', 'Home', 'Work']);
    expect(list.querySelector('.sep')!.getAttribute('role')).toBe('none');
    field('n').focus();
    const [password] = await openMenu('n');
    const detail = password!.querySelector('.detail.mono')!;
    expect(detail.textContent).toBe(GENERATED.password);
    expect([...detail.querySelectorAll('.n')].map((n) => n.textContent)).toEqual(['7', '42']);
  });

  it('opens on a click in the field and closes on Escape', async () => {
    html(LOGIN_FORM);
    start([LOGIN]);
    field('u').focus();
    field('u').click();
    await flush();
    expect(menuHost()).toBeDefined();
    press(field('u'), 'Escape');
    expect(menuHost()).toBeUndefined();
  });

  it('only offers suggestions that fit the field', async () => {
    html(LOGIN_FORM);
    start([GENERATED, { kind: 'card', id: 'c', title: 'Visa' }, LOGIN]);
    const items = await openMenu('p');
    expect(items).toHaveLength(1);
  });

  it('never opens for search boxes', async () => {
    html(`<input id="q" type="search"><button>Search</button>`);
    const host = start([LOGIN]);
    await openMenu('q');
    expect(host.getSuggestions).not.toHaveBeenCalled();
  });

  it('ignores a synthetic ArrowDown: a page cannot open the menu or move focus into it', async () => {
    html(LOGIN_FORM);
    const host = start([LOGIN], { testing: { pickDelayMs: 0 } });
    expect(await openMenu('u')).toEqual([]);
    expect(host.getSuggestions).not.toHaveBeenCalled();
    expect(field('u').value).toBe('');
  });

  it('refuses a pick right after the menu appears', async () => {
    html(LOGIN_FORM);
    start([LOGIN], { testing: { trustAllEvents: true } });
    const [item] = await openMenu('u');
    press(item!, 'Enter');
    await flush();
    expect(blocked).toEqual(['too-fast']);
    expect(field('u').value).toBe('');
  });

  it('refuses when the page has restyled the menu', async () => {
    html(LOGIN_FORM);
    start([LOGIN]);
    const [item] = await openMenu('u');
    menuHost()!.style.setProperty('opacity', '0', 'important');
    await flush();
    press(item!, 'Enter');
    await flush();
    expect(blocked).toEqual(['menu-tampered']);
    expect(field('u').value).toBe('');
  });

  it('refuses when something now covers the field', async () => {
    html(`${LOGIN_FORM}<div id="cover"></div>`);
    start([LOGIN]);
    const [item] = await openMenu('u');
    const rect = field('u').getBoundingClientRect();
    document.getElementById('cover')!.setAttribute('data-rect', `${rect.x} ${rect.y} ${rect.width} ${rect.height}`);
    press(item!, 'Enter');
    await flush();
    expect(blocked).toEqual(['field-covered']);
    expect(field('u').value).toBe('');
  });

  it('tells the host when the user asks for a see-through field', async () => {
    html(`<form style="opacity:0.05"><input id="u" autocomplete="username"><input id="p" type="password"><button>Log in</button></form>`);
    const host = start([LOGIN]);
    await openMenu('u');
    expect(host.getSuggestions).not.toHaveBeenCalled();
    expect(blocked).toEqual(['field-transparent']);
  });

  it('fills a suggested password into new and confirm fields and saves a draft', async () => {
    html(`<form><input id="e" type="email" autocomplete="email" value="sam@example.test">
      <input id="n" type="password" autocomplete="new-password" minlength="12"><input id="c" type="password" placeholder="Confirm password">
      <button>Create account</button></form>`);
    const host = start([GENERATED]);
    const [item] = await openMenu('n');
    expect(host.getSuggestions).toHaveBeenCalledWith(expect.objectContaining({ passwordConstraints: { minLength: 12 } }));
    press(item!, 'Enter');
    await flush();
    expect([field('n').value, field('c').value]).toEqual([GENERATED.password, GENERATED.password]);
    expect(host.resolve).not.toHaveBeenCalled();
    expect(saves).toEqual([
      expect.objectContaining({ username: 'sam@example.test', password: GENERATED.password, formType: 'signup', draft: true, trigger: 'generated' }),
    ]);
  });

  it('fills a key only into the field it was picked for, after a pick', async () => {
    html(KEY_FORM);
    const host = start([{ kind: 'api-credential', id: 'a1', title: 'Stripe (stripe.com)', subtitle: 'stripe.com' }, LOGIN]);
    vi.mocked(host.resolve).mockResolvedValue({ 'api-credential': 'FAKE-value' });
    const items = await openMenu('k');
    expect(items).toHaveLength(1);
    expect(items[0]!.textContent).toContain('Stripe (stripe.com)');
    expect(items[0]!.textContent).not.toContain('FAKE-value');
    expect(field('k').value).toBe('');
    items[0]!.click();
    await flush();
    expect(field('k').value).toBe('FAKE-value');
    expect(field('s').value).toBe('');
  });

  it('won’t fill a key into a covered field', async () => {
    html(KEY_FORM);
    const host = start([{ kind: 'api-credential', id: 'a1', title: 'Stripe' }]);
    vi.mocked(host.resolve).mockResolvedValue({ 'api-credential': 'FAKE-value' });
    const [item] = await openMenu('k');
    const stubbed = document.elementsFromPoint;
    const cover = document.createElement('div');
    document.body.append(cover);
    document.elementsFromPoint = function (x: number, y: number) {
      return y >= 300 && y < 400 ? stubbed.call(this, x, y) : [cover];
    };
    item!.click();
    await flush();
    expect(blocked).toContain('field-covered');
    expect(field('k').value).toBe('');
  });

  it('shows "Use a masked email" disabled on sign-up email fields', async () => {
    html(`<form><input id="e" type="email"><input id="n" type="password" autocomplete="new-password"><button>Sign up</button></form>`);
    start([]);
    const items = await openMenu('e');
    expect(items).toHaveLength(1);
    expect(items[0]!.getAttribute('aria-disabled')).toBe('true');
    expect(items[0]!.textContent).toContain('Needs setup');
  });

  it('fills a masked email into the field it was asked for, even one marked as the username', async () => {
    html(`<form><input id="e" type="email" autocomplete="username"><input id="r" type="email" placeholder="Recovery email">
      <input id="n" type="password" autocomplete="new-password"><button>Create account</button></form>`);
    const MASKED: Suggestion = { kind: 'masked-email', id: 'm1' };
    const host = start([MASKED]);
    vi.mocked(host.resolve).mockResolvedValue({ email: 'shop.x7k2@alias.example' });
    const [item] = await openMenu('e');
    expect(item!.textContent).toContain('Use a masked email');
    expect(item!.getAttribute('aria-disabled')).not.toBe('true');
    press(item!, 'Enter');
    await flush();
    expect(host.resolve).toHaveBeenCalledWith(MASKED, expect.objectContaining({ fieldType: 'username', formType: 'signup' }));
    expect([field('e').value, field('r').value]).toEqual(['shop.x7k2@alias.example', '']);
  });

  it("doesn't offer a masked email in a sign-up username that isn't an email box", async () => {
    html(`<form><input id="u" autocomplete="username"><input id="n" type="password" autocomplete="new-password"><button>Sign up</button></form>`);
    start([{ kind: 'masked-email', id: 'm1' }]);
    expect(await openMenu('u')).toEqual([]);
  });

  it('asks first in a frame from another site, then shows its suggestions', async () => {
    html(LOGIN_FORM);
    const APPROVAL: Suggestion = { kind: 'frame-approval', id: 'a1', frameHost: 'accounts.idp.test', site: 'shop.test' };
    let approved = false;
    const host = start([]);
    vi.mocked(host.getSuggestions).mockImplementation(async () => (approved ? [LOGIN] : [APPROVAL, LOGIN]));
    host.approveFrame = vi.fn(async () => (approved = true));

    const [prompt, ...rest] = await openMenu('u');
    expect(rest).toEqual([]);
    expect(prompt!.textContent).toContain('Allow Octa Pass here');
    expect(prompt!.textContent).toContain('This form is from accounts.idp.test, inside shop.test.');
    press(prompt!, 'Enter');
    await flush();
    expect(host.approveFrame).toHaveBeenCalledWith(APPROVAL, expect.objectContaining({ fieldType: 'username' }));
    expect(host.resolve).not.toHaveBeenCalled();
    expect(field('u').value).toBe('');

    // The menu comes back with the frame's own logins.
    const [login] = options();
    expect(login!.textContent).toContain('Example');
    press(login!, 'Enter');
    await flush();
    expect([field('u').value, field('p').value]).toEqual(['alex', 'pw']);
  });

  it('shows the approval in any field, and nothing more when it is turned down', async () => {
    html(`<form><input id="n" autocomplete="cc-number"></form>`);
    const host = start([{ kind: 'frame-approval', id: 'a1', frameHost: 'pay.test', site: 'shop.test' }, { kind: 'card', id: 'c', title: 'Visa' }]);
    host.approveFrame = vi.fn(async () => false);
    const [prompt, ...rest] = await openMenu('n');
    expect(rest).toEqual([]);
    press(prompt!, 'Enter');
    await flush();
    expect(menuHost()).toBeUndefined();
    expect(field('n').value).toBe('');
  });

  it('refuses an approval pick right after the menu appears, like any other', async () => {
    html(LOGIN_FORM);
    const host = start([{ kind: 'frame-approval', id: 'a1', frameHost: 'accounts.idp.test', site: 'shop.test' }], { testing: { trustAllEvents: true } });
    host.approveFrame = vi.fn(async () => true);
    const [prompt] = await openMenu('u');
    press(prompt!, 'Enter');
    await flush();
    expect(blocked).toEqual(['too-fast']);
    expect(host.approveFrame).not.toHaveBeenCalled();
  });

  describe('logins for other parts of the site', () => {
    const OTHERS: Suggestion = {
      kind: 'other-logins',
      id: 'o',
      site: 'example.com',
      logins: [
        { id: 's1', title: 'Shop', username: 'sam', host: 'shop.example.com' },
        { id: 's2', title: 'Mail', host: 'mail.example.com' },
      ],
    };

    it('shows one quiet entry after the page’s own logins, whatever order the host sent', async () => {
      html(LOGIN_FORM);
      start([OTHERS, LOGIN]);
      const items = await openMenu('u');
      expect(items.map((i) => i.textContent)).toEqual(['Examplealex', 'Logins for other parts of example.com']);
      expect(items[1]!.classList.contains('quiet')).toBe(true);
      // Nothing about the logins themselves until the user asks.
      expect(items[1]!.textContent).not.toContain('shop.example.com');
    });

    it('expands in place on a pick, then fills the sibling the user picks', async () => {
      html(LOGIN_FORM);
      const host = start([LOGIN, OTHERS]);
      const [, quiet] = await openMenu('u');
      press(quiet!, 'ArrowDown');
      press(quiet!, 'Enter');
      await flush();
      expect(host.resolve).not.toHaveBeenCalled();
      expect(field('u').value).toBe('');
      const items = options();
      expect(items.map((i) => i.textContent)).toEqual(['Examplealex', 'Shopsam on shop.example.com', 'MailNo username on mail.example.com']);
      // The keyboard lands on the first of the logins it opened.
      expect(shadow.roots.get(menuHost()!)!.activeElement).toBe(items[1]);
      press(items[1]!, 'Enter');
      await flush();
      expect(host.resolve).toHaveBeenCalledWith({ kind: 'other-login', id: 's1', title: 'Shop', username: 'sam', host: 'shop.example.com' }, expect.objectContaining({ fieldType: 'username' }));
      expect([field('u').value, field('p').value]).toEqual(['alex', 'pw']);
    });

    it('is only in sign-in fields, and never fills by itself', async () => {
      html(`${LOGIN_FORM}<form><input id="n" type="password" autocomplete="new-password"><button>Sign up</button></form>`);
      const host = start([OTHERS]);
      expect(await openMenu('n')).toEqual([]);
      const [quiet] = await openMenu('p');
      expect(quiet!.textContent).toBe('Logins for other parts of example.com');
      expect(host.resolve).not.toHaveBeenCalled();
      expect(field('p').value).toBe('');
    });

    it('takes no sibling the host sent as a suggestion of its own, nor an empty list', async () => {
      html(LOGIN_FORM);
      start([{ kind: 'other-login', id: 's1', title: 'Shop', host: 'shop.example.com' }, { ...OTHERS, logins: [] } as Suggestion]);
      expect(await openMenu('u')).toEqual([]);
    });

    it('expands and fills only on the user’s own picks, with the usual checks', async () => {
      html(LOGIN_FORM);
      const host = start([OTHERS], { testing: { trustAllEvents: true } });
      const [quiet] = await openMenu('u');
      press(quiet!, 'Enter');
      await flush();
      expect(blocked).toEqual(['too-fast']);
      expect(options().map((i) => i.textContent)).toEqual(['Logins for other parts of example.com']);
      expect(host.resolve).not.toHaveBeenCalled();
    });

    it('ignores a pick the page made up', async () => {
      html(LOGIN_FORM);
      const host = start([OTHERS]);
      const [quiet] = await openMenu('u');
      // From here on, events are the page's.
      engine!.stop();
      engine = createAutofill({ host, testing: { pickDelayMs: 0 } });
      quiet!.click();
      await flush();
      expect(host.resolve).not.toHaveBeenCalled();
    });

    it('refuses a sibling pick on a restyled menu', async () => {
      html(LOGIN_FORM);
      const host = start([OTHERS]);
      const [quiet] = await openMenu('u');
      press(quiet!, 'Enter');
      await flush();
      const [sibling] = options();
      menuHost()!.style.setProperty('opacity', '0', 'important');
      await flush();
      press(sibling!, 'Enter');
      await flush();
      expect(blocked).toEqual(['menu-tampered']);
      expect(host.resolve).not.toHaveBeenCalled();
      expect(field('u').value).toBe('');
    });
  });

  it('fills a login inside an open shadow root', async () => {
    html(`<div id="host"></div>`);
    const root = document.getElementById('host')!.attachShadow({ mode: 'open' });
    root.innerHTML = `<form><input id="u" autocomplete="username"><input id="p" type="password"><button>Log in</button></form>`;
    start([LOGIN]);
    const input = root.getElementById('u') as HTMLInputElement;
    input.focus();
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, composed: true }));
    await flush();
    press(options()[0]!, 'Enter');
    await flush();
    expect((root.getElementById('p') as HTMLInputElement).value).toBe('pw');
  });

  it('explains a classification', () => {
    html(LOGIN_FORM);
    start([]);
    const explanation = engine!.explain(field('u'))!;
    expect(explanation.type).toBe('username');
    expect(explanation.formType).toBe('login');
    expect(explanation.text).toContain('autocomplete="username"');
  });
});

/** A key the user types, as a browser handles it: `beforeinput`, the edit unless cancelled, then `input`. */
function type(element: HTMLInputElement, text: string) {
  for (const data of text) {
    const before = new InputEvent('beforeinput', { inputType: 'insertText', data, bubbles: true, composed: true, cancelable: true });
    if (!element.dispatchEvent(before)) continue;
    element.value += data;
    element.dispatchEvent(new InputEvent('input', { inputType: 'insertText', data, bubbles: true, composed: true }));
  }
}

function backspace(element: HTMLInputElement) {
  const before = new InputEvent('beforeinput', { inputType: 'deleteContentBackward', bubbles: true, composed: true, cancelable: true });
  if (!element.dispatchEvent(before)) return;
  element.value = element.value.slice(0, -1);
  element.dispatchEvent(new InputEvent('input', { inputType: 'deleteContentBackward', bubbles: true, composed: true }));
}

const titles = (items: HTMLElement[]) => items.map((item) => item.querySelector('.title')!.textContent);

describe('the menu narrows to what the user types in the username field', () => {
  const ALEX: Suggestion = { kind: 'login', id: 'a', title: 'Work', username: 'alex@work.example' };
  const SAM: Suggestion = { kind: 'login', id: 's', title: 'Home', username: 'sam@home.example' };
  const OTHERS: Suggestion = {
    kind: 'other-logins',
    id: 'o',
    site: 'example.com',
    logins: [{ id: 'x', title: 'Shop', username: 'sam.shop', host: 'shop.example.com' }],
  };

  it('matches the username or the title, ignoring case', () => {
    expect(filterSuggestions([ALEX, SAM], 'ALEX')).toEqual([ALEX]);
    expect(filterSuggestions([ALEX, SAM], 'home')).toEqual([SAM]);
    expect(filterSuggestions([ALEX, SAM], '  ')).toEqual([ALEX, SAM]);
    expect(filterSuggestions([ALEX, SAM], 'nobody')).toEqual([]);
  });

  it('keeps the unlock entry and narrows logins for other parts of the site', () => {
    const unlock: Suggestion = { kind: 'login', id: 'unlock', title: 'Unlock Octa Pass', pinned: true };
    expect(filterSuggestions([unlock, OTHERS], 'nobody')).toEqual([unlock]);
    expect(filterSuggestions([ALEX, OTHERS], 'sam')).toEqual([OTHERS]);
    expect(filterSuggestions([OTHERS], 'alex')).toEqual([]);
  });

  it('opens as the user types, narrows with each key, and closes when nothing matches', async () => {
    html(LOGIN_FORM);
    start([ALEX, SAM]);
    field('u').focus();
    type(field('u'), 's');
    await flush();
    expect(titles(options())).toEqual(['Home']);
    backspace(field('u'));
    await flush();
    expect(titles(options())).toEqual(['Work', 'Home']);
    type(field('u'), 'zz');
    await flush();
    expect(menuHost()).toBeUndefined();
  });

  it('filters by text already in the field when the menu opens', async () => {
    html(LOGIN_FORM);
    field('u').value = 'alex';
    start([ALEX, SAM]);
    expect(titles(await openMenu('u'))).toEqual(['Work']);
  });

  it('shows every login again in a field it filled itself', async () => {
    html(LOGIN_FORM);
    const host = start([ALEX, SAM]);
    vi.mocked(host.resolve).mockResolvedValue({ username: 'alex@work.example', 'current-password': 'pw' });
    press((await openMenu('u'))[0]!, 'Enter');
    await flush();
    expect(field('u').value).toBe('alex@work.example');
    field('u').click();
    await flush();
    expect(titles(options())).toEqual(['Work', 'Home']);
  });

  it("doesn't filter the password field", async () => {
    html(LOGIN_FORM);
    field('p').value = 'zz';
    start([ALEX, SAM]);
    expect(await openMenu('p')).toHaveLength(2);
  });
});

describe('asking the host and scanning only when needed', () => {
  const mouseDown = (element: Element) => element.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));

  it('reuses the answer when the menu opens again on the same field, and asks again after a pick', async () => {
    html(LOGIN_FORM);
    const host = start([LOGIN]);
    await openMenu('u');
    press(field('u'), 'Escape');
    expect(menuHost()).toBeUndefined();
    const [item] = await openMenu('u');
    expect(host.getSuggestions).toHaveBeenCalledTimes(1);
    press(item!, 'Enter');
    await flush();
    field('u').click();
    await flush();
    expect(host.getSuggestions).toHaveBeenCalledTimes(2);
  });

  it('asks again each time while locked', async () => {
    html(LOGIN_FORM);
    const host = start([{ kind: 'login', id: 'unlock', title: 'Unlock Octa Pass', pinned: true }]);
    await openMenu('u');
    press(field('u'), 'Escape');
    await openMenu('u');
    expect(host.getSuggestions).toHaveBeenCalledTimes(2);
  });

  it('asks as the mouse button goes down in a field, so the click opens the menu without waiting', async () => {
    html(LOGIN_FORM);
    const host = start([LOGIN]);
    mouseDown(field('u'));
    field('u').focus();
    expect(host.getSuggestions).toHaveBeenCalledTimes(1);
    field('u').click();
    await flush();
    expect(options()).toHaveLength(1);
    expect(host.getSuggestions).toHaveBeenCalledTimes(1);
  });

  it('asks nothing ahead for a press the page made up, or on focus alone', async () => {
    html(LOGIN_FORM);
    const host = start([LOGIN], { testing: { pickDelayMs: 0 } });
    mouseDown(field('u'));
    field('u').focus();
    field('p').focus();
    await flush();
    expect(host.getSuggestions).not.toHaveBeenCalled();
  });

  it("doesn't rescan the page for a click, focus or key outside any field", async () => {
    html(`${LOGIN_FORM}<a id="a" href="#x">Link</a><button id="b">Go</button>`);
    start([LOGIN]);
    const walker = vi.spyOn(document, 'createTreeWalker');
    document.getElementById('b')!.focus();
    document.getElementById('b')!.click();
    document.getElementById('a')!.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, composed: true }));
    expect(walker).not.toHaveBeenCalled();
    await openMenu('u');
    expect(walker).toHaveBeenCalled();
    walker.mockRestore();
  });

  it('rescans when a frame loads, not when an image does', () => {
    html(`${LOGIN_FORM}<img id="i" alt=""><iframe id="f"></iframe>`);
    start([]);
    const timers = vi.spyOn(globalThis, 'setTimeout');
    document.getElementById('i')!.dispatchEvent(new Event('load'));
    expect(timers).not.toHaveBeenCalled();
    document.getElementById('f')!.dispatchEvent(new Event('load'));
    expect(timers).toHaveBeenCalledTimes(1);
    timers.mockRestore();
  });

  it('closes the menu on scroll at once, and places the field icon once per frame', async () => {
    html(`<form><input id="u" autocomplete="username" data-rect="16 16 240 32"><input id="p" type="password"><button>Log in</button></form>`);
    start([LOGIN]);
    field('u').focus();
    field('u').click();
    await flush();
    expect(menuHost()).toBeDefined();
    const rects = vi.spyOn(field('u'), 'getBoundingClientRect');
    for (let i = 0; i < 5; i++) window.dispatchEvent(new Event('scroll'));
    expect(menuHost()).toBeUndefined();
    expect(rects).not.toHaveBeenCalled();
    await new Promise((resolve) => requestAnimationFrame(resolve));
    await flush();
    expect(rects).toHaveBeenCalledTimes(1);
  });

  it('keeps a menu opened by a click that came right after the field scrolled into view', async () => {
    html(`<form><input id="u" autocomplete="username" data-rect="16 16 240 32"><input id="p" type="password"><button>Log in</button></form>`);
    start([LOGIN]);
    field('u').focus();
    window.dispatchEvent(new Event('scroll'));
    field('u').click();
    await flush();
    expect(menuHost()).toBeDefined();
    await new Promise((resolve) => requestAnimationFrame(resolve));
    await flush();
    expect(menuHost()).toBeDefined();
  });
});

describe('fill on page load', () => {
  const FILLED = { username: 'alex', 'current-password': 'pw' };

  function startAuto(answer: typeof FILLED | null = FILLED, suggestions: Suggestion[] = [LOGIN]) {
    const autoFill = vi.fn(async () => answer);
    const host: AutofillHost = { getSuggestions: vi.fn(async () => suggestions), resolve: vi.fn(async () => FILLED), autoFill };
    engine = createAutofill({ host, testing: { trustAllEvents: true, pickDelayMs: 0 } });
    return autoFill;
  }

  it('fills the login form with what the host gives, without moving focus', async () => {
    html(`${LOGIN_FORM}<input id="q" type="search">`);
    field('q').focus();
    const autoFill = startAuto();
    await flush();
    expect(autoFill).toHaveBeenCalledTimes(1);
    expect(autoFill).toHaveBeenCalledWith(expect.objectContaining({ formType: 'login' }));
    expect([field('u').value, field('p').value]).toEqual(['alex', 'pw']);
    expect(document.activeElement).toBe(field('q'));
  });

  it('asks once per form, and leaves a form the user or the page already filled in', async () => {
    html(LOGIN_FORM);
    field('u').value = 'sam';
    const autoFill = startAuto();
    engine!.scan();
    await flush();
    expect(autoFill).not.toHaveBeenCalled();
    expect(field('p').value).toBe('');
  });

  it('never fills sign-up or change-password forms', async () => {
    html(`<form><input id="e" type="email" autocomplete="username"><input id="n" type="password" autocomplete="new-password"><button>Create account</button></form>`);
    const autoFill = startAuto();
    await flush();
    expect(autoFill).not.toHaveBeenCalled();
  });

  it("leaves the form when the user starts typing before the host answers", async () => {
    html(LOGIN_FORM);
    let answer!: (values: typeof FILLED) => void;
    const host: AutofillHost = {
      getSuggestions: vi.fn(async () => []),
      resolve: vi.fn(async () => null),
      autoFill: () => new Promise((resolve) => (answer = resolve)),
    };
    engine = createAutofill({ host, testing: { trustAllEvents: true } });
    field('u').value = 's';
    answer(FILLED);
    await flush();
    expect([field('u').value, field('p').value]).toEqual(['s', '']);
  });

  it('replaces the account and its password with what the user types over the account', async () => {
    html(LOGIN_FORM);
    startAuto();
    await flush();
    expect([field('u').value, field('p').value]).toEqual(['alex', 'pw']);
    field('u').focus();
    type(field('u'), 'sa');
    expect([field('u').value, field('p').value]).toEqual(['sa', '']);
  });

  it('typing over the password replaces only the password', async () => {
    html(LOGIN_FORM);
    startAuto();
    await flush();
    field('p').focus();
    type(field('p'), 'n');
    expect([field('u').value, field('p').value]).toEqual(['alex', 'n']);
  });

  it('a delete key empties the filled value', async () => {
    html(LOGIN_FORM);
    startAuto();
    await flush();
    backspace(field('u'));
    expect([field('u').value, field('p').value]).toEqual(['', '']);
  });

  it('still opens the full list on a click in a filled field', async () => {
    html(LOGIN_FORM);
    startAuto(FILLED, [LOGIN, { kind: 'login', id: 'l2', title: 'Other', username: 'sam' }]);
    await flush();
    field('u').focus();
    field('u').click();
    await flush();
    expect(titles(options())).toEqual(['Example', 'Other']);
  });

  it('fills nothing when the host says no', async () => {
    html(LOGIN_FORM);
    startAuto(null);
    await flush();
    expect([field('u').value, field('p').value]).toEqual(['', '']);
  });
});
