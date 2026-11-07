import { createAutofill, type Autofill } from '../engine';
import { html, stubLayout } from '../test/layout';
import type { DetailsSaveReport, SaveReport } from '../types';

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

let restore: () => void;
let engine: Autofill;
let saves: SaveReport[];
let details: DetailsSaveReport[];

beforeEach(() => {
  restore = stubLayout();
  saves = [];
  details = [];
});
afterEach(() => {
  engine.stop();
  restore();
  history.replaceState(null, '', '/');
});

function start(markup: string) {
  html(markup);
  engine = createAutofill({
    host: { getSuggestions: async () => [], resolve: async () => null, onSave: (report) => saves.push(report), onSaveDetails: (report) => details.push(report) },
  });
}

function type(id: string, value: string) {
  const input = document.getElementById(id) as HTMLInputElement;
  input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true }));
}

const LOGIN = `<form id="f"><input id="u" autocomplete="username"><input id="p" type="password"><button id="go">Log in</button></form>`;

describe('save detection', () => {
  it('reports a submitted login', () => {
    start(LOGIN);
    type('u', 'sam');
    type('p', 'secret-1');
    document.getElementById('f')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    expect(saves).toEqual([
      { url: location.href, username: 'sam', password: 'secret-1', formType: 'login', trigger: 'submit', draft: false },
    ]);
  });

  it('reports a formless login once the page navigates, with the values typed before it cleared them', async () => {
    start(`<div><input id="u" placeholder="Email"><input id="p" type="password"><button id="go" type="button">Sign in</button></div>`);
    type('u', 'sam@example.test');
    type('p', 'secret-2');
    document.getElementById('go')!.click();
    type('u', '');
    type('p', '');
    history.pushState(null, '', '/home');
    await wait(400);
    expect(saves).toEqual([expect.objectContaining({ username: 'sam@example.test', password: 'secret-2', trigger: 'navigation' })]);
  });

  it('reports a login after the host sees a request complete', async () => {
    start(LOGIN.replace('<button id="go">', '<button id="go" type="button">'));
    type('u', 'sam');
    type('p', 'secret-3');
    document.getElementById('go')!.click();
    engine.requestCompleted();
    await wait(300);
    expect(saves).toEqual([expect.objectContaining({ password: 'secret-3', trigger: 'request' })]);
  });

  it('stays quiet when a sign-in attempt goes nowhere', async () => {
    start(LOGIN.replace('<button id="go">', '<button id="go" type="button">'));
    type('u', 'sam');
    type('p', 'wrong');
    document.getElementById('go')!.click();
    await wait(400);
    expect(saves).toEqual([]);
  });

  it('pairs the identifier from step one with the password from step two', () => {
    start(`<form id="s1"><input id="id" type="email" autocomplete="username"><button>Next</button></form>`);
    type('id', 'sam@example.test');
    document.getElementById('s1')!.dispatchEvent(new Event('submit', { bubbles: true }));
    document.body.innerHTML = `<form id="s2"><input id="p" type="password" autocomplete="current-password"><button>Sign in</button></form>`;
    engine.scan();
    type('p', 'secret-4');
    document.getElementById('s2')!.dispatchEvent(new Event('submit', { bubbles: true }));
    expect(saves).toEqual([expect.objectContaining({ username: 'sam@example.test', password: 'secret-4', formType: 'login' })]);
  });

  it('reports the new and old password of a password change', () => {
    start(`<form id="f"><input id="a" type="password" autocomplete="current-password"><input id="b" type="password" autocomplete="new-password">
      <input id="c" type="password" placeholder="Confirm"><button>Change password</button></form>`);
    type('a', 'old-pass');
    type('b', 'new-pass');
    type('c', 'new-pass');
    document.getElementById('f')!.dispatchEvent(new Event('submit', { bubbles: true }));
    expect(saves).toEqual([expect.objectContaining({ password: 'new-pass', oldPassword: 'old-pass', formType: 'change-password' })]);
  });

  it('reports each credential once', () => {
    start(LOGIN);
    type('u', 'sam');
    type('p', 'secret-5');
    const form = document.getElementById('f')!;
    form.dispatchEvent(new Event('submit', { bubbles: true }));
    form.dispatchEvent(new Event('submit', { bubbles: true }));
    expect(saves).toHaveLength(1);
  });

  it('hears a submit inside an open shadow root', () => {
    start(`<div id="host"></div>`);
    const root = document.getElementById('host')!.attachShadow({ mode: 'open' });
    root.innerHTML = LOGIN;
    engine.scan();
    const set = (id: string, value: string) => {
      const input = root.getElementById(id) as HTMLInputElement;
      input.value = value;
      input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    };
    set('u', 'sam');
    set('p', 'secret-6');
    root.getElementById('f')!.dispatchEvent(new Event('submit', { bubbles: true }));
    expect(saves).toEqual([expect.objectContaining({ username: 'sam', password: 'secret-6' })]);
  });
});

const ADDRESS = `<form id="f">
  <input id="name" autocomplete="name"><input id="email" type="email" autocomplete="email"><input id="tel" type="tel" autocomplete="tel">
  <input id="line1" autocomplete="address-line1"><input id="city" autocomplete="address-level2"><input id="zip" autocomplete="postal-code">
  <select id="country" autocomplete="country"><option value="">Choose</option><option value="GB">United Kingdom</option><option value="US">United States</option></select>
  <input id="secret" name="notes"><button id="go">Continue</button></form>`;

const CARD = `<form id="f"><input id="holder" autocomplete="cc-name"><input id="number" autocomplete="cc-number">
  <select id="mm" autocomplete="cc-exp-month"><option value="">MM</option><option value="1">01</option><option value="8">08</option></select>
  <select id="yy" autocomplete="cc-exp-year"><option value="">YYYY</option><option value="2027">2027</option></select>
  <input id="cvc" autocomplete="cc-csc"><button id="pay">Pay</button></form>`;

function choose(id: string, value: string) {
  const select = document.getElementById(id) as HTMLSelectElement;
  select.value = value;
  select.dispatchEvent(new Event('change', { bubbles: true }));
}

describe('address and card save detection', () => {
  it('reports a submitted address with only the fields it classified', () => {
    start(ADDRESS);
    type('name', 'Maya Haddad');
    type('email', 'maya@example.test');
    type('tel', '+44 20 7946 0000');
    type('line1', '1 High Street');
    type('city', 'London');
    type('zip', 'N1 9GU');
    choose('country', 'GB');
    type('secret', 'leave me alone');
    document.getElementById('f')!.dispatchEvent(new Event('submit', { bubbles: true }));
    expect(details).toEqual([
      {
        kind: 'identity',
        url: location.href,
        trigger: 'submit',
        values: { name: 'Maya Haddad', email: 'maya@example.test', tel: '+44 20 7946 0000', 'address-line1': '1 High Street', 'address-level2': 'London', 'postal-code': 'N1 9GU', country: 'United Kingdom' },
      },
    ]);
    expect(saves).toEqual([]);
  });

  it('stays quiet for a name and email without an address', () => {
    start(`<form id="f"><input id="name" autocomplete="name"><input id="email" type="email" autocomplete="email"><button>Subscribe</button></form>`);
    type('name', 'Maya Haddad');
    type('email', 'maya@example.test');
    document.getElementById('f')!.dispatchEvent(new Event('submit', { bubbles: true }));
    expect(details).toEqual([]);
  });

  it('reports a card from selects for the expiry, with the security code for the host to drop', () => {
    start(CARD);
    type('holder', 'Maya Haddad');
    type('number', '4242 4242 4242 4242');
    choose('mm', '8');
    choose('yy', '2027');
    type('cvc', '123');
    document.getElementById('f')!.dispatchEvent(new Event('submit', { bubbles: true }));
    expect(details).toEqual([
      { kind: 'card', url: location.href, trigger: 'submit', values: { 'cc-name': 'Maya Haddad', 'cc-number': '4242424242424242', 'cc-exp': '08/27', 'cc-csc': '123' } },
    ]);
  });

  it('ignores a card number that fails the checksum', () => {
    start(CARD);
    type('number', '4242 4242 4242 4241');
    document.getElementById('f')!.dispatchEvent(new Event('submit', { bubbles: true }));
    expect(details).toEqual([]);
  });

  it('reports a card from a single-page checkout once the payment request completes', async () => {
    start(CARD.replace('<button id="pay">', '<button id="pay" type="button">'));
    type('number', '5555555555554444');
    document.getElementById('pay')!.click();
    type('number', '');
    engine.requestCompleted();
    await wait(300);
    expect(details).toEqual([expect.objectContaining({ kind: 'card', trigger: 'request', values: { 'cc-number': '5555555555554444' } })]);
  });
});
