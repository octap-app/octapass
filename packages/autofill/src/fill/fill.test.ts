import { scanDocument } from '../scan';
import { html, stubLayout } from '../test/layout';
import type { FillValues } from '../types';
import { planFill, runFill } from './fill';

let restore: () => void;
beforeEach(() => (restore = stubLayout()));
afterEach(() => restore());

const CARD: FillValues = { 'cc-name': 'Alex Doe', 'cc-number': '4111111111111111', 'cc-exp': '09/29', 'cc-csc': '123' };

function fill(markup: string, values: FillValues) {
  html(markup);
  const form = scanDocument().forms.find((f) => f.type !== 'unknown')!;
  const origin = form.fields[0]!.element;
  const result = runFill(planFill(form, values), origin, () => false);
  const read = (id: string) => (document.getElementById(id) as HTMLInputElement).value;
  return { result, read };
}

describe('planFill and runFill', () => {
  it('fills a login into its own form only', () => {
    const { read } = fill(
      `<form><input id="u" autocomplete="username"><input id="p" type="password"><button>Log in</button></form>
       <form><input id="other" autocomplete="username"><input id="p2" type="password"><button>Log in</button></form>`,
      { username: 'alex', 'current-password': 'pw' },
    );
    expect([read('u'), read('p'), read('other'), read('p2')]).toEqual(['alex', 'pw', '', '']);
  });

  it('puts a new password in the confirm field too, and leaves the current one alone', () => {
    const { read } = fill(
      `<form><input id="a" type="password" autocomplete="current-password"><input id="b" type="password" autocomplete="new-password">
       <input id="c" type="password" placeholder="Confirm"><button>Save</button></form>`,
      { 'new-password': 'N3w!' },
    );
    expect([read('a'), read('b'), read('c')]).toEqual(['', 'N3w!', 'N3w!']);
  });

  it('skips hidden decoy fields', () => {
    const { result, read } = fill(
      `<form><input id="u" autocomplete="username" data-rect="0 0 200 30"><input id="p" type="password" data-rect="0 40 200 30">
       <input id="h" autocomplete="username" style="display:none"><button>Log in</button></form>`,
      { username: 'alex', 'current-password': 'pw' },
    );
    expect([read('u'), read('p'), read('h')]).toEqual(['alex', 'pw', '']);
    expect(result.skipped.map((s) => s.reason)).toEqual(['hidden']);
  });

  it('fills nothing when any field of the fill is drawn over', () => {
    const { result, read } = fill(
      `<form><input id="u" autocomplete="username" data-rect="0 0 200 30"><input id="p" type="password" data-rect="0 40 200 30">
       <div data-rect="0 40 200 30"></div><button>Log in</button></form>`,
      { username: 'alex', 'current-password': 'pw' },
    );
    expect([read('u'), read('p')]).toEqual(['', '']);
    expect(result.filled).toEqual([]);
    expect(result.skipped.map((s) => s.reason)).toEqual(['refused', 'covered']);
  });

  it('never fills a code that does not fit the split boxes', () => {
    const boxes = Array.from({ length: 4 }, (_, i) => `<input id="d${i}" maxlength="1">`).join('');
    const { read } = fill(`<form>${boxes}<button>Verify</button></form>`, { 'one-time-code': '123456' });
    expect(Array.from({ length: 4 }, (_, i) => read(`d${i}`)).join('')).toBe('');
  });

  it('spreads a one-time code over split boxes', () => {
    const boxes = Array.from({ length: 6 }, (_, i) => `<input id="d${i}" maxlength="1">`).join('');
    const { read } = fill(`<form>${boxes}<button>Verify</button></form>`, { 'one-time-code': '123 456' });
    expect(Array.from({ length: 6 }, (_, i) => read(`d${i}`)).join('')).toBe('123456');
  });

  it('formats a card expiry the way each field asks', () => {
    const { read } = fill(
      `<form><input id="n" autocomplete="cc-number"><input id="e" autocomplete="cc-exp" placeholder="MM / YYYY">
       <input id="c" autocomplete="cc-csc"><button>Pay</button></form>`,
      CARD,
    );
    expect([read('n'), read('e'), read('c')]).toEqual(['4111111111111111', '09 / 2029', '123']);
  });

  it('derives month and year fields from the expiry', () => {
    const years = ['2028', '2029', '2030', '2031', '2032'].map((y) => `<option value="${y.slice(2)}">${y}</option>`).join('');
    const { read } = fill(
      `<form><input id="n" autocomplete="cc-number"><input id="m" autocomplete="cc-exp-month" maxlength="2">
       <select id="y" autocomplete="cc-exp-year">${years}</select><button>Pay</button></form>`,
      CARD,
    );
    expect([read('m'), read('y')]).toEqual(['09', '29']);
  });

  it('splits a full name and finds the country option by name', () => {
    const { read } = fill(
      `<form><input id="f" autocomplete="given-name"><input id="l" autocomplete="family-name">
       <select id="co" autocomplete="country"><option value="">Choose</option><option value="ca">Canada</option><option value="usa">United States</option></select>
       <button>Save</button></form>`,
      { name: 'Alex van Doe', country: 'US' },
    );
    expect([read('f'), read('l'), read('co')]).toEqual(['Alex van', 'Doe', 'usa']);
  });

  it('puts both address lines in a street textarea only when there is no second-line field', () => {
    const values = { 'address-line1': '1 Test Street', 'address-line2': 'Apt 2', 'postal-code': '90210' };
    const alone = fill(`<form><textarea id="s" autocomplete="street-address"></textarea><input id="z" autocomplete="postal-code"><button>Save</button></form>`, values);
    expect(alone.read('s')).toBe('1 Test Street\nApt 2');
    const split = fill(
      `<form><textarea id="s" autocomplete="street-address"></textarea><input id="a" autocomplete="address-line2">
       <input id="z" autocomplete="postal-code"><button>Save</button></form>`,
      values,
    );
    expect([split.read('s'), split.read('a')]).toEqual(['1 Test Street', 'Apt 2']);
  });
});

