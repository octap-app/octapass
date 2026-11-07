import { classifyFields } from '../classify/form';
import { html, stubLayout } from '../test/layout';
import type { FillableElement } from '../types';
import { addressValues, cardValues, isCardNumber, normalizeExpiry } from './details';

let restore: () => void;
beforeEach(() => {
  restore = stubLayout();
});
afterEach(() => restore());

function form(markup: string, values: Record<string, string>) {
  html(markup);
  for (const [id, value] of Object.entries(values)) (document.getElementById(id) as FillableElement).value = value;
  return classifyFields(Array.from(document.querySelectorAll<FillableElement>('input, select, textarea')))[0]!;
}

describe('card and address values', () => {
  it('checks card numbers with Luhn', () => {
    expect(isCardNumber('4242424242424242')).toBe(true);
    expect(isCardNumber('378282246310005')).toBe(true);
    expect(isCardNumber('4242424242424241')).toBe(false);
    expect(isCardNumber('42424242')).toBe(false);
  });

  it('normalizes the ways people type an expiry', () => {
    expect(normalizeExpiry('8/27')).toBe('08/27');
    expect(normalizeExpiry('08 / 2027')).toBe('08/27');
    expect(normalizeExpiry('0827')).toBe('08/27');
    expect(normalizeExpiry('13/27')).toBeUndefined();
  });

  it('joins a card number split over four boxes', () => {
    const boxes = [1, 2, 3, 4].map((n) => `<input id="n${n}" autocomplete="cc-number" maxlength="4">`).join('');
    const card = form(`<form>${boxes}<input id="exp" autocomplete="cc-exp"></form>`, { n1: '4242', n2: '4242', n3: '4242', n4: '4242', exp: '12/30' });
    expect(cardValues(card)).toEqual({ 'cc-number': '4242424242424242', 'cc-exp': '12/30' });
  });

  it('splits a street address typed in one box', () => {
    const address = form(`<form><textarea id="street" autocomplete="street-address"></textarea><input id="zip" autocomplete="postal-code"></form>`, {
      street: '1 High Street\nFlat 2',
      zip: 'N1 9GU',
    });
    expect(addressValues(address)).toEqual({ 'address-line1': '1 High Street', 'address-line2': 'Flat 2', 'postal-code': 'N1 9GU' });
  });
});
