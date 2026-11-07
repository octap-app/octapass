import { isSelect, isTextArea } from '../dom/is';
import { ADDRESS_SAVE_FIELDS, type AddressValues, type CardValues, type FillableElement, type Form } from '../types';

/** What a field holds: a select's chosen option text (not a placeholder option), anything else's value. */
function read(element: FillableElement): string {
  if (isSelect(element)) {
    const option = element.selectedOptions[0];
    return option && option.value !== '' ? (option.text.trim() || option.value) : '';
  }
  return element.value.trim();
}

/** The visible fields of one type, in order, with what they hold. */
function typed(form: Form, type: string): { element: FillableElement; value: string }[] {
  return form.fields
    .filter((f) => f.type === type && f.fillable)
    .map((f) => ({ element: f.element, value: read(f.element) }))
    .filter((f) => f.value);
}

/** Digits that pass the Luhn check, the checksum every payment card number carries. */
export function isCardNumber(digits: string): boolean {
  if (!/^\d{12,19}$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) d = d * 2 > 9 ? d * 2 - 9 : d * 2;
    sum += d;
  }
  return sum % 10 === 0;
}

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];

function month(element: FillableElement): string | undefined {
  const candidates = isSelect(element) ? [element.value, element.selectedOptions[0]?.text ?? ''] : [element.value];
  for (const text of candidates) {
    const number = /\d{1,2}/.exec(text)?.[0];
    if (number && Number(number) >= 1 && Number(number) <= 12) return number.padStart(2, '0');
    const name = MONTHS.findIndex((m) => text.trim().toLowerCase().startsWith(m));
    if (name >= 0) return String(name + 1).padStart(2, '0');
  }
  return undefined;
}

function year(element: FillableElement): string | undefined {
  const candidates = isSelect(element) ? [element.value, element.selectedOptions[0]?.text ?? ''] : [element.value];
  for (const text of candidates) {
    const found = /^\s*(\d{4}|\d{2})\s*$/.exec(text)?.[1];
    if (found) return found.slice(-2);
  }
  return undefined;
}

/** `MM/YY` from `MM/YY`, `MM / YYYY`, `MM-YY` or `MMYY`. */
export function normalizeExpiry(text: string): string | undefined {
  const parts = /^\s*(\d{1,2})\s*[/\-.\s]\s*(\d{4}|\d{2})\s*$/.exec(text) ?? /^\s*(\d{2})(\d{2})\s*$/.exec(text);
  if (!parts || Number(parts[1]) < 1 || Number(parts[1]) > 12) return undefined;
  return `${parts[1]!.padStart(2, '0')}/${parts[2]!.slice(-2)}`;
}

/** The card typed into a card form, or undefined without a valid card number. */
export function cardValues(form: Form): CardValues | undefined {
  // A number split over several boxes is read in order.
  const number = typed(form, 'cc-number').map((f) => f.value.replace(/[\s-]/g, '')).join('');
  if (!isCardNumber(number)) return undefined;
  const values: CardValues = { 'cc-number': number };
  const name = typed(form, 'cc-name')[0]?.value;
  if (name) values['cc-name'] = name;
  const exp = typed(form, 'cc-exp')[0];
  const mm = typed(form, 'cc-exp-month')[0];
  const yy = typed(form, 'cc-exp-year')[0];
  const expiry = exp ? normalizeExpiry(exp.value) : mm && yy && month(mm.element) && year(yy.element) ? `${month(mm.element)}/${year(yy.element)}` : undefined;
  if (expiry) values['cc-exp'] = expiry;
  const csc = typed(form, 'cc-csc')[0]?.value;
  if (csc && /^\d{3,4}$/.test(csc)) values['cc-csc'] = csc;
  return values;
}

/**
 * The address typed into an address form, or undefined when it isn't one: a street line and a city
 * or postcode are needed, so a name-and-email form (a newsletter, a contact form) never counts.
 */
export function addressValues(form: Form): AddressValues | undefined {
  const values: AddressValues = {};
  for (const type of ADDRESS_SAVE_FIELDS) {
    const field = typed(form, type)[0];
    if (field) values[type] = field.value;
  }
  // A street address in one textarea: its first line, and the rest as line 2.
  const street = typed(form, 'address-line1')[0];
  if (street && isTextArea(street.element) && !values['address-line2']) {
    const [first, ...rest] = street.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    values['address-line1'] = first!;
    if (rest.length) values['address-line2'] = rest.join(', ');
  }
  if (!values['address-line1'] || !(values['address-level2'] || values['postal-code'])) return undefined;
  return values;
}
