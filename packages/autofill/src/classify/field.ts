import { isInput, isSelect, isTextArea } from '../dom/is';
import { fieldHints, type HintSource } from '../dom/text';
import type { FieldType, FillableElement, Signal } from '../types';
import { credentialHint } from './apiKey';
import { ATTRIBUTE, match, type Concept } from './lexicon';

const WEIGHT: Record<Exclude<HintSource, 'autocomplete'>, number> = {
  label: 40,
  placeholder: 32,
  attribute: 30,
  description: 15,
};

/** A field type needs this much evidence; less is `unknown`. */
export const MIN_SCORE = 25;

const AUTOCOMPLETE: Record<string, FieldType> = {
  username: 'username',
  email: 'email',
  'current-password': 'current-password',
  'new-password': 'new-password',
  'one-time-code': 'one-time-code',
  'cc-name': 'cc-name',
  'cc-given-name': 'cc-name',
  'cc-family-name': 'cc-name',
  'cc-number': 'cc-number',
  'cc-exp': 'cc-exp',
  'cc-exp-month': 'cc-exp-month',
  'cc-exp-year': 'cc-exp-year',
  'cc-csc': 'cc-csc',
  name: 'name',
  'given-name': 'given-name',
  'family-name': 'family-name',
  tel: 'tel',
  'tel-national': 'tel',
  organization: 'organization',
  'street-address': 'address-line1',
  'address-line1': 'address-line1',
  'address-line2': 'address-line2',
  'address-level1': 'address-level1',
  'address-level2': 'address-level2',
  'postal-code': 'postal-code',
  country: 'country',
  'country-name': 'country',
  bday: 'bday',
};

// Concepts that name a field type. When several match the same text, the longest keyword wins, so
// 'Name on card' is a card name rather than a name and 'Email address' isn't a street address.
const FIELD_CONCEPTS: [Concept, FieldType][] = [
  ['username', 'username'],
  ['email', 'email'],
  ['password', 'current-password'],
  ['one-time-code', 'one-time-code'],
  ['cc-number', 'cc-number'],
  ['cc-name', 'cc-name'],
  ['cc-exp', 'cc-exp'],
  ['cc-csc', 'cc-csc'],
  ['given-name', 'given-name'],
  ['family-name', 'family-name'],
  ['name', 'name'],
  ['tel', 'tel'],
  ['organization', 'organization'],
  ['address-line2', 'address-line2'],
  ['address-line1', 'address-line1'],
  ['address-level2', 'address-level2'],
  ['address-level1', 'address-level1'],
  ['postal-code', 'postal-code'],
  ['country', 'country'],
  ['bday', 'bday'],
  ['search', 'search'],
];

const PASSWORD_TYPES = new Set<FieldType>(['current-password', 'new-password', 'confirm-password']);
// Sites use type=password for codes and card secrets too.
const ALLOWED_ON_PASSWORD_INPUT = new Set<FieldType>([...PASSWORD_TYPES, 'one-time-code', 'cc-csc', 'cc-number', 'api-credential']);

/** The input types the engine looks at; the rest (checkbox, file, submit…) are never classified. */
const TEXT_LIKE = new Set(['text', 'email', 'password', 'tel', 'number', 'search', 'url', 'date', 'month', 'hidden', '']);

export function isCandidate(element: Element): element is FillableElement {
  if (isInput(element)) return TEXT_LIKE.has(element.type);
  return isSelect(element) || isTextArea(element);
}

function matchConcept(concept: Concept, text: string, source: HintSource): string | undefined {
  const keyword = match(concept, text);
  if (keyword) return keyword;
  if (source === 'attribute') return ATTRIBUTE[concept]?.exec(text)?.[0];
  return undefined;
}

function textSignals(text: string, source: Exclude<HintSource, 'autocomplete'>, isPassword: boolean): Signal[] {
  const found: { type: FieldType; keyword: string }[] = [];
  for (const [concept, type] of FIELD_CONCEPTS) {
    const keyword = matchConcept(concept, text, source);
    if (keyword) found.push({ type, keyword });
  }
  const longest = Math.max(0, ...found.map((f) => f.keyword.length));
  const winners = found.filter((f) => f.keyword.length === longest);
  const where = source === 'attribute' ? 'name/id' : source;
  const signals: Signal[] = winners.map(({ type, keyword }) => ({
    type,
    score: WEIGHT[source],
    source,
    reason: `${where} "${text}" matches "${keyword}"`,
  }));

  // 'New', 'Confirm' and 'Current' refine a password, even on their own next to a password input.
  if (isPassword || winners.some((w) => w.type === 'current-password')) {
    for (const [concept, type] of [
      ['confirm', 'confirm-password'],
      ['new', 'new-password'],
      ['current', 'current-password'],
    ] as const) {
      const keyword = matchConcept(concept, text, source);
      if (keyword) {
        signals.push({ type, score: WEIGHT[source], source, reason: `${where} "${text}" says "${keyword}"` });
        break;
      }
    }
  }

  // Month and year only mean a card expiry inside a card form; the form step drops them elsewhere.
  for (const [concept, type] of [
    ['month', 'cc-exp-month'],
    ['year', 'cc-exp-year'],
  ] as const) {
    const keyword = matchConcept(concept, text, source);
    if (keyword) signals.push({ type, score: WEIGHT[source] - 5, source, reason: `${where} "${text}" says "${keyword}"` });
  }
  return signals;
}

/** The shortest key the classifier expects; a box that holds less is for a code. */
const MIN_CREDENTIAL_LENGTH = 20;
const MASKED_CREDENTIAL = 25;

/**
 * Evidence that a field takes an API key or token, from its name, labels and placeholder. One hint that
 * it's about something else ('Token name') outweighs the rest: such a field is often `name="token"`.
 */
function credentialSignals(element: FillableElement, hints: ReturnType<typeof fieldHints>): Signal[] {
  const textBox = isTextArea(element) || (isInput(element) && ['text', 'password', ''].includes(element.type));
  if (!textBox || element.inputMode === 'numeric') return [];
  if (element.maxLength > 0 && element.maxLength < MIN_CREDENTIAL_LENGTH) return [];
  const signals: Signal[] = [];
  for (const source of ['attribute', 'label', 'placeholder'] as const) {
    for (const text of hints[source]) {
      const hint = credentialHint(text);
      if (hint === false) return [];
      if (hint) signals.push({ type: 'api-credential', score: WEIGHT[source], source, reason: `${source === 'attribute' ? 'name/id' : source} "${text}" names a key or token` });
    }
  }
  // Masking the box says nothing against a key, so naming one has to beat `type="password"`.
  if (signals.length > 0 && isInput(element) && element.type === 'password') {
    signals.push({ type: 'api-credential', score: MASKED_CREDENTIAL, source: 'type', reason: 'a masked box named as a key' });
  }
  return signals;
}

const MONTH_NAMES = /^(0?[1-9]|1[0-2])$|^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)/i;
const YEAR = /^(\d{2}|\d{4})$/;
const COUNTRY_OPTIONS = /^(us|usa|united states|canada|germany|france|united kingdom|mexico|india|japan|egypt|brazil)$/i;

/** Phone dial codes ('+44', 'UK (+44)') list countries too, but they're part of a phone number. */
function hasDialCodes(select: HTMLSelectElement): boolean {
  const texts = Array.from(select.options, (o) => o.text);
  return texts.length > 0 && texts.filter((t) => /\+\s?\d/.test(t)).length / texts.length >= 0.5;
}

function optionSignals(select: HTMLSelectElement): Signal[] {
  if (hasDialCodes(select)) return [];
  const values = Array.from(select.options, (o) => (o.value || o.text).trim()).filter(Boolean);
  if (values.length === 0) return [];
  const share = (test: RegExp) => values.filter((v) => test.test(v)).length / values.length;
  if (values.length >= 12 && values.length <= 13 && share(MONTH_NAMES) >= 0.9) {
    return [{ type: 'cc-exp-month', score: 20, source: 'options', reason: 'options are the 12 months' }];
  }
  if (values.length >= 5 && share(YEAR) >= 0.9) {
    return [{ type: 'cc-exp-year', score: 20, source: 'options', reason: 'options are years' }];
  }
  const texts = Array.from(select.options, (o) => o.text.trim());
  if (values.length >= 20 && [...values, ...texts].filter((v) => COUNTRY_OPTIONS.test(v)).length >= 2) {
    return [{ type: 'country', score: 45, source: 'options', reason: 'options are countries' }];
  }
  return [];
}

/** Every piece of evidence about what a single field is, before looking at the rest of its form. */
export function fieldSignals(element: FillableElement): Signal[] {
  const hints = fieldHints(element);
  const inputType = isInput(element) ? element.type : '';
  const isPassword = inputType === 'password';
  const signals: Signal[] = [];

  const token = hints.autocomplete.findLast((t) => t in AUTOCOMPLETE);
  if (token) {
    signals.push({ type: AUTOCOMPLETE[token]!, score: 100, source: 'autocomplete', reason: `autocomplete="${token}"` });
  }
  const byType = (type: FieldType, score: number) => signals.push({ type, score, source: 'type', reason: `type="${inputType}"` });
  if (isPassword) byType('current-password', 50);
  if (inputType === 'email') byType('email', 50);
  if (inputType === 'tel') byType('tel', 30);
  if (inputType === 'search') byType('search', 80);
  if (element.closest('[role=search]')) {
    signals.push({ type: 'search', score: 60, source: 'form', reason: 'inside role="search"' });
  }
  if (isSelect(element)) signals.push(...optionSignals(element));

  for (const source of ['attribute', 'label', 'placeholder', 'description'] as const) {
    for (const text of hints[source]) signals.push(...textSignals(text, source, isPassword));
  }

  signals.push(...credentialSignals(element, hints));

  if (isPassword) return signals.filter((s) => ALLOWED_ON_PASSWORD_INPUT.has(s.type));
  // Even when labelled 'Country', a dial-code select isn't an address country.
  if (isSelect(element) && hasDialCodes(element)) return signals.filter((s) => s.type !== 'country');
  return signals;
}

/** Adds up evidence per type, counting only the strongest signal from each source. */
export function scores(signals: Signal[]): Map<FieldType, number> {
  const best = new Map<FieldType, Map<string, number>>();
  for (const { type, source, score } of signals) {
    const bySource = best.get(type) ?? new Map<string, number>();
    bySource.set(source, Math.max(bySource.get(source) ?? 0, score));
    best.set(type, bySource);
  }
  const totals = new Map<FieldType, number>();
  for (const [type, bySource] of best) totals.set(type, [...bySource.values()].reduce((a, b) => a + b, 0));

  // 'New' and 'Confirm' refine a password rather than compete with it: they add to the evidence that
  // the field is a password at all (its type, the word 'password'), which otherwise counts as current.
  const generic = [...(best.get('current-password') ?? new Map<string, number>())]
    .filter(([source]) => source !== 'autocomplete')
    .reduce((sum, [, score]) => sum + score, 0);
  for (const type of ['new-password', 'confirm-password'] as const) {
    const own = totals.get(type);
    if (own !== undefined) totals.set(type, own + generic);
  }
  return totals;
}

export function bestType(signals: Signal[], allowed?: (type: FieldType) => boolean, min = MIN_SCORE): FieldType {
  let best: FieldType = 'unknown';
  let top = min - 1;
  for (const [type, score] of scores(signals)) {
    if (allowed && !allowed(type)) continue;
    if (score > top) [best, top] = [type, score];
  }
  return best;
}
