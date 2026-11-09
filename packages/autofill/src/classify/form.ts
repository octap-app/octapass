import { isButton, isInput, isSelect } from '../dom/is';
import { contextText, elementText, headingBefore, normalize } from '../dom/text';
import { composedParent, visibilityProblem } from '../dom/visibility';
import {
  BANK_FIELD_TYPES,
  CARD_FIELD_TYPES,
  DATABASE_FIELD_TYPES,
  IDENTITY_FIELD_TYPES,
  type Field,
  type FieldType,
  type FillableElement,
  type Form,
  type FormType,
} from '../types';
import { bestType, fieldSignals, scores } from './field';
import { match } from './lexicon';

const CARD = new Set<FieldType>(CARD_FIELD_TYPES);
const MIN_CARD_SCORE = 20;
const IDENTITY = new Set<FieldType>(IDENTITY_FIELD_TYPES);
const BANK = new Set<FieldType>(BANK_FIELD_TYPES);
const DATABASE = new Set<FieldType>(DATABASE_FIELD_TYPES);
/** What a masked box can hold that isn't a password, once the form has had its say. */
const MASKED_VALUES = new Set<FieldType>(['api-credential', 'iban', 'bank-account-number', 'license-key', 'document-number']);
const PASSWORD = new Set<FieldType>(['current-password', 'new-password', 'confirm-password']);
const IDENTIFIER = new Set<FieldType>(['username', 'email', 'tel']);

const TOGGLE = /show|hide|reveal|toggle|eye|mostrar|ocultar|afficher|masquer|anzeigen|ausblenden|exibir|показать|显示|表示|اظهار|عرض|दिखाएं/;

/** A button that submits or advances a form, as opposed to 'show password' toggles and icons. */
function isSubmitLike(element: Element): boolean {
  if (isInput(element)) return element.type === 'submit' || element.type === 'image';
  const text = elementText(element);
  if (!text || TOGGLE.test(text)) return false;
  const declared = element.getAttribute('type');
  if (isButton(element) && declared !== 'button' && declared !== 'reset') return true;
  return !!(match('login', text) || match('signup', text) || match('next', text) || match('change', text) ||
    /submit|send|save|verify|pay|order|checkout|enviar|envoyer|senden|absenden|отправить|提交|送信|ارسال|إرسال|भेजें|जमा/.test(text));
}

const BUTTONS = 'button, input[type=submit], input[type=image], [role=button], a[href], div[onclick], span[onclick]';

/**
 * The element that groups a field without a <form>: the nearest ancestor that also holds a submit-like
 * button, so a header search box and a sign-in panel on the same page end up in different groups.
 */
function formlessContainer(field: Element): Element {
  const doc = field.ownerDocument;
  let fallback: Element = doc.body ?? doc.documentElement;
  for (let node = composedParent(field); node; node = composedParent(node)) {
    if (node.ownerDocument !== doc) break;
    if (node === doc.body || node === doc.documentElement) return node;
    if (Array.from(node.querySelectorAll(BUTTONS)).some(isSubmitLike)) return node;
    fallback = node;
  }
  return fallback;
}

function owner(element: FillableElement): Element {
  return element.form ?? formlessContainer(element);
}

interface Draft {
  element: FillableElement;
  fillable: boolean;
  signals: Field['signals'];
  type: FieldType;
  segment?: number;
}

function note(draft: Draft, type: FieldType, reason: string): void {
  draft.type = type;
  draft.signals.push({ type, score: 0, source: 'form', reason });
}

function has(draft: Draft, type: FieldType, source?: (s: string) => boolean): boolean {
  return draft.signals.some((s) => s.type === type && (!source || source(s.source)));
}

const isPasswordInput = (d: Draft) => isInput(d.element) && d.element.type === 'password';

/** Four or more adjacent one-character inputs are one code split into boxes. */
function splitCode(drafts: Draft[]): Draft[] {
  let run: Draft[] = [];
  let best: Draft[] = [];
  for (const draft of drafts) {
    const single = isInput(draft.element) && draft.element.maxLength === 1;
    if (single) run.push(draft);
    else run = [];
    if (run.length > best.length) best = [...run];
  }
  return best.length >= 4 ? best : [];
}

function passwordRoles(passwords: Draft[], reasons: string[]): void {
  const explicitCurrent = passwords.find(
    (d) => has(d, 'current-password', (s) => s === 'autocomplete') || d.signals.some((s) => /says/.test(s.reason) && s.type === 'current-password'),
  );
  const current = explicitCurrent ?? (passwords.length >= 3 ? passwords[0] : undefined);
  const rest = passwords.filter((d) => d !== current);
  if (current) note(current, 'current-password', current === explicitCurrent ? 'marked as the current password' : 'first of three passwords');
  const labelledConfirm = rest.find((d) => has(d, 'confirm-password'));
  const confirm = labelledConfirm ?? (rest.length >= 2 ? rest[rest.length - 1] : undefined);
  for (const draft of rest) {
    if (draft === confirm) note(draft, 'confirm-password', labelledConfirm ? 'labelled as a confirmation' : 'second new password');
    else note(draft, 'new-password', current ? 'the password that replaces the current one' : 'first new password');
  }
  reasons.push(`${passwords.length} passwords: ${passwords.map((d) => d.type).join(', ')}`);
}

/** The field a sign-in form identifies the account with, in order of how sure we are. */
function identifier(drafts: Draft[], password: Draft | undefined): Draft | undefined {
  const before = password ? drafts.slice(0, drafts.indexOf(password)) : drafts;
  const candidates = before.length > 0 ? before : drafts;
  for (const type of ['username', 'email', 'tel'] as const) {
    const found = candidates.findLast((d) => d.type === type);
    if (found) return found;
  }
  return candidates.findLast((d) => d.type === 'unknown' && !(isSelect(d.element)));
}

interface Intent {
  /** What the form's buttons, or failing that its headings and links, say it does. */
  purpose?: 'login' | 'signup';
  change: boolean;
  next: boolean;
  /** It talks about a one-time code, or a button says to verify. */
  code: boolean;
}

function intent(container: Element, reasons: string[]): Intent {
  const buttons = Array.from(container.querySelectorAll(BUTTONS)).filter(isSubmitLike).map(elementText).join(' | ');
  const context = `${contextText(container)} | ${headingBefore(container)} | ${normalize(container.ownerDocument.title)}`;
  const result: Intent = { change: false, next: !!match('next', buttons), code: !!(match('one-time-code', `${buttons} | ${context}`) || match('confirm', buttons)) };
  for (const [where, text] of [['button', buttons], ['heading or link', context]] as const) {
    const login = match('login', text);
    const signup = match('signup', text);
    const change = match('change', text);
    if (change && !result.change) {
      result.change = true;
      reasons.push(`${where} says "${change}"`);
    }
    if (!result.purpose && (login ? 1 : 0) + (signup ? 1 : 0) === 1) {
      result.purpose = login ? 'login' : 'signup';
      reasons.push(`${where} says "${login ?? signup}"`);
    }
  }
  return result;
}

/**
 * A sign-in always wins over a key: `type=password` next to an account field, or on a form that says it
 * signs in, is that account's password whatever it's called, and `name="token"` there is a 2FA code.
 */
function settleCredentials(visible: Draft[], says: Intent): void {
  const account = visible.some((d) => IDENTIFIER.has(d.type));
  for (const draft of visible) {
    if (draft.type !== 'api-credential') continue;
    if (isPasswordInput(draft) && (account || says.purpose === 'login')) {
      note(draft, bestType(draft.signals, (t) => t !== 'api-credential'), 'the password of a sign-in form, not a key');
    } else if (has(draft, 'one-time-code') && (says.code || says.purpose === 'login')) {
      note(draft, 'one-time-code', 'a token on a sign-in step is a one-time code');
    }
  }
}

function classify(container: Element, drafts: Draft[]): { type: FormType; reasons: string[] } {
  const reasons: string[] = [];
  const visible = drafts.filter((d) => d.fillable && d.type !== 'search');
  const says = intent(container, reasons);

  // One-time code split into boxes.
  const segments = splitCode(visible);
  segments.forEach((d, i) => {
    note(d, 'one-time-code', `box ${i + 1} of ${segments.length} one-character inputs`);
    d.segment = i;
  });
  if (segments.length > 0) reasons.push(`a code split over ${segments.length} inputs`);

  // Cards: card types only count when the form clearly takes a card.
  const isCard =
    visible.some((d) => d.type === 'cc-number' || has(d, 'cc-number', (s) => s === 'autocomplete')) ||
    visible.filter((d) => CARD.has(d.type)).length >= 2;
  for (const d of drafts) {
    if (segments.includes(d)) continue;
    if (isCard) {
      // In a card form a 'security code' is the CVC, and selects of months and years are the expiry
      // even with nothing but their options to go on.
      const card = bestType(d.signals, (t) => t !== 'one-time-code' || !has(d, 'cc-csc'), MIN_CARD_SCORE);
      if (card !== d.type) note(d, card, 'inside a card form');
    } else if (CARD.has(d.type)) {
      note(d, bestType(d.signals, (t) => !CARD.has(t)), 'not a card form');
    }
  }
  if (isCard) {
    reasons.push('has card fields');
    return { type: 'card', reasons };
  }

  // Bank fields count only on a form that clearly takes a bank account, and never beside a password:
  // some sites sign in with an 'Account number' and a 'Sort code'. Database fields count only beside
  // exactly one password: a console's sign-in with its server or database. Elsewhere both are words.
  const masked = visible.filter((d) => PASSWORD.has(d.type));
  const isBank = masked.length === 0 && (visible.some((d) => d.type === 'iban') || visible.filter((d) => BANK.has(d.type)).length >= 2);
  const isDatabase = masked.length === 1 && visible.some((d) => d.type === 'db-host' || d.type === 'db-name');
  for (const d of drafts) {
    if (BANK.has(d.type) && !isBank) note(d, bestType(d.signals, (t) => !CARD.has(t) && !BANK.has(t) && (isDatabase || !DATABASE.has(t))), 'not a bank form');
    if (DATABASE.has(d.type) && !isDatabase) note(d, bestType(d.signals, (t) => !CARD.has(t) && !DATABASE.has(t) && (isBank || !BANK.has(t))), 'not a database form');
  }
  if (isDatabase) reasons.push('a server or database field beside the password');

  settleCredentials(visible, says);

  const passwords = visible.filter((d) => PASSWORD.has(d.type) || (isPasswordInput(d) && !MASKED_VALUES.has(d.type) && !segments.includes(d)));
  if (passwords.length >= 2) {
    passwordRoles(passwords, reasons);
    const changing = passwords.some((d) => d.type === 'current-password');
    const id = identifier(visible, passwords[0]);
    if (id && id.type !== 'email' && id.type !== 'username') note(id, 'username', 'the account field of the form');
    if (changing) return { type: 'change-password', reasons };
    return { type: says.change && says.purpose !== 'signup' ? 'change-password' : 'signup', reasons };
  }

  if (passwords.length === 1) {
    const password = passwords[0]!;
    const scored = scores(password.signals);
    const saysNew = (scored.get('new-password') ?? 0) > (scored.get('current-password') ?? 0);
    const others = visible.filter((d) => d !== password && d.type !== 'one-time-code');
    const personal = others.filter((d) => IDENTITY.has(d.type) && d.type !== 'email' && d.type !== 'tel').length;
    const markedCurrent = has(password, 'current-password', (s) => s === 'autocomplete');
    // A database console's server, user, database and port aren't a sign-up's extra fields.
    const signup =
      saysNew ||
      (!isDatabase && (says.purpose === 'signup' || (says.purpose !== 'login' && !markedCurrent && (personal >= 1 || others.length >= 3))));
    if (signup) {
      note(password, 'new-password', saysNew ? 'labelled as a new password' : 'the password of a sign-up form');
      if (others.length === 0 && says.change && says.purpose !== 'signup') return { type: 'change-password', reasons };
      if (personal >= 1 || others.length >= 3) reasons.push(`${others.length} other fields`);
      return { type: 'signup', reasons };
    }
    note(password, 'current-password', 'the password of a sign-in form');
    const id = identifier(visible, password);
    if (id) note(id, 'username', 'the account field of a sign-in form');
    else {
      const hidden = drafts.find((d) => !d.fillable && IDENTIFIER.has(d.type));
      if (hidden) note(hidden, 'username', 'a hidden account field next to the password');
    }
    return { type: isDatabase ? 'database' : 'login', reasons };
  }

  if (visible.some((d) => d.type === 'one-time-code')) return { type: 'one-time-code', reasons };

  const id = identifier(visible, undefined);
  const looksLikeAccount =
    id && (id.type === 'username' || says.purpose === 'login' || says.next) && says.purpose !== 'signup';
  if (id && looksLikeAccount && visible.length <= 2) {
    note(id, 'username', 'the only account field of a sign-in step');
    return { type: 'identifier', reasons };
  }

  // An address form with an IBAN (a direct debit checkout) stays an address form, so it's still saved
  // as one; its bank fields fill all the same.
  const identity = visible.filter((d) => IDENTITY.has(d.type));
  if (identity.length >= 2 || identity.some((d) => d.type.startsWith('address') || d.type === 'postal-code')) {
    reasons.push(`${identity.length} personal details fields`);
    return { type: 'identity', reasons };
  }
  if (isBank) {
    reasons.push('has bank account fields');
    return { type: 'bank', reasons };
  }
  if (identity.length === 1 && identity[0]!.type === 'email') return { type: 'identity', reasons };
  return { type: 'unknown', reasons };
}

/** Groups fields into forms and settles each field's type with what the rest of the form says. */
export function classifyFields(elements: FillableElement[]): Form[] {
  const groups = new Map<Element, Draft[]>();
  for (const element of elements) {
    const signals = fieldSignals(element);
    const draft: Draft = { element, fillable: visibilityProblem(element) === null, signals, type: bestType(signals) };
    const container = owner(element);
    groups.set(container, [...(groups.get(container) ?? []), draft]);
  }
  const forms: Form[] = [];
  for (const [container, drafts] of groups) {
    const { type, reasons } = classify(container, drafts);
    forms.push({
      element: container,
      type,
      reasons,
      fields: drafts.map(({ element, fillable, signals, type: fieldType, segment }) => ({
        element,
        type: fieldType,
        fillable,
        signals,
        ...(segment === undefined ? {} : { segment }),
      })),
    });
  }
  return forms;
}
