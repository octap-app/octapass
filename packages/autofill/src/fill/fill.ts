import { isSelect, isTextArea } from '../dom/is';
import { coverProblem, visibilityProblem, type CoverProblem, type VisibilityProblem } from '../dom/visibility';
import type { Field, FieldType, FillableElement, FillValues, Form } from '../types';
import { setValue } from './value';

export interface FillStep {
  field: Field;
  value: string;
  /** Other spellings a select may use ('9' for '09', 'United States' for 'US'). */
  alternatives: string[];
}

function hintText(element: FillableElement): string {
  return `${element.getAttribute('placeholder') ?? ''} ${element.getAttribute('aria-label') ?? ''} ${
    Array.from(element.labels ?? [], (l) => l.textContent).join(' ')
  }`.toLowerCase();
}

function maxLength(element: FillableElement): number {
  return isSelect(element) ? -1 : element.maxLength;
}

/** `MM/YY` or `MM/YYYY` from the host, as month and two- and four-digit years. */
function expiry(value: string | undefined): { month: string; yy: string; yyyy: string } | undefined {
  const parts = /^\s*(\d{1,2})\s*[/-]\s*(\d{2}|\d{4})\s*$/.exec(value ?? '');
  if (!parts) return undefined;
  const month = parts[1]!.padStart(2, '0');
  const year = parts[2]!;
  return { month, yy: year.slice(-2), yyyy: year.length === 4 ? year : `20${year}` };
}

const MONTHS = ['january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november', 'december'];

function countryNames(code: string, doc: Document): string[] {
  if (!/^[a-z]{2}$/i.test(code)) return [];
  const names: string[] = [];
  for (const locale of new Set(['en', doc.documentElement.lang || 'en'])) {
    try {
      const name = new Intl.DisplayNames([locale], { type: 'region' }).of(code.toUpperCase());
      if (name) names.push(name);
    } catch {
      // An unknown page language: English is enough.
    }
  }
  return code.toUpperCase() === 'US' ? [...names, 'USA', 'United States of America'] : names;
}

function splitName(name: string | undefined): [string, string] | undefined {
  const parts = name?.trim().split(/\s+/);
  if (!parts || parts.length < 2) return undefined;
  return [parts.slice(0, -1).join(' '), parts[parts.length - 1]!];
}

/** Spaces and dashes go when a code doesn't fit the field as written: `12-34-56` in a 6-character box. */
function fitted(value: string | undefined, element: FillableElement): string | undefined {
  const limit = maxLength(element);
  return value && limit > 0 && value.length > limit ? value.replace(/[\s-]/g, '') : value;
}

function valueFor(field: Field, values: FillValues, form: Form): Omit<FillStep, 'field'> | undefined {
  const element = field.element;
  const type = field.type as Exclude<FieldType, 'search' | 'unknown'>;
  const one = (value: string | undefined, alternatives: string[] = []) =>
    value ? { value, alternatives } : undefined;
  const exp = expiry(values['cc-exp']);
  const hint = hintText(element);

  switch (type) {
    case 'confirm-password':
      return one(values['confirm-password'] ?? values['new-password']);
    case 'one-time-code': {
      const code = values['one-time-code'];
      if (field.segment === undefined) return one(code);
      // A code that doesn't fit the boxes exactly is never filled partly; the host copies it instead.
      const digits = code?.replace(/\s/g, '');
      const boxes = form.fields.filter((f) => f.type === 'one-time-code' && f.segment !== undefined).length;
      return digits?.length === boxes ? one(digits[field.segment]) : undefined;
    }
    case 'name':
      return one(values.name ?? ([values['given-name'], values['family-name']].filter(Boolean).join(' ') || undefined));
    case 'given-name':
      return one(values['given-name'] ?? splitName(values.name)?.[0]);
    case 'family-name':
      return one(values['family-name'] ?? splitName(values.name)?.[1]);
    case 'cc-exp': {
      if (values['cc-exp'] === undefined || !exp) return one(values['cc-exp']);
      const long = /yyyy|aaaa|jjjj/.test(hint) || maxLength(element) >= 7;
      const separator = /\d?\s\/\s|mm \/ /.test(hint) ? ' / ' : '/';
      const year = long ? exp.yyyy : exp.yy;
      if (maxLength(element) === 4) return one(`${exp.month}${exp.yy}`);
      return one(`${exp.month}${separator}${year}`);
    }
    case 'cc-exp-month':
      if (values['cc-exp-month']) return one(values['cc-exp-month']);
      if (!exp) return undefined;
      return one(maxLength(element) === 1 ? String(Number(exp.month)) : exp.month, [
        String(Number(exp.month)),
        MONTHS[Number(exp.month) - 1]!,
        MONTHS[Number(exp.month) - 1]!.slice(0, 3),
      ]);
    case 'cc-exp-year': {
      if (values['cc-exp-year']) return one(values['cc-exp-year']);
      if (!exp) return undefined;
      const short = maxLength(element) === 2 || (/\byy\b|^yy$|\baa\b|\bjj\b/.test(hint.trim()) && !/yyyy/.test(hint));
      return short ? one(exp.yy, [exp.yyyy]) : one(exp.yyyy, [exp.yy]);
    }
    case 'country': {
      const code = values.country;
      return code ? one(code, countryNames(code, element.ownerDocument)) : undefined;
    }
    case 'address-line1':
      // A street-address textarea takes both lines, unless the form has its own second line.
      const ownLine2 = form.fields.some((f) => f.type === 'address-line2' && f.fillable);
      if (isTextArea(element) && values['address-line2'] && !ownLine2) {
        return one([values['address-line1'], values['address-line2']].filter(Boolean).join('\n'));
      }
      return one(values['address-line1']);
    case 'iban':
      // Written without spaces: forms that take spaces take it this way too, and many refuse them.
      return one(values.iban?.replace(/\s/g, '').toUpperCase());
    case 'bic':
    case 'bank-account-number':
    case 'bank-routing':
      return one(fitted(values[type], element));
    case 'db-host': {
      // Consoles without a port field (Adminer, phpMyAdmin) take `host:port` in the server field.
      const host = values['db-host'];
      const port = values['db-port'];
      const ownPort = form.fields.some((f) => f.type === 'db-port' && f.fillable);
      return one(host && port && !ownPort ? `${host}:${port}` : host);
    }
    default:
      return one(values[type]);
  }
}

/** What to put where: only fields of this form, only types the host gave a value for. */
export function planFill(form: Form, values: FillValues): FillStep[] {
  const steps: FillStep[] = [];
  for (const field of form.fields) {
    if (field.type === 'search' || field.type === 'unknown') continue;
    const step = valueFor(field, values, form);
    if (step) steps.push({ field, ...step });
  }
  return steps;
}

export interface FillResult {
  filled: FillableElement[];
  /** `refused`: not filled because another field of the same fill was drawn over. */
  skipped: { element: FillableElement; reason: VisibilityProblem | CoverProblem | 'no-option' | 'refused' }[];
}

/**
 * Fills the planned fields that are visible and of a usable size, then returns focus to `origin`. Hidden
 * fields are skipped (decoys are common). If any planned field is drawn over by the page, nothing is
 * filled at all: a covered field is a sign of an overlay attack, not of a field to leave out. The caller
 * has already checked the gesture and the origin field itself. With no `origin` (a fill on page load)
 * focus stays where it is.
 */
export function runFill(steps: FillStep[], origin: FillableElement | null, ownUi: (element: Element) => boolean): FillResult {
  const result: FillResult = { filled: [], skipped: [] };
  const checked = steps.map((step) => {
    const hidden = visibilityProblem(step.field.element);
    const covered = hidden ? null : coverProblem(step.field.element, ownUi);
    return { step, problem: hidden ?? (covered === 'covered' ? covered : null) };
  });
  if (checked.some(({ problem }) => problem === 'covered')) {
    for (const { step, problem } of checked) result.skipped.push({ element: step.field.element, reason: problem ?? 'refused' });
  } else {
    for (const { step, problem } of checked) {
      const { element } = step.field;
      if (problem) result.skipped.push({ element, reason: problem });
      else if (setValue(element, step.value, step.alternatives, origin !== null)) result.filled.push(element);
      else result.skipped.push({ element, reason: 'no-option' });
    }
  }
  if (origin?.isConnected) origin.focus({ preventScroll: true });
  return result;
}
