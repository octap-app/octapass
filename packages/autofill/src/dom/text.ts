import type { FillableElement } from '../types';
import { isElement, isInput } from './is';

/**
 * Lower-cases and folds text so one keyword list matches its common spellings: Latin accents are dropped
 * ('Contraseña' → 'contrasena'), Arabic diacritics and letter variants are unified, full-width forms are
 * narrowed. Devanagari and CJK are left alone because their combining marks carry meaning.
 */
export function normalize(text: string): string {
  return text
    .normalize('NFKC')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .normalize('NFC')
    .replace(/[ً-ٰٟـ]/g, '')
    .replace(/[أإآٱ]/g, 'ا')
    .replace(/ى/g, 'ي')
    .replace(/ة/g, 'ه')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Splits identifiers into words: 'userName' / 'user_name' / 'user-name' → 'user name'. */
export function words(identifier: string): string {
  return normalize(identifier.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[^\p{L}\p{N}]+/gu, ' '));
}

export type HintSource = 'autocomplete' | 'attribute' | 'label' | 'placeholder' | 'description';

export interface FieldHints {
  autocomplete: string[];
  /** `name` and `id`, split into words. */
  attribute: string[];
  /** `<label>`, `aria-label`, `aria-labelledby` and a short leading text in the same container. */
  label: string[];
  placeholder: string[];
  /** `title` and `aria-describedby`. */
  description: string[];
}

function textOf(element: Element | null | undefined): string {
  if (!element) return '';
  // Inputs nested inside a <label> would add their values to its text; take text nodes only.
  let text = '';
  const walker = element.ownerDocument.createTreeWalker(element, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT, {
    acceptNode: (node) =>
      isElement(node) && /^(SCRIPT|STYLE|SELECT|TEXTAREA|OPTION)$/.test(node.tagName)
        ? NodeFilter.FILTER_REJECT
        : NodeFilter.FILTER_ACCEPT,
  });
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    if (node.nodeType === Node.TEXT_NODE) text += ` ${node.nodeValue ?? ''}`;
  }
  return normalize(text);
}

function byIds(element: Element, attribute: string): string[] {
  const root = element.getRootNode() as Document | ShadowRoot;
  return (element.getAttribute(attribute) ?? '')
    .split(/\s+/)
    .filter(Boolean)
    .map((id) => textOf(root.getElementById?.(id)))
    .filter(Boolean);
}

const MAX_LEADING_TEXT = 40;

/**
 * Text right before the field in its parent, for pages that put a label in a <span> or <div>
 * without associating it. Only short text counts, so paragraphs of help text don't leak in.
 */
function leadingText(element: Element): string | undefined {
  for (let node = element.previousSibling, steps = 0; node && steps < 3; node = node.previousSibling, steps++) {
    if (isElement(node) && /^(INPUT|SELECT|TEXTAREA|BUTTON)$/.test(node.tagName)) return undefined;
    const text = isElement(node) ? textOf(node) : normalize(node.textContent ?? '');
    if (text) return text.length <= MAX_LEADING_TEXT ? text : undefined;
  }
  const parent = element.parentElement;
  if (parent && parent.children.length <= 3 && parent.firstElementChild !== element) {
    const sibling = parent.firstElementChild;
    if (sibling && !/^(INPUT|SELECT|TEXTAREA|BUTTON)$/.test(sibling.tagName)) {
      const text = textOf(sibling);
      if (text && text.length <= MAX_LEADING_TEXT) return text;
    }
  }
  return undefined;
}

export function fieldHints(element: FillableElement): FieldHints {
  const labels = Array.from(element.labels ?? [], (label) => textOf(label));
  const aria = element.getAttribute('aria-label');
  const label = [...labels, ...(aria ? [normalize(aria)] : []), ...byIds(element, 'aria-labelledby')];
  if (label.length === 0) {
    const leading = leadingText(element);
    if (leading) label.push(leading);
  }
  const placeholder = element.getAttribute('placeholder');
  const title = element.getAttribute('title');
  return {
    autocomplete: normalize(element.getAttribute('autocomplete') ?? '')
      .split(' ')
      .filter(Boolean),
    attribute: [element.getAttribute('name'), element.id].filter((v): v is string => !!v).map(words),
    label: label.filter(Boolean),
    placeholder: placeholder ? [normalize(placeholder)] : [],
    description: [...(title ? [normalize(title)] : []), ...byIds(element, 'aria-describedby')],
  };
}

/** Visible text of an element, normalized: for buttons, headings and links. */
export function elementText(element: Element): string {
  if (isInput(element)) return normalize(element.value);
  return normalize(`${textOf(element)} ${element.getAttribute('aria-label') ?? ''}`);
}

/**
 * Words around a form that describe what it is for, its headings, legend, links, ids and checkbox labels
 * ('Remember me', 'I agree to the terms'). Its buttons are read separately: they say it best.
 */
export function contextText(container: Element): string {
  const parts: string[] = [];
  for (const value of [container.id, container.getAttribute('name'), container.getAttribute('action'), container.className]) {
    if (typeof value === 'string' && value) parts.push(words(value));
  }
  for (const element of container.querySelectorAll('h1, h2, h3, h4, legend, a, label')) {
    if (element.tagName === 'LABEL' && !element.querySelector('input[type=checkbox]')) {
      const control = (element as HTMLLabelElement).control;
      if (!(isInput(control) && control.type === 'checkbox')) continue;
    }
    parts.push(textOf(element));
  }
  return parts.filter(Boolean).join(' | ');
}

/** The nearest heading above a container, for pages that title a form outside it ('Create your account'). */
export function headingBefore(container: Element): string {
  let element: Element | null = container;
  for (let depth = 0; element && depth < 4; depth++, element = element.parentElement) {
    for (let sibling = element.previousElementSibling; sibling; sibling = sibling.previousElementSibling) {
      const heading = sibling.matches('h1, h2, h3, legend') ? sibling : sibling.querySelector('h1, h2, h3');
      if (heading) return textOf(heading);
    }
  }
  return '';
}
