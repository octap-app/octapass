// Small notices the content script shows in the page: save prompts and short confirmations. They
// stack in one closed shadow root in the top layer (inside an open modal <dialog>, when there is
// one, since everything outside it is inert), and only trusted clicks and key presses count.

import { direction, getLocale } from '@octapass/web/src/i18n/core';
// Relative paths: these packages don't export them, and a closed shadow root can't see any stylesheet
// of ours. The same tokens as the inline menu, and the brand's own tile.
import { LIGHT, tokenCss } from '../../../../packages/autofill/src/menu/tokens';
import tileSvg from '../../../../packages/ui/src/assets/logo-tile.svg?raw';

/** At most this many toasts at once; a new one pushes the oldest out. Questions always stay. */
const MAX_TOASTS = 3;

// Sizes in px, not rem: a rem follows the page's root font size. `all: initial` comes before the
// tokens, so it doesn't reset their `color-scheme`.
const CSS = `
.root { all: initial; position: fixed; inset-block-start: 12px; inset-inline-end: 12px; display: flex; flex-direction: column; gap: 8px;
  inline-size: min(360px, calc(100vw - 24px)); max-block-size: calc(100vh - 24px); overflow-y: auto; overscroll-behavior: contain;
  pointer-events: none; font-family: var(--font-sans); font-size: 14px; line-height: 1.4; color: var(--ink);
  -webkit-font-smoothing: antialiased; -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
${tokenCss('.root')}
.root { --button: ${LIGHT['--trust']}; --radius-sm: 8px; --radius: 12px; }
.root *, .root *::before, .root *::after { box-sizing: border-box; }
svg { display: block; flex: none; }
.card { pointer-events: auto; position: relative; overflow: hidden; display: flex; flex-direction: column; gap: 12px;
  padding-block: 10px 14px; padding-inline: 14px 10px; border-radius: 14px; background: var(--raised);
  border: 1px solid var(--line); box-shadow: var(--shadow-pop); }
.head { display: flex; align-items: center; gap: 8px; min-block-size: 28px; color: var(--mist); font-size: 12px; font-weight: 600; letter-spacing: 0.01em; }
.tile svg { inline-size: 18px; block-size: 18px; }
.close { all: unset; margin-inline-start: auto; flex: none; display: grid; place-items: center; inline-size: 28px; block-size: 28px;
  border-radius: var(--radius-sm); color: var(--mist); cursor: pointer; }
.close svg { inline-size: 16px; block-size: 16px; }
.close:hover { background: var(--hover); color: var(--ink); }
.body { display: flex; flex-direction: column; gap: 12px; padding-inline-end: 4px; }
.site { display: flex; align-items: center; gap: 12px; min-inline-size: 0; }
.monogram { flex: none; display: grid; place-items: center; inline-size: 38px; block-size: 38px; border-radius: 11px;
  color: white; font-weight: 700; font-size: 16px; text-transform: uppercase;
  background: linear-gradient(135deg, hsl(var(--h) 72% 56%), hsl(calc(var(--h) + 30) 68% 42%)); }
.text { display: flex; flex-direction: column; gap: 1px; min-inline-size: 0; }
.title { font-size: 15px; font-weight: 650; line-height: 1.3; letter-spacing: -0.01em; text-wrap: balance; }
.host { color: var(--trust-text); font-size: 13px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rows { display: flex; flex-direction: column; border-radius: var(--radius); background: var(--tile); }
.row { display: flex; align-items: center; gap: 10px; min-block-size: 38px; padding: 8px 12px; overflow-wrap: anywhere; }
.row + .row { border-block-start: 1px solid var(--line); }
.row svg { inline-size: 16px; block-size: 16px; color: var(--mist); }
.mask { font-family: var(--font-mono); letter-spacing: 0.12em; color: var(--mist); }
.note { display: flex; gap: 8px; color: var(--mist); font-size: 13px; }
.note svg { inline-size: 15px; block-size: 15px; margin-block-start: 2px; }
.check { display: flex; align-items: center; gap: 8px; color: var(--ink); font-size: 13px; cursor: pointer; }
.check input { margin: 0; inline-size: 16px; block-size: 16px; accent-color: var(--button); }
.actions { display: flex; flex-wrap: wrap; align-items: center; justify-content: flex-end; gap: 8px; padding-inline-end: 4px; }
button { font: inherit; }
.btn { display: inline-flex; align-items: center; justify-content: center; min-block-size: 32px; padding: 0 14px; border-radius: 999px;
  font-size: 14px; font-weight: 600; cursor: pointer; border: 1px solid transparent; }
.primary { background: var(--button); color: white; }
.primary:hover { filter: brightness(1.08); }
.secondary { background: var(--tile); color: var(--ink); border-color: var(--line); }
.secondary:hover { background: color-mix(in srgb, var(--tile), var(--ink) 6%); }
.quiet { all: unset; margin-inline-end: auto; padding: 6px 2px; color: var(--mist); font-size: 13px; font-weight: 500; cursor: pointer;
  text-decoration: underline; text-decoration-color: transparent; text-underline-offset: 0.2em; }
.quiet:hover { color: var(--ink); text-decoration-color: currentColor; }
.close:focus-visible, .btn:focus-visible, .quiet:focus-visible, .check input:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
.toast { flex-direction: row; align-items: flex-start; gap: 10px; padding-block: 12px; }
.toast .tile { padding-block-start: 1px; }
.toast .text { flex: 1; gap: 2px; padding-block-start: 1px; }
.toast .title { font-size: 14px; font-weight: 600; }
.toast .detail { color: var(--mist); font-size: 13px; overflow-wrap: anywhere; }
.toast .close { margin-block: -4px; }
.progress { display: none; }
@media (prefers-reduced-motion: no-preference) {
  .card { animation: enter 200ms var(--ease-out); }
  .progress { display: block; position: absolute; inset-inline: 0; inset-block-end: 0; block-size: 2px; background: var(--trust);
    opacity: 0.55; transform-origin: left; animation: drain linear forwards; }
  [dir='rtl'] .progress { transform-origin: right; }
  .paused .progress { animation-play-state: paused; }
}
@keyframes enter { from { opacity: 0; transform: translateY(-8px) scale(0.98); } }
@keyframes drain { to { transform: scaleX(0); } }
`;

const ICONS = {
  close: '<path d="M6 6l12 12M18 6 6 18"/>',
  user: '<circle cx="12" cy="8.5" r="3.5"/><path d="M5 19.5a7 7 0 0 1 14 0"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 8.5-8.5M16.5 6.5l2.5 2.5M14 9l2 2"/>',
  card: '<rect x="3" y="5.5" width="18" height="13" rx="2.5"/><path d="M3 10h18M7 15h3"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  mapPin: '<path d="M12 20.5s6.5-5.4 6.5-10.5a6.5 6.5 0 0 0-13 0c0 5.1 6.5 10.5 6.5 10.5Z"/><circle cx="12" cy="10" r="2.5"/>',
  code: '<path d="m8 8-4 4 4 4M16 8l4 4-4 4M13.5 5.5l-3 13"/>',
  lock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
  login: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.3 2.3 3.4 5.2 3.4 8.5s-1.1 6.2-3.4 8.5c-2.3-2.3-3.4-5.2-3.4-8.5S9.7 5.8 12 3.5Z"/>',
} as const;

export type RowIcon = Exclude<keyof typeof ICONS, 'close'>;

/** A line of what's being saved. `masked`: a password, shown as dots; `text` is then its accessible name. */
export interface Row {
  icon: RowIcon;
  text: string;
  masked?: boolean;
}

// ---------- The layer ----------

interface Layer {
  host: HTMLElement;
  stack: HTMLElement;
}

let layer: Layer | undefined;
let sheet: CSSStyleSheet | null | undefined;
let ids = 0;
/** How to take each card away, for the toast limit. */
const closers = new WeakMap<HTMLElement, () => void>();

/** One parsed stylesheet for every notice in this frame (no re-parsing per notice); `null` without constructable sheets. */
function sharedSheet(): CSSStyleSheet | null {
  if (sheet !== undefined) return sheet;
  try {
    sheet = new CSSStyleSheet();
    sheet.replaceSync(CSS);
  } catch {
    sheet = null;
  }
  return sheet;
}

function style(root: ShadowRoot): void {
  const shared = sharedSheet();
  if (shared && 'adoptedStyleSheets' in root) {
    try {
      root.adoptedStyleSheets = [shared];
      // Firefox can refuse a sheet made in a content script's isolated world; a <style> works there.
      if (root.adoptedStyleSheets.includes(shared)) return;
    } catch {
      // Below.
    }
  }
  const element = document.createElement('style');
  element.textContent = CSS;
  root.append(element);
}

function createLayer(): Layer {
  const host = document.createElement('octapass-notice');
  host.setAttribute('popover', 'manual');
  host.style.cssText = 'all: initial !important; position: fixed !important; inset: 0 !important; inline-size: 0 !important; block-size: 0 !important; overflow: visible !important; border: 0 !important; background: none !important';
  const root = host.attachShadow({ mode: 'closed' });
  style(root);
  const stack = document.createElement('div');
  stack.className = 'root';
  root.append(stack);
  return { host, stack };
}

/** Everything outside an open modal <dialog> is inert, so a notice there couldn't be answered. */
function container(): Element {
  return document.querySelector('dialog:modal') ?? document.body ?? document.documentElement;
}

/** Puts the layer where it can be answered, on top of the top layer (a popover the page opened since). */
function raise({ host }: Layer): void {
  const parent = container();
  // Moving it closes the popover, so it's shown again below.
  if (host.parentNode !== parent) parent.append(host);
  try {
    // Not while the user is in a notice: hiding it would move their focus back to the page.
    if (host.matches(':popover-open') && !host.matches(':focus-within')) host.hidePopover();
    if (!host.matches(':popover-open')) host.showPopover?.();
  } catch {
    // No popover support, or the page took it out: it's still fixed on top of the page.
  }
}

function add(card: HTMLElement): void {
  layer ??= createLayer();
  // In the extension's language, whatever the page's is.
  layer.stack.lang = getLocale();
  layer.stack.dir = direction();
  layer.stack.prepend(card);
  const toasts = [...layer.stack.querySelectorAll<HTMLElement>(':scope > .toast')];
  for (const old of toasts.slice(MAX_TOASTS)) closers.get(old)?.();
  raise(layer);
}

/** Takes a card away; the last one takes the layer with it. */
function remove(card: HTMLElement): void {
  card.remove();
  closers.delete(card);
  if (layer && !layer.stack.firstElementChild) {
    layer.host.remove();
    layer = undefined;
  }
}

// ---------- Building blocks ----------

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function icon(name: keyof typeof ICONS): SVGSVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.75');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  // Our own constant markup, never page data.
  svg.innerHTML = ICONS[name];
  return svg;
}

/** The brand tile (below 24 px the bare mark is too thin), with a gradient id of its own. */
function tile(): HTMLElement {
  const span = el('span', 'tile');
  const id = `op-t-${++ids}`;
  // Our own constant markup, never page data.
  span.innerHTML = tileSvg
    .replace(/<title>.*?<\/title>/, '')
    .replaceAll('op-t', id)
    .replace('width="64" height="64"', 'aria-hidden="true" focusable="false"');
  return span;
}

/** A stable hue per host, like the vault's avatars. */
function hue(name: string): number {
  let hash = 0;
  for (const char of name.toLowerCase()) hash = (hash * 31 + char.codePointAt(0)!) >>> 0;
  return hash % 360;
}

/** Data from the page or the vault: its own direction, so an Arabic UI doesn't scramble a host or an email. */
function data(tag: 'span' | 'div', className: string, text: string): HTMLElement {
  const element = el(tag, className, text);
  element.dir = 'auto';
  return element;
}

/** Calls `handler` only for the user's own input, never for events the page made up. */
function trusted<E extends Event>(handler: (event: E) => void): (event: E) => void {
  return (event) => {
    if (event.isTrusted) handler(event);
  };
}

function closeButton(label: string, onClose: () => void): HTMLButtonElement {
  const button = el('button', 'close');
  button.type = 'button';
  button.setAttribute('aria-label', label);
  button.title = label;
  button.append(icon('close'));
  button.addEventListener('click', trusted(onClose));
  return button;
}

// ---------- Toasts ----------

export interface ToastOptions {
  /** How long it shows; hovering or focusing it pauses the clock. */
  ms?: number;
  /** The close button's accessible name. */
  dismiss?: string;
}

/** A confirmation that goes away by itself, with a bar that shows how long it has left. */
export function showToast(title: string, detail?: string, { ms = 4000, dismiss = 'Dismiss' }: ToastOptions = {}): () => void {
  const card = el('section', 'card toast');
  card.setAttribute('role', 'status');
  card.setAttribute('aria-live', 'polite');
  const text = el('div', 'text');
  text.append(el('div', 'title', title));
  if (detail) text.append(el('div', 'detail', detail));
  const progress = el('div', 'progress');
  progress.style.setProperty('animation-duration', `${ms}ms`);
  progress.setAttribute('aria-hidden', 'true');

  let timer: ReturnType<typeof setTimeout> | undefined;
  let remaining = ms;
  let started = 0;
  const close = () => {
    clearTimeout(timer);
    timer = undefined;
    remove(card);
  };
  const run = () => {
    started = performance.now();
    timer = setTimeout(close, remaining);
  };
  const pause = () => {
    if (timer === undefined) return;
    clearTimeout(timer);
    timer = undefined;
    remaining = Math.max(0, remaining - (performance.now() - started));
    card.classList.add('paused');
  };
  const resume = () => {
    if (timer !== undefined || !card.isConnected || card.matches(':hover, :focus-within')) return;
    card.classList.remove('paused');
    run();
  };
  card.addEventListener('pointerenter', pause);
  card.addEventListener('focusin', pause);
  card.addEventListener('pointerleave', resume);
  // After focus has moved: still inside, it stays paused.
  card.addEventListener('focusout', () => void setTimeout(resume));

  card.append(tile(), text, closeButton(dismiss, close), progress);
  closers.set(card, close);
  add(card);
  run();
  return close;
}

// ---------- Questions ----------

export interface Answer<A extends string> {
  value: A;
  label: string;
}

export interface Question<A extends string> {
  title: string;
  /** The site it's for, shown under the title. */
  host?: string;
  /** What would be saved. */
  rows?: Row[];
  /** A quieter line under the rows. */
  note?: string;
  /** A box the user can tick, unticked to start with. */
  check?: string;
  /** Save, Update, Add. */
  primary: Answer<A>;
  /** "Not now": also what the close button and Escape mean. */
  secondary: Answer<A>;
  /** "Never for this site": a link-like button at the start of the actions. */
  quiet?: Answer<A>;
  /** The close button's accessible name; the secondary answer's label by default. */
  closeLabel?: string;
}

/** Asks a question; a click the page synthesised is ignored, and so is a tick it set. Returns a way to take it back. */
export function askUser<A extends string>(question: Question<A>, onAnswer: (answer: A, checked: boolean) => void): () => void {
  const card = el('section', 'card');
  card.setAttribute('role', 'dialog');
  const titleId = `octapass-notice-${++ids}`;
  card.setAttribute('aria-labelledby', titleId);

  let answered = false;
  const close = () => {
    answered = true;
    remove(card);
  };
  let checked = false;
  const answer = (value: A) => {
    if (answered) return;
    close();
    onAnswer(value, checked);
  };

  const head = el('div', 'head');
  head.append(tile(), el('span', '', 'Octa Pass'), closeButton(question.closeLabel ?? question.secondary.label, () => answer(question.secondary.value)));

  const body = el('div', 'body');
  const site = el('div', 'site');
  const text = el('div', 'text');
  const title = el('div', 'title', question.title);
  title.id = titleId;
  text.append(title);
  if (question.host) {
    const monogram = el('span', 'monogram', Array.from(question.host.replace(/^www\./, ''))[0] ?? '?');
    monogram.style.setProperty('--h', String(hue(question.host)));
    monogram.setAttribute('aria-hidden', 'true');
    site.append(monogram);
    text.append(data('div', 'host', question.host));
  }
  site.append(text);
  body.append(site);

  if (question.rows?.length) {
    const rows = el('div', 'rows');
    for (const { icon: name, text: value, masked } of question.rows) {
      const row = el('div', 'row');
      if (masked) {
        row.setAttribute('aria-label', value);
        row.setAttribute('role', 'img');
        // A fixed length: the prompt never has the password, and shouldn't hint at its length.
        row.append(icon(name), el('span', 'mask', '••••••••••'));
      } else {
        row.append(icon(name), data('span', '', value));
      }
      rows.append(row);
    }
    body.append(rows);
  }
  if (question.note) {
    const note = el('div', 'note');
    note.append(icon('lock'), el('span', '', question.note));
    body.append(note);
  }
  if (question.check) {
    const label = el('label', 'check');
    const input = el('input', '');
    input.type = 'checkbox';
    input.addEventListener('change', (event) => {
      checked = event.isTrusted && input.checked;
      input.checked = checked;
    });
    label.append(input, question.check);
    body.append(label);
  }

  const actions = el('div', 'actions');
  const button = ({ value, label }: Answer<A>, className: string) => {
    const element = el('button', className, label);
    element.type = 'button';
    element.addEventListener('click', trusted(() => answer(value)));
    actions.append(element);
  };
  if (question.quiet) button(question.quiet, 'quiet');
  button(question.secondary, 'btn secondary');
  button(question.primary, 'btn primary');

  card.addEventListener(
    'keydown',
    trusted((event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.stopPropagation();
      answer(question.secondary.value);
    }),
  );

  card.append(head, body, actions);
  closers.set(card, close);
  add(card);
  return close;
}

/** For tests: forgets the layer between them. */
export function resetNotices(): void {
  layer?.host.remove();
  layer = undefined;
}
