import { isElement } from '../dom/is';
import type { Suggestion } from '../types';
import { CHEVRON, GLYPHS, LOCK, TILE } from './glyphs';
import { Layer, type LayerProblem } from './layer';
import { LIST_MAX_HEIGHT, MENU_CSS } from './styles';

export interface MenuLabels {
  menu: string;
  icon: string;
  suggestedPassword: string;
  maskedEmail: string;
  needsSetup: string;
  oneTimeCode: string;
  noUsername: string;
  allowFrame: string;
  /** `{frame}` and `{site}` are filled in. */
  frameNotice: string;
  /** The quiet entry for logins on other parts of the site; `{site}` is filled in. */
  otherLogins: string;
  /** Under such a login's title; `{username}` and `{host}` are filled in. */
  otherLoginDetail: string;
  /** The footer's keyboard hints: next to ↑↓, and next to ↵. */
  hintMove: string;
  hintPick: string;
}

export const DEFAULT_LABELS: MenuLabels = {
  menu: 'Octa Pass',
  icon: 'Octa Pass: show suggestions',
  suggestedPassword: 'Use suggested password',
  maskedEmail: 'Use a masked email',
  needsSetup: 'Needs setup',
  oneTimeCode: 'Fill one-time code',
  noUsername: 'No username',
  allowFrame: 'Allow Octa Pass here',
  frameNotice: 'This form is from {frame}, inside {site}.',
  otherLogins: 'Logins for other parts of {site}',
  otherLoginDetail: '{username} on {host}',
  hintMove: 'Move',
  hintPick: 'Choose',
};

export type Theme = 'system' | 'light' | 'dark';

export interface Entry {
  suggestion: Suggestion;
  title: string;
  detail?: string;
  /** Show the detail as data (the suggested password preview). */
  mono?: boolean;
  /** Let the detail wrap instead of cutting it short (a sentence, not a value). */
  wrap?: boolean;
  badge?: string;
  /** Drawn quieter than the suggestions (the entry for logins on other parts of the site). */
  quiet?: boolean;
  disabled: boolean;
}

export function entryFor(suggestion: Suggestion, labels: MenuLabels): Entry {
  switch (suggestion.kind) {
    case 'login':
      // The unlock entry (pinned, while locked) has no account to name.
      return { suggestion, title: suggestion.title, ...(suggestion.pinned ? {} : { detail: suggestion.username || labels.noUsername }), disabled: false };
    case 'generated-password':
      return { suggestion, title: labels.suggestedPassword, detail: suggestion.password, mono: true, disabled: false };
    case 'masked-email':
      return {
        suggestion,
        title: labels.maskedEmail,
        ...(suggestion.disabled ? { badge: suggestion.note ?? labels.needsSetup } : {}),
        disabled: !!suggestion.disabled,
      };
    case 'one-time-code':
      return { suggestion, title: labels.oneTimeCode, detail: suggestion.title, disabled: false };
    case 'card':
    case 'identity':
    case 'api-credential':
      return {
        suggestion,
        title: suggestion.title,
        ...(suggestion.subtitle ? { detail: suggestion.subtitle } : {}),
        disabled: false,
      };
    case 'frame-approval':
      return {
        suggestion,
        title: labels.allowFrame,
        detail: labels.frameNotice.replaceAll('{frame}', suggestion.frameHost).replaceAll('{site}', suggestion.site),
        wrap: true,
        disabled: false,
      };
    case 'other-logins':
      return { suggestion, title: labels.otherLogins.replaceAll('{site}', suggestion.site), quiet: true, disabled: false };
    case 'other-login':
      return {
        suggestion,
        title: suggestion.title,
        detail: labels.otherLoginDetail.replaceAll('{username}', suggestion.username || labels.noUsername).replaceAll('{host}', suggestion.host),
        disabled: false,
      };
  }
}

export interface MenuHandlers {
  pick(entry: Entry, event: Event, element: HTMLElement): void;
  /** Escape or Tab: close, and give focus back to the field when `refocus`. */
  dismiss(refocus: boolean): void;
}

const GAP = 4;
const MARGIN = 8;
/** The panel's tallest: the list at its cap plus the header, the footer and room for a larger minimum font. */
const MAX_HEIGHT = LIST_MAX_HEIGHT + 96;
/** The website icon's size in CSS px (its canvas is drawn at the screen's density). */
const ICON_SIZE = 20;

/** Entries of one section sit together, with a hairline between sections. */
function section(suggestion: Suggestion): string {
  return suggestion.kind === 'other-login' ? 'other-logins' : suggestion.kind;
}

/** The tile letter for a login without a website icon: its title's first character. */
function initial(title: string): string {
  return Array.from(title.trim())[0]?.toLocaleUpperCase() ?? '';
}

/** Letters, digits and symbols of a suggested password told apart by colour, as runs of text. */
function passwordRuns(password: string): { text: string; kind: '' | 'n' | 's' }[] {
  const runs: { text: string; kind: '' | 'n' | 's' }[] = [];
  for (const char of password) {
    const kind = /\p{N}/u.test(char) ? 'n' : /[\p{L}\p{M}]/u.test(char) ? '' : 's';
    const last = runs.at(-1);
    if (last?.kind === kind) last.text += char;
    else runs.push({ text: char, kind });
  }
  return runs;
}

/** The suggestion list: a listbox in a protected top-layer host, styled with the Octa Pass tokens. */
export class Menu {
  private readonly layer: Layer;
  private readonly wrapper: HTMLElement;
  private readonly site: HTMLElement;
  private readonly dot: HTMLElement;
  private readonly list: HTMLElement;
  private items: { entry: Entry; element: HTMLElement }[] = [];
  /** Each SVG parsed once, then cloned for every row that draws it. */
  private readonly svgs = new Map<string, Element>();
  /** When the menu last appeared or moved; picks right after that are too fast to be deliberate. */
  shownAt = 0;

  constructor(
    private readonly doc: Document,
    private readonly handlers: MenuHandlers,
    labels: MenuLabels,
    theme: Theme,
  ) {
    this.layer = new Layer(doc, 'octapass-menu', MENU_CSS);
    this.wrapper = this.element('div', 'root');
    if (theme !== 'system') this.wrapper.dataset.theme = theme;
    const panel = this.element('div', 'panel');

    // The header and footer are drawn only: the listbox is labelled, and each entry says what it is.
    const head = this.element('div', 'head');
    head.setAttribute('aria-hidden', 'true');
    this.dot = this.element('span', 'dot', '·');
    this.site = this.element('span', 'site');
    head.append(this.svg(TILE), this.element('span', 'brand', labels.menu), this.dot, this.site);

    this.list = this.element('div', 'list');
    this.list.setAttribute('role', 'listbox');
    this.list.setAttribute('aria-label', labels.menu);

    const foot = this.element('div', 'foot');
    foot.setAttribute('aria-hidden', 'true');
    const hint = (keys: string[], text: string) => {
      const span = this.element('span', 'hint');
      span.append(...keys.map((key) => this.element('kbd', '', key)), text);
      return span;
    };
    foot.append(hint(['↑', '↓'], labels.hintMove), hint(['↵'], labels.hintPick));

    panel.append(head, this.list, foot);
    this.wrapper.append(panel);
    this.layer.root.append(this.wrapper);

    // Keep focus in the page's field while clicking; keyboard users move focus in with ArrowDown.
    panel.addEventListener('mousedown', (event) => event.preventDefault());
    this.list.addEventListener('click', (event) => {
      const item = this.itemFor(event.target);
      if (item && !item.entry.disabled) this.handlers.pick(item.entry, event, item.element);
    });
    this.list.addEventListener('keydown', (event) => this.onKey(event));
  }

  get isOpen(): boolean {
    return this.layer.isShown;
  }

  get host(): HTMLElement {
    return this.layer.host;
  }

  private element<K extends keyof HTMLElementTagNameMap>(tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
    const element = this.doc.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  private svg(markup: string): Node {
    let parsed = this.svgs.get(markup);
    if (!parsed) {
      const template = this.doc.createElement('template');
      template.innerHTML = markup;
      parsed = template.content.firstElementChild!;
      this.svgs.set(markup, parsed);
    }
    return parsed.cloneNode(true);
  }

  private itemFor(target: EventTarget | null) {
    const element = isElement(target) ? target.closest('.item') : null;
    return this.items.find((item) => item.element === element);
  }

  private glyph(suggestion: Suggestion): HTMLElement {
    const glyph = this.element('span', 'glyph');
    if (suggestion.kind === 'login' && suggestion.pinned) {
      glyph.classList.add('lock');
      glyph.append(this.svg(LOCK));
    } else if ((suggestion.kind === 'login' || suggestion.kind === 'other-login') && initial(suggestion.title)) {
      // A letter tile until (and unless) the website icon arrives. Drawn by CSS, so it isn't text.
      const letter = initial(suggestion.title);
      glyph.classList.add('letter');
      if ((letter.codePointAt(0) ?? 0) % 2 === 1) glyph.classList.add('alt');
      glyph.dataset.letter = letter;
    } else {
      glyph.append(this.svg(GLYPHS[suggestion.kind]));
    }
    return glyph;
  }

  private row(entry: Entry, index: number): HTMLElement {
    const element = this.element('div', entry.quiet ? 'item quiet' : 'item');
    element.id = `op-item-${index}`;
    element.setAttribute('role', 'option');
    element.setAttribute('aria-selected', 'false');
    element.tabIndex = -1;
    if (entry.disabled) element.setAttribute('aria-disabled', 'true');
    const text = this.element('span', 'text');
    text.append(this.element('span', 'title', entry.title));
    if (entry.detail) {
      const detail = this.element('span', entry.mono ? 'detail mono' : entry.wrap ? 'detail wrap' : 'detail');
      if (entry.mono) detail.append(...passwordRuns(entry.detail).map(({ text, kind }) => (kind ? this.element('span', kind, text) : text)));
      else detail.textContent = entry.detail;
      text.append(detail);
    }
    element.append(this.glyph(entry.suggestion), text);
    if (entry.badge) element.append(this.element('span', 'badge', entry.badge));
    if (entry.quiet) {
      const chevron = this.svg(CHEVRON) as Element;
      chevron.setAttribute('class', 'chev');
      element.append(chevron);
    }
    return element;
  }

  private render(entries: Entry[], site: string): void {
    this.site.textContent = site;
    this.dot.hidden = this.site.hidden = !site;
    const rows: HTMLElement[] = [];
    this.items = entries.map((entry, index) => {
      const element = this.row(entry, index);
      const previous = entries[index - 1];
      if (previous && section(previous.suggestion) !== section(entry.suggestion)) {
        const separator = this.element('div', 'sep');
        separator.setAttribute('role', 'none');
        rows.push(separator);
      }
      rows.push(element);
      return { entry, element };
    });
    this.list.replaceChildren(...rows);
    this.list.scrollTop = 0;
  }

  /**
   * Opens below the field (above when there's no room), aligned to its inline start. `site` is the
   * page's host, named in the header.
   */
  open(anchor: DOMRect, rtl: boolean, entries: Entry[], container?: Element, site = ''): void {
    this.render(entries, site);
    const view = this.doc.defaultView ?? window;
    const width = Math.min(360, Math.max(280, anchor.width));
    const left = Math.min(
      Math.max(MARGIN, rtl ? anchor.right - width : anchor.left),
      Math.max(MARGIN, view.innerWidth - width - MARGIN),
    );
    this.wrapper.dir = rtl ? 'rtl' : 'ltr';
    delete this.wrapper.dataset.place;
    this.layer.show({ top: `${anchor.bottom + GAP}px`, left: `${left}px`, width: `${width}px` }, container);
    const roomBelow = view.innerHeight - anchor.bottom - GAP - MARGIN;
    // Measuring forces a layout: only when the menu might not fit below.
    if (roomBelow < MAX_HEIGHT) {
      const height = this.layer.host.getBoundingClientRect().height;
      if (height > roomBelow && anchor.top - GAP - MARGIN > roomBelow) {
        this.layer.move({ top: `${Math.max(MARGIN, anchor.top - GAP - height)}px`, left: `${left}px`, width: `${width}px` });
        this.wrapper.dataset.place = 'above';
      }
    }
    this.shownAt = performance.now();
  }

  /** Replaces an entry's glyph with its website icon, if the entry is still showing. */
  setIcon(suggestionId: string, bitmap: ImageBitmap): void {
    const item = this.items.find((i) => i.entry.suggestion.id === suggestionId);
    const glyph = item?.element.querySelector<HTMLElement>('.glyph');
    if (!glyph) return;
    // Sharp at any zoom level or screen density: the canvas has a pixel for every device pixel.
    const density = Math.min(4, Math.max(1, (this.doc.defaultView ?? window).devicePixelRatio || 1));
    const size = Math.round(ICON_SIZE * density);
    const canvas = this.doc.createElement('canvas');
    canvas.width = canvas.height = size;
    const context = canvas.getContext('2d');
    if (context) {
      const scale = Math.min(size / bitmap.width, size / bitmap.height);
      const [w, h] = [bitmap.width * scale, bitmap.height * scale];
      context.imageSmoothingQuality = 'high';
      context.drawImage(bitmap, (size - w) / 2, (size - h) / 2, w, h);
    }
    glyph.className = 'glyph site';
    delete glyph.dataset.letter;
    glyph.replaceChildren(canvas);
  }

  /** Moves keyboard focus to the first item that can be picked (and, given `which`, is one of those). */
  focusFirst(which: (entry: Entry) => boolean = () => true): boolean {
    const first = this.items.find((item) => !item.entry.disabled && which(item.entry)) ?? this.items.find((item) => !item.entry.disabled);
    first?.element.focus();
    return !!first;
  }

  private onKey(event: KeyboardEvent): void {
    const enabled = this.items.filter((item) => !item.entry.disabled);
    const current = enabled.findIndex((item) => item.element === this.layer.root.activeElement);
    const move = (index: number) => {
      const target = enabled[(index + enabled.length) % enabled.length];
      target?.element.focus();
    };
    switch (event.key) {
      case 'ArrowDown':
        move(current + 1);
        break;
      case 'ArrowUp':
        move(current - 1);
        break;
      case 'Home':
        move(0);
        break;
      case 'End':
        move(enabled.length - 1);
        break;
      case 'Enter':
      case ' ': {
        const item = enabled[current];
        if (item) this.handlers.pick(item.entry, event, item.element);
        break;
      }
      case 'Escape':
        this.handlers.dismiss(true);
        break;
      case 'Tab':
        this.handlers.dismiss(true);
        break;
      default:
        return;
    }
    event.preventDefault();
    event.stopPropagation();
  }

  /** Integrity of the menu where the user picked: still ours, unchanged, and on top at that point. */
  check(element: HTMLElement): LayerProblem | null {
    const rect = element.getBoundingClientRect();
    return this.layer.check({ x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 });
  }

  owns(element: Element): boolean {
    return this.layer.owns(element);
  }

  close(): void {
    this.layer.hide();
    this.items = [];
  }
}
