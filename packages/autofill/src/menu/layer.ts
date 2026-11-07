import { MIN_OPACITY } from '../dom/visibility';

// Inline !important declarations beat any page stylesheet, including the page's own !important rules.
const HOST_STYLE: Record<string, string> = {
  all: 'initial',
  position: 'fixed',
  inset: 'auto',
  margin: '0',
  padding: '0',
  border: '0',
  background: 'transparent',
  overflow: 'visible',
  display: 'block',
  opacity: '1',
  visibility: 'visible',
  transform: 'none',
  translate: 'none',
  scale: 'none',
  rotate: 'none',
  filter: 'none',
  'backdrop-filter': 'none',
  'clip-path': 'none',
  mask: 'none',
  'mix-blend-mode': 'normal',
  'pointer-events': 'auto',
  'content-visibility': 'visible',
  zoom: '1',
  width: 'auto',
  height: 'auto',
  'max-width': 'none',
  'max-height': 'none',
  'z-index': '2147483647',
};

// What the computed style must still say when the user picks something. Anything else means the page
// restyled or replaced our element.
const EXPECTED: [keyof CSSStyleDeclaration & string, (value: string) => boolean][] = [
  ['display', (v) => v === 'block'],
  ['visibility', (v) => v === 'visible'],
  ['opacity', (v) => v === '1'],
  ['transform', (v) => v === 'none'],
  ['filter', (v) => v === 'none'],
  ['clipPath', (v) => v === 'none' || v === ''],
  ['mixBlendMode', (v) => v === 'normal' || v === ''],
  ['contentVisibility', (v) => v === 'visible' || v === ''],
];

export type LayerProblem = 'tampered' | 'covered';

/** Each layer's CSS, parsed once per document: a closed root keeps it across every hide and show. */
const SHEETS = new WeakMap<Document, Map<string, CSSStyleSheet>>();

/**
 * Styles the root with a constructed stylesheet, which stays parsed while the host is out of the DOM
 * between menus (a <style> is processed again each time it's inserted). False where that isn't
 * available (older engines, or a content script that can't adopt sheets), for a <style> instead.
 */
function adopt(doc: Document, root: ShadowRoot, css: string): boolean {
  const Sheet = (doc.defaultView as (Window & typeof globalThis) | null)?.CSSStyleSheet;
  if (!Sheet || !('adoptedStyleSheets' in root) || typeof Sheet.prototype.replaceSync !== 'function') return false;
  try {
    let sheets = SHEETS.get(doc);
    if (!sheets) SHEETS.set(doc, (sheets = new Map()));
    let sheet = sheets.get(css);
    if (!sheet) {
      sheet = new Sheet();
      sheet.replaceSync(css);
      sheets.set(css, sheet);
    }
    root.adoptedStyleSheets = [sheet];
    return root.adoptedStyleSheets.length === 1;
  } catch {
    return false;
  }
}

/**
 * A host element for our UI: a closed shadow root inside a `popover` shown in the top layer, so page
 * z-indexes can't cover it, with inline !important styles the page's CSS can't override. Any change the
 * page makes to the host afterwards (attributes, removal, closing the popover) marks the layer tampered.
 */
export class Layer {
  readonly host: HTMLElement;
  readonly root: ShadowRoot;
  private tampered = false;
  private shown = false;
  private container: Element;
  private readonly observer: MutationObserver;

  constructor(
    private readonly doc: Document,
    tag: string,
    css: string,
  ) {
    this.container = doc.documentElement;
    this.host = doc.createElement(tag);
    this.root = this.host.attachShadow({ mode: 'closed' });
    if (!adopt(doc, this.root, css)) {
      const sheet = doc.createElement('style');
      sheet.textContent = css;
      this.root.append(sheet);
    }
    this.observer = new MutationObserver(() => {
      this.tampered = true;
    });
    this.host.addEventListener('toggle', (event) => {
      if ((event as ToggleEvent).newState === 'closed' && this.shown) this.tampered = true;
    });
  }

  /** Our own writes to the host, so the observer doesn't take them for the page's. */
  private write(change: () => void): void {
    change();
    this.observer.takeRecords();
  }

  private styleHost(position: Record<string, string>): void {
    for (const [name, value] of Object.entries({ ...HOST_STYLE, ...position })) {
      this.host.style.setProperty(name, value, 'important');
    }
  }

  get isShown(): boolean {
    return this.shown;
  }

  /**
   * Shows the layer at viewport coordinates. `container` is the root element, or the open modal
   * <dialog> holding the field: everything outside a modal dialog is inert, our popover included.
   */
  show(position: Record<string, string>, container: Element = this.doc.documentElement): void {
    const supportsPopover = typeof this.host.showPopover === 'function';
    if (this.shown && container !== this.container) this.hide();
    this.container = container;
    this.write(() => {
      this.styleHost(position);
      if (!this.host.isConnected) {
        if (supportsPopover) this.host.popover = 'manual';
        container.append(this.host);
        this.observer.observe(this.host, { attributes: true });
      }
      if (supportsPopover && !this.host.matches(':popover-open')) this.host.showPopover();
    });
    this.shown = true;
  }

  move(position: Record<string, string>): void {
    if (this.shown) this.write(() => this.styleHost(position));
  }

  hide(): void {
    if (!this.shown) return;
    this.shown = false;
    this.write(() => {
      if (typeof this.host.hidePopover === 'function' && this.host.matches(':popover-open')) this.host.hidePopover();
      this.host.remove();
    });
    this.observer.disconnect();
    // A fresh start for the next time: the page can't have touched an element that wasn't in the DOM.
    this.tampered = false;
  }

  /**
   * Whether the layer is still ours and visible. With a point, also checks that nothing is drawn on top
   * of it there (a page popover opened after ours, a modal dialog).
   */
  check(point?: { x: number; y: number }): LayerProblem | null {
    if (this.observer.takeRecords().length > 0) this.tampered = true;
    if (this.tampered || !this.shown || this.host.parentNode !== this.container) return 'tampered';
    if (typeof this.host.showPopover === 'function' && !this.host.matches(':popover-open')) return 'tampered';
    const view = this.doc.defaultView ?? window;
    const style = view.getComputedStyle(this.host);
    if (EXPECTED.some(([property, ok]) => !ok(String(style[property] ?? '')))) return 'tampered';
    if (Number.parseFloat(view.getComputedStyle(this.doc.documentElement).opacity) < MIN_OPACITY) return 'tampered';
    if (point && typeof this.doc.elementsFromPoint === 'function') {
      const top = this.doc.elementsFromPoint(point.x, point.y)[0];
      if (top !== this.host) return 'covered';
    }
    return null;
  }

  owns(element: Element): boolean {
    return element === this.host;
  }
}
