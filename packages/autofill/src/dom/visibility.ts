import { isDocument, isInput, isLabel, isShadowRoot } from './is';

/** Smallest width or height (CSS px) a field must have to be filled; 1×1 inputs are a classic decoy. */
const MIN_SIZE = 6;
/** Below this combined opacity a field or our menu counts as invisible. */
export const MIN_OPACITY = 0.6;

export type VisibilityProblem = 'hidden' | 'zero-size' | 'off-screen' | 'transparent' | 'not-editable';

/** The parent across shadow boundaries and out of same-origin frames. */
export function composedParent(element: Element): Element | null {
  if (element.parentElement) return element.parentElement;
  const root = element.getRootNode();
  if (isShadowRoot(root)) return root.host;
  return isDocument(root) ? root.defaultView?.frameElement ?? null : null;
}

function style(element: Element): CSSStyleDeclaration {
  return (element.ownerDocument.defaultView ?? window).getComputedStyle(element);
}

/** True for an empty `clip: rect(…)` / `clip-path: inset(50%)` and friends: the "visually hidden" pattern. */
function clipped(s: CSSStyleDeclaration): boolean {
  const rect = /rect\(([^)]*)\)/.exec(s.clip)?.[1]?.split(/[\s,]+/).map((v) => Number.parseFloat(v));
  if (rect && rect.length === 4 && rect.every(Number.isFinite)) {
    const [top, right, bottom, left] = rect as [number, number, number, number];
    if (bottom - top < MIN_SIZE || right - left < MIN_SIZE) return true;
  }
  return /inset\(\s*(50%|100%)/.test(s.clipPath) || /circle\(\s*0/.test(s.clipPath);
}

/**
 * Why a field can't be filled, or `null` when it's a visible, editable field of a usable size.
 * This doesn't check whether something covers it; see `coverProblem`.
 */
export function visibilityProblem(element: HTMLElement): VisibilityProblem | null {
  if (!element.isConnected) return 'hidden';
  if (isInput(element) && element.type === 'hidden') return 'hidden';
  if ((element as HTMLInputElement).disabled || (element as HTMLInputElement).readOnly) return 'not-editable';

  const own = style(element);
  if (own.visibility === 'hidden' || own.visibility === 'collapse') return 'hidden';
  let opacity = 1;
  let fixed = false;
  for (let node: Element | null = element; node; node = composedParent(node)) {
    const s = node === element ? own : style(node);
    if (s.display === 'none' || s.contentVisibility === 'hidden' || clipped(s)) return 'hidden';
    const value = Number.parseFloat(s.opacity);
    if (Number.isFinite(value)) opacity *= value;
    if (s.position === 'fixed') fixed = true;
  }
  if (opacity < MIN_OPACITY) return 'transparent';

  const rect = element.getBoundingClientRect();
  if (rect.width < MIN_SIZE || rect.height < MIN_SIZE) return 'zero-size';
  const view = element.ownerDocument.defaultView;
  if (view) {
    // Positioned far outside the page ('left: -9999px' or 'left: 200vw'): the page can't be scrolled
    // there, so the user can never see what gets filled.
    const page = element.ownerDocument.scrollingElement ?? element.ownerDocument.documentElement;
    if (rect.right + view.scrollX <= 0 || rect.bottom + view.scrollY <= 0) return 'off-screen';
    // (A zero scroll size means no layout, as in jsdom: nothing to compare against.)
    if (page && page.scrollWidth > 0 && (rect.left + view.scrollX >= page.scrollWidth || rect.top + view.scrollY >= page.scrollHeight)) return 'off-screen';
    // A fixed element doesn't move when scrolling: outside the viewport, it stays out of sight.
    if (fixed && (rect.left >= view.innerWidth || rect.top >= view.innerHeight || rect.right <= 0 || rect.bottom <= 0)) return 'off-screen';
  }
  return null;
}

/** The point list we probe: the centre and four points around it, inset so borders don't count. */
function probes(rect: DOMRect): [number, number][] {
  const x = rect.left + rect.width / 2;
  const y = rect.top + rect.height / 2;
  const dx = rect.width * 0.3;
  const dy = rect.height * 0.25;
  return [
    [x, y],
    [x - dx, y - dy],
    [x + dx, y - dy],
    [x - dx, y + dy],
    [x + dx, y + dy],
  ];
}

type HitRoot = Pick<Document, 'elementsFromPoint'>;

function hitRoot(element: Element): HitRoot | null {
  const root = element.getRootNode() as Partial<HitRoot>;
  if (typeof root.elementsFromPoint === 'function') return root as HitRoot;
  const doc = element.ownerDocument as Partial<HitRoot>;
  return typeof doc.elementsFromPoint === 'function' ? (doc as HitRoot) : null;
}

/** Whether `top`, the topmost element at a point, is the element itself or something that belongs to it. */
function ownsPoint(element: Element, top: Element, allowed: (top: Element) => boolean): boolean {
  if (top === element || element.contains(top) || allowed(top)) return true;
  // A <label> drawn over its own input (floating labels) forwards clicks to it.
  return isLabel(top) && top.control === element;
}

export type CoverProblem = 'covered' | 'not-in-view';

/**
 * Whether something is drawn over `element`. Checks a few points inside it with `elementsFromPoint`,
 * in its own shadow root and then the frame element in each parent document. More than half of the
 * visible points must hit the element. `allowed` accepts our own UI (the field icon).
 */
export function coverProblem(element: Element, allowed: (top: Element) => boolean = () => false): CoverProblem | null {
  const root = hitRoot(element);
  if (!root) return null;
  const view = element.ownerDocument.defaultView;
  const width = view?.innerWidth ?? Infinity;
  const height = view?.innerHeight ?? Infinity;
  const points = probes(element.getBoundingClientRect()).filter(
    ([x, y]) => x >= 0 && y >= 0 && x < width && y < height,
  );
  if (points.length === 0) return 'not-in-view';
  const hits = points.filter(([x, y]) => {
    const top = root.elementsFromPoint(x, y)[0];
    return top !== undefined && ownsPoint(element, top, allowed);
  }).length;
  if (hits * 2 <= points.length) return 'covered';
  const frame = view?.frameElement;
  return frame ? coverProblem(frame, allowed) : null;
}
