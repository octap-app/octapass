// jsdom has no layout. These stubs give every element a box: `data-rect="x y w h"` when set, otherwise a
// 240×32 row of its own (by document order), so nothing overlaps unless a test says so. `elementsFromPoint`
// answers from those boxes, topmost = last in document order.

function box(element: Element): DOMRect {
  const own = element.getAttribute('data-rect');
  if (own) {
    const [x, y, w, h] = own.split(/\s+/).map(Number);
    return new DOMRect(x, y, w, h);
  }
  const index = Array.from((element.getRootNode() as ParentNode).querySelectorAll('*')).indexOf(element);
  return new DOMRect(16, 16 + index * 40, 240, 32);
}

export function stubLayout(): () => void {
  const originalRect = Element.prototype.getBoundingClientRect;
  const originalFromPoint = (Document.prototype as Partial<Document>).elementsFromPoint;
  Element.prototype.getBoundingClientRect = function (this: Element) {
    return box(this);
  };
  const fromPoint = (scope: string) =>
    function (this: Document | ShadowRoot, x: number, y: number) {
      const hits = Array.from(this.querySelectorAll(scope)).filter((element) => {
        const r = box(element);
        return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
      });
      return hits.reverse();
    };
  Document.prototype.elementsFromPoint = fromPoint('body *');
  (ShadowRoot.prototype as Partial<DocumentOrShadowRoot>).elementsFromPoint = fromPoint('*');
  return () => {
    Element.prototype.getBoundingClientRect = originalRect;
    if (originalFromPoint) Document.prototype.elementsFromPoint = originalFromPoint;
    else delete (Document.prototype as Partial<Document>).elementsFromPoint;
    delete (ShadowRoot.prototype as Partial<DocumentOrShadowRoot>).elementsFromPoint;
  };
}

/** Records closed shadow roots as they're attached, so tests can look inside our UI. */
export function captureShadowRoots(): { roots: Map<Element, ShadowRoot>; restore: () => void } {
  const roots = new Map<Element, ShadowRoot>();
  const original = Element.prototype.attachShadow;
  Element.prototype.attachShadow = function (this: Element, init: ShadowRootInit) {
    const root = original.call(this, init);
    roots.set(this, root);
    return root;
  };
  return { roots, restore: () => (Element.prototype.attachShadow = original) };
}

export function html(markup: string): void {
  document.title = '';
  document.body.innerHTML = markup;
}
