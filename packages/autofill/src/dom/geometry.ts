import { isDialog } from './is';
import { composedParent } from './visibility';

/**
 * An element's rect in the coordinates of `top`'s viewport, adding the offsets of every same-origin frame
 * in between, so UI drawn in the top document lines up with a field inside a frame.
 */
export function rectIn(top: Document, element: Element): DOMRect {
  let rect = element.getBoundingClientRect();
  let doc = element.ownerDocument;
  while (doc !== top) {
    const frame = doc.defaultView?.frameElement;
    if (!frame) break;
    const outer = frame.getBoundingClientRect();
    rect = new DOMRect(rect.x + outer.x + frame.clientLeft, rect.y + outer.y + frame.clientTop, rect.width, rect.height);
    doc = frame.ownerDocument;
  }
  return rect;
}

/** The open modal <dialog> in `top` that holds an element (directly, or through shadow roots and frames). */
export function modalContainer(top: Document, element: Element): Element | undefined {
  for (let node: Element | null = element; node; node = composedParent(node)) {
    if (node.ownerDocument === top && isDialog(node) && node.matches(':modal')) return node;
  }
  return undefined;
}

/** Right-to-left fields put our icon on the left and align the menu to their right edge. */
export function isRtl(element: Element): boolean {
  return (element.ownerDocument.defaultView ?? window).getComputedStyle(element).direction === 'rtl';
}
