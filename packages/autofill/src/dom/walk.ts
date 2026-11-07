import { isCandidate } from '../classify/field';
import type { FillableElement, FrameReport } from '../types';
import { isDocument, isFrame, isIFrame } from './is';

export interface WalkOptions {
  /**
   * Returns an element's shadow root. Defaults to the open one (`element.shadowRoot`); the extension
   * passes `chrome.dom.openOrClosedShadowRoot` to reach closed roots too.
   */
  shadowRoot?: (element: Element) => ShadowRoot | null;
}

export interface Walk {
  fields: FillableElement[];
  /** Same-origin frame documents we walked into, so the engine can listen to them. */
  documents: Document[];
  /** Shadow roots we walked into, for mutation observers. */
  shadowRoots: ShadowRoot[];
  frames: FrameReport[];
}

function frameOrigin(frame: HTMLIFrameElement | HTMLFrameElement): string | null {
  if (isIFrame(frame) && frame.sandbox.length > 0 && !frame.sandbox.contains('allow-same-origin')) {
    return null;
  }
  const src = frame.getAttribute('src');
  if (!src) return null;
  try {
    const origin = new URL(src, frame.baseURI).origin;
    return origin === 'null' ? null : origin;
  } catch {
    return null;
  }
}

/** Every candidate field in composed-tree order: through shadow roots and into same-origin frames. */
export function walk(doc: Document, options: WalkOptions = {}): Walk {
  const shadowOf = options.shadowRoot ?? ((element: Element) => element.shadowRoot);
  const result: Walk = { fields: [], documents: [doc], shadowRoots: [], frames: [] };

  const visit = (root: Document | ShadowRoot) => {
    const walker = (isDocument(root) ? root : root.ownerDocument).createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const element = node as Element;
      if (isCandidate(element)) result.fields.push(element);
      const shadow = shadowOf(element);
      if (shadow) {
        result.shadowRoots.push(shadow);
        visit(shadow);
      }
      if (isFrame(element)) {
        let inner: Document | null = null;
        try {
          inner = element.contentDocument;
        } catch {
          inner = null;
        }
        if (inner) {
          result.documents.push(inner);
          visit(inner);
        } else {
          result.frames.push({ element, origin: frameOrigin(element), crossOrigin: true });
        }
      }
    }
  };
  visit(doc);
  return result;
}
