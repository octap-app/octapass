// Realm-safe type checks. `instanceof HTMLInputElement` is false for an input in a same-origin frame,
// whose elements come from that frame's own window.

const HTML = 'http://www.w3.org/1999/xhtml';

export const isElement = (node: unknown): node is Element => (node as Node | null)?.nodeType === 1;
export const isDocument = (node: unknown): node is Document => (node as Node | null)?.nodeType === 9;
export const isShadowRoot = (node: unknown): node is ShadowRoot =>
  (node as Node | null)?.nodeType === 11 && 'host' in (node as object);

const tag =
  <T extends Element>(name: string) =>
  (node: unknown): node is T =>
    isElement(node) && node.localName === name && node.namespaceURI === HTML;

export const isInput = tag<HTMLInputElement>('input');
export const isSelect = tag<HTMLSelectElement>('select');
export const isTextArea = tag<HTMLTextAreaElement>('textarea');
export const isButton = tag<HTMLButtonElement>('button');
export const isLabel = tag<HTMLLabelElement>('label');
export const isDialog = tag<HTMLDialogElement>('dialog');
export const isIFrame = tag<HTMLIFrameElement>('iframe');
export const isFrame = (node: unknown): node is HTMLIFrameElement | HTMLFrameElement =>
  isIFrame(node) || tag<HTMLFrameElement>('frame')(node);
