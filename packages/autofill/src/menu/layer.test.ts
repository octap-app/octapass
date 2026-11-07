import { Layer } from './layer';

const flush = () => new Promise((resolve) => setTimeout(resolve));

describe('Layer', () => {
  let layer: Layer;
  beforeEach(() => {
    layer = new Layer(document, 'octapass-test', '');
    layer.show({ top: '10px', left: '10px' });
  });
  afterEach(() => layer.hide());

  it('pins its host styles inline with !important', () => {
    expect(layer.host.style.getPropertyPriority('opacity')).toBe('important');
    expect(layer.host.style.getPropertyValue('position')).toBe('fixed');
    expect(layer.check()).toBeNull();
  });

  it('survives its own moves', async () => {
    layer.move({ top: '50px', left: '10px' });
    await flush();
    expect(layer.check()).toBeNull();
  });

  it('notices the page changing the host', async () => {
    layer.host.style.opacity = '0';
    await flush();
    expect(layer.check()).toBe('tampered');
  });

  it('notices the page moving or removing the host', () => {
    document.body.append(layer.host);
    expect(layer.check()).toBe('tampered');
  });

  it('notices the page restyling it from a stylesheet it cannot beat', () => {
    const style = document.createElement('style');
    style.textContent = 'octapass-test { opacity: 0 !important; display: none !important; }';
    document.head.append(style);
    expect(layer.check()).toBeNull();
    style.remove();
  });

  it('starts clean after being hidden and shown again', async () => {
    layer.host.setAttribute('inert', '');
    await flush();
    layer.hide();
    layer.show({ top: '0px', left: '0px' });
    expect(layer.check()).toBeNull();
  });

  it('flags another element on top at the picked point', () => {
    const original = document.elementsFromPoint;
    document.elementsFromPoint = () => [document.body];
    expect(layer.check({ x: 1, y: 1 })).toBe('covered');
    document.elementsFromPoint = original;
  });
});

describe('Layer styles', () => {
  const captured = new Map<Element, ShadowRoot>();
  const attach = Element.prototype.attachShadow;
  beforeEach(() => {
    Element.prototype.attachShadow = function (this: Element, init: ShadowRootInit) {
      const root = attach.call(this, init);
      captured.set(this, root);
      return root;
    };
  });
  afterEach(() => {
    Element.prototype.attachShadow = attach;
    captured.clear();
    delete (ShadowRoot.prototype as { adoptedStyleSheets?: unknown }).adoptedStyleSheets;
  });

  it('parses its CSS once per document where constructed stylesheets can be adopted', () => {
    const adopted = new WeakMap<ShadowRoot, CSSStyleSheet[]>();
    Object.defineProperty(ShadowRoot.prototype, 'adoptedStyleSheets', {
      configurable: true,
      get(this: ShadowRoot) {
        return adopted.get(this) ?? [];
      },
      set(this: ShadowRoot, sheets: CSSStyleSheet[]) {
        adopted.set(this, sheets);
      },
    });
    const replace = vi.spyOn(CSSStyleSheet.prototype, 'replaceSync');
    const [a, b] = [new Layer(document, 'octapass-a', '.x { color: red; }'), new Layer(document, 'octapass-b', '.x { color: red; }')];
    const [rootA, rootB] = [captured.get(a.host)!, captured.get(b.host)!];
    expect(replace).toHaveBeenCalledTimes(1);
    expect(rootA.adoptedStyleSheets).toHaveLength(1);
    expect(rootA.adoptedStyleSheets[0]).toBe(rootB.adoptedStyleSheets[0]);
    expect(rootA.querySelector('style')).toBeNull();
    replace.mockRestore();
  });

  it('falls back to a <style> where they cannot', () => {
    const layer = new Layer(document, 'octapass-c', '.y { color: blue; }');
    expect(captured.get(layer.host)!.querySelector('style')!.textContent).toBe('.y { color: blue; }');
  });
});
