import { TILE } from './glyphs';
import { Layer } from './layer';
import { ICON_CSS } from './styles';

const SIZE = 20;
const INSET = 6;

/** The small Octa Pass button drawn inside the focused field, at its inline end. */
export class FieldIcon {
  private readonly layer: Layer;

  constructor(doc: Document, label: string, activate: (event: MouseEvent) => void) {
    this.layer = new Layer(doc, 'octapass-icon', ICON_CSS);
    const wrapper = doc.createElement('div');
    wrapper.className = 'root';
    const button = doc.createElement('button');
    button.type = 'button';
    button.tabIndex = -1;
    button.setAttribute('aria-label', label);
    button.title = label;
    button.append(parseSvg(doc, TILE));
    // Keep focus in the field: the icon is a pointer shortcut, the keyboard uses ArrowDown.
    button.addEventListener('mousedown', (event) => event.preventDefault());
    button.addEventListener('click', activate);
    wrapper.append(button);
    this.layer.root.append(wrapper);
  }

  /** Fields too small to hold the icon without hiding their text don't get one. */
  static fits(anchor: DOMRect): boolean {
    return anchor.height >= SIZE + 2 && anchor.width >= 6 * SIZE;
  }

  show(anchor: DOMRect, rtl: boolean, container?: Element): void {
    const left = rtl ? anchor.left + INSET : anchor.right - INSET - SIZE;
    this.layer.show({ top: `${anchor.top + (anchor.height - SIZE) / 2}px`, left: `${left}px` }, container);
  }

  hide(): void {
    this.layer.hide();
  }

  owns(element: Element): boolean {
    return this.layer.owns(element);
  }
}

/** Our own constant SVG markup as nodes of `doc`, without assigning `innerHTML` (AMO flags that). */
function parseSvg(doc: Document, markup: string): Element {
  const parsed = new DOMParser().parseFromString(markup, 'text/html').body.firstElementChild!;
  return doc.importNode(parsed, true);
}
