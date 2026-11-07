import { isSelect } from '../dom/is';
import type { FillableElement } from '../types';

/**
 * The value setter from the element's own prototype. React (and others) install an instance-level
 * `value` property that records what the framework set; calling the native setter underneath it makes
 * the following `input` event count as a real change instead of being swallowed.
 */
function nativeSetter(element: FillableElement): ((value: string) => void) | undefined {
  for (let proto = Object.getPrototypeOf(element); proto; proto = Object.getPrototypeOf(proto)) {
    const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
    if (descriptor?.set) return descriptor.set;
  }
  return undefined;
}

function dispatch(element: FillableElement, value: string): void {
  const view = element.ownerDocument.defaultView ?? window;
  const init = { bubbles: true, composed: true };
  element.dispatchEvent(
    typeof view.InputEvent === 'function'
      ? new view.InputEvent('input', { ...init, inputType: 'insertReplacementText', data: value })
      : new view.Event('input', init),
  );
  element.dispatchEvent(new view.Event('change', { bubbles: true }));
}

const fold = (text: string) => text.trim().toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');

/** The option that best matches a value: exact value or text, then numerically equal, then a prefix. */
export function chooseOption(select: HTMLSelectElement, candidates: string[]): HTMLOptionElement | undefined {
  const options = Array.from(select.options).filter((o) => !o.disabled);
  const wanted = candidates.map(fold).filter(Boolean);
  const tests: ((o: HTMLOptionElement, w: string) => boolean)[] = [
    (o, w) => fold(o.value) === w || fold(o.text) === w,
    (o, w) => /^\d+$/.test(w) && (Number(o.value) === Number(w) || Number(o.text) === Number(w)),
    (o, w) => w.length >= 3 && fold(o.text).startsWith(w),
  ];
  for (const test of tests) {
    for (const w of wanted) {
      const found = options.find((o) => test(o, w));
      if (found) return found;
    }
  }
  return undefined;
}

/**
 * Sets a field's value and fires the events frameworks listen to (React and Svelte: `input`; Vue's
 * `v-model`: `input`, or `change` with `.lazy`; Angular: `input`, then `blur` marks it touched).
 * Returns false when a select has no matching option. `focus` false leaves focus where it is (a fill
 * on page load, which must not move it or scroll the page).
 */
export function setValue(element: FillableElement, value: string, alternatives: string[] = [], focus = true): boolean {
  if (isSelect(element)) {
    const option = chooseOption(element, [value, ...alternatives]);
    if (!option) return false;
    if (focus) element.focus({ preventScroll: true });
    option.selected = true;
    dispatch(element, option.value);
    return true;
  }
  if (focus) element.focus({ preventScroll: true });
  const setter = nativeSetter(element);
  if (setter) setter.call(element, value);
  else element.value = value;
  dispatch(element, value);
  return true;
}

/**
 * Empties a field without firing events: the user's own keystroke, about to land in it, fires them.
 * For typing over a value filled on page load.
 */
export function clearQuietly(element: FillableElement): void {
  if (isSelect(element)) return;
  const setter = nativeSetter(element);
  if (setter) setter.call(element, '');
  else element.value = '';
}
