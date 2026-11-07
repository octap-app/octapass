/**
 * IntersectionObserver v2 (`trackVisibility`), where the browser has it: it reports an element as not
 * visible when anything may cover it or when opacity, filters or transforms change how it looks. Browsers
 * without it give no answer, and the `elementsFromPoint` checks stand alone.
 */
export class VisibilityTracker {
  private readonly observer?: IntersectionObserver;
  private readonly seen = new WeakMap<Element, boolean>();

  constructor(view: Window & typeof globalThis) {
    const Observer = view.IntersectionObserver;
    if (typeof Observer !== 'function') return;
    try {
      const options = { threshold: [0], trackVisibility: true, delay: 100 } as IntersectionObserverInit;
      this.observer = new Observer((entries: IntersectionObserverEntry[]) => {
        for (const entry of entries) {
          const visible = (entry as IntersectionObserverEntry & { isVisible?: boolean }).isVisible;
          if (typeof visible === 'boolean') this.seen.set(entry.target, visible);
        }
      }, options);
    } catch {
      this.observer = undefined;
    }
  }

  observe(element: Element): void {
    this.observer?.observe(element);
  }

  unobserve(element: Element): void {
    this.observer?.unobserve(element);
    this.seen.delete(element);
  }

  /** False when v2 says the element isn't fully visible; undefined when it can't tell. */
  visible(element: Element): boolean | undefined {
    return this.seen.get(element);
  }

  disconnect(): void {
    this.observer?.disconnect();
  }
}
