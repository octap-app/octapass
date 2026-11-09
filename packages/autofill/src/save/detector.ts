import { isDocument, isElement, isInput } from '../dom/is';
import { visibilityProblem } from '../dom/visibility';
import type { AddressValues, CardValues, DetailsSaveReport, Form, FormType, SaveReport } from '../types';
import { addressValues, cardValues } from './details';

// A database console's sign-in is saved as a login, as it was before it had a form type of its own.
const SAVABLE = new Set<FormType>(['login', 'signup', 'change-password', 'database']);
/** How long a click on a sign-in button waits for a request, a navigation or the form going away. */
const SETTLE_MS = 4000;
const POLL_MS = 150;
/** How long an identifier typed on step one of a sign-in is kept for the password step. */
const IDENTIFIER_MS = 10 * 60 * 1000;

interface LoginSnapshot {
  kind: 'login';
  form: Form;
  username?: string;
  password: string;
  oldPassword?: string;
}

type Snapshot =
  | LoginSnapshot
  | { kind: 'identity'; form: Form; values: AddressValues }
  | { kind: 'card'; form: Form; values: CardValues };

interface Pending {
  snapshot: Snapshot;
  url: string;
  since: number;
  timer: ReturnType<typeof setInterval>;
}

export interface SaveDetectorOptions {
  /** The form that contains an element, from the engine's latest scan. */
  formOf(element: Element): Form | undefined;
  report(report: SaveReport): void;
  reportDetails?(report: DetailsSaveReport): void;
  url(): string;
}

/** The field whose disappearing means a form went through. */
const WATCHED: Record<Snapshot['kind'], string[]> = {
  login: ['current-password', 'new-password'],
  card: ['cc-number'],
  identity: ['address-line1'],
};

const SUBMIT_BUTTON = 'button, input[type=submit], input[type=image], [role=button]';

function value(form: Form, type: string, fillableOnly = false): string | undefined {
  const field = form.fields.find((f) => f.type === type && (!fillableOnly || f.fillable) && f.element.value);
  return field?.element.value || undefined;
}

/**
 * Notices credentials being submitted: a form `submit`, or a click / Enter on a sign-in form followed by
 * a completed request, a URL change (SPA navigation) or the form disappearing. Address and card forms
 * are noticed the same way. It reports at most once per credential, address or card; the host decides
 * whether to ask the user.
 */
export class SaveDetector {
  private readonly targets = new WeakSet<EventTarget>();
  private readonly cleanups: (() => void)[] = [];
  private readonly reported = new Set<string>();
  private readonly lastValues = new WeakMap<Element, Snapshot>();
  private pending?: Pending;
  private identifier?: { value: string; at: number };
  private lastRequest = 0;

  constructor(private readonly options: SaveDetectorOptions) {
    const observer = typeof PerformanceObserver === 'function' ? this.observeRequests() : undefined;
    if (observer) this.cleanups.push(() => observer.disconnect());
  }

  /** Requests the page makes show up in the resource timeline, which an isolated world can read too. */
  private observeRequests(): PerformanceObserver | undefined {
    try {
      const observer = new PerformanceObserver((list) => {
        if (list.getEntries().some((e) => /^(fetch|xmlhttprequest|beacon)$/.test((e as PerformanceResourceTiming).initiatorType))) {
          this.requestCompleted();
        }
      });
      observer.observe({ type: 'resource', buffered: false });
      return observer;
    } catch {
      return undefined;
    }
  }

  /** Listens on a document or shadow root (`submit` doesn't cross shadow boundaries). */
  attach(target: Document | ShadowRoot): void {
    if (this.targets.has(target)) return;
    this.targets.add(target);
    const on = <K extends keyof DocumentEventMap>(type: K, listener: (event: DocumentEventMap[K]) => void) => {
      target.addEventListener(type, listener as EventListener, true);
      this.cleanups.push(() => target.removeEventListener(type, listener as EventListener, true));
    };
    on('input', (event) => this.remember(event));
    on('change', (event) => this.remember(event));
    on('submit', (event) => {
      const form = isElement(event.target) ? this.options.formOf(event.target) : undefined;
      if (form) this.submitted(form, 'submit');
    });
    on('click', (event) => {
      const button = (event.composedPath()[0] as Element | undefined)?.closest?.(SUBMIT_BUTTON);
      const form = button ? this.options.formOf(button) : undefined;
      if (form) this.attempted(form);
    });
    on('keydown', (event) => {
      if (event.key !== 'Enter') return;
      const field = event.composedPath()[0];
      const form = isInput(field) ? this.options.formOf(field) : undefined;
      if (form) this.attempted(form);
    });
    if (isDocument(target)) {
      const view = target.defaultView;
      const leaving = () => this.settle('navigation');
      view?.addEventListener('pagehide', leaving);
      this.cleanups.push(() => view?.removeEventListener('pagehide', leaving));
    }
  }

  /** The host saw a request finish (the extension can tell from `webRequest`). */
  requestCompleted(): void {
    this.lastRequest = performance.now();
  }

  /** A suggested password was filled: save a draft now, so it can't be lost (plan 05). */
  generated(form: Form, password: string): void {
    const username = this.usernameOf(form);
    this.send({ kind: 'login', form, password, ...(username ? { username } : {}) }, 'generated', true);
  }

  private usernameOf(form: Form): string | undefined {
    const own = value(form, 'username') ?? (form.type === 'signup' ? value(form, 'email') : undefined);
    if (own) return own;
    const remembered = this.identifier;
    return remembered && performance.now() - remembered.at < IDENTIFIER_MS ? remembered.value : undefined;
  }

  private snapshot(form: Form): Snapshot | undefined {
    if (form.type === 'card') {
      const values = cardValues(form);
      return values && { kind: 'card', form, values };
    }
    if (form.type === 'identity') {
      const values = addressValues(form);
      return values && { kind: 'identity', form, values };
    }
    if (form.type === 'identifier') {
      const id = value(form, 'username', true);
      if (id) this.identifier = { value: id, at: performance.now() };
      return undefined;
    }
    if (!SAVABLE.has(form.type)) return undefined;
    const password = value(form, form.type === 'login' ? 'current-password' : 'new-password', true);
    if (!password) return undefined;
    const username = this.usernameOf(form);
    const oldPassword = form.type === 'change-password' ? value(form, 'current-password', true) : undefined;
    return { kind: 'login', form, password, ...(username ? { username } : {}), ...(oldPassword ? { oldPassword } : {}) };
  }

  /** Keeps the last values typed, because SPAs often clear the fields before we get to look. */
  private remember(event: Event): void {
    const field = event.composedPath()[0];
    if (!(isElement(field))) return;
    const form = this.options.formOf(field);
    const snapshot = form && this.snapshot(form);
    if (form && snapshot) this.lastValues.set(form.element, snapshot);
  }

  private current(form: Form): Snapshot | undefined {
    return this.snapshot(form) ?? this.lastValues.get(form.element);
  }

  private submitted(form: Form, trigger: SaveReport['trigger']): void {
    const snapshot = this.current(form);
    if (this.pending?.snapshot.form.element === form.element) this.clearPending();
    if (snapshot) this.send(snapshot, trigger, false);
  }

  /** A click or Enter on a form: wait to see whether the sign-in (or checkout) went through. */
  private attempted(form: Form): void {
    const snapshot = this.current(form);
    if (!snapshot) return;
    this.clearPending();
    const since = performance.now();
    const timer = setInterval(() => this.poll(), POLL_MS);
    this.pending = { snapshot, url: this.options.url(), since, timer };
  }

  private poll(): void {
    const pending = this.pending;
    if (!pending) return;
    const watched = WATCHED[pending.snapshot.kind];
    const field = pending.snapshot.form.fields.find((f) => f.fillable && watched.includes(f.type));
    if (this.lastRequest > pending.since) this.settle('request');
    else if (this.options.url() !== pending.url) this.settle('navigation');
    else if (field && visibilityProblem(field.element)) this.settle('navigation');
    else if (performance.now() - pending.since > SETTLE_MS) this.clearPending();
  }

  private settle(trigger: Exclude<SaveReport['trigger'], 'generated'>): void {
    const pending = this.pending;
    if (!pending) return;
    this.clearPending();
    this.send(pending.snapshot, trigger, false, pending.url);
  }

  private clearPending(): void {
    if (this.pending) clearInterval(this.pending.timer);
    this.pending = undefined;
  }

  private send(snapshot: Snapshot, trigger: SaveReport['trigger'], draft: boolean, url = this.options.url()): void {
    if (snapshot.kind !== 'login') {
      if (trigger === 'generated') return;
      const key = JSON.stringify([snapshot.kind, snapshot.values]);
      if (this.reported.has(key)) return;
      this.reported.add(key);
      this.options.reportDetails?.(
        snapshot.kind === 'card' ? { kind: 'card', url, values: snapshot.values, trigger } : { kind: 'identity', url, values: snapshot.values, trigger },
      );
      return;
    }
    const key = [draft, snapshot.username, snapshot.password, snapshot.form.type].join('\n');
    if (this.reported.has(key)) return;
    this.reported.add(key);
    this.options.report({
      url,
      ...(snapshot.username ? { username: snapshot.username } : {}),
      password: snapshot.password,
      ...(snapshot.oldPassword ? { oldPassword: snapshot.oldPassword } : {}),
      formType: snapshot.form.type,
      trigger,
      draft,
    });
  }

  stop(): void {
    this.clearPending();
    for (const cleanup of this.cleanups.splice(0)) cleanup();
  }
}
