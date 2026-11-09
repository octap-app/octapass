import { isRtl, modalContainer, rectIn } from './dom/geometry';
import { pastedToken, recognizeApiKey } from './classify/apiKey';
import { isCandidate } from './classify/field';
import { isDocument, isElement, isFrame, isInput, isShadowRoot, isTextArea } from './dom/is';
import { coverProblem, visibilityProblem } from './dom/visibility';
import type { WalkOptions } from './dom/walk';
import { planFill, runFill, type FillResult } from './fill/fill';
import { clearQuietly, setValue } from './fill/value';
import { VisibilityTracker } from './guard/visibilityTracker';
import { FieldIcon } from './menu/icon';
import { DEFAULT_LABELS, entryFor, Menu, type Entry, type MenuLabels, type Theme } from './menu/menu';
import { SaveDetector } from './save/detector';
import { explainField, scanDocument, type Explanation } from './scan';
import { BANK_FIELD_TYPES, DATABASE_FIELD_TYPES } from './types';
import type {
  AutofillHost,
  BlockReason,
  Field,
  FieldType,
  FillableElement,
  FillValues,
  Form,
  FormType,
  PasswordConstraints,
  Scan,
  Suggestion,
  SuggestionKind,
  SuggestionRequest,
} from './types';

export interface AutofillOptions extends WalkOptions {
  host: AutofillHost;
  /** The document to run in. In the extension, the content script's own document. */
  document?: Document;
  labels?: Partial<MenuLabels>;
  theme?: Theme;
  /** Called after every fill with what was filled and skipped (for diagnostics and tests). */
  onFill?: (result: FillResult) => void;
  /** Test hooks. Never set these in the extension. */
  testing?: {
    /** Accept synthetic events as user gestures (jsdom can't create trusted ones). */
    trustAllEvents?: boolean;
    /** Minimum time between the menu appearing and a pick. Default 250 ms. */
    pickDelayMs?: number;
  };
}

export interface Autofill {
  /** Classifies every form now. */
  scan(): Scan;
  /** Why a field got its type, or undefined when it isn't a candidate field. */
  explain(element: Element): Explanation | undefined;
  /** Tell the engine a page request completed (from `webRequest`), for save detection. */
  requestCompleted(): void;
  stop(): void;
}

const PICK_DELAY_MS = 250;
/** How long the host's answer for a field is reused: reopening the menu doesn't ask again. */
const ANSWER_TTL_MS = 15_000;
/** How long a login without a website icon waits before the host is asked for one again. */
const ICON_RETRY_MS = 30_000;
/** Background rescans take at most about 1/20 of the main thread on pages that keep changing... */
const RESCAN_SHARE = 20;
/** ...and wait no longer than this. */
const RESCAN_MAX_WAIT_MS = 2_000;
const LOGIN_TYPES = new Set<FieldType>(['username', 'current-password']);
const NEW_PASSWORD_TYPES = new Set<FieldType>(['new-password', 'confirm-password']);
const IDENTITY_TYPES = new Set<FieldType>([
  'email', 'name', 'given-name', 'family-name', 'tel', 'organization', 'bday', 'address-line1', 'address-line2',
  'address-level2', 'address-level1', 'postal-code', 'country',
]);

/**
 * Where a pasted key can be offered for saving. Everything the engine knows to be something else stays
 * out: passwords and usernames above all, but also searches, cards and addresses. `one-time-code` is
 * here for `name="token"` boxes: no code passes `recognizeApiKey`.
 */
const API_KEY_PASTE_TYPES = new Set<FieldType>(['api-credential', 'unknown', 'one-time-code']);

const BANK_TYPES = new Set<FieldType>(BANK_FIELD_TYPES);
const DATABASE_TYPES = new Set<FieldType>(DATABASE_FIELD_TYPES);

/**
 * The kinds that fill only the field they were picked from, and the value each one fills there. A
 * licence key, an ID number or a wallet address never spreads to other fields of the form.
 */
const SINGLE_FIELD: Partial<Record<SuggestionKind, Exclude<FieldType, 'search' | 'unknown'>>> = {
  'api-credential': 'api-credential',
  'software-license': 'license-key',
  'id-document': 'document-number',
  'crypto-wallet': 'wallet-address',
};

/** What a fill on page load may put in: a login form's account and password, nothing else. */
const AUTO_FILL_TYPES = new Set<FieldType>(['username', 'current-password']);

const fold = (text: string) => text.trim().toLocaleLowerCase();

/**
 * The suggestions whose username or title has `query` in it: what the user typed in the username
 * field. Pinned entries (the unlock entry) and the kinds that aren't logins always stay.
 */
export function filterSuggestions(suggestions: Suggestion[], query: string): Suggestion[] {
  const wanted = fold(query);
  if (!wanted) return suggestions;
  const has = (...texts: (string | undefined)[]) => texts.some((text) => text !== undefined && fold(text).includes(wanted));
  return suggestions.flatMap((s): Suggestion[] => {
    if (s.kind === 'login') return s.pinned || has(s.username, s.title) ? [s] : [];
    if (s.kind === 'other-logins') {
      const logins = s.logins.filter((login) => has(login.username, login.title));
      return logins.length > 0 ? [{ ...s, logins }] : [];
    }
    return [s];
  });
}

/** An email box, whatever the page calls it: sign-up forms often mark it `autocomplete="username"`. */
function takesEmail(element: FillableElement): boolean {
  return isInput(element) && (element.type === 'email' || element.inputMode === 'email');
}

/** Which suggestions make sense in a field. */
function relevantKinds({ type: field, element }: Field, form: FormType): SuggestionKind[] {
  if (field === 'api-credential') return ['api-credential'];
  if (field === 'license-key') return ['software-license'];
  if (field === 'document-number') return ['id-document'];
  if (field === 'wallet-address') return ['crypto-wallet'];
  if (BANK_TYPES.has(field)) return ['bank-account'];
  if (DATABASE_TYPES.has(field)) return ['database'];
  // A database console's sign-in: the site's own logins first, then the databases.
  if (LOGIN_TYPES.has(field) && form === 'database') return ['login', 'other-logins', 'database'];
  if (field === 'one-time-code') return ['one-time-code'];
  if (NEW_PASSWORD_TYPES.has(field)) return ['generated-password'];
  if (field === 'username' && form === 'signup' && takesEmail(element)) return ['masked-email'];
  if (LOGIN_TYPES.has(field)) return form === 'signup' ? [] : ['login', 'other-logins'];
  if (field.startsWith('cc-')) return ['card'];
  if (field === 'email' && form === 'signup') return ['masked-email', 'identity'];
  if (IDENTITY_TYPES.has(field)) return ['identity'];
  return [];
}

function constraints(element: FillableElement): PasswordConstraints | undefined {
  if (!(isInput(element))) return undefined;
  const result: PasswordConstraints = {};
  if (element.minLength > 0) result.minLength = element.minLength;
  if (element.maxLength > 0) result.maxLength = element.maxLength;
  if (element.pattern) result.pattern = element.pattern;
  const rules = element.getAttribute('passwordrules');
  if (rules) result.rules = rules;
  return Object.keys(result).length > 0 ? result : undefined;
}

/** One answer from `host.getSuggestions`, kept for the field it was asked for. */
interface Answer {
  key: string;
  at: number;
  promise: Promise<Suggestion[]>;
  /** Shown already. A locked answer (the unlock entry) is shown once, then asked for again. */
  used: boolean;
  locked?: boolean;
}

interface Active {
  field: Field;
  form: Form;
  request?: SuggestionRequest;
  /** The host's last answer for this field, or one asked for ahead (a press in the field). */
  answer?: Answer;
  /** What the menu shows, so picking the entry for other parts of the site can expand it in place. */
  suggestions?: Suggestion[];
  /** Everything the host offered for the field, before filtering by what the user typed. */
  all?: Suggestion[];
  /** Bumped on every focus change, so a slow host answer for an old field is dropped. */
  token: number;
}

class Engine implements Autofill {
  private readonly doc: Document;
  private readonly host: AutofillHost;
  private readonly labels: MenuLabels;
  private readonly menu: Menu;
  private readonly icon: FieldIcon;
  private readonly tracker: VisibilityTracker;
  private readonly detector: SaveDetector;
  private readonly cleanups: (() => void)[] = [];
  private readonly listening = new WeakSet<EventTarget>();
  private readonly reportedFrames = new WeakSet<Element>();
  private readonly mutations: MutationObserver;
  private forms: Form[] = [];
  private byElement = new Map<Element, { field: Field; form: Form }>();
  private stale = true;
  private rescanTimer?: ReturnType<typeof setTimeout>;
  private active?: Active;
  private token = 0;
  /** Login forms already offered to `host.autoFill`: each is asked once. */
  private readonly autoFillTried = new WeakSet<Element>();
  /** Fields filled on page load and still holding what was filled, until the user types over them. */
  private readonly autoFilled = new Map<FillableElement, { value: string; type: FieldType; group: FillableElement[] }>();
  /** What the engine itself last put in a field: that's not text to filter the menu by. */
  private readonly ownValues = new WeakMap<FillableElement, string>();
  /** Website icons already decoded, by suggestion id, so filtering as the user types doesn't ask again. */
  private readonly icons = new Map<string, Promise<ImageBitmap | null>>();
  /** When the host last had no icon for a login, so every keystroke doesn't ask again. */
  private readonly noIcon = new Map<string, number>();
  /** The field the user is pressing the mouse button in: its focus asks the host ahead of the click. */
  private pressed?: Element;
  private repositionFrame?: number;
  /** How long the last scan took and when it ended, to space out background rescans. */
  private scanCost = 0;
  private scannedAt = 0;

  constructor(private readonly options: AutofillOptions) {
    this.doc = options.document ?? document;
    this.host = options.host;
    this.labels = { ...DEFAULT_LABELS, ...options.labels };
    this.menu = new Menu(
      this.doc,
      { pick: (entry, event, element) => void this.pick(entry, event, element), dismiss: (refocus) => this.dismiss(refocus) },
      this.labels,
      options.theme ?? 'system',
    );
    this.icon = new FieldIcon(this.doc, this.labels.icon, (event) => {
      if (this.trusted(event)) void this.openMenu(false, true);
    });
    this.tracker = new VisibilityTracker((this.doc.defaultView ?? window) as Window & typeof globalThis);
    this.detector = new SaveDetector({
      formOf: (element) => this.formOf(element),
      report: (report) => this.host.onSave?.(report),
      reportDetails: (report) => this.host.onSaveDetails?.(report),
      url: () => this.doc.location.href,
    });
    this.mutations = new MutationObserver((records) => {
      const ours = (node: Node) => isElement(node) && this.isOwnUi(node);
      const onlyOurs = (r: MutationRecord) =>
        ours(r.target) || (r.type === 'childList' && [...r.addedNodes, ...r.removedNodes].every(ours));
      if (!records.every(onlyOurs)) this.markStale(200);
    });
    const view = this.doc.defaultView;
    // The field moves from under the menu: close it right away, and place the icon once per frame
    // however many scroll events (one per scrolling element) arrive in it.
    const reposition = () => {
      if (!this.active) return;
      this.closeMenu();
      if (this.repositionFrame !== undefined || !view) return;
      // Only the icon: a menu opened since (a click right after the field scrolled into view) stays.
      this.repositionFrame = view.requestAnimationFrame(() => {
        this.repositionFrame = undefined;
        this.placeIcon();
      });
    };
    view?.addEventListener('scroll', reposition, true);
    view?.addEventListener('resize', reposition);
    this.cleanups.push(() => {
      view?.removeEventListener('scroll', reposition, true);
      view?.removeEventListener('resize', reposition);
      if (this.repositionFrame !== undefined) view?.cancelAnimationFrame(this.repositionFrame);
    });
    this.scan();
    const focused = this.doc.activeElement;
    if (focused && focused !== this.doc.body) this.activate(focused);
  }

  private trusted(event: Event): boolean {
    return event.isTrusted || !!this.options.testing?.trustAllEvents;
  }

  private isOwnUi(element: Element): boolean {
    return this.menu.owns(element) || this.icon.owns(element);
  }

  scan(): Scan {
    const started = performance.now();
    const result = scanDocument(this.doc, this.options);
    this.forms = result.forms;
    this.byElement = new Map(result.forms.flatMap((form) => form.fields.map((field) => [field.element, { field, form }])));
    this.stale = false;
    for (const doc of result.walk.documents) this.listen(doc);
    for (const root of result.walk.shadowRoots) this.listen(root);
    for (const frame of result.frames) {
      if (this.reportedFrames.has(frame.element)) continue;
      this.reportedFrames.add(frame.element);
      this.host.onFrame?.(frame);
    }
    // Keep the active field's form current: the page may have revealed a step or added a confirm field.
    if (this.active) {
      const found = this.byElement.get(this.active.field.element);
      if (found) Object.assign(this.active, found);
    }
    this.offerAutoFill();
    this.scannedAt = performance.now();
    this.scanCost = this.scannedAt - started;
    return { forms: result.forms, frames: result.frames };
  }

  private lookup(element: Element): { field: Field; form: Form } | undefined {
    if (this.stale || !this.byElement.has(element)) this.scan();
    return this.byElement.get(element);
  }

  /** The form an element belongs to: its field's form, or the innermost form container holding it. */
  private formOf(element: Element): Form | undefined {
    const own = this.byElement.get(element);
    if (own) return own.form;
    if (this.stale) this.scan();
    let best: Form | undefined;
    for (const form of this.forms) {
      if (form.element.contains(element) && (!best || best.element.contains(form.element))) best = form;
    }
    return best;
  }

  explain(element: Element): Explanation | undefined {
    const found = this.lookup(element);
    return found && explainField(found.field, found.form);
  }

  requestCompleted(): void {
    this.detector.requestCompleted();
  }

  private listen(target: Document | ShadowRoot): void {
    if (this.listening.has(target)) return;
    this.listening.add(target);
    // `submit` stays inside its shadow root, so save detection listens on every root.
    this.detector.attach(target);
    // Focus, click and key events from open shadow roots reach the document with their real target in
    // composedPath(); only closed roots (reached through the extension's API) need their own listeners.
    if (isShadowRoot(target) && target.mode === 'open') return;
    const on = <K extends keyof DocumentEventMap>(type: K, listener: (event: DocumentEventMap[K]) => void) => {
      target.addEventListener(type, listener as EventListener, true);
      this.cleanups.push(() => target.removeEventListener(type, listener as EventListener, true));
    };
    on('focusin', (event) => this.onFocus(event));
    on('focusout', (event) => this.onBlur(event));
    on('mousedown', (event) => this.onPress(event));
    on('click', (event) => this.onClick(event));
    on('keydown', (event) => this.onKey(event));
    on('paste', (event) => this.onPaste(event));
    on('beforeinput', (event) => this.onBeforeInput(event));
    on('input', (event) => this.onInput(event));
    if (isDocument(target)) {
      const attributeFilter = ['type', 'style', 'class', 'hidden', 'open', 'autocomplete'];
      this.mutations.observe(target, { childList: true, subtree: true, attributes: true, attributeFilter });
      // A frame that loads later (or navigates) gets a new document: rescan to pick it up. `load` reaches
      // this capturing listener for every image and script too; those don't change any form.
      // Its events are listened to at once: a field focused before that rescan would otherwise get no
      // menu, and the rescan can wait up to RESCAN_MAX_WAIT_MS on a slow page.
      on('load', (event) => {
        if (!isFrame(event.target)) return;
        const frameDoc = event.target.contentDocument;
        if (frameDoc) this.listen(frameDoc);
        this.markStale(50);
      });
    }
  }

  /** Rescans after the page settles, so new frames are reported even if no field gets focus. */
  private markStale(delay: number): void {
    this.stale = true;
    clearTimeout(this.rescanTimer);
    // A scan walks the whole page. Where that's slow and the page keeps changing, wait longer between
    // background scans; anything the user touches is looked up (and rescanned, if stale) right then.
    const spacing = Math.min(RESCAN_MAX_WAIT_MS, this.scanCost * RESCAN_SHARE - (performance.now() - this.scannedAt));
    this.rescanTimer = setTimeout(() => this.scan(), Math.max(delay, spacing));
  }

  private targetOf(event: Event): Element | undefined {
    const target = event.composedPath()[0];
    return isElement(target) ? target : undefined;
  }

  private onFocus(event: FocusEvent): void {
    const target = this.targetOf(event);
    if (!target) return;
    const pressed = this.pressed === target;
    this.pressed = undefined;
    if (this.activate(target) && pressed) this.prefetch();
  }

  /**
   * The user pressing the mouse button in a field: the click that follows opens the menu, so the host
   * is asked now (on the focus this press gives, or right away in the field that has it).
   */
  private onPress(event: MouseEvent): void {
    const target = this.targetOf(event);
    this.pressed = undefined;
    if (!target || event.button !== 0 || !this.trusted(event) || !isCandidate(target)) return;
    if (this.active?.field.element === target) this.prefetch();
    else this.pressed = target;
  }

  /** Whether an element can be, or hold, a field: everything else is never looked up (no rescan). */
  private mayHoldField(element: Element): boolean {
    if (isCandidate(element) || isFrame(element)) return true;
    // Focus in a closed shadow root reaches the document at its host: the scan finds what's inside.
    return (this.options.shadowRoot ?? ((e: Element) => e.shadowRoot))(element) !== null;
  }

  /** Starts a session on a field: from focus, or a click / ArrowDown in a field focused before we ran. */
  private activate(target: Element): boolean {
    if (this.isOwnUi(target)) return false;
    if (this.active?.field.element === target) return true;
    // A click, focus or ArrowDown on a link, a button or the page itself: no field, and no scan.
    if (!this.mayHoldField(target)) return false;
    // Visibility changes without a mutation we'd see (a dialog opening, a stylesheet loading): look again.
    this.stale = true;
    const found = this.lookup(target);
    if (!found) return false;
    this.deactivate();
    if (!found.field.fillable || relevantKinds(found.field, found.form.type).length === 0) return false;
    this.active = { ...found, token: ++this.token };
    const anchor = rectIn(this.doc, target);
    if (FieldIcon.fits(anchor)) this.icon.show(anchor, isRtl(target), modalContainer(this.doc, target));
    return true;
  }

  /**
   * Focus leaving the field or our menu: once focus settles, keep the session only if it went to the
   * other one. `relatedTarget` can't tell: it's retargeted across shadow roots and null across frames.
   */
  private onBlur(event: FocusEvent): void {
    const target = this.targetOf(event);
    const active = this.active;
    if (!active || !target || (target !== active.field.element && !this.isOwnUi(target))) return;
    setTimeout(() => {
      if (this.active !== active) return;
      const field = active.field.element;
      const fieldFocused = (field.getRootNode() as Document | ShadowRoot).activeElement === field && field.ownerDocument.hasFocus();
      const ownFocused = this.doc.activeElement !== null && this.isOwnUi(this.doc.activeElement);
      if (!fieldFocused && !ownFocused) this.deactivate();
    });
  }

  private onClick(event: MouseEvent): void {
    const target = this.targetOf(event);
    if (!target || !this.trusted(event)) return;
    if (this.activate(target)) void this.openMenu(false);
    else this.explainRefusal(target);
  }

  /**
   * The user asked for the menu on a field we won't fill because it's see-through or covered (a
   * clickjacking setup): tell the host, so the extension can say why nothing happened.
   */
  private explainRefusal(target: Element): void {
    const found = this.byElement.get(target);
    if (!found || relevantKinds(found.field, found.form.type).length === 0) return;
    const reason = this.fieldRefusal(found.field.element);
    if (reason && reason !== 'field-hidden') this.block(reason, found.field.element, false);
  }

  private onKey(event: KeyboardEvent): void {
    const target = this.targetOf(event);
    if (!target || this.isOwnUi(target)) return;
    if (event.key === 'ArrowDown' && !event.shiftKey && !event.ctrlKey && !event.metaKey) {
      // Only the user's own key press opens the menu or moves focus into it. A page can dispatch a
      // synthetic ArrowDown; acting on it would let the user's next real Enter pick an entry.
      if (!this.trusted(event)) return;
      if (!this.activate(target)) {
        this.explainRefusal(target);
        return;
      }
      event.preventDefault();
      if (this.menu.isOpen) this.menu.focusFirst();
      else void this.openMenu(true, true);
    } else if (event.key === 'Escape' && this.menu.isOpen && target === this.active?.field.element) {
      event.preventDefault();
      this.closeMenu();
    }
  }

  /** Looks at a paste the user made (a page can synthesise one) and tells the host if it's an API key. */
  private onPaste(event: ClipboardEvent): void {
    if (!this.host.onApiKey || !this.trusted(event)) return;
    const target = this.targetOf(event);
    if (!target || this.isOwnUi(target) || !(isInput(target) || isTextArea(target))) return;
    const value = pastedToken(event.clipboardData?.getData('text/plain') ?? '');
    if (!value) return;
    const field = this.lookup(target)?.field;
    if (!field?.fillable || field.segment !== undefined || !API_KEY_PASTE_TYPES.has(field.type)) return;
    // Named as a key is the only way a password input gets here.
    if (isInput(target) && target.type === 'password' && field.type !== 'api-credential') return;
    const kind = recognizeApiKey(value, field.signals.some((s) => s.type === 'api-credential'));
    if (kind) this.host.onApiKey({ kind, value });
  }

  /**
   * Fill on page load (`host.autoFill`): each login form of this document, once, when its account and
   * password fields are all empty and can be seen. Same-origin frames' forms are left to the menu.
   */
  private offerAutoFill(): void {
    if (!this.host.autoFill) return;
    for (const form of this.forms) {
      if (this.autoFillTried.has(form.element) || (form.type !== 'login' && form.type !== 'identifier')) continue;
      const fields = form.fields.filter((f) => f.fillable && f.segment === undefined && AUTO_FILL_TYPES.has(f.type));
      if (fields.length === 0 || fields.some((f) => f.element.ownerDocument !== this.doc)) continue;
      if (form.type === 'login' && !fields.some((f) => f.type === 'current-password')) continue;
      // Something's already there (the page's own, or the user's): leave the form alone for good.
      if (fields.some((f) => f.element.value !== '')) {
        this.autoFillTried.add(form.element);
        continue;
      }
      // Not on screen yet (a closed dialog, a later step): asked again on a later scan.
      if (fields.some((f) => this.fieldRefusal(f.element))) continue;
      this.autoFillTried.add(form.element);
      void this.autoFill(form, fields);
    }
  }

  private async autoFill(form: Form, fields: Field[]): Promise<void> {
    let answer: Awaited<ReturnType<NonNullable<AutofillHost['autoFill']>>>;
    try {
      answer = (await this.host.autoFill?.(this.request(fields[0]!, form))) ?? null;
    } catch {
      return;
    }
    if (!answer) return;
    // The host may take a moment: the user may have started typing, or the page moved on.
    if (fields.some((f) => !f.element.isConnected || f.element.value !== '' || this.fieldRefusal(f.element))) return;
    const values: FillValues = {};
    if (answer.username) values.username = answer.username;
    if (answer['current-password']) values['current-password'] = answer['current-password'];
    const plan = planFill(form, values).filter((step) => fields.includes(step.field));
    if (plan.length === 0) return;
    const result = runFill(plan, null, (top) => this.isOwnUi(top));
    for (const element of result.filled) {
      const type = plan.find((step) => step.field.element === element)!.field.type;
      this.autoFilled.set(element, { value: element.value, type, group: result.filled });
      this.ownValues.set(element, element.value);
    }
    this.options.onFill?.(result);
  }

  /**
   * The user typing in a field filled on page load: what was filled goes, and their text takes its
   * place. Over the account, the password goes too: it was that account's.
   */
  private onBeforeInput(event: InputEvent): void {
    if (!this.trusted(event) || this.autoFilled.size === 0) return;
    const target = this.targetOf(event) as FillableElement | undefined;
    const filled = target && this.autoFilled.get(target);
    if (!target || !filled) return;
    const group = filled.type === 'username' ? filled.group : [target];
    const clear = group.filter((element) => {
      const entry = this.autoFilled.get(element);
      this.autoFilled.delete(element);
      return entry !== undefined && element.isConnected && element.value === entry.value;
    });
    for (const element of clear) {
      if (element !== target) setValue(element, '', [], false);
    }
    if (!clear.includes(target)) return;
    if (event.inputType.startsWith('insert')) {
      // The keystroke itself lands in the empty field and fires the page's input event.
      clearQuietly(target);
    } else {
      // Deleting from a filled value empties it: nothing is left for the key to delete.
      event.preventDefault();
      setValue(target, '', [], false);
    }
  }

  /** The user typed in the username field: the menu narrows to the logins that match, or opens to show them. */
  private onInput(event: Event): void {
    if (!this.trusted(event)) return;
    const active = this.active;
    if (!active || this.targetOf(event) !== active.field.element || active.field.type !== 'username') return;
    // Fetched again while locked, so unlocking in the popup shows the logins on the next key.
    if (!active.all || active.all.some((s) => s.kind === 'login' && s.pinned)) {
      if (this.menu.isOpen) this.closeMenu();
      void this.openMenu(false);
      return;
    }
    const shown = this.visible(active, active.all);
    if (shown.length === 0) this.closeMenu();
    else this.showMenu(active, shown, false);
  }

  /** What the menu shows of `suggestions`: filtered by the field's text, unless the engine put it there. */
  private visible(active: Active, suggestions: Suggestion[]): Suggestion[] {
    const element = active.field.element;
    if (active.field.type !== 'username' || this.ownValues.get(element) === element.value) return suggestions;
    return filterSuggestions(suggestions, element.value);
  }

  private deactivate(): void {
    this.closeMenu();
    this.icon.hide();
    this.active = undefined;
  }

  private dismiss(refocus: boolean): void {
    const field = this.active?.field.element;
    this.closeMenu();
    if (refocus && field?.isConnected) field.focus({ preventScroll: true });
  }

  private closeMenu(): void {
    if (!this.menu.isOpen) return;
    this.tracker.unobserve(this.menu.host);
    this.menu.close();
  }

  private placeIcon(): void {
    const active = this.active;
    if (!active) return;
    const anchor = rectIn(this.doc, active.field.element);
    if (FieldIcon.fits(anchor)) this.icon.show(anchor, isRtl(active.field.element), modalContainer(this.doc, active.field.element));
    else this.icon.hide();
  }

  private request(field: Field, form: Form): SuggestionRequest {
    const doc = field.element.ownerDocument;
    const passwordConstraints = NEW_PASSWORD_TYPES.has(field.type) ? constraints(field.element) : undefined;
    return {
      url: doc.location.href,
      pageUrl: this.doc.location.href,
      formType: form.type,
      fieldType: field.type,
      secure: doc.location.protocol !== 'http:',
      ...(passwordConstraints ? { passwordConstraints } : {}),
    };
  }

  /** `asked`: the user asked for the menu (the field's icon, ArrowDown), so an empty one says so. */
  private async openMenu(focus: boolean, asked = false): Promise<void> {
    const active = this.active;
    if (!active) return;
    if (this.menu.isOpen) {
      if (focus) this.menu.focusFirst();
      return;
    }
    const request = this.request(active.field, active.form);
    const kinds = relevantKinds(active.field, active.form.type);
    const answer = await this.answer(active, request, true);
    // A frame from another site asks first, whatever the field.
    const approval = answer.find((s) => s.kind === 'frame-approval');
    const fitting = answer.filter((s) => kinds.includes(s.kind));
    // Logins for other parts of the site: one quiet entry, after everything the page's own part has.
    const others = fitting.find((s) => s.kind === 'other-logins' && s.logins.length > 0);
    const suggestions = approval ? [approval] : [...fitting.filter((s) => s.kind !== 'other-logins'), ...(others ? [others] : [])];
    if (!approval && kinds.includes('masked-email') && !suggestions.some((s) => s.kind === 'masked-email')) {
      suggestions.unshift({ kind: 'masked-email', id: 'masked-email', disabled: true, note: this.labels.needsSetup });
    }
    if (this.active?.token !== active.token || this.menu.isOpen) return;
    active.all = suggestions;
    const shown = this.visible(active, suggestions);
    if (shown.length === 0 && !asked) return;
    active.request = request;
    this.showMenu(active, shown, focus);
  }

  /**
   * The host's suggestions for the field: the answer kept for it when that's recent and asked for the
   * same thing, or a new one. Every change the user makes (a pick) drops it; see `pick`.
   */
  private answer(active: Active, request: SuggestionRequest, use: boolean): Promise<Suggestion[]> {
    const key = JSON.stringify(request);
    const kept = active.answer;
    const reusable = kept && kept.key === key && performance.now() - kept.at < ANSWER_TTL_MS && !(kept.used && kept.locked);
    let answer = reusable ? kept : undefined;
    if (!answer) {
      const asked: Answer = { key, at: performance.now(), promise: this.host.getSuggestions(request), used: false };
      // Settled here too, so a request asked ahead that fails is no unhandled rejection; `openMenu` gets the error.
      asked.promise.then(
        (list) => (asked.locked = list.some((s) => s.kind === 'login' && s.pinned)),
        () => active.answer === asked && (active.answer = undefined),
      );
      answer = active.answer = asked;
    }
    if (use) answer.used = true;
    return answer.promise;
  }

  /** Asks the host for the active field's suggestions before the menu is opened. */
  private prefetch(): void {
    const active = this.active;
    if (active && !this.menu.isOpen) void this.answer(active, this.request(active.field, active.form), false);
  }

  private showMenu(active: Active, suggestions: Suggestion[], focus: boolean, first?: SuggestionKind): void {
    active.suggestions = suggestions;
    const element = active.field.element;
    const entries = suggestions.map((s) => entryFor(s, this.labels));
    const site = (element.ownerDocument.location?.hostname ?? '').replace(/^www\./, '');
    this.menu.open(rectIn(this.doc, element), isRtl(element), entries, modalContainer(this.doc, element), site);
    this.tracker.observe(this.menu.host);
    if (focus) this.menu.focusFirst(first ? (entry) => entry.suggestion.kind === first : undefined);
    this.showIcons(entries);
  }

  /**
   * The quiet entry, picked: the same menu again with that entry replaced by the logins it stands for,
   * each a pick of its own with every check a pick has (and a fresh delay, since the menu changed).
   */
  private expandOthers(active: Active, others: Extract<Suggestion, { kind: 'other-logins' }>, focus: boolean): void {
    const shown = active.suggestions ?? [];
    const logins = others.logins.map((login): Suggestion => ({ ...login, kind: 'other-login' }));
    this.showMenu(active, [...shown.filter((s) => s !== others), ...logins], focus, 'other-login');
  }

  /** Website icons for the menu's logins, as they arrive. Decoded here: no request the page could see. */
  private showIcons(entries: Entry[]): void {
    const view = this.doc.defaultView as (Window & typeof globalThis) | null;
    const decode = view?.createImageBitmap?.bind(view);
    if (!this.host.siteIcon || !decode) return;
    for (const { suggestion } of entries) {
      // The unlock entry is no login of a website.
      if (suggestion.kind !== 'login' || suggestion.pinned) continue;
      const none = this.noIcon.get(suggestion.id);
      if (none !== undefined && performance.now() - none < ICON_RETRY_MS) continue;
      let icon = this.icons.get(suggestion.id);
      if (!icon) {
        icon = this.host
          .siteIcon(suggestion)
          .then((blob) => (blob ? decode(blob) : null))
          .catch(() => null);
        this.icons.set(suggestion.id, icon);
      }
      void icon.then((bitmap) => {
        // None (locked, or no icon yet): asked again on a later open, not on every key.
        if (!bitmap) {
          this.icons.delete(suggestion.id);
          this.noIcon.set(suggestion.id, performance.now());
        } else this.menu.setIcon(suggestion.id, bitmap);
      });
    }
  }

  private block(reason: BlockReason, field: FillableElement, close = true): void {
    if (close) this.closeMenu();
    this.host.onBlocked?.(reason, field);
  }

  /** The checks between a pick and a fill. Every one of them refuses rather than guesses. */
  private refusal(event: Event, element: HTMLElement, field: FillableElement): BlockReason | null {
    if (!this.trusted(event)) return 'no-gesture';
    const problem = this.menu.check(element);
    if (problem) return problem === 'covered' ? 'menu-covered' : 'menu-tampered';
    if (this.tracker.visible(this.menu.host) === false) return 'menu-covered';
    return this.fieldRefusal(field);
  }

  private fieldRefusal(field: FillableElement): BlockReason | null {
    const hidden = visibilityProblem(field);
    if (hidden) return hidden === 'transparent' ? 'field-transparent' : 'field-hidden';
    if (coverProblem(field, (top) => this.isOwnUi(top))) return 'field-covered';
    return null;
  }

  private async pick(entry: Entry, event: Event, element: HTMLElement): Promise<void> {
    const active = this.active;
    if (!active?.request) return;
    const field = active.field.element;
    if (performance.now() - this.menu.shownAt < (this.options.testing?.pickDelayMs ?? PICK_DELAY_MS)) {
      this.block('too-fast', field, false);
      return;
    }
    const refused = this.refusal(event, element, field);
    if (refused) {
      this.block(refused, field);
      return;
    }
    // Back to the field before the menu goes away, or focus would fall to <body> and end the session.
    field.focus({ preventScroll: true });
    this.closeMenu();
    // What the host offers may change now (a frame allowed, a login used, a password taken): ask again next time.
    active.answer = undefined;
    const { suggestion } = entry;
    if (suggestion.kind === 'other-logins') {
      if (this.active?.token === active.token) this.expandOthers(active, suggestion, event.type === 'keydown');
      return;
    }
    if (suggestion.kind === 'frame-approval') {
      const approved = (await this.host.approveFrame?.(suggestion, active.request)) ?? false;
      if (approved && this.active?.token === active.token) void this.openMenu(event.type === 'keydown');
      return;
    }
    const values: FillValues | null =
      suggestion.kind === 'generated-password'
        ? { 'new-password': suggestion.password }
        : await this.host.resolve(suggestion, active.request);
    if (!values || this.active?.token !== active.token) return;
    // The host may take a moment (unlocking): look again before writing anything.
    const late = this.fieldRefusal(field);
    if (late) {
      this.block(late, field);
      return;
    }
    const form = this.lookup(field)?.form ?? active.form;
    // A masked email, a key, a licence key, an ID number or a wallet address goes in the field it was
    // asked for, not in every such field of the form.
    const singleType = suggestion.kind === 'masked-email' ? 'email' : SINGLE_FIELD[suggestion.kind];
    const single = singleType && values[singleType];
    const plan = singleType ? (single ? [{ field: active.field, value: single, alternatives: [] }] : []) : planFill(form, values);
    const result = runFill(plan, field, (top) => this.isOwnUi(top));
    for (const element of result.filled) {
      this.autoFilled.delete(element);
      this.ownValues.set(element, element.value);
    }
    if (suggestion.kind === 'generated-password' && result.filled.length > 0) {
      this.detector.generated(form, suggestion.password);
    }
    this.options.onFill?.(result);
  }

  stop(): void {
    clearTimeout(this.rescanTimer);
    this.deactivate();
    this.mutations.disconnect();
    this.tracker.disconnect();
    this.detector.stop();
    this.autoFilled.clear();
    this.icons.clear();
    this.noIcon.clear();
    for (const cleanup of this.cleanups.splice(0)) cleanup();
  }
}

/** Starts the engine on a document: it scans, watches for changes and shows the inline menu. */
export function createAutofill(options: AutofillOptions): Autofill {
  return new Engine(options);
}
