// The public vocabulary of @octapass/autofill. The engine never sees the vault: it classifies fields,
// asks the host for suggestions, renders the menu and fills what the host hands back after a user gesture.

import type { ApiKeyKind } from './classify/apiKey';

export const LOGIN_FIELD_TYPES = [
  'username',
  'current-password',
  'new-password',
  'confirm-password',
  'one-time-code',
] as const;

export const IDENTITY_FIELD_TYPES = [
  'email',
  'name',
  'given-name',
  'family-name',
  'tel',
  'organization',
  'bday',
  'address-line1',
  'address-line2',
  'address-level2',
  'address-level1',
  'postal-code',
  'country',
] as const;

export const CARD_FIELD_TYPES = ['cc-name', 'cc-number', 'cc-exp', 'cc-exp-month', 'cc-exp-year', 'cc-csc'] as const;

export type LoginFieldType = (typeof LOGIN_FIELD_TYPES)[number];
export type IdentityFieldType = (typeof IDENTITY_FIELD_TYPES)[number];
export type CardFieldType = (typeof CARD_FIELD_TYPES)[number];
/** `search` and `unknown` fields never get a menu. `api-credential` takes an API key or bearer token. */
export type FieldType = LoginFieldType | IdentityFieldType | CardFieldType | 'api-credential' | 'search' | 'unknown';

export type FormType =
  | 'login'
  | 'identifier'
  | 'signup'
  | 'change-password'
  | 'one-time-code'
  | 'card'
  | 'identity'
  | 'unknown';

export type FillableElement = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

export type SignalSource =
  | 'autocomplete'
  | 'type'
  | 'attribute'
  | 'label'
  | 'placeholder'
  | 'description'
  | 'options'
  | 'form';

/** One scored piece of evidence, as returned by `explain()`. */
export interface Signal {
  type: FieldType;
  score: number;
  source: SignalSource;
  reason: string;
}

export interface Field {
  element: FillableElement;
  type: FieldType;
  /** Visible, enabled, editable and of a usable size. Hidden fields are classified but never filled. */
  fillable: boolean;
  /** Position within a split one-time code (0-based), when the code is spread over several inputs. */
  segment?: number;
  signals: Signal[];
}

export interface Form {
  /** The `<form>`, or the container that groups formless fields. */
  element: Element;
  type: FormType;
  fields: Field[];
  reasons: string[];
}

export interface FrameReport {
  element: HTMLIFrameElement | HTMLFrameElement;
  /** The frame's origin when it can be read from `src`, otherwise `null` (opaque or unknown). */
  origin: string | null;
  crossOrigin: true;
}

export interface Scan {
  forms: Form[];
  frames: FrameReport[];
}

// ---- host contract ----

/** Constraints for the host's password generator, read from the field. */
export interface PasswordConstraints {
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  /** The raw `passwordrules` attribute (Apple's syntax). */
  rules?: string;
}

export interface SuggestionRequest {
  /** URL of the document that holds the field (a same-origin frame's own URL). */
  url: string;
  /** URL of the document the engine runs in. Differs from `url` for same-origin frames. */
  pageUrl: string;
  formType: FormType;
  fieldType: FieldType;
  /** False for `http:` pages, so the host can warn before filling passwords or codes. */
  secure: boolean;
  passwordConstraints?: PasswordConstraints;
}

export type Suggestion =
  /** `pinned`: listed whatever the user types in the field (the "Unlock Octa Pass" entry while locked). */
  | { kind: 'login'; id: string; title: string; username?: string; pinned?: boolean }
  | { kind: 'generated-password'; id: string; password: string }
  | { kind: 'masked-email'; id: string; disabled?: boolean; note?: string }
  | { kind: 'one-time-code'; id: string; title: string }
  | { kind: 'card'; id: string; title: string; subtitle?: string }
  | { kind: 'identity'; id: string; title: string; subtitle?: string }
  | { kind: 'api-credential'; id: string; title: string; subtitle?: string }
  /**
   * Asked first in a frame from another site: `frameHost` is the frame's own host and `site` the
   * page it's inside, both as the browser reports them. Picking it calls `approveFrame`.
   */
  | { kind: 'frame-approval'; id: string; frameHost: string; site: string }
  /**
   * Last in login fields, quietly: logins saved for other parts of the page's site (`shop.example.com`
   * on `login.example.com`), which are never offered or filled by themselves. `site` is the shared
   * domain to name ("example.com"). A trusted pick expands it in place into `other-login` entries.
   */
  | { kind: 'other-logins'; id: string; site: string; logins: OtherLogin[] }
  /** One of those logins, shown with the host it's saved for. Only the engine makes these, on expanding. */
  | ({ kind: 'other-login' } & OtherLogin);

/** A login saved for another part of the page's site; `host` is where it's saved, for display. */
export interface OtherLogin {
  id: string;
  title: string;
  username?: string;
  host: string;
}

export type SuggestionKind = Suggestion['kind'];

/** Values to fill, keyed by field type. `cc-exp` is `MM/YY`; month and year fields are derived from it. */
export type FillValues = Partial<Record<Exclude<FieldType, 'search' | 'unknown'>, string>>;

export interface SaveReport {
  url: string;
  username?: string;
  password: string;
  /** The password being replaced, on change-password forms. */
  oldPassword?: string;
  formType: FormType;
  trigger: 'submit' | 'request' | 'navigation' | 'generated';
  /** A suggested password was just used: save it as an unconfirmed draft right away (plan 05). */
  draft: boolean;
}

/** The address fields a save report can carry. Organization and birthday aren't saved from forms. */
export const ADDRESS_SAVE_FIELDS = [
  'name',
  'given-name',
  'family-name',
  'email',
  'tel',
  'address-line1',
  'address-line2',
  'address-level2',
  'address-level1',
  'postal-code',
  'country',
] as const;

/** What was typed into an address form, by field type. A select gives its option's text. */
export type AddressValues = Partial<Record<(typeof ADDRESS_SAVE_FIELDS)[number], string>>;

/** What was typed into a card form: `cc-number` as digits only (it passed the Luhn check), `cc-exp` as `MM/YY`. */
export type CardValues = Partial<Record<'cc-name' | 'cc-number' | 'cc-exp' | 'cc-csc', string>>;

/**
 * A submitted address or card form, detected like a login. Only fields the engine classified are read,
 * and only visible ones. A card's security code is included when typed; the host decides whether to keep it.
 */
export type DetailsSaveReport =
  | { kind: 'identity'; url: string; values: AddressValues; trigger: Exclude<SaveReport['trigger'], 'generated'> }
  | { kind: 'card'; url: string; values: CardValues; trigger: Exclude<SaveReport['trigger'], 'generated'> };

/** A trusted paste of what looks like an API key. The value stays with the host until the user says to save it. */
export interface ApiKeyPaste {
  kind: ApiKeyKind;
  value: string;
}

export type BlockReason =
  | 'no-gesture'
  | 'field-hidden'
  | 'field-covered'
  | 'field-transparent'
  | 'menu-covered'
  | 'menu-tampered'
  | 'too-fast';

export interface AutofillHost {
  /** Suggestions the host matched for this page. Domain matching (PSL, exact host) is the host's job. */
  getSuggestions(request: SuggestionRequest): Promise<Suggestion[]>;
  /** Values for a suggestion the user picked. Called only after a trusted gesture on the menu. */
  resolve(suggestion: Suggestion, request: SuggestionRequest): Promise<FillValues | null>;
  /**
   * Fill on page load: a username and password to put in a login form of the top document as soon as
   * it shows, with no gesture, or null to leave it empty. Asked once per form, only while its fields
   * are empty, visible and uncovered. The host decides everything else (the setting, https, the
   * page's own host, which login). Typing over a filled field clears what was filled. Without this,
   * nothing is filled until the user picks.
   */
  autoFill?(request: SuggestionRequest): Promise<Pick<FillValues, 'username' | 'current-password'> | null>;
  onSave?(report: SaveReport): void;
  /** An address or card form was submitted. */
  onSaveDetails?(report: DetailsSaveReport): void;
  /** An API key was pasted into a field that isn't a login's. Without this, pastes aren't looked at. */
  onApiKey?(paste: ApiKeyPaste): void;
  /**
   * The user picked a `frame-approval` entry. When it resolves true, the menu opens again with the
   * frame's suggestions.
   */
  approveFrame?(suggestion: Extract<Suggestion, { kind: 'frame-approval' }>, request: SuggestionRequest): Promise<boolean>;
  /** A cross-origin frame the engine won't look into. The extension decides (per-origin approval). */
  onFrame?(frame: FrameReport): void;
  /**
   * The website icon for a login suggestion, as image bytes, or null to keep the glyph. The menu
   * draws it as pixels in its closed shadow root, so the page can't tell which site it is for.
   */
  siteIcon?(suggestion: Extract<Suggestion, { kind: 'login' }>): Promise<Blob | null>;
  onBlocked?(reason: BlockReason, field: FillableElement): void;
}
