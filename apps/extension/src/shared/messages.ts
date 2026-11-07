// Messages between content scripts and the service worker. The service worker takes the page's
// URL from the browser's `sender`, never from these messages.

import type { ApiKeyKind, DetailsSaveReport, FieldType, FillValues, FormType, PasswordConstraints, SaveReport, Suggestion } from '@octapass/autofill';
import type { SessionStatus } from '@octapass/vault-client';

/** What the service worker needs from the engine's `SuggestionRequest`; the URLs come from the browser. */
export interface FieldContext {
  formType: FormType;
  fieldType: FieldType;
  passwordConstraints?: PasswordConstraints;
}

export type ContentRequest =
  | { type: 'suggestions'; field: FieldContext }
  | { type: 'resolve'; suggestion: Pick<Suggestion, 'kind' | 'id'> }
  /** The engine saw a login being submitted (or a suggested password used). */
  | { type: 'save'; report: Omit<SaveReport, 'url'> }
  /** The engine saw an address or card form being submitted. */
  | { type: 'saveDetails'; report: DistributiveOmit<DetailsSaveReport, 'url'> }
  /** A page just loaded: is there a save prompt to show from before a navigation? */
  | { type: 'pendingSave' }
  /** An API key was pasted: may the page offer to save it? Only its kind: the value stays in the page's content script. */
  | { type: 'offerApiKey'; apiKey: ApiKeyKind }
  /**
   * `saveCode`: the user ticked "Also save the security code" on a card prompt. `credential`: the API
   * key, only when the user chose Save on its prompt.
   */
  | { type: 'answerSave'; id: string; answer: SaveAnswer; saveCode?: boolean; credential?: string }
  /** The user allowed Octa Pass in this frame, from the inline menu (it's from another site than the page). */
  | { type: 'approveFrame' }
  | { type: 'openApp' }
  /** The website icon for a login the menu shows: base64 PNG or null. */
  | { type: 'siteIcon'; id: string }
  /**
   * A login from "Logins for other parts of …" (`id`) was just filled: the offer to add this page's
   * website to it, if there is one (`WebsitePrompt` or null).
   */
  | { type: 'websitePrompt'; id: string }
  /** The user's answer to that offer, by the prompt's id. */
  | { type: 'answerWebsite'; id: string; answer: WebsiteAnswer }
  /** The language chosen in the popup's settings (`LanguagePreference`). */
  | { type: 'language' }
  /**
   * A login form showed in the top frame: what to fill in it now, with no pick (`AutoFillResponse`).
   * Answered only with "Fill logins when a page opens" on.
   */
  | { type: 'autoFill' };

/** A login's username and password for a fill on page load, or null for none. */
export type AutoFillResponse = Pick<FillValues, 'username' | 'current-password'> | null;

export interface SuggestionsResponse {
  status: SessionStatus;
  suggestions: Suggestion[];
}

/** What to fill; `error` (a `VaultErrorCode`) when making a masked email failed. */
export type ResolveResponse = FillValues | { error: string } | null;

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

export type SaveAnswer = 'save' | 'notNow' | 'never';

/**
 * What the page should ask the user, if anything. It never holds a card number or security code: a
 * card is named by its brand, last four digits and expiry. An API key is named by its service.
 */
export interface SavePrompt {
  id: string;
  kind: 'save' | 'update';
  item: 'login' | 'identity' | 'card' | 'apiKey';
  host: string;
  username?: string;
  /** An address on one line. */
  address?: string;
  card?: { brand?: string; last4: string; expiry?: string };
  /** A security code was typed with the card: offer to keep it too (unticked). */
  offerCode?: boolean;
  /** What an API key looks like it's for ('GitHub'); missing when only the field said it's a key. */
  service?: string;
  /** Octa Pass is locked: a Save waits, sealed, and is added to the vault at the next unlock. */
  locked?: boolean;
}

/**
 * After a login for another part of the site was filled: "Add {host} to this login?". Only for a login
 * in a vault the user can change, and only when it doesn't have the page's website yet.
 */
export interface WebsitePrompt {
  id: string;
  /** The page's host, without `www.`. */
  host: string;
  /** The login's title. */
  title: string;
}

export type WebsiteAnswer = 'add' | 'notNow';

export type SaveResponse = { prompt: SavePrompt } | { saved: 'draft' | 'confirmed' } | null;

/** From the service worker to a tab's top frame: fill this login (the user clicked Fill in the popup). */
export interface FillMessage {
  type: 'fill';
  values: FillValues;
  /** The origin the login was matched against. The page refuses if it has navigated elsewhere since. */
  origin: string;
}
