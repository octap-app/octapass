// The seam between the content script and whatever detects forms and fills them. The host contract
// is `@octapass/autofill`'s own; the adapter keeps the rest of the extension independent of how the
// engine is started.

import { createAutofill, planFill, runFill, scanDocument, type AutofillHost, type FillResult, type FillValues, type MenuLabels } from '@octapass/autofill';

export type { AutofillHost, FillValues, Suggestion, SuggestionRequest } from '@octapass/autofill';

export interface AutofillEngine {
  /** Starts watching the document; returns a function that stops. `onFill` hears what each fill did. */
  start(host: AutofillHost, onFill?: (result: FillResult) => void, labels?: MenuLabels): () => void;
  /** Fills a login into the page's login form (the popup's Fill button), with the engine's checks. */
  fillLogin(values: FillValues): FillResult | undefined;
}

/** Closed shadow roots too: Chrome's `chrome.dom` API, Firefox's `openOrClosedShadowRoot()`. */
function closedShadowRoot(element: Element): ShadowRoot | null {
  try {
    const firefox = (element as Element & { openOrClosedShadowRoot?: () => ShadowRoot | null }).openOrClosedShadowRoot;
    return firefox ? firefox.call(element) : (chrome.dom?.openOrClosedShadowRoot(element as HTMLElement) ?? null);
  } catch {
    // Chrome throws for elements it won't look into (SVG, other namespaces).
    return null;
  }
}

export const octaPassAutofill: AutofillEngine = {
  start(host, onFill, labels) {
    const autofill = createAutofill({ host, shadowRoot: closedShadowRoot, ...(onFill ? { onFill } : {}), ...(labels ? { labels } : {}) });
    return () => autofill.stop();
  },
  fillLogin(values) {
    const forms = scanDocument(document, { shadowRoot: closedShadowRoot }).forms.filter((f) => f.type === 'login' || f.type === 'identifier');
    const form = forms.find((f) => f.fields.some((field) => field.fillable && field.type === 'current-password')) ?? forms.find((f) => f.fields.some((field) => field.fillable));
    const origin = form?.fields.find((field) => field.fillable && (field.type === 'username' || field.type === 'current-password'));
    return form && origin ? runFill(planFill(form, values), origin.element, () => false) : undefined;
  },
};
