// @octapass/autofill: form detection, the inline menu and safe filling for the Octa Pass browser extension.
// It never sees the vault; see AutofillHost for the contract with the extension.

export { createAutofill, type Autofill, type AutofillOptions } from './engine';
export { scanDocument, explainField, type Explanation } from './scan';
export { classifyFields } from './classify/form';
export { fieldSignals } from './classify/field';
export { planFill, runFill, type FillResult, type FillStep } from './fill/fill';
export { setValue } from './fill/value';
export { isCardNumber, normalizeExpiry } from './save/details';
export { API_KEY_SERVICES, credentialHint, pastedToken, recognizeApiKey, type ApiKeyKind } from './classify/apiKey';
export { DEFAULT_LABELS, type MenuLabels, type Theme } from './menu/menu';
export * from './types';
