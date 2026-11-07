// The content script (isolated world): runs the autofill engine against the service worker, relays
// passkey requests, and shows save prompts. The service worker matches everything to this frame's
// URL as the browser reports it.

import type { ApiKeyPaste, DetailsSaveReport, FillResult, MenuLabels, SaveReport, Suggestion } from '@octapass/autofill';
import { resolveLocale, setLocale, type LanguagePreference } from '@octapass/web/src/i18n/core';
import { tx } from '../i18n';
import { apiKeyOffers } from './apiKeyOffer';
import type { AutoFillResponse, ContentRequest, FillMessage, ResolveResponse, SaveAnswer, SavePrompt, SaveResponse, SuggestionsResponse, WebsitePrompt } from '../shared/messages';
import { copyCode } from './clipboard';
import { octaPassAutofill } from './engine';
import { askUser, showToast, type Row } from './notice';
import { startPasskeyRelay } from './passkeyRelay';

const ask = <T>(message: ContentRequest) => chrome.runtime.sendMessage<ContentRequest, T>(message);

startPasskeyRelay();

// The language chosen in the popup, or else the browser's. Notices and the menu wait for it.
const language = ask<LanguagePreference>({ type: 'language' }).then(
  (preference) => setLocale(resolveLocale(preference ?? 'system')),
  () => setLocale(resolveLocale()),
);

function menuLabels(): MenuLabels {
  const key = (name: keyof MenuLabels) => tx(`menu.${name}`);
  return { menu: key('menu'), icon: key('icon'), suggestedPassword: key('suggestedPassword'), maskedEmail: key('maskedEmail'), needsSetup: key('needsSetup'), oneTimeCode: key('oneTimeCode'), noUsername: key('noUsername'), allowFrame: key('allowFrame'), frameNotice: key('frameNotice'), otherLogins: key('otherLogins'), otherLoginDetail: key('otherLoginDetail'), hintMove: key('hintMove'), hintPick: key('hintPick') };
}

function maskedEmailHint(code: string) {
  if (code === 'maskedEmailToken') return 'page.maskedEmailToken';
  if (code === 'maskedEmailRateLimited') return 'page.maskedEmailRateLimited';
  return 'page.maskedEmailOther';
}

const TITLES = {
  login: { save: 'page.saveTitle', update: 'page.updateTitle' },
  identity: { save: 'page.saveAddressTitle', update: 'page.updateAddressTitle' },
  card: { save: 'page.saveCardTitle', update: 'page.updateCardTitle' },
  apiKey: { save: 'page.saveApiKeyTitle', update: 'page.saveApiKeyTitle' },
} as const;

/** What would be saved, as rows: never the secret itself, which the page has and the prompt doesn't. */
function promptRows({ item, service, username, address, card }: SavePrompt): Row[] {
  if (item === 'apiKey') return [{ icon: 'code', text: service ? tx('page.apiKeyDetected', { service }) : tx('page.apiKeyFromField') }];
  if (card) {
    const ending: Row = { icon: 'card', text: tx('page.cardEnding', { brand: card.brand ?? tx('page.card'), last4: card.last4 }) };
    return card.expiry ? [ending, { icon: 'clock', text: tx('page.cardExpires', { expiry: card.expiry }) }] : [ending];
  }
  if (item === 'identity') return address ? [{ icon: 'mapPin', text: address }] : [];
  // A login's save and update both carry a password.
  return [...(username ? [{ icon: 'user', text: username } as const] : []), { icon: 'key', text: tx('page.password'), masked: true }];
}

type PromptAnswered = (answer: SaveAnswer, saveCode: boolean) => void;

function prompt(save: SavePrompt, answered?: PromptAnswered): () => void {
  return askUser<SaveAnswer>(
    {
      title: tx(TITLES[save.item][save.kind]),
      host: save.host,
      rows: promptRows(save),
      // Locked: a Save waits, sealed, until the next unlock adds it to the vault.
      ...(save.locked ? { note: tx('page.lockedSave') } : {}),
      ...(save.offerCode ? { check: tx('page.saveCode') } : {}),
      primary: { value: 'save', label: tx(save.kind === 'save' ? 'page.save' : 'page.update') },
      secondary: { value: 'notNow', label: tx('page.notNow') },
      quiet: { value: 'never', label: tx('page.never') },
    },
    answered ?? ((answer: SaveAnswer, saveCode) => void ask({ type: 'answerSave', id: save.id, answer, ...(saveCode ? { saveCode } : {}) })),
  );
}

/** A confirmation in the extension's language; `failed` ones stay a little longer to be read. */
function toast(title: string, detail?: string, failed = false): void {
  showToast(title, detail, { dismiss: tx('page.dismiss'), ...(failed ? { ms: 6000 } : {}) });
}

const onApiKey = apiKeyOffers({
  offer: (apiKey) => ask<SaveResponse>({ type: 'offerApiKey', apiKey }),
  show: prompt,
  answer: (id, answer, credential) => ask<boolean | null>({ type: 'answerSave', id, answer, ...(credential ? { credential } : {}) }),
  saved: (ok) => (ok ? toast(tx('page.apiKeySaved')) : toast(tx('page.apiKeyNotSaved'), tx('page.apiKeyNotSavedBody'), true)),
});

/** The inline menu's entry while the vault is locked, in the user's language, listed whatever the user types. */
function unlockTitle(suggestions: Suggestion[]): Suggestion[] {
  return suggestions.map((s) => (s.kind === 'login' ? { ...s, title: tx('menu.unlock'), pinned: true } : s.kind === 'api-credential' ? { ...s, title: tx('menu.unlock') } : s));
}

async function onSave({ url: _url, ...report }: SaveReport): Promise<void> {
  const response = await ask<SaveResponse>({ type: 'save', report });
  if (!response) return;
  if ('prompt' in response) prompt(response.prompt);
  else if (response.saved === 'draft') toast(tx('page.savedDraft'), tx('page.savedDraftBody'));
}

async function onSaveDetails({ url: _url, ...report }: DetailsSaveReport): Promise<void> {
  const response = await ask<SaveResponse>({ type: 'saveDetails', report });
  if (response && 'prompt' in response) prompt(response.prompt);
}

/** After a login from another part of the site was filled: "Add {host} to this login?" */
async function offerWebsite(id: string): Promise<void> {
  const offer = await ask<WebsitePrompt | null>({ type: 'websitePrompt', id });
  if (!offer) return;
  askUser(
    {
      title: tx('page.addWebsiteTitle'),
      host: offer.host,
      rows: [{ icon: 'login', text: offer.title }],
      primary: { value: 'add', label: tx('page.add') },
      secondary: { value: 'notNow', label: tx('page.notNow') },
    },
    (answer) =>
      void ask<boolean>({ type: 'answerWebsite', id: offer.id, answer }).then((added) => {
        if (answer !== 'add') return;
        if (added) toast(tx('page.websiteAdded', { host: offer.host, title: offer.title }));
        else toast(tx('page.websiteNotAdded', { host: offer.host }), undefined, true);
      }),
  );
}

// A one-time code the engine couldn't fill (split boxes it doesn't fit, a refused fill) is copied instead.
let lastCode: string | undefined;
// A login picked from "Logins for other parts of …": once it's in the page, offer to add the page to it.
let lastOtherLogin: string | undefined;
function onFill(result: FillResult): void {
  const other = lastOtherLogin;
  lastOtherLogin = undefined;
  if (other && result.filled.length > 0) void offerWebsite(other);
  const code = lastCode;
  lastCode = undefined;
  if (!code || result.filled.length > 0 || result.skipped.some((s) => s.reason === 'covered' || s.reason === 'refused')) return;
  void copyCode(code).then(
    () => toast(tx('page.codeCopied'), tx('page.codeCopiedBody')),
    () => toast(tx('page.codeFailed'), tx('page.codeFailedBody'), true),
  );
}

void language.then(() =>
  octaPassAutofill.start(
    {
      getSuggestions: async ({ formType, fieldType, passwordConstraints }) => {
        const response = await ask<SuggestionsResponse>({ type: 'suggestions', field: { formType, fieldType, ...(passwordConstraints ? { passwordConstraints } : {}) } });
        return response?.status === 'locked' ? unlockTitle(response.suggestions) : (response?.suggestions ?? []);
      },
      resolve: async ({ kind, id }) => {
        const values = (await ask<ResolveResponse>({ type: 'resolve', suggestion: { kind, id } })) ?? null;
        if (values && 'error' in values) {
          toast(tx('page.maskedEmailFailed'), tx(maskedEmailHint(values.error)), true);
          return null;
        }
        lastCode = values?.['one-time-code'];
        lastOtherLogin = values && kind === 'other-login' ? id : undefined;
        return values;
      },
      // Bytes from the service worker, drawn by the menu: the page sees no request for them.
      siteIcon: async ({ id }) => {
        const png = await ask<string | null>({ type: 'siteIcon', id });
        return png ? new Blob([Uint8Array.from(atob(png), (c) => c.charCodeAt(0))], { type: 'image/png' }) : null;
      },
      // The service worker allows this frame's own origin (from `sender`) on the page's site.
      approveFrame: async () => (await ask<boolean>({ type: 'approveFrame' })) === true,
      onSave: (report) => void onSave(report),
      onSaveDetails: (report) => void onSaveDetails(report),
      // Top frame only (same-origin frames are its engine's too): a frame can't name the site a key is for.
      ...(window === window.top ? { onApiKey: (paste: ApiKeyPaste) => void onApiKey(paste) } : {}),
      // Fill on page load, top frame only; the service worker checks the frame, the page and the setting again.
      ...(window === window.top ? { autoFill: async () => (await ask<AutoFillResponse>({ type: 'autoFill' })) ?? null } : {}),
    },
    onFill,
    menuLabels(),
  ),
);

// A save prompt from before the last navigation (the engine reports a login just as the page leaves).
if (window === window.top) void language.then(() => ask<SavePrompt | null>({ type: 'pendingSave' })).then((save) => save && prompt(save));

// The popup's Fill button, relayed by the service worker to the top frame only.
chrome.runtime.onMessage.addListener((message: FillMessage, sender) => {
  if (sender.id !== chrome.runtime.id || sender.tab || message.type !== 'fill' || window !== window.top) return;
  // The tab may have navigated between the service worker's check and this message.
  if (location.origin !== message.origin) return;
  octaPassAutofill.fillLogin(message.values);
});
