# @octapass/autofill

The autofill engine for the Octa Pass browser extension's content script. Framework-free TypeScript with no runtime dependencies. It **never sees the vault**: it finds and classifies form fields, asks a host callback for suggestions, renders the inline menu, and fills what the host hands back after a user gesture. Plans: [05 Clients and autofill](../../plans/05-clients-and-autofill.md), [03 Security model](../../plans/03-security-model.md), [12 Milestone 2](../../plans/12-milestone-2-extension-foundations.md).

```ts
import { createAutofill } from '@octapass/autofill';

const engine = createAutofill({
  host: {
    // Matched by the extension (PSL registrable domain, exact host, equivalent domains). Never by the engine.
    getSuggestions: (request) => background.suggestionsFor(request),
    // Called only after a trusted pick on our menu. Return null to cancel (locked vault, user said no).
    resolve: (suggestion, request) => background.valuesFor(suggestion, request),
    onSave: (report) => background.offerToSave(report),       // the host decides whether to prompt
    onSaveDetails: (report) => background.offerToSave(report), // a submitted address or card form
    onApiKey: (paste) => offerApiKey(paste),                  // a pasted API key; keep `paste.value` until the user says Save
    onFrame: (frame) => background.crossOriginFrame(frame),   // per-origin approval is the extension's call
    onBlocked: (reason, field) => console.debug('autofill refused:', reason),
  },
  shadowRoot: (element) => chrome.dom.openOrClosedShadowRoot(element),
});
```

Run it in the content script's **isolated world**: page scripts can then neither patch the functions it relies on (`attachShadow`, the value setters) nor read its closed shadow roots.

## What it does

| Part | Files | Notes |
|---|---|---|
| Field classification | `classify/field.ts`, `classify/lexicon.ts` | Scored signals: `autocomplete` tokens (100), input type, then name/id, labels (`<label>`, `aria-label`, `aria-labelledby`, nearby text), placeholder and title, in English and the ten most used languages incl. Arabic. Longest keyword wins (`Name on card` is `cc-name`, not `name`). |
| Form classification | `classify/form.ts` | Groups fields by `<form>` or, without one, by the nearest container with a submit-like button (not a show-password toggle). Resolves passwords (current / new / confirm), the account field, split one-time codes, card forms and identity forms from structure and from what the buttons and headings say. |
| API keys | `classify/apiKey.ts` | Pure functions: a value is a key if the whole of it has a known shape (`ghp_…`, `sk_live_…`, JWTs with a real header, `opsa1_…`), or if the field is named as a key and the value looks random. Fields named as a key or token are `api-credential`; a sign-in always wins over that name. A trusted `paste` in such a field or an unclassified one goes to `onApiKey`, never one in a password, username, search, card or address field. |
| `explain()` | `scan.ts` | Every signal and form-level reason behind a field's type, as data and as text. |
| DOM walking | `dom/walk.ts` | Open (or, with the extension's API, closed) shadow roots and same-origin frames. Cross-origin frames are reported to the host, never entered. |
| Inline menu | `menu/` | A field icon and a listbox, each in a closed shadow root inside a `popover="manual"` host in the top layer (inside an open modal `<dialog>` when the field is in one). Octa Pass tokens in light and dark, keyboard accessible: ArrowDown opens and moves in, arrows / Home / End move, Enter or Space picks, Escape and Tab go back to the field. |
| Filling | `fill/` | Native value setter plus `input` and `change` events, so React, Vue, Angular and Svelte notice. Confirm fields get the new password; expiries, names, countries and split codes are formatted for each field. |
| Save detection | `save/detector.ts` | Reports `{ url, username, password, oldPassword?, formType, trigger, draft }` on `submit`, or after a click / Enter followed by a completed request, a URL change or the form disappearing. A picked suggested password is reported at once as a draft. Address and card forms are reported the same way through `onSaveDetails` (`save/details.ts`): only classified, visible fields; an address needs a street line and a city or postcode; a card number must pass Luhn, and expiries become `MM/YY`. |

## Safety rules

The engine refuses rather than guesses. Each refusal is reported through `onBlocked`.

- **User gesture**: a pick must be a trusted event on our own menu, at least 250 ms after the menu appeared or moved (`no-gesture`, `too-fast`).
- **Hidden fields** are never offered or filled: `type=hidden`, `display: none`, `visibility: hidden`, combined opacity below 0.6, empty `clip` / `clip-path`, smaller than 6 px, off-screen, disabled or read-only (`field-hidden`, `field-transparent`).
- **Covered fields**: `elementsFromPoint` at five points of the field (and of each frame around it) must mostly hit the field, its own label or our icon (`field-covered`). Other fields in the form that are covered are skipped.
- **Our UI**: host styles are inline `!important` (beating any page stylesheet, animations included), and any change the page makes to the host (attributes, moving it, closing the popover) marks it tampered. At pick time its computed style is checked, nothing may be on top at the picked point, and IntersectionObserver v2 must not report it hidden where supported (`menu-tampered`, `menu-covered`).
- **Only the form you picked from** is filled, and only with values the host returned for that pick. An API key goes only in the field it was picked for. After the host answers, the field is checked again before anything is written.
- **Not the engine's job**: domain matching, `http:` warnings (`request.secure` tells the host), cross-origin frame approval and re-prompting for CVVs belong to the extension.

## Tests

```sh
pnpm --filter @octapass/autofill test        # Vitest + jsdom unit tests
pnpm --filter @octapass/autofill typecheck
pnpm --filter @octapass/autofill corpus      # every page of tools/autofill-corpus in the system Chrome
```

The corpus runner is described in [`tools/autofill-corpus/README.md`](../../tools/autofill-corpus/README.md).
