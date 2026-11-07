# Autofill corpus

Synthetic, self-contained HTML pages that exercise `@octapass/autofill` in a real browser, each with a JSON file describing what a correct engine does on it. No real brands' code or markup, no network requests: everything a page needs is inline.

```sh
pnpm --filter @octapass/autofill corpus            # all pages
pnpm --filter @octapass/autofill corpus -- login   # pages whose name contains "login"
```

The runner (`run.mjs`) bundles the engine with Vite, serves `pages/` on two local origins (`127.0.0.1` and `localhost`, so frames between them are cross-origin), opens every page in the system Chrome through `playwright-core`, runs the checks below and prints an accuracy score (passed checks / all checks). It exits non-zero below `--min-accuracy` (default `1`). `--verbose` prints every check with the engine's `explain()` output, `--headed` shows the browser. Set `CHROME_PATH` if Chrome isn't in the usual place.

The engine runs in the page's main world here, with a fake host that returns the fixtures below. A fill scenario focuses the field, presses ArrowDown (opens the menu and moves into it), waits 400 ms and presses Enter, all as real (trusted) input. A refused fill passes when nothing changed and the host was told why (`onBlocked`).

Pages 01–60 were written first; 61–76 were written later, without looking at the engine, as a held-out set (95.0% on first run, see `plans/12` History).

## Files

- `pages/<slug>.html`: the page. Helper pages it loads (iframes) live in `pages/frames/` and have no JSON.
- `pages/<slug>.json`: the expectations.
- `{{CROSS_ORIGIN}}` anywhere in a served page is replaced with the second origin (for example `http://localhost:41235`), so `<iframe src="{{CROSS_ORIGIN}}/frames/pay.html">` is a cross-origin frame.

## Selectors

A selector is a CSS selector, or several joined with ` >>> ` to step into an open shadow root or an iframe's document: `login-card >>> #password` is `#password` inside `login-card`'s shadow root, `iframe#signin >>> #user` is `#user` inside that frame.

## Expectations

```jsonc
{
  "description": "Classic username + password login",
  // Every input that matters, with the type a human expert would give it. "none" means the engine must
  // not offer or fill it (hidden decoys, search boxes, honeypots, unrelated fields).
  "fields": {
    "#user": "username",
    "#pass": "current-password",
    "#honeypot": "none"
  },
  // The form type of the form that contains a field.
  "forms": [{ "field": "#user", "type": "login" }],
  // Frames the engine must report to the host instead of handling them.
  "frames": [{ "selector": "iframe#pay", "crossOrigin": true }],
  // Fill scenarios, run in order on a fresh load of the page.
  "fills": [
    {
      "focus": "#user",                 // the field the user opens the menu from
      "pick": "login",                  // which kind of suggestion the user picks (see Fixtures)
      "expect": { "#user": "alex@example.test", "#pass": "correct-horse-42!", "#honeypot": "" },
      "refused": false                  // true: the engine must refuse, and every "expect" value is checked unchanged
    }
  ],
  // Save detection: steps the user takes, then the report the host must receive (or "none").
  "saves": [
    {
      "steps": [
        { "type": ["#user", "sam@example.test"] },
        { "type": ["#pass", "Typed-pass-99"] },
        { "click": "#submit" }          // or { "press": "Enter" }, { "wait": 300 }, { "select": ["#country", "GB"] }
      ],
      "expect": { "username": "sam@example.test", "password": "Typed-pass-99", "formType": "login" }
    }
  ]
}
```

`expect` compares an input's or select's `value`, and any other element's `textContent` (trimmed), so pages can show framework state in an `<output>`. In `saves`, an empty expected value means the report leaves that key out. An address or card form's report is expected as `{ "kind": "identity" | "card", "values": { … } }`, with exactly those values (field types as keys).

### Field types

| Group | Types |
|---|---|
| Login | `username` (the account identifier in sign-in forms and identifier steps, even when it is an email input), `current-password`, `new-password`, `confirm-password`, `one-time-code` |
| Sign-up and identity | `email`, `username`, `name`, `given-name`, `family-name`, `tel`, `organization`, `bday`, `address-line1`, `address-line2`, `address-level2` (city), `address-level1` (state, region), `postal-code`, `country` |
| Card | `cc-name`, `cc-number`, `cc-exp` (one MM/YY field), `cc-exp-month`, `cc-exp-year`, `cc-csc` |
| Other | `none` |

### Form types

`login` (has a password the user signs in with, with or without an identifier), `identifier` (the first step of a multi-step sign-in: identifier only), `signup`, `change-password`, `one-time-code`, `card`, `identity` (personal details and addresses).

### Fixtures

The runner's host matches every page and returns one suggestion of the picked kind, with these values:

| Pick | Values |
|---|---|
| `login` | username `alex@example.test`, password `correct-horse-42!` |
| `generated-password` | `Lantern-ruby-T7#qv-42` |
| `one-time-code` | `123456` |
| `card` | cardholder `Alex Doe`, number `4111111111111111`, expiry `09/29`, CVV `123` |
| `identity` | Alex Doe, `alex@example.test`, `+15555550100`, Example Labs, 1 Test Street, Apt 2, Springfield, CA, `90210`, `US`, born `1990-04-12` |

Month and year selects or inputs take the format the field asks for (`09`, `9`, `29` or `2029`); a country select takes the option whose value or text matches `US` / United States.
