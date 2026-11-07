# Native resources

Generates the strings and design tokens the native iPhone and Android apps use ([plan 17](../../plans/17-native-mobile-apps.md)), so they say the same thing and look the same as the web vault. Node built-ins only; no dependencies.

```sh
node tools/native-resources/generate.mjs              # write every file
node tools/native-resources/generate.mjs --check      # change nothing; exit 1 and list the files that are out of date
node --test "tools/native-resources/test/*.test.mjs"  # unit tests, plus aapt2 and Java checks when the Android SDK and a JDK are installed
```

The generated files are committed. Run `--check` in CI, and the generator after any change to a source.

## Sources and outputs

| Source | |
|---|---|
| `apps/web/src/i18n/en.ts`, `ar.ts` | The web vault's catalogs: every message, keyed as in `t('common.back')` |
| `apps/web/src/i18n/phone.ts` | Words only the phone apps say, under the `phone.` prefix (`phone.scan`) |
| `packages/ui/src/styles/tokens.css` | Colours (light and dark), the gradient, type sizes, radii, motion, fonts |

| Output | |
|---|---|
| `apps/ios/Packages/OctaPassResources/Sources/OctaPassResources/Resources/Localizable.xcstrings` | String Catalog, `en` and `ar` |
| `…/OctaPassResources/L10n.swift` | Typed accessors: `L10n.common.back`, `L10n.list.searchPlaceholder(count: 3)` |
| `…/OctaPassResources/Tokens.swift` | `Tokens.Colors.trust.color` (follows light/dark), `Tokens.TypeScale.md`, … |
| `…/Tests/OctaPassResourcesTests/Resources/expected.json` | What the web vault shows for a sample of messages; the Swift tests compare `L10n` with it |
| `apps/android/resources/src/main/res/values/strings.xml`, `values-ar/strings.xml` | `<string>` and `<plurals>` |
| `apps/android/resources/src/main/kotlin/app/octapass/resources/Tokens.kt` | Plain constants, no Compose dependency |

The Swift package has its own tests (`xcodebuild test -scheme OctaPassResources -destination 'platform=macOS'` in its folder). `swift build` compiles it, but only Xcode's build turns the String Catalog into `.strings`/`.stringsdict`, so string lookups need `xcodebuild`.

## Adding or changing a string

Add it to the web vault's `en.ts` and `ar.ts` (or, for words only the phone apps use, `apps/web/src/i18n/phone.ts`), as for the web, then run the generator. Never edit the generated files: the next run overwrites them and `--check` fails until it does.

## Conventions

**Keys.** The catalog key is the String Catalog key (`common.back`). Android names replace every character that isn't a letter, digit or `_` with `_` (`import.help.onepassword-1pux` → `import_help_onepassword_1pux`). Swift accessors nest one type per group; a segment with `-x` becomes `X`, one starting with a digit gets a leading `_` (`L10n.strength.score._0`, `L10n.import.help._2fas`), and Swift keywords are escaped where they're declared (callers still write `L10n.import.done(count:)`). Two keys that end up with the same name stop the generator with both named; it never overwrites one with the other.

**Placeholder numbering.** `{name}` placeholders become positional arguments numbered from 1 in order of first appearance in the English message: for a counted message, in its `other` form first, then any name only another form uses. A counted message always takes `count`, numbered last if no English form shows it. Translations keep these numbers wherever their words put the placeholder. Swift functions take the arguments in the same order, labelled by name.

**Numbers and text.** `count` is always an integer (`%lld` on iOS, `%d` on Android), as are placeholders named like a count: `n`, `step`, `left`, `max`, `members`, `views`, `bits` (`INTEGER_PLACEHOLDERS` in `lib/messages.mjs`). A name that is a number in one message and formatted text in others is listed per key in `INTEGER_OVERRIDES` (`{total}` in `signUp.stepOf`, `{days}` in `trash.note`). Everything else is text (`%@`, `%s`): names, emails, and dates, sizes or durations the app has already formatted. A new placeholder that should be a number needs adding to one of those lists.

**Plurals.** A message is counted if any language counts it: English may say "Hides in {count} s" where Arabic needs forms. Each language gets the plural categories it uses (English `one`/`other`, Arabic all six), a missing form takes the `other` text, and a form the language doesn't use is dropped, as `Intl.PluralRules` would never pick it. In the String Catalog, a message whose only argument is `count`, and whose general form shows it, varies the whole string by plural; any other counted message puts the forms in a `count` substitution (`%#@count@`, `argNum` = the count's position), with the other arguments at their positions inside each form. On Android, counted messages are `<plurals>`; call `getQuantityString(id, count, args…)` with every argument in order.

**Escaping.** A message with arguments is a format string, so a literal `%` becomes `%%`; one without arguments is used as is (Android: `formatted="false"` when it contains `%`). Android text is escaped for aapt2: `\`, `'`, `"`, `&`, `<`, `>`, newlines and tabs, a leading `@` or `?`, and spaces aapt2 would collapse.

**Language, digits and bidi.** The web vault shows Western digits in Arabic, groups them (`1,234`) and isolates inserted text (FSI…PDI) so a Latin name keeps its order. On iOS, `L10n` formats in the shown language with Western digits (`ar@numbers=latn`), which matters beyond digits: Foundation picks the plural form by the formatting locale, not by the bundle's language. Use `L10n.setLanguage(_:)` for a language chosen in the app, never a bundle on its own. Foundation isolates `%@` arguments in a right-to-left format by itself. On Android, `%d` doesn't group digits and nothing is isolated: wrap inserted text with `BidiFormatter.unicodeWrap`, and format large numbers before passing them as text if grouping matters.

**Tokens.** Every colour token with its light and dark value (`rgb()`/alpha and `color-mix(in srgb, …)` resolved to concrete sRGB plus alpha; a token the dark theme doesn't override keeps its light value). The gradient is exported as its angle and stops. Sizes are points (iOS) or sp/dp (Android) at 16 per CSS rem; a fluid `clamp()` size is its minimum, since phones are narrow. Durations are milliseconds (Kotlin) or seconds (Swift); easings are `cubic-bezier` control points. Font families drop fontsource's " Variable" suffix. Shadows aren't exported yet, and the CSS has no spacing scale, so none is invented. A token the generator doesn't recognise stops it, so nothing is dropped silently: teach `lib/tokens.mjs` about it.
