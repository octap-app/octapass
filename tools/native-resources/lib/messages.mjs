// The catalogs as a flat list of messages, each with its arguments numbered for the native
// format strings. Pure functions: no files, so the tests can feed them small catalogs.

export const PLURAL_CATEGORIES = ['zero', 'one', 'two', 'few', 'many', 'other'];

const PLACEHOLDER = /\{(\w+)\}/g;

/**
 * Placeholders that are numbers (`%lld` on iOS, `%d` on Android). Everything else is text (`%@`,
 * `%s`): names, emails, dates and sizes the app has already formatted. `count` is always a number,
 * since it picks the plural form.
 */
export const INTEGER_PLACEHOLDERS = new Set(['count', 'n', 'step', 'left', 'max', 'members', 'views', 'bits']);

/** Names that are numbers in one message and text in others, by message key. */
export const INTEGER_OVERRIDES = {
  'signUp.stepOf': ['total'], // "Step {step} of {total}"; elsewhere {total} is a formatted size
  'trash.note': ['days'], // "after {days} days"; elsewhere {days} is a counted phrase like "7 days"
};

/** A message is a string, or an object whose keys are all plural categories (with `other`). */
export function isPlural(node) {
  if (typeof node !== 'object' || node === null || Array.isArray(node)) return false;
  const keys = Object.keys(node);
  return keys.length > 0 && keys.every((k) => PLURAL_CATEGORIES.includes(k)) && typeof node.other === 'string';
}

/** `{ a: { b: 'x' } }` → Map { 'a.b' => 'x' }, in catalog order. */
export function flatten(catalog, prefix = '') {
  const out = new Map();
  for (const [key, node] of Object.entries(catalog)) {
    if (typeof node === 'string' || isPlural(node)) out.set(prefix + key, node);
    else if (typeof node === 'object' && node !== null) for (const [k, v] of flatten(node, `${prefix}${key}.`)) out.set(k, v);
    else throw new Error(`${prefix}${key}: not a message or a group`);
  }
  return out;
}

/** Placeholder names in order of first appearance. */
export function placeholders(text) {
  return [...new Set([...text.matchAll(PLACEHOLDER)].map((m) => m[1]))];
}

/** The forms of a message, the general (`other`) form first. */
function forms(message) {
  if (typeof message === 'string') return [message];
  return [message.other, ...PLURAL_CATEGORIES.filter((c) => c !== 'other' && typeof message[c] === 'string').map((c) => message[c])];
}

/**
 * The arguments of a message, numbered from 1 in order of first appearance in the English message
 * (its `other` form first for a counted message, then any name only the other forms use). A counted
 * message always takes `count`, last if its text never shows it.
 */
export function argumentsFor(key, english) {
  const names = [...new Set(forms(english).flatMap(placeholders))];
  if (isPlural(english) && !names.includes('count')) names.push('count');
  const overrides = INTEGER_OVERRIDES[key] ?? [];
  return names.map((name, i) => ({
    name,
    position: i + 1,
    kind: INTEGER_PLACEHOLDERS.has(name) || overrides.includes(name) ? 'int' : 'text',
  }));
}

/**
 * `text` with each `{name}` replaced by `specifier(argument)`. When the message takes arguments
 * it's a format string, so a literal `%` becomes `%%`; a message without any is shown as is.
 */
export function toFormat(text, args, specifier) {
  const byName = new Map(args.map((a) => [a.name, a]));
  const escaped = args.length ? text.replaceAll('%', '%%') : text;
  return escaped.replace(PLACEHOLDER, (_, name) => {
    const arg = byName.get(name);
    if (!arg) throw new Error(`{${name}} has no argument`);
    return specifier(arg);
  });
}

/** The plural categories a language uses, in the order above. */
export function categoriesFor(locale) {
  const used = new Intl.PluralRules(locale).resolvedOptions().pluralCategories;
  return PLURAL_CATEGORIES.filter((c) => used.includes(c));
}

/**
 * A message in one language as the native files need it: a string, or every plural form the
 * language uses (a missing form gets the `other` text, a form the language doesn't use is dropped,
 * as Intl.PluralRules never picks it on the web either).
 */
function localize(message, plural, locale) {
  if (!plural) return message;
  const source = typeof message === 'string' ? { other: message } : message;
  return Object.fromEntries(categoriesFor(locale).map((c) => [c, source[c] ?? source.other]));
}

/**
 * Every message of `catalogs` (`{ en, ar, … }`, nested as the web vault's are), checked: a
 * translation can't add keys or placeholders. A message is counted if any language counts it
 * (English may say "Hides in {count} s" where Arabic needs six forms). Keys a translation lacks
 * are left out of it.
 */
export function buildMessages(catalogs, sourceLocale = 'en') {
  const source = flatten(catalogs[sourceLocale]);
  const others = Object.entries(catalogs)
    .filter(([locale]) => locale !== sourceLocale)
    .map(([locale, catalog]) => [locale, flatten(catalog)]);
  const problems = [];

  for (const [locale, flat] of others) for (const key of flat.keys()) if (!source.has(key)) problems.push(`${locale} ${key}: not in ${sourceLocale}`);

  const messages = [];
  for (const [key, english] of source) {
    // Counted if any language counts it: English can say "Hides in {count} s" where Arabic needs forms.
    const plural = isPlural(english) || others.some(([, flat]) => isPlural(flat.get(key)));
    if (plural && !isPlural(english) && !placeholders(english).includes('count')) problems.push(`${key}: counted in a translation, but ${sourceLocale} has no {count}`);
    const args = argumentsFor(key, plural && !isPlural(english) ? { other: english } : english);
    const known = new Set(args.map((a) => a.name));
    const text = { [sourceLocale]: localize(english, plural, sourceLocale) };
    for (const [locale, flat] of others) {
      const message = flat.get(key);
      if (message === undefined) continue;
      for (const form of forms(message)) for (const name of placeholders(form)) if (!known.has(name)) problems.push(`${locale} ${key}: {${name}} isn't in ${sourceLocale}`);
      text[locale] = localize(message, plural, locale);
    }
    messages.push({ key, plural, args, text });
  }
  if (problems.length) throw new Error(`Catalog problems:\n  ${problems.join('\n  ')}`);
  return messages;
}

/** The phone app's own words go under `phone.`; a key the web catalog already has is an error. */
export function mergeCatalogs(web, phone, prefix = 'phone') {
  const out = {};
  for (const locale of new Set([...Object.keys(web), ...Object.keys(phone)])) {
    const base = web[locale] ?? {};
    if (prefix in base) throw new Error(`The web catalog already has a "${prefix}" group`);
    out[locale] = { ...base, [prefix]: phone[locale] ?? {} };
  }
  return out;
}

/** Counts that reach every Arabic and English plural form. */
export const SAMPLE_COUNTS = [0, 1, 2, 3, 11, 100];

/** Right-to-left languages, where the web vault isolates inserted text (FSI … PDI). */
const RIGHT_TO_LEFT = new Set(['ar']);
export const FSI = '\u2068';
export const PDI = '\u2069';

/**
 * What the web vault's `format()` shows for each message with sample arguments: text arguments
 * are the placeholder's name in capitals, other numbers 7. Like the web vault (and Foundation's
 * String(format:locale:) for an RTL locale), inserted text is isolated in a right-to-left language.
 * Numbers stay below 1000, since the web groups digits and %d doesn't. The native tests check
 * their output against these.
 */
export function expectations(messages, { plainSamples = Infinity } = {}) {
  const cases = [];
  let plain = 0;
  for (const message of messages) {
    if (message.args.length === 0 && plain++ >= plainSamples && !message.text.en.includes('%')) continue;
    const counts = message.plural ? SAMPLE_COUNTS : [undefined];
    for (const [locale, text] of Object.entries(message.text)) {
      const rules = new Intl.PluralRules(locale);
      for (const count of counts) {
        const values = Object.fromEntries(message.args.map((a) => [a.name, a.name === 'count' && message.plural ? count : a.kind === 'int' ? 7 : a.name.toUpperCase()]));
        const template = message.plural ? (text[rules.select(count)] ?? text.other) : text;
        const isolate = RIGHT_TO_LEFT.has(locale);
        const expected = template.replace(PLACEHOLDER, (_, name) => (typeof values[name] === 'string' && isolate ? `${FSI}${values[name]}${PDI}` : String(values[name])));
        cases.push({ key: message.key, locale, args: message.args.map((a) => values[a.name]), expected });
      }
    }
  }
  return cases;
}
