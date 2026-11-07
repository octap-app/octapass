// The language machinery every catalog shares: which language is showing, plural forms, number and
// date formats. No messages here, so a content script can use it without the web vault's catalog.
//
// Messages are plain strings with {placeholders}; counted messages use Intl.PluralRules categories
// ({ zero, one, two, few, many, other }), so each language has the forms it needs: English uses one
// and other, Arabic all six. Adding a language means adding a catalog with the same keys to every
// `translator`, and listing it in LOCALES.

export type Plural = { other: string } & Partial<Record<Intl.LDMLPluralRule, string>>;
export type Catalog = { [key: string]: string | Plural | Catalog };

/** A message is a string, or an object whose keys are all plural forms (`{ web, …, other }` is a group). */
type IsMessage<V> = V extends string ? true : Exclude<keyof V, Intl.LDMLPluralRule> extends never ? true : false;

/** Another language's catalog for `T`: the same keys, each message a string or plural forms. */
export type Translation<T> = { [K in keyof T]: IsMessage<T[K]> extends true ? string | Plural : Translation<T[K]> };

export type Leaves<T, Prefix extends string = ''> = {
  [K in keyof T & string]: IsMessage<T[K]> extends true ? `${Prefix}${K}` : Leaves<T[K], `${Prefix}${K}.`>;
}[keyof T & string];

export type MessageVars = Record<string, string | number>;

export type Locale = 'en' | 'ar';
export type LanguagePreference = 'system' | Locale;
export const LOCALES: readonly Locale[] = ['en', 'ar'];

// Arabic screens use Western digits (0–9): passwords, codes and Secret Keys already do, and two
// digit sets on one screen are harder to read.
const INTL_LOCALE: Record<Locale, string> = { en: 'en', ar: 'ar-u-nu-latn' };
const RIGHT_TO_LEFT: ReadonlySet<Locale> = new Set(['ar']);

const BYTE_UNITS = ['byte', 'kilobyte', 'megabyte', 'gigabyte', 'terabyte'] as const;

function formatsFor(locale: Locale) {
  const tag = INTL_LOCALE[locale];
  return {
    plurals: new Intl.PluralRules(tag),
    numbers: new Intl.NumberFormat(tag),
    short: new Intl.DateTimeFormat(tag, { day: 'numeric', month: 'short', year: 'numeric' }),
    long: new Intl.DateTimeFormat(tag, { day: 'numeric', month: 'long', year: 'numeric', hour: 'numeric', minute: '2-digit' }),
    relative: new Intl.RelativeTimeFormat(tag, { numeric: 'auto' }),
    bytes: BYTE_UNITS.map(
      (unit) => new Intl.NumberFormat(tag, { style: 'unit', unit, unitDisplay: unit === 'byte' ? 'long' : 'short', maximumFractionDigits: 1 }),
    ),
  };
}

let current: Locale = 'en';
let formats = formatsFor(current);

export function getLocale(): Locale {
  return current;
}

export function direction(locale: Locale = current): 'ltr' | 'rtl' {
  return RIGHT_TO_LEFT.has(locale) ? 'rtl' : 'ltr';
}

/** The language to show: the one chosen in Settings, or the first of the system's languages we have. */
export function resolveLocale(preference: LanguagePreference = 'system', languages: readonly string[] = systemLanguages()): Locale {
  if (preference !== 'system') return preference;
  for (const tag of languages) {
    const base = tag.toLowerCase().split('-')[0] as Locale;
    if (LOCALES.includes(base)) return base;
  }
  return 'en';
}

function systemLanguages(): readonly string[] {
  if (typeof navigator === 'undefined') return [];
  return navigator.languages?.length ? navigator.languages : [navigator.language];
}

/** Switches every catalog and formatter in this script. */
export function setLocale(locale: Locale): void {
  current = locale;
  formats = formatsFor(locale);
}

/** `setLocale`, and `lang` and `dir` on the page, for a page that is ours. */
export function applyLocale(locale: Locale): void {
  setLocale(locale);
  document.documentElement.lang = locale;
  document.documentElement.dir = direction(locale);
}

function lookup(catalog: Catalog, key: string): string | Plural | undefined {
  let node: string | Plural | Catalog | undefined = catalog;
  for (const part of key.split('.')) node = typeof node === 'object' ? (node as Catalog)[part] : undefined;
  if (typeof node === 'string' || (node && typeof node.other === 'string')) return node as string | Plural;
  return undefined;
}

// Inserted text (a name, an email, a website) is isolated from the sentence around it, so a Latin
// email inside an Arabic sentence keeps its own order and doesn't pull the punctuation with it.
const FSI = '⁨';
const PDI = '⁩';

export function format(message: string | Plural, vars: MessageVars = {}): string {
  const template = typeof message === 'string' ? message : (message[formats.plurals.select(Number(vars.count ?? 0))] ?? message.other);
  const isolate = direction() === 'rtl';
  return template.replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = vars[name];
    if (value === undefined) return match;
    if (typeof value === 'number') return formats.numbers.format(value);
    return isolate ? `${FSI}${value}${PDI}` : value;
  });
}

/**
 * A `t` for one set of catalogs. Each app's own strings use one too, so they follow the same
 * language as the web vault's screens. A key missing from a translation falls back to English.
 */
export function translator<T extends Catalog>(catalogs: { en: T } & Record<Exclude<Locale, 'en'>, Translation<T>>) {
  return (key: Leaves<T>, vars: MessageVars = {}): string => {
    const message = lookup(catalogs[current] as Catalog, key) ?? lookup(catalogs.en, key);
    if (message === undefined) throw new Error(`Missing message: ${key}`);
    return format(message, vars);
  };
}

export function formatNumber(value: number): string {
  return formats.numbers.format(value);
}

export function formatDate(iso: string, style: 'short' | 'long' = 'short'): string {
  return formats[style].format(new Date(iso));
}

/** "820 bytes", "1.4 MB", "1 GB": binary multiples, so limits like 100 MiB read as round numbers. */
export function formatBytes(bytes: number): string {
  let unit = 0;
  let value = bytes;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  return formats.bytes[unit]!.format(value);
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 365 * 86_400_000],
  ['month', 30 * 86_400_000],
  ['week', 7 * 86_400_000],
  ['day', 86_400_000],
  ['hour', 3_600_000],
  ['minute', 60_000],
];

/** "5 minutes ago", "yesterday", "in 3 days": the largest unit that fits, for times near now. */
export function formatRelative(iso: string, now: number = Date.now()): string {
  const diff = Date.parse(iso) - now;
  for (const [unit, ms] of UNITS) {
    if (Math.abs(diff) >= ms) return formats.relative.format(Math.round(diff / ms), unit);
  }
  return formats.relative.format(0, 'minute');
}
