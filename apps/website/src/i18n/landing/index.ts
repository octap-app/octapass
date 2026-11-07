// The website's own strings, one JSON file per language, so Weblate can edit them directly.
// Docs interface strings are in src/content/i18n; docs pages are in the repo-root docs/ folder.
import ar from './ar.json';
import en from './en.json';

export type Locale = 'en' | 'ar';
export const LOCALES: readonly Locale[] = ['en', 'ar'];

const strings: Record<Locale, typeof en> = { en, ar };

export const stringsFor = (locale: Locale) => strings[locale];
export const dirFor = (locale: Locale) => (locale === 'ar' ? 'rtl' : 'ltr');

/** A site path in `locale`: `/docs/` stays as it is in English and becomes `/ar/docs/` in Arabic. */
export const localePath = (locale: Locale, path: string) => (locale === 'en' ? path : `/${locale}${path}`);
