import type { Catalog, Locale, Plural } from './core';

// What each app's catalog test checks about a translation of its English catalog. Not used at run
// time; it lives here so the web vault, the extension and the apps check theirs the same way.

/** Names and formats people know in Latin letters (Wi-Fi security and sign-in methods too), so a message of only these needn't change. */
const NAMES = /Octa Pass Connect|Octa Pass|Touch ID|Windows Hello|Windows|Android|Linux|Mac|Bitwarden|1Password|JSON|CSV|CXF|PIN|MM\/YY|Wi-Fi|SSH|OpenSSH|Ed25519|ECDSA|RSA|P-256|P-384|WPA|WEP|EAP-FAST|PEAP|TTLS|LEAP|PWD|MSCHAPv2|MSCHAP|CHAP|GTC|PAP|IBAN|OAuth|OpenID Connect|SAML|SCIM|JWT|PostgreSQL|SQL Server|SQLite|MongoDB|Redis|Oracle/g;
const sameEverywhere = (message: string) => /^[\s\p{P}\p{S}\d]*$/u.test(message.replace(NAMES, ''));

const placeholders = (message: string) => new Set([...message.matchAll(/\{(\w+)\}/g)].map((m) => m[1]!));
const forms = (message: string | Plural): string[] => (typeof message === 'string' ? [message] : Object.values(message).filter((v): v is string => typeof v === 'string'));
const isMessage = (node: unknown): node is string | Plural =>
  typeof node === 'string' || (typeof node === 'object' && node !== null && Object.keys(node).every((k) => ['zero', 'one', 'two', 'few', 'many', 'other'].includes(k)));

function leaves(catalog: Catalog, prefix = ''): Map<string, string | Plural> {
  const out = new Map<string, string | Plural>();
  for (const [key, node] of Object.entries(catalog)) {
    if (isMessage(node)) out.set(prefix + key, node);
    else for (const [k, v] of leaves(node as Catalog, `${prefix}${key}.`)) out.set(k, v);
  }
  return out;
}

/**
 * Everything wrong with `translation` as the `locale` version of `en`: keys missing or extra,
 * counted messages without every plural form the language uses, placeholders that don't match,
 * and messages left in English.
 */
export function translationProblems(en: Catalog, translation: Catalog, locale: Locale): string[] {
  const problems: string[] = [];
  const source = leaves(en);
  const target = leaves(translation);
  const categories = new Intl.PluralRules(locale).resolvedOptions().pluralCategories;

  for (const key of target.keys()) if (!source.has(key)) problems.push(`${key}: not in English`);
  for (const [key, english] of source) {
    const message = target.get(key);
    if (message === undefined) {
      problems.push(`${key}: missing`);
      continue;
    }
    if (typeof english !== 'string') {
      const missing = typeof message === 'string' ? categories : categories.filter((c) => !(c in message));
      if (missing.length) problems.push(`${key}: no ${missing.join(', ')} form`);
    }
    const known = new Set(forms(english).flatMap((f) => [...placeholders(f)]));
    for (const form of forms(message)) {
      for (const name of placeholders(form)) if (!known.has(name)) problems.push(`${key}: {${name}} isn’t in English`);
    }
    // The general form keeps every value but the count, which the words for 0, 1 and 2 can stand in for.
    const general = typeof message === 'string' ? message : message.other;
    for (const name of known) if (name !== 'count' && !placeholders(general).has(name)) problems.push(`${key}: {${name}} is missing`);
    const englishForms = new Set(forms(english));
    if (forms(message).some((form) => englishForms.has(form) && !sameEverywhere(form))) problems.push(`${key}: still in English`);
  }
  return problems;
}
