// The fields of the item types that have no screen of their own (plan 01): one table that the editor,
// the detail view and validation are built from. The core has the same table in
// `crates/octapass-core/src/item_fields.rs`; `tests/vectors/item-fields.json` there checks both.
// Labels are the catalog's `itemFields.<key>` and `itemChoices.<key>.<choice>`.

import { looksLikeAddress } from './paymentQr';
import type { CustomItemFieldKind, ItemType, TableItemType } from './types';

export type ItemFieldKind = 'text' | 'code' | 'choice' | 'date' | 'email' | 'port' | 'secret' | 'secretLong';

export interface ItemFieldSpec {
  /** The JSON key in the item's details. */
  key: string;
  kind: ItemFieldKind;
  choices: readonly string[];
}

const field = (key: string, kind: ItemFieldKind): ItemFieldSpec => ({ key, kind, choices: [] });
const choice = (key: string, choices: readonly string[]): ItemFieldSpec => ({ key, kind: 'choice', choices });

export const ITEM_FIELDS: Readonly<Record<TableItemType, readonly ItemFieldSpec[]>> = {
  bankAccount: [
    field('bankName', 'text'),
    field('accountHolder', 'text'),
    choice('accountType', ['checking', 'savings', 'business', 'other']),
    field('iban', 'code'),
    field('accountNumber', 'code'),
    field('routingNumber', 'code'),
    field('swift', 'code'),
    field('branch', 'text'),
    field('pin', 'secret'),
  ],
  apiCredential: [
    choice('credentialType', ['apiKey', 'bearerToken', 'oauth', 'jwt', 'basicAuth', 'other']),
    field('username', 'text'),
    field('key', 'secretLong'),
    field('secret', 'secretLong'),
    field('host', 'code'),
    field('expiryDate', 'date'),
  ],
  softwareLicense: [
    field('product', 'text'),
    field('version', 'text'),
    field('licenseKey', 'secretLong'),
    field('licensedTo', 'text'),
    field('email', 'email'),
    field('publisher', 'text'),
    field('orderNumber', 'code'),
    field('purchaseDate', 'date'),
    field('expiryDate', 'date'),
  ],
  idDocument: [
    choice('documentType', ['passport', 'driverLicense', 'nationalId', 'other']),
    field('number', 'secret'),
    field('fullName', 'text'),
    field('birthDate', 'date'),
    field('issuer', 'text'),
    field('country', 'text'),
    field('issueDate', 'date'),
    field('expiryDate', 'date'),
  ],
  cryptoWallet: [field('walletName', 'text'), field('seedPhrase', 'secretLong'), field('passphrase', 'secret')],
  database: [
    choice('databaseType', ['postgresql', 'mysql', 'sqlServer', 'oracle', 'mongodb', 'redis', 'sqlite', 'server', 'other']),
    field('host', 'code'),
    field('port', 'port'),
    field('database', 'code'),
    field('username', 'text'),
    field('password', 'secret'),
    field('connectionString', 'secretLong'),
  ],
};

/** A custom item's field kinds, in the order the editor offers them. */
export const CUSTOM_FIELD_KINDS: readonly CustomItemFieldKind[] = ['text', 'hidden', 'multiline', 'url', 'date', 'email', 'phone', 'totp'];

export function isTableType(type: ItemType): type is TableItemType {
  return type in ITEM_FIELDS;
}

export function isSecretKind(kind: ItemFieldKind): boolean {
  return kind === 'secret' || kind === 'secretLong';
}

/** Only these show without asking. Every other kind, a newer one included, counts as a secret. */
export function customKindIsPlain(kind: string): boolean {
  return kind === 'text' || kind === 'url' || kind === 'date' || kind === 'email' || kind === 'phone';
}

/** The field a table type's or custom item's list subtitle comes from. Never a secret: lists and search read subtitles. */
export const SUBTITLE_KEYS: Partial<Record<ItemType, string>> = {
  bankAccount: 'bankName',
  apiCredential: 'host',
  database: 'host',
  softwareLicense: 'licensedTo',
  idDocument: 'fullName',
  cryptoWallet: 'walletName',
  custom: 'templateName',
};

export function isDate(text: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (!match) return false;
  const [year, month, day] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  return days !== undefined && day >= 1 && day <= days;
}

export function isPort(text: string): boolean {
  return /^\d+$/.test(text) && Number(text) >= 1 && Number(text) <= 65535;
}

/** A SWIFT code: 4 letters, the 2-letter country, 2 location characters, and an optional branch. */
export function isSwift(text: string): boolean {
  return /^[A-Za-z]{6}[A-Za-z\d]{2}([A-Za-z\d]{3})?$/.test(text);
}

/** An IBAN without spaces, in capitals. */
export function normalizeIban(text: string): string {
  return text.replace(/\s/g, '').toUpperCase();
}

/** An IBAN's shape and its ISO 7064 mod-97 check digits (spaces and case don't matter). */
export function isIban(text: string): boolean {
  const iban = normalizeIban(text);
  if (!/^[A-Z]{2}\d{2}[A-Z\d]{11,30}$/.test(iban)) return false;
  let remainder = 0;
  for (const char of iban.slice(4) + iban.slice(0, 4)) {
    const value = parseInt(char, 36);
    remainder = (remainder * (value < 10 ? 10 : 100) + value) % 97;
  }
  return remainder === 1;
}

function isEmail(text: string): boolean {
  return /^[^\s@]+@[^\s@.]+\.[^\s@]+$/.test(text);
}

/** `[field, message]` for each value that can't be saved; `message` is under the catalog's `validation`. */
export function validateItemFields(type: string, details: Record<string, unknown>): [string, string][] {
  const text = (key: string) => (typeof details[key] === 'string' ? (details[key] as string).trim() : '');
  const errors: [string, string][] = [];
  for (const spec of ITEM_FIELDS[type as TableItemType] ?? []) {
    const value = text(spec.key);
    if (!value) continue;
    if (spec.kind === 'date' && !isDate(value)) errors.push([spec.key, 'date']);
    if (spec.kind === 'port' && !isPort(value)) errors.push([spec.key, 'port']);
    if (spec.kind === 'email' && !isEmail(value)) errors.push([spec.key, 'email']);
  }
  if (type === 'bankAccount') {
    if (text('iban') && !isIban(text('iban'))) errors.push(['iban', 'iban']);
    if (text('swift') && !isSwift(text('swift'))) errors.push(['swift', 'swift']);
  }
  if (type === 'cryptoWallet') {
    ((details.addresses ?? []) as { address?: string }[]).forEach((entry, i) => {
      if (entry.address && !looksLikeAddress(entry.address)) errors.push([`addresses.${i}`, 'walletAddress']);
    });
  }
  return errors;
}
