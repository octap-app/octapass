import { VaultError } from '../../errors';
import type { CustomField, ItemDetails, ItemOverview, ItemType } from '../../types';
import { parseCsv } from '../csv';
import { hostnameOf } from '../url';

export interface ParsedImport {
  items: { overview: ItemOverview; details: ItemDetails }[];
  skipped: number;
  warnings: string[];
}

const MAX_WARNINGS = 20;

export function invalidFile(reason: string): never {
  throw new VaultError('invalidImportFile', reason);
}

/** Collects items, skips and warnings; caps the warnings so a broken file doesn't flood the UI. */
export class ImportCollector {
  private readonly result: ParsedImport = { items: [], skipped: 0, warnings: [] };

  add(item: ParsedImport['items'][number]): void {
    this.result.items.push(item);
  }

  /** Without a warning when the caller reports a batch of skips in one line instead. */
  skip(warning?: string): void {
    this.result.skipped++;
    if (warning) this.warn(warning);
  }

  warn(warning: string): void {
    this.result.warnings.push(warning);
  }

  finish(): ParsedImport {
    const { warnings } = this.result;
    if (warnings.length <= MAX_WARNINGS) return this.result;
    return { ...this.result, warnings: [...warnings.slice(0, MAX_WARNINGS), `…and ${warnings.length - MAX_WARNINGS} more.`] };
  }
}

/** Trimmed text, or undefined when empty, so no empty strings get written. */
export function clean(value: unknown): string | undefined {
  if (typeof value === 'number') return String(value);
  if (typeof value !== 'string') return undefined;
  return value.trim() || undefined;
}

/** Passwords keep their spaces: leading or trailing ones can be part of the password. */
export function cleanPassword(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

export function isTrue(value: string | undefined): boolean {
  return /^(true|yes|y|1)$/i.test(value?.trim() ?? '');
}

export function splitTags(value: string | undefined): string[] {
  return (value ?? '').split(/[;,]/).flatMap((tag) => clean(tag) ?? []);
}

/** Drops undefined values and empty arrays, so optional fields are absent rather than empty. */
export function compact<T extends object>(value: T): T {
  return Object.fromEntries(
    Object.entries(value).filter(([, v]) => v !== undefined && !(Array.isArray(v) && v.length === 0)),
  ) as T;
}

export function overview(
  type: ItemType,
  fields: { title?: string; urls?: string[]; subtitle?: string; tags?: string[]; favorite?: boolean },
): ItemOverview {
  const urls = fields.urls?.flatMap((url) => clean(url) ?? []) ?? [];
  const title = clean(fields.title) ?? (urls[0] && hostnameOf(urls[0])) ?? 'Untitled';
  return compact({
    schemaVersion: 1,
    title,
    type,
    urls,
    subtitle: clean(fields.subtitle),
    tags: fields.tags?.flatMap((tag) => clean(tag) ?? []),
    favorite: fields.favorite || undefined,
  });
}

export interface LoginFields {
  title?: string;
  urls?: string[];
  username?: string;
  password?: string;
  totp?: string;
  notes?: string;
  tags?: string[];
  favorite?: boolean;
  customFields?: CustomField[];
}

/**
 * A login, or a secure note when only notes are present. Undefined when there is nothing worth keeping.
 * Bitwarden and CSV one-time code secrets may be a bare secret or an otpauth URI; both are kept as is.
 */
export function loginOrNote(fields: LoginFields): ParsedImport['items'][number] | undefined {
  const urls = fields.urls?.flatMap((url) => clean(url) ?? []) ?? [];
  const username = clean(fields.username);
  const password = cleanPassword(fields.password);
  const totp = clean(fields.totp);
  const notes = clean(fields.notes);
  const customFields = fields.customFields ?? [];
  const { title, tags, favorite } = fields;
  if (urls.length === 0 && !username && !password && !totp && customFields.length === 0) {
    if (!notes) return undefined;
    return {
      overview: overview('secureNote', { title, tags, favorite }),
      details: { schemaVersion: 1, notes },
    };
  }
  return {
    overview: overview('login', { title, urls, subtitle: username, tags, favorite }),
    details: compact({ schemaVersion: 1, username, password, totp, notes, customFields }),
  };
}

/** A CSV file whose first row is a header; `get` reads a cell by any of the given header names. */
export interface CsvTable {
  rows: { number: number; get(...names: string[]): string | undefined }[];
  has(...names: string[]): boolean;
}

/** Header names are matched case-insensitively, with spaces and dashes read as underscores. */
export function csvTable(text: string): CsvTable {
  const [header, ...rows] = parseCsv(text);
  if (!header) invalidFile('The file is empty.');
  const normalise = (name: string) => name.trim().toLowerCase().replace(/[\s-]+/g, '_');
  const columns = header.map(normalise);
  const indexOf = (names: string[]) => {
    for (const name of names) {
      const index = columns.indexOf(name);
      if (index >= 0) return index;
    }
    return -1;
  };
  return {
    has: (...names) => indexOf(names) >= 0,
    rows: rows
      .map((cells, i) => ({ cells, number: i + 2 }))
      .filter(({ cells }) => cells.some((cell) => cell.trim() !== ''))
      .map(({ cells, number }) => ({
        number,
        get: (...names) => {
          const index = indexOf(names);
          return index < 0 ? undefined : cells[index];
        },
      })),
  };
}

export function skippedRow(number: number): string {
  return `Row ${number} skipped: no URL, username, password or notes.`;
}
