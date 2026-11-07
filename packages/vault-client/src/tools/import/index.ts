import { VaultError } from '../../errors';
import type { ImportSource } from '../../types';
import { parseBitwarden } from './bitwarden';
import { parseChrome } from './chrome';
import { parseGenericCsv } from './generic-csv';
import { parseOnePassword } from './onepassword';
import { parseOctaPass } from './octapass';
import type { ParsedImport } from './shared';

export type { ParsedImport } from './shared';

/** The importers written in TypeScript, for hosts without the core. The core has them all. */
const PARSERS: Partial<Record<ImportSource, (text: string) => ParsedImport>> = {
  chrome: parseChrome,
  'bitwarden-json': parseBitwarden,
  'onepassword-csv': parseOnePassword,
  'generic-csv': parseGenericCsv,
  octapass: parseOctaPass,
};

/**
 * Throws VaultError('invalidImportFile') when the text isn't in the chosen format at all, or the
 * source needs the core.
 */
export function parseImport(source: ImportSource, text: string): ParsedImport {
  const parse = PARSERS[source];
  if (!parse) throw new VaultError('invalidImportFile', 'This app can’t import that format here yet.');
  return parse(text);
}
