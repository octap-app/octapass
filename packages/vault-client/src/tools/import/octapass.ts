import type { ItemDetails, ItemOverview } from '../../types';
import { ImportCollector, invalidFile, type ParsedImport } from './shared';

/**
 * Octa Pass's plaintext JSON export, for hosts without the core (the demo vault). The core reads it
 * everywhere else, and the encrypted export too. Attachments can't come back from it: their files
 * aren't in the plaintext export.
 */
export function parseOctaPass(text: string): ParsedImport {
  let document: { format?: unknown; version?: unknown; items?: unknown };
  try {
    document = JSON.parse(text);
  } catch {
    invalidFile('This isn’t an Octa Pass export.');
  }
  if (document?.format !== 'octapass-export' || !Array.isArray(document.items)) invalidFile('This isn’t an Octa Pass export.');
  if (typeof document.version === 'number' && document.version > 1) invalidFile('This export was made by a newer version of Octa Pass.');
  const out = new ImportCollector();
  let leftOut = 0;
  document.items.forEach((entry: { overview?: ItemOverview; details?: ItemDetails }, index: number) => {
    const { overview, details } = entry ?? {};
    if (!overview || typeof overview.title !== 'string' || typeof overview.type !== 'string' || !details || typeof details !== 'object') {
      out.skip(`Item ${index + 1} skipped: it isn’t a valid Octa Pass item.`);
      return;
    }
    const { attachments, ...rest } = details as ItemDetails & { attachments?: unknown[] };
    leftOut += attachments?.length ?? 0;
    out.add({ overview, details: rest as ItemDetails });
  });
  if (leftOut > 0) out.warn(`${leftOut} attached ${leftOut === 1 ? 'file' : 'files'} aren't in this export: only the encrypted export includes them.`);
  return out.finish();
}
