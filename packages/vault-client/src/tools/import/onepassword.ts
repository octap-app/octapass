import { csvTable, ImportCollector, invalidFile, isTrue, loginOrNote, skippedRow, splitTags, type ParsedImport } from './shared';

/** 1Password 8: Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes. */
export function parseOnePassword(text: string): ParsedImport {
  const table = csvTable(text);
  if (!table.has('title') || !table.has('password')) {
    invalidFile('This is not a 1Password CSV export: it needs at least the columns Title and Password.');
  }
  const out = new ImportCollector();
  let archived = 0;
  for (const row of table.rows) {
    if (isTrue(row.get('archived'))) {
      archived++;
      out.skip();
      continue;
    }
    const item = loginOrNote({
      title: row.get('title'),
      urls: [row.get('url') ?? ''],
      username: row.get('username'),
      password: row.get('password'),
      totp: row.get('otpauth'),
      notes: row.get('notes'),
      tags: splitTags(row.get('tags')),
      favorite: isTrue(row.get('favorite')),
    });
    if (item) out.add(item);
    else out.skip(skippedRow(row.number));
  }
  if (archived > 0) out.warn(`${archived} archived ${archived === 1 ? 'item was' : 'items were'} skipped.`);
  return out.finish();
}
