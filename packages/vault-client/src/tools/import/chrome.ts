import { csvTable, ImportCollector, invalidFile, loginOrNote, skippedRow, type ParsedImport } from './shared';

/** Chrome, Edge and Brave: name,url,username,password[,note], sometimes with a leading origin column. */
export function parseChrome(text: string): ParsedImport {
  const table = csvTable(text);
  if (!table.has('name') || !table.has('url') || !table.has('username') || !table.has('password')) {
    invalidFile('This is not a Chrome password export: it needs the columns name, url, username and password.');
  }
  const out = new ImportCollector();
  for (const row of table.rows) {
    const item = loginOrNote({
      title: row.get('name'),
      urls: [row.get('url') ?? ''],
      username: row.get('username'),
      password: row.get('password'),
      notes: row.get('note', 'notes'),
    });
    if (item) out.add(item);
    else out.skip(skippedRow(row.number));
  }
  return out.finish();
}
