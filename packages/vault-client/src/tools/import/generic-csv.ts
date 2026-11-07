import { clean, csvTable, ImportCollector, invalidFile, isTrue, loginOrNote, skippedRow, splitTags, type ParsedImport } from './shared';

// Header names used by common exporters (LastPass, Bitwarden CSV, KeePass, Dashlane, browsers), most specific first.
const COLUMNS = {
  title: ['title', 'name'],
  url: ['url', 'website', 'uri', 'login_uri'],
  username: ['username', 'login_username', 'user', 'login', 'email'],
  password: ['password', 'login_password'],
  totp: ['totp', 'login_totp', 'otp', 'otpauth', '2fa'],
  notes: ['notes', 'note', 'extra', 'comments'],
  tags: ['tags'],
  folder: ['folder', 'grouping'],
  favorite: ['favorite', 'fav'],
};

// LastPass exports secure notes as rows whose URL is this placeholder.
const LASTPASS_NOTE_URL = 'http://sn';

export function parseGenericCsv(text: string): ParsedImport {
  const table = csvTable(text);
  if (!table.has(...COLUMNS.password) && !table.has(...COLUMNS.url)) {
    invalidFile('No password or URL column found. Name the columns in the first row, for example title, url, username, password.');
  }
  const out = new ImportCollector();
  for (const row of table.rows) {
    const url = row.get(...COLUMNS.url);
    // A folder is one tag even if its name has commas; a tags column lists several.
    const folder = clean(row.get(...COLUMNS.folder));
    const item = loginOrNote({
      title: row.get(...COLUMNS.title),
      urls: url?.trim() === LASTPASS_NOTE_URL ? [] : [url ?? ''],
      username: row.get(...COLUMNS.username),
      password: row.get(...COLUMNS.password),
      totp: row.get(...COLUMNS.totp),
      notes: row.get(...COLUMNS.notes),
      tags: [...splitTags(row.get(...COLUMNS.tags)), ...(folder ? [folder] : [])],
      favorite: isTrue(row.get(...COLUMNS.favorite)),
    });
    if (item) out.add(item);
    else out.skip(skippedRow(row.number));
  }
  return out.finish();
}
