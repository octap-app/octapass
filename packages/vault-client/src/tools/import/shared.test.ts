import { isVaultError } from '../../errors';
import { compact, csvTable, ImportCollector, loginOrNote, overview, splitTags } from './shared';

describe('loginOrNote', () => {
  it('builds a trimmed login without empty fields', () => {
    expect(loginOrNote({ title: ' GitHub ', urls: [' https://github.com ', ''], username: ' octocat ', password: ' pw ', notes: '  ' })).toEqual({
      overview: { schemaVersion: 1, title: 'GitHub', type: 'login', urls: ['https://github.com'], subtitle: 'octocat' },
      details: { schemaVersion: 1, username: 'octocat', password: ' pw ' },
    });
  });

  it('falls back to the hostname, then Untitled, for the title', () => {
    expect(loginOrNote({ urls: ['https://www.example.com/login'], password: 'x' })?.overview.title).toBe('example.com');
    expect(loginOrNote({ password: 'x' })?.overview.title).toBe('Untitled');
  });

  it('makes a secure note when only notes are present', () => {
    expect(loginOrNote({ title: 'Wi-Fi', notes: 'key: abc', tags: ['home'], favorite: true })).toEqual({
      overview: { schemaVersion: 1, title: 'Wi-Fi', type: 'secureNote', tags: ['home'], favorite: true },
      details: { schemaVersion: 1, notes: 'key: abc' },
    });
  });

  it('returns undefined when nothing is worth keeping', () => {
    expect(loginOrNote({ title: 'Lonely title', urls: [''] })).toBeUndefined();
  });
});

describe('helpers', () => {
  it('splits tags on commas and semicolons', () => {
    expect(splitTags(' work; dev ,, home ')).toEqual(['work', 'dev', 'home']);
    expect(splitTags(undefined)).toEqual([]);
  });

  it('compacts away undefined values and empty arrays', () => {
    expect(compact({ a: 1, b: undefined, c: [], d: [1], e: '' })).toEqual({ a: 1, d: [1], e: '' });
    expect(Object.keys(compact({ a: undefined }))).toEqual([]);
  });

  it('keeps favorite only when true', () => {
    expect(overview('login', { favorite: false })).toEqual({ schemaVersion: 1, title: 'Untitled', type: 'login' });
  });

  it('caps the warnings', () => {
    const out = new ImportCollector();
    for (let i = 1; i <= 25; i++) out.skip(`Row ${i} skipped.`);
    const result = out.finish();
    expect(result.skipped).toBe(25);
    expect(result.warnings).toHaveLength(21);
    expect(result.warnings.at(-1)).toBe('…and 5 more.');
  });

  it('reads CSV cells by normalised header names and numbers rows like a spreadsheet', () => {
    const table = csvTable('Login URI,User-Name\r\nhttps://a.example,alice\r\n,\r\nhttps://b.example,bob\r\n');
    expect(table.has('login_uri')).toBe(true);
    expect(table.rows.map((r) => [r.number, r.get('user_name'), r.get('missing', 'login_uri')])).toEqual([
      [2, 'alice', 'https://a.example'],
      [4, 'bob', 'https://b.example'],
    ]);
  });

  it('rejects an empty CSV file', () => {
    try {
      csvTable('﻿\r\n');
      expect.unreachable();
    } catch (error) {
      expect(isVaultError(error, 'invalidImportFile')).toBe(true);
    }
  });
});
