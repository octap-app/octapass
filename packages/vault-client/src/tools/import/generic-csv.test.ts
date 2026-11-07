import { parseImport } from './index';

describe('parseImport generic-csv', () => {
  it('reads a LastPass export, including its secure notes', () => {
    const lastpass = [
      'url,username,password,totp,extra,name,grouping,fav',
      'https://www.amazon.com/ap/signin,shopper@example.com,hunter2,,,Amazon,"Shopping, Online",1',
      'http://sn,,,,"NoteType:Wi-Fi\nSSID:home",Home Wi-Fi,Home,0',
    ].join('\n');
    expect(parseImport('generic-csv', lastpass).items).toEqual([
      {
        overview: {
          schemaVersion: 1,
          title: 'Amazon',
          type: 'login',
          urls: ['https://www.amazon.com/ap/signin'],
          subtitle: 'shopper@example.com',
          tags: ['Shopping, Online'],
          favorite: true,
        },
        details: { schemaVersion: 1, username: 'shopper@example.com', password: 'hunter2' },
      },
      {
        overview: { schemaVersion: 1, title: 'Home Wi-Fi', type: 'secureNote', tags: ['Home'] },
        details: { schemaVersion: 1, notes: 'NoteType:Wi-Fi\nSSID:home' },
      },
    ]);
  });

  it('reads a Bitwarden CSV export', () => {
    const bitwarden =
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n' +
      'Work,1,login,Jira,,,0,https://acme.atlassian.net,dev@acme.example,pa55,JBSWY3DPEHPK3PXP\n';
    expect(parseImport('generic-csv', bitwarden).items[0]).toEqual({
      overview: {
        schemaVersion: 1,
        title: 'Jira',
        type: 'login',
        urls: ['https://acme.atlassian.net'],
        subtitle: 'dev@acme.example',
        tags: ['Work'],
        favorite: true,
      },
      details: { schemaVersion: 1, username: 'dev@acme.example', password: 'pa55', totp: 'JBSWY3DPEHPK3PXP' },
    });
  });

  it('accepts a URL-only file and titles items by hostname', () => {
    const result = parseImport('generic-csv', 'Website,Email,Tags\nhttps://www.reddit.com,a@example.com,"social;fun"\n');
    expect(result.items[0]?.overview).toEqual({
      schemaVersion: 1,
      title: 'reddit.com',
      type: 'login',
      urls: ['https://www.reddit.com'],
      subtitle: 'a@example.com',
      tags: ['social', 'fun'],
    });
  });

  it('skips unusable rows with a short warning', () => {
    const result = parseImport('generic-csv', 'title,password,notes\nOnly a title,,\nOk,pw,\n');
    expect(result.items).toHaveLength(1);
    expect(result.skipped).toBe(1);
    expect(result.warnings).toEqual(['Row 2 skipped: no URL, username, password or notes.']);
  });

  it('rejects files without a password or URL column', () => {
    expect(() => parseImport('generic-csv', 'title,notes\nA,b\n')).toThrow(expect.objectContaining({ code: 'invalidImportFile' }));
  });
});
