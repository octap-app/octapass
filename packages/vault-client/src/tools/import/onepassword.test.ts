import { VaultError } from '../../errors';
import { parseImport } from './index';

const ONEPASSWORD = `Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
GitHub,https://github.com,octocat,s3cret!,otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub,true,false,dev;work,"Personal account
second line"
Old bank,https://bank.example,me,oldpw,,false,true,,
Old forum,https://forum.example,me,pw2,,false,TRUE,,
Router,,,admin123,,false,false,"home, network",
,,,,,false,false,,
`;

describe('parseImport onepassword-csv', () => {
  it('imports logins with one-time codes, tags and favourites', () => {
    const result = parseImport('onepassword-csv', ONEPASSWORD);
    expect(result.items).toEqual([
      {
        overview: {
          schemaVersion: 1,
          title: 'GitHub',
          type: 'login',
          urls: ['https://github.com'],
          subtitle: 'octocat',
          tags: ['dev', 'work'],
          favorite: true,
        },
        details: {
          schemaVersion: 1,
          username: 'octocat',
          password: 's3cret!',
          totp: 'otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub',
          notes: 'Personal account\nsecond line',
        },
      },
      {
        overview: { schemaVersion: 1, title: 'Router', type: 'login', tags: ['home', 'network'] },
        details: { schemaVersion: 1, password: 'admin123' },
      },
    ]);
  });

  it('skips archived and empty rows with a warning', () => {
    const result = parseImport('onepassword-csv', ONEPASSWORD);
    expect(result.skipped).toBe(3);
    expect(result.warnings).toEqual(['Row 6 skipped: no URL, username, password or notes.', '2 archived items were skipped.']);
  });

  it('matches headers case-insensitively', () => {
    const result = parseImport('onepassword-csv', 'title,PASSWORD\nWiki,pw\n');
    expect(result.items[0]?.details).toEqual({ schemaVersion: 1, password: 'pw' });
  });

  it('rejects other files', () => {
    expect(() => parseImport('onepassword-csv', 'name,url,username,password\n')).toThrow(
      expect.objectContaining({ code: 'invalidImportFile' }),
    );
    expect(() => parseImport('onepassword-csv', '{"encrypted":false}')).toThrow(VaultError);
  });
});
