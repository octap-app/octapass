import { VaultError } from '../../errors';
import { parseImport } from './index';

const CHROME = [
  'name,url,username,password,note',
  'github.com,https://github.com/session,octocat,correct-horse,',
  'accounts.google.com,https://accounts.google.com/signin/v2/challenge/pwd,alice@gmail.com,"p@ss,word",Recovery phone ends 42',
  ',,,,',
  ',,,,just a note',
  ',,lonely-user,,',
  '',
].join('\r\n');

describe('parseImport chrome', () => {
  it('imports logins and skips empty rows', () => {
    const result = parseImport('chrome', CHROME);
    expect(result.items).toEqual([
      {
        overview: { schemaVersion: 1, title: 'github.com', type: 'login', urls: ['https://github.com/session'], subtitle: 'octocat' },
        details: { schemaVersion: 1, username: 'octocat', password: 'correct-horse' },
      },
      {
        overview: {
          schemaVersion: 1,
          title: 'accounts.google.com',
          type: 'login',
          urls: ['https://accounts.google.com/signin/v2/challenge/pwd'],
          subtitle: 'alice@gmail.com',
        },
        details: { schemaVersion: 1, username: 'alice@gmail.com', password: 'p@ss,word', notes: 'Recovery phone ends 42' },
      },
      {
        overview: { schemaVersion: 1, title: 'Untitled', type: 'secureNote' },
        details: { schemaVersion: 1, notes: 'just a note' },
      },
      {
        overview: { schemaVersion: 1, title: 'Untitled', type: 'login', subtitle: 'lonely-user' },
        details: { schemaVersion: 1, username: 'lonely-user' },
      },
    ]);
    expect(result.skipped).toBe(0);
  });

  it('accepts the variant with a leading origin column and no note', () => {
    const result = parseImport('chrome', 'origin,name,url,username,password\nhttps://x.example,,https://x.example/login,me,pw\n');
    expect(result.items[0]?.overview).toMatchObject({ title: 'x.example', urls: ['https://x.example/login'] });
  });

  it('rejects other files', () => {
    expect(() => parseImport('chrome', 'Title,Url,Username\nA,b,c')).toThrow(VaultError);
    expect(() => parseImport('chrome', '')).toThrow(VaultError);
  });
});
