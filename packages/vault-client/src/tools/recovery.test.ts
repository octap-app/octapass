import type { Item, ItemOverview, LoginDetails } from '../types';
import { buildRecoveryMap, mailSitesFor, normalizePhone } from './recovery';

let nextId = 0;
function login(title: string, details: Omit<LoginDetails, 'schemaVersion'>, overview: Partial<ItemOverview> = {}): Item {
  return {
    id: `item-${++nextId}`,
    vaultId: 'v1',
    revision: 1,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    overview: { schemaVersion: 1, title, type: 'login', ...overview },
    details: { schemaVersion: 1, ...details },
  };
}

describe('buildRecoveryMap', () => {
  it('groups logins by recovery email, ignoring case, most used first', () => {
    const a = login('Bank', { username: 'ali', recovery: { email: 'Ali@Example.com' } });
    const b = login('Shop', { username: 'ali', recovery: { email: 'ali@example.com ' } });
    const c = login('Forum', { username: 'ali', recovery: { email: 'other@example.com' } });
    const { recovery } = buildRecoveryMap([c, a, b]);
    expect(recovery.map((r) => [r.value, r.logins.map((l) => l.title)])).toEqual([
      ['Ali@Example.com', ['Bank', 'Shop']],
      ['other@example.com', ['Forum']],
    ]);
  });

  it('counts the email a login signs in with, once per login', () => {
    const a = login('Shop', { username: 'ali@example.com' });
    const b = login('Bank', { username: 'ALI@example.com', recovery: { email: 'ali@example.com' } });
    const c = login('Chat', { username: 'not an email' });
    const { recovery } = buildRecoveryMap([a, b, c]);
    expect(recovery).toHaveLength(1);
    expect(recovery[0]!.logins.map((l) => l.title)).toEqual(['Shop', 'Bank']);
  });

  it('groups phones by their digits', () => {
    const a = login('Bank', { recovery: { phone: '+962 7 9000-0000' } });
    const b = login('Shop', { recovery: { phone: '+96279000 0000' } });
    const c = login('Chat', { recovery: { phone: '  ' } });
    const { recovery } = buildRecoveryMap([a, b, c]);
    expect(recovery).toEqual([expect.objectContaining({ kind: 'phone', value: '+962 7 9000-0000', logins: [expect.objectContaining({ title: 'Bank' }), expect.objectContaining({ title: 'Shop' })] })]);
  });

  it('notes where a contact is linked: an Identity or a masked email alias', () => {
    const a = login('Bank', { recovery: { email: 'me@example.com', emailSource: { kind: 'identity', itemId: 'id-1' }, phone: '+1 555', phoneSource: { kind: 'identity', itemId: 'id-1' } } });
    const b = login('Shop', { username: 'x7k2@simplelogin.com', recovery: { email: 'x7k2@simplelogin.com', emailSource: { kind: 'alias', provider: 'simplelogin', aliasId: '42' } } });
    const { recovery } = buildRecoveryMap([a, b]);
    expect(recovery.find((r) => r.value === 'me@example.com')).toMatchObject({ identityId: 'id-1' });
    expect(recovery.find((r) => r.kind === 'phone')).toMatchObject({ identityId: 'id-1' });
    expect(recovery.find((r) => r.value === 'x7k2@simplelogin.com')).toMatchObject({ aliasProvider: 'simplelogin', logins: [expect.objectContaining({ title: 'Shop' })] });
  });

  it("finds the email's own login and flags it when it has no two-step sign-in", () => {
    const gmail = login('Google', { username: 'ali@gmail.com' }, { urls: ['https://accounts.google.com'] });
    const a = login('Bank', { recovery: { email: 'ali@gmail.com' } });
    const b = login('Shop', { username: 'ali@gmail.com' }, { urls: ['https://shop.example'] });
    const { recovery, recoveryNo2fa } = buildRecoveryMap([gmail, a, b]);
    expect(recovery[0]).toMatchObject({ value: 'ali@gmail.com', account: { itemId: gmail.id, twoStep: false } });
    expect(recovery[0]!.logins.map((l) => l.title)).toEqual(['Bank', 'Shop']);
    expect(recoveryNo2fa).toEqual([{ itemId: gmail.id, vaultId: 'v1', title: 'Google', subtitle: 'ali@gmail.com', email: 'ali@gmail.com', accounts: 2 }]);
  });

  it('accepts any second step on the email account, and a username without the domain', () => {
    const withTotp = login('Proton', { username: 'ali', totp: 'JBSWY3DPEHPK3PXP' }, { urls: ['https://account.proton.me'] });
    const viaKey = login('Work mail', { username: 'sam@work.example', recovery: { twoFactorMethod: 'key' } }, { urls: ['https://mail.work.example'] });
    const a = login('Bank', { recovery: { email: 'ali@pm.me' } });
    const b = login('Shop', { recovery: { email: 'sam@work.example' } });
    const { recovery, recoveryNo2fa } = buildRecoveryMap([withTotp, viaKey, a, b]);
    expect(recovery.map((r) => r.account?.twoStep)).toEqual([true, true]);
    expect(recoveryNo2fa).toEqual([]);
  });

  it("doesn't take a login on another site for the email account, and skips emails that reset nothing else", () => {
    const elsewhere = login('Shop', { username: 'ali@gmail.com' }, { urls: ['https://shop.example'] });
    const gmailOnly = login('Google', { username: 'sam@gmail.com' }, { urls: ['https://google.com'] });
    const { recovery, recoveryNo2fa } = buildRecoveryMap([elsewhere, gmailOnly]);
    expect(recovery.map((r) => r.value)).toEqual(['ali@gmail.com']);
    expect(recovery[0]!.account).toBeUndefined();
    expect(recoveryNo2fa).toEqual([]);
  });

  it('only looks at logins', () => {
    const identity: Item = { ...login('Me', {}), overview: { schemaVersion: 1, title: 'Me', type: 'identity' }, details: { schemaVersion: 1, email: 'me@example.com' } };
    const password: Item = login('Wi-Fi', { username: 'me@example.com' }, { type: 'password' });
    expect(buildRecoveryMap([identity, password]).recovery).toEqual([]);
  });
});

describe('helpers', () => {
  it('maps mail domains to the site their account lives on', () => {
    expect(mailSitesFor('a@gmail.com')).toEqual(['google.com']);
    expect(mailSitesFor('a@hotmail.com')).toContain('live.com');
    expect(mailSitesFor('a@mail.company.co.uk')).toEqual(['company.co.uk']);
  });

  it('normalises phone numbers', () => {
    expect(normalizePhone(' +1 (555) 010-0000 ')).toBe('+15550100000');
    expect(normalizePhone('0790 000 000')).toBe('0790000000');
  });
});
