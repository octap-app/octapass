import type { CardDetails, Item, ItemOverview, LoginDetails, StrengthEstimate } from '../types';
import { buildHealthReport, emailBreachAddresses, parseExpiry, withoutWarnings } from './health';

let nextId = 0;
function login(title: string, details: Omit<LoginDetails, 'schemaVersion'>, overview: Partial<ItemOverview> = {}): Item {
  const id = `item-${++nextId}`;
  return {
    id,
    vaultId: 'v1',
    revision: 1,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    overview: { schemaVersion: 1, title, type: 'login', ...overview },
    details: { schemaVersion: 1, ...details },
  };
}

// Password text decides the fake results: "weakN" scores N, "pwnedN" was breached N times.
const deps = {
  estimateStrength: (p: string): StrengthEstimate => {
    const weak = /^weak(\d)/.exec(p);
    return { score: weak ? (Number(weak[1]) as StrengthEstimate['score']) : 4, guessesLog10: 12 };
  },
  checkBreached: vi.fn(async (p: string) => Number(/pwned(\d+)/.exec(p)?.[1] ?? 0)),
};
const NOW = new Date('2026-10-23T12:00:00.000Z');

beforeEach(() => deps.checkBreached.mockClear());

describe('buildHealthReport', () => {
  it('scores an empty vault 100', async () => {
    expect(await buildHealthReport([], deps, NOW)).toEqual({
      score: 100,
      checked: 0,
      weak: [],
      reused: [],
      breached: [],
      breachCheckCompleted: true,
      missing2fa: [],
      recovery: [],
      recoveryNo2fa: [],
      recoveryBreached: [],
      old: [],
      passkeyAvailable: [],
      insecureUrls: [],
      expiring: [],
      lowBackupCodes: [],
      emailBreaches: { enabled: false, recoveryEmails: false, found: [] },
      dismissed: [],
      generatedAt: NOW.toISOString(),
    });
  });

  it('only checks logins and passwords that have a password', async () => {
    const items: Item[] = [
      login('A', { password: 'strong-a' }),
      login('B', { username: 'b' }),
      login('C', { password: '' }),
      login('D', { password: 'strong-d' }, { type: 'password' }),
      { ...login('Note', {}), overview: { schemaVersion: 1, title: 'Note', type: 'secureNote' }, details: { schemaVersion: 1, notes: 'x' } },
    ];
    const report = await buildHealthReport(items, deps, NOW);
    expect(report.checked).toBe(2);
    expect(report.score).toBe(100);
  });

  it('lists weak passwords with their score and the subtitle fallback', async () => {
    const a = login('A', { username: 'alice', password: 'weak1-a' });
    const b = login('B', { username: 'bob', password: 'weak2-b' }, { subtitle: 'Work' });
    const c = login('C', { password: 'weak3-c' });
    const report = await buildHealthReport([a, b, c], deps, NOW);
    expect(report.weak).toEqual([
      { itemId: a.id, vaultId: 'v1', title: 'A', subtitle: 'alice', score: 1, warning: `weak:${a.id}:${Date.parse(a.createdAt) / 1000}` },
      { itemId: b.id, vaultId: 'v1', title: 'B', subtitle: 'Work', score: 2, warning: `weak:${b.id}:${Date.parse(b.createdAt) / 1000}` },
    ]);
    // (0.3 + 0.6 + 1) / 3
    expect(report.score).toBe(63);
  });

  it('groups reused passwords, largest group first', async () => {
    const items = [
      login('A', { password: 'same-1' }),
      login('B', { password: 'same-2' }),
      login('C', { password: 'same-2' }),
      login('D', { password: 'same-1' }),
      login('E', { password: 'same-2' }),
      login('F', { password: 'unique' }),
    ];
    const report = await buildHealthReport(items, deps, NOW);
    expect(report.reused.map((group) => group.map((e) => e.title))).toEqual([
      ['B', 'C', 'E'],
      ['A', 'D'],
    ]);
    // Five reused at 0.5, one healthy: 3.5 / 6
    expect(report.score).toBe(58);
  });

  it('checks each unique password once and lists breached items', async () => {
    const items = [
      login('A', { password: 'pwned12' }),
      login('B', { password: 'pwned12' }),
      login('C', { password: 'fine' }),
    ];
    const report = await buildHealthReport(items, deps, NOW);
    expect(deps.checkBreached).toHaveBeenCalledTimes(2);
    expect(report.breachCheckCompleted).toBe(true);
    expect(report.breached.map((e) => [e.title, e.count])).toEqual([
      ['A', 12],
      ['B', 12],
    ]);
    expect(report.score).toBe(33);
  });

  it('runs at most four breach checks at a time', async () => {
    let running = 0;
    let peak = 0;
    const checkBreached = async () => {
      peak = Math.max(peak, ++running);
      await new Promise((resolve) => setTimeout(resolve, 1));
      running--;
      return 0;
    };
    const items = Array.from({ length: 10 }, (_, i) => login(`I${i}`, { password: `p${i}` }));
    await buildHealthReport(items, { ...deps, checkBreached }, NOW);
    expect(peak).toBe(4);
  });

  it('still reports when the breach check fails', async () => {
    const items = [login('A', { password: 'pwned3' }), login('B', { password: 'weak0' })];
    const report = await buildHealthReport(
      items,
      { ...deps, checkBreached: async (p) => (p === 'weak0' ? Promise.reject(new Error('offline')) : 3) },
      NOW,
    );
    expect(report.breachCheckCompleted).toBe(false);
    expect(report.breached).toEqual([]);
    expect(report.weak).toHaveLength(1);
    expect(report.score).toBe(65);
  });

  it('flags logins for two-factor sites that have no second factor saved', async () => {
    const plain = login('GitHub', { password: 'x1' }, { urls: ['https://github.com/login'] });
    const subdomain = login('AWS', {}, { urls: ['example.org', 'https://aws.amazon.com/console'] });
    const withTotp = login('GitLab', { password: 'x2', totp: 'JBSWY3DPEHPK3PXP' }, { urls: ['gitlab.com'] });
    const withPasskey = login('Google', { password: 'x3', passkeys: [{ rpId: 'google.com', userName: 'a', createdAt: '2026-01-01' }] }, { urls: ['google.com'] });
    const viaSms = login('PayPal', { password: 'x4', recovery: { twoFactorMethod: 'sms' } }, { urls: ['paypal.com'] });
    const none = login('Stripe', { password: 'x5', recovery: { twoFactorMethod: 'none' } }, { urls: ['dashboard.stripe.com'] });
    const unknownSite = login('Blog', { password: 'x6' }, { urls: ['https://my-blog.example'] });

    const report = await buildHealthReport([plain, subdomain, withTotp, withPasskey, viaSms, none, unknownSite], deps, NOW);
    expect(report.missing2fa.map((e) => e.title)).toEqual(['GitHub', 'AWS', 'Stripe']);
    // GitHub and Stripe are checked items at 0.85; the other four are healthy: 5.7 / 6
    expect(report.score).toBe(95);
  });

  it('multiplies the penalties together', async () => {
    const items = [
      login('A', { password: 'weak2-shared' }, { urls: ['github.com'] }),
      login('B', { password: 'weak2-shared' }),
    ];
    const report = await buildHealthReport(items, deps, NOW);
    // A: 0.6 × 0.5 × 0.85 = 0.255; B: 0.6 × 0.5 = 0.3
    expect(report.score).toBe(28);
  });
});

describe('the checks added for 1.0', () => {
  const card = (title: string, expiry: string): Item => ({
    ...login(title, {}),
    overview: { schemaVersion: 1, title, type: 'card' },
    details: { schemaVersion: 1, expiry } as CardDetails,
  });
  const fresh = (title: string, details: Omit<LoginDetails, 'schemaVersion'>, overview: Partial<ItemOverview> = {}) => ({
    ...login(title, details, overview),
    createdAt: '2026-09-01T00:00:00.000Z',
  });

  it('lists http:// logins, except on this device and the local network', async () => {
    const shop = fresh('Shop', { password: 'a1' }, { urls: ['http://shop.example/login'] });
    const router = fresh('Router', { password: 'a2' }, { urls: ['http://192.168.1.1'] });
    const nas = fresh('NAS', { password: 'a3' }, { urls: ['http://nas.local:5000'] });
    const dev = fresh('Dev', { password: 'a4' }, { urls: ['http://localhost:3000'] });
    const safe = fresh('Safe', { password: 'a5' }, { urls: ['https://safe.example'] });
    const bare = fresh('Bare', { password: 'a6' }, { urls: ['bare.example'] });
    const second = fresh('Second', { password: 'a7' }, { urls: ['https://two.example', 'http://two.example/old'] });
    const report = await buildHealthReport([shop, router, nas, dev, safe, bare, second], deps, NOW);
    expect(report.insecureUrls.map((e) => [e.title, e.url])).toEqual([
      ['Shop', 'http://shop.example/login'],
      ['Second', 'http://two.example/old'],
    ]);
    // Two of seven at 0.85.
    expect(report.score).toBe(96);
  });

  it('reads the expiry formats and rejects nonsense', () => {
    expect(parseExpiry('02/28')).toBe('2028-02-29');
    expect(parseExpiry('2/2027')).toBe('2027-02-28');
    expect(parseExpiry('12 / 26')).toBe('2026-12-31');
    expect(parseExpiry('2027-04')).toBe('2027-04-30');
    expect(parseExpiry('2027-04-15')).toBe('2027-04-15');
    expect(parseExpiry('2027-04-15T00:00:00Z')).toBe('2027-04-15');
    for (const bad of ['', '13/27', '00/27', '2027-13', '2027-02-30', 'soon', undefined]) expect(parseExpiry(bad)).toBeUndefined();
  });

  it('lists what expires within 60 days, the soonest first', async () => {
    const idDocument = (title: string, expiryDate: string): Item => ({ ...login(title, {}), overview: { schemaVersion: 1, title, type: 'idDocument' as never }, details: { schemaVersion: 1, expiryDate } as never });
    const passport = idDocument('Passport', '2026-11-05');
    const nationalId = idDocument('ID', '2026-12-22');
    const typed = (type: string, title: string, details: object): Item => ({ ...login(title, {}), overview: { schemaVersion: 1, title, type: type as never }, details: { schemaVersion: 1, ...details } as never });
    const apiKey = typed('apiCredential', 'API key', { expiryDate: '2026-10-30' });
    const licence = typed('softwareLicense', 'Editor', { expiryDate: '2026-11-20' });
    const lateLicence = typed('softwareLicense', 'IDE', { expiryDate: '2027-06-01' });
    const forever = typed('softwareLicense', 'Perpetual', {});
    // A date on a type without an expiry isn't one.
    const note = typed('secureNote', 'Note', { expiryDate: '2026-10-30' });
    const items = [card('Later', '01/27'), card('Soon', '10/26'), card('Expired', '09/26'), card('Blank', ''), card('Far', '12/30'), passport, nationalId, apiKey, licence, lateLicence, forever, note];
    const report = await buildHealthReport(items, deps, NOW);
    expect(report.expiring.map((e) => [e.title, e.expiresOn, e.daysLeft])).toEqual([
      ['Expired', '2026-09-30', -23],
      ['API key', '2026-10-30', 7],
      ['Soon', '2026-10-31', 8],
      ['Passport', '2026-11-05', 13],
      ['Editor', '2026-11-20', 28],
      ['ID', '2026-12-22', 60],
    ]);
    expect(report.score).toBe(100);
  });

  it('flags sites that take passkeys, unless one is saved', async () => {
    const plain = fresh('GitHub', { password: 'b1' }, { urls: ['https://github.com/login'] });
    const saved = fresh('PayPal', { password: 'b2', passkeys: [{ rpId: 'paypal.com', userName: 'a', createdAt: '2026-01-01' }] }, { urls: ['paypal.com'] });
    const unknown = fresh('Blog', { password: 'b3' }, { urls: ['https://my-blog.example'] });
    const report = await buildHealthReport([plain, saved, unknown], deps, NOW);
    expect(report.passkeyAvailable.map((e) => e.title)).toEqual(['GitHub']);
  });

  it('warns at two unused backup codes or fewer', async () => {
    const codes = (unused: number, used = 3) => [...Array.from({ length: unused }, (_, i) => ({ code: `u${i}`, used: false })), ...Array.from({ length: used }, (_, i) => ({ code: `x${i}`, used: true }))];
    const items = [
      fresh('Three', { recovery: { backupCodes: codes(3) } }),
      fresh('Two', { recovery: { backupCodes: codes(2) } }),
      fresh('None left', { recovery: { backupCodes: codes(0) } }),
      fresh('No codes', { recovery: { backupCodes: [] } }),
    ];
    const report = await buildHealthReport(items, deps, NOW);
    expect(report.lowBackupCodes.map((e) => [e.title, e.unused])).toEqual([
      ['Two', 2],
      ['None left', 0],
    ]);
  });

  it('lists passwords unchanged for a year, the oldest first, and leaves the score alone', async () => {
    const twoYears = login('Two years', { password: 'c1' });
    twoYears.createdAt = '2024-10-23T12:00:00.000Z';
    const oneYear = login('Exactly a year', { password: 'c2' });
    oneYear.createdAt = '2025-10-23T12:00:00.000Z';
    const edited = login('Edited yesterday', { password: 'c3' });
    edited.createdAt = '2024-01-01T00:00:00.000Z';
    edited.updatedAt = '2026-10-22T00:00:00.000Z';
    const changed = login('Changed', { password: 'c4', passwordHistory: [{ password: 'older', changedAt: '2026-08-01T00:00:00.000Z' }] });
    changed.createdAt = '2020-01-01T00:00:00.000Z';
    const imported = login('Imported', { password: 'c5' }, { createdAt: '2022-01-01T00:00:00.000Z' });
    const report = await buildHealthReport([oneYear, twoYears, edited, changed, imported], deps, NOW);
    expect(report.old.map((e) => e.title)).toEqual(['Imported', 'Edited yesterday', 'Two years', 'Exactly a year']);
    expect(report.old[3]!.ageDays).toBe(365);
    expect(report.score).toBe(100);
  });

  it('offers the site’s change-password page on warnings a new password fixes', async () => {
    const a = fresh('A', { password: 'weak1-x' }, { urls: ['http://www.shop.example/login?x=1'] });
    const b = fresh('B', { password: 'weak1-y' });
    const report = await buildHealthReport([a, b], deps, NOW);
    expect(report.weak[0]!.changePasswordUrl).toBe('https://www.shop.example/.well-known/change-password');
    expect(report.weak[1]!.changePasswordUrl).toBeUndefined();
  });
});

describe('dismissing warnings', () => {
  const settings = (dismissed: string[]) => ({ schemaVersion: 1 as const, dismissed });

  it('leaves a dismissed warning out of the list and the score, and names it', async () => {
    const a = login('A', { password: 'weak0-a' });
    const b = login('B', { password: 'strong' });
    const before = await buildHealthReport([a, b], deps, NOW);
    const report = await buildHealthReport([a, b], { ...deps, settings: settings([before.weak[0]!.warning!]) }, NOW);
    expect(report.weak).toEqual([]);
    expect(report.score).toBe(100);
    expect(report.dismissed).toMatchObject([{ itemId: a.id, check: 'weak' }]);
  });

  it('warns again once the password changes', async () => {
    const a = login('A', { password: 'weak0-a' });
    const { weak } = await buildHealthReport([a], deps, NOW);
    const changed: Item = { ...a, details: { schemaVersion: 1, password: 'weak0-b', passwordHistory: [{ password: 'weak0-a', changedAt: '2026-10-22T00:00:00.000Z' }] } };
    const report = await buildHealthReport([changed], { ...deps, settings: settings([weak[0]!.warning!]) }, NOW);
    expect(report.weak).toHaveLength(1);
    expect(report.dismissed).toEqual([]);
  });

  it('dismisses a reused group as a whole, and a new member brings it back whole', async () => {
    const a = login('A', { password: 'same' });
    const b = login('B', { password: 'same' });
    const first = await buildHealthReport([a, b], deps, NOW);
    const keys = first.reused[0]!.map((e) => e.warning!);
    const quiet = await buildHealthReport([a, b], { ...deps, settings: settings(keys) }, NOW);
    expect(quiet.reused).toEqual([]);
    expect(quiet.score).toBe(100);
    expect(quiet.dismissed.map((e) => e.check)).toEqual(['reused', 'reused']);

    const c = login('C', { password: 'same' });
    const back = await buildHealthReport([a, b, c], { ...deps, settings: settings(keys) }, NOW);
    expect(back.reused[0]!.map((e) => e.title)).toEqual(['A', 'B', 'C']);
    expect(back.dismissed).toEqual([]);
  });

  it('warns again about a new expiry date or fewer backup codes', async () => {
    const base = login('Card', {});
    const cardItem = (expiry: string): Item => ({ ...base, overview: { schemaVersion: 1, title: 'Card', type: 'card' }, details: { schemaVersion: 1, expiry } as CardDetails });
    const { expiring } = await buildHealthReport([cardItem('10/26')], deps, NOW);
    const same = await buildHealthReport([cardItem('10/26')], { ...deps, settings: settings([expiring[0]!.warning!]) }, NOW);
    expect(same.expiring).toEqual([]);
    const renewed = await buildHealthReport([cardItem('11/26')], { ...deps, settings: settings([expiring[0]!.warning!]) }, NOW);
    expect(renewed.expiring).toHaveLength(1);

    const coded = (unused: number) => login('Codes', { recovery: { backupCodes: Array.from({ length: unused }, (_, i) => ({ code: `c${i}`, used: false })) } });
    const two = coded(2);
    const { lowBackupCodes } = await buildHealthReport([two], deps, NOW);
    const oneLeft: Item = { ...coded(1), id: two.id };
    const fewer = await buildHealthReport([oneLeft], { ...deps, settings: settings([lowBackupCodes[0]!.warning!]) }, NOW);
    expect(fewer.lowBackupCodes).toHaveLength(1);
  });

  it('hides warnings at once with withoutWarnings', async () => {
    const a = login('A', { password: 'weak0-a' });
    const report = await buildHealthReport([a], deps, NOW);
    expect(withoutWarnings(report, new Set([report.weak[0]!.warning!])).weak).toEqual([]);
  });
});

describe('email breach results', () => {
  const breach = { name: 'Adobe', title: 'Adobe', domain: 'adobe.com', breachDate: '2013-10-04', dataClasses: ['Email addresses'] };

  it('shows nothing while alerts are off, even with old results', async () => {
    const settings = { schemaVersion: 1 as const, emailBreachAlerts: { enabled: false, found: [{ address: 'a@b.example', breaches: [breach] }] } };
    const report = await buildHealthReport([], { ...deps, settings }, NOW);
    expect(report.emailBreaches).toEqual({ enabled: false, recoveryEmails: false, found: [] });
  });

  it('lists findings, marks what is new, and dismisses per address and breach', async () => {
    const other = { ...breach, name: 'Canva', title: 'Canva' };
    const settings = {
      schemaVersion: 1 as const,
      dismissed: [] as string[],
      emailBreachAlerts: {
        enabled: true,
        checkedAt: '2026-10-23T00:00:00.000Z',
        found: [{ address: 'A@b.example', breaches: [breach, other] }],
        previous: ['emailBreach:a@b.example:Adobe'],
      },
    };
    const report = await buildHealthReport([], { ...deps, settings }, NOW);
    expect(report.emailBreaches.found.map((f) => [f.name, f.isNew])).toEqual([
      ['Adobe', false],
      ['Canva', true],
    ]);
    settings.dismissed = [report.emailBreaches.found[0]!.warning];
    const after = await buildHealthReport([], { ...deps, settings }, NOW);
    expect(after.emailBreaches.found.map((f) => f.name)).toEqual(['Canva']);
    expect(after.dismissed).toMatchObject([{ check: 'emailBreach', title: 'Adobe', subtitle: 'A@b.example' }]);
  });

  it('checks the account email and aliases once each, not other emails', () => {
    const contact = (value: string, aliasProvider?: 'addy') => ({ kind: 'email' as const, value, logins: [], ...(aliasProvider ? { aliasProvider } : {}) });
    const recovery = [contact('me@b.example', 'addy'), contact('alias@relay.example', 'addy'), contact('colleague@work.example'), { kind: 'phone' as const, value: '+1555', logins: [] }];
    expect(emailBreachAddresses('Me@b.example', { recovery })).toEqual(['Me@b.example', 'alias@relay.example']);
    expect(emailBreachAddresses(undefined, { recovery: [] })).toEqual([]);
  });
});
