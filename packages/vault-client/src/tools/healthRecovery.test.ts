// "Recovery email breached" (plan 06): recovery emails found by email breach alerts, and the second
// opt-in that sends the addresses that are neither the account email nor an alias.
import type { EmailBreach, Item, LoginDetails, StrengthEstimate, VaultService } from '../types';
import { buildHealthReport, emailBreachAddresses, withoutWarnings } from './health';
import { createHealthSettings, warningKey, type HealthSettingsDetails } from './healthSettings';

let nextId = 0;
function login(title: string, url: string, details: Omit<LoginDetails, 'schemaVersion'>): Item {
  return {
    id: `item-${++nextId}`,
    vaultId: 'v1',
    revision: 1,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    overview: { schemaVersion: 1, title, type: 'login', urls: [url] },
    details: { schemaVersion: 1, ...details },
  };
}

const deps = { estimateStrength: (): StrengthEstimate => ({ score: 4, guessesLog10: 12 }), checkBreached: async () => 0 };
const breach = (name: string): EmailBreach => ({ name, title: name, breachDate: '2024-01-01', dataClasses: ['Passwords'] });
const NOW = new Date('2026-11-08T12:00:00.000Z');

function vaultOf(items: Item[]) {
  const gmail = login('Gmail', 'https://mail.google.com', { username: 'me@gmail.com', password: 'p1' });
  const shop = login('Shop', 'https://shop.example', { username: 'shopper', password: 'p2', recovery: { email: 'me@gmail.com' } });
  const bank = login('Bank', 'https://bank.example', { username: 'banker', password: 'p3', recovery: { email: 'Me@Gmail.com' } });
  const forum = login('Forum', 'https://forum.example', { username: 'old@isp.example', password: 'p4' });
  const relay = login('Relay', 'https://relay.example', {
    username: 'me',
    password: 'p5',
    recovery: { email: 'alias@relay.example', emailSource: { kind: 'alias', provider: 'simplelogin', aliasId: '1' } },
  });
  return { gmail, shop, bank, forum, relay, items: [gmail, shop, bank, forum, relay, ...items] };
}

const alerts = (found: { address: string; breaches: EmailBreach[] }[], extra: Partial<NonNullable<HealthSettingsDetails['emailBreachAlerts']>> = {}): HealthSettingsDetails => ({
  schemaVersion: 1,
  emailBreachAlerts: { enabled: true, checkedAt: NOW.toISOString(), found, ...extra },
});

describe('recovery email breached', () => {
  it('lists each breached recovery email with the logins it can reset, opening its own login', async () => {
    const { items, gmail } = vaultOf([]);
    const settings = alerts([
      { address: 'me@gmail.com', breaches: [breach('Zeta'), breach('Alpha')] },
      { address: 'old@isp.example', breaches: [breach('Isp')] },
      { address: 'nobody@else.example', breaches: [breach('Other')] },
    ]);
    const report = await buildHealthReport(items, { ...deps, settings }, NOW);
    expect(report.recoveryBreached).toEqual([
      // The Gmail login itself isn't counted: it's the inbox, not a login the inbox resets.
      {
        itemId: gmail.id,
        vaultId: 'v1',
        title: 'Gmail',
        subtitle: 'me@gmail.com',
        email: 'me@gmail.com',
        accounts: 2,
        breaches: ['Alpha', 'Zeta'],
        warning: warningKey('recoveryBreached', 'me@gmail.com', 'Alpha,Zeta'),
      },
      // No login for that inbox: the row has no item and shows the address.
      {
        itemId: '',
        vaultId: '',
        title: 'old@isp.example',
        email: 'old@isp.example',
        accounts: 1,
        breaches: ['Isp'],
        warning: warningKey('recoveryBreached', 'old@isp.example', 'Isp'),
      },
    ]);
    // An address that resets nothing isn't a recovery email.
    expect(report.recoveryBreached.some((entry) => entry.email === 'nobody@else.example')).toBe(false);
    // Not part of the score.
    expect(report.score).toBe((await buildHealthReport(items, deps, NOW)).score);
  });

  it('shows nothing while alerts are off, and leaves out breaches the user dismissed', async () => {
    const { items } = vaultOf([]);
    const found = [{ address: 'me@gmail.com', breaches: [breach('Alpha')] }];
    expect((await buildHealthReport(items, { ...deps, settings: alerts(found, { enabled: false }) }, NOW)).recoveryBreached).toEqual([]);
    const dismissedBreach = { ...alerts(found), dismissed: [warningKey('emailBreach', 'me@gmail.com', 'Alpha')] };
    expect((await buildHealthReport(items, { ...deps, settings: dismissedBreach }, NOW)).recoveryBreached).toEqual([]);
  });

  it('can be dismissed, and comes back with a new breach', async () => {
    const { items } = vaultOf([]);
    const key = warningKey('recoveryBreached', 'me@gmail.com', 'Alpha');
    const one = { ...alerts([{ address: 'me@gmail.com', breaches: [breach('Alpha')] }]), dismissed: [key] };
    const report = await buildHealthReport(items, { ...deps, settings: one }, NOW);
    expect(report.recoveryBreached).toEqual([]);
    expect(report.dismissed.find((d) => d.warning === key)).toMatchObject({ check: 'recoveryBreached', subtitle: 'me@gmail.com' });

    const two = { ...alerts([{ address: 'me@gmail.com', breaches: [breach('Alpha'), breach('Beta')] }]), dismissed: [key] };
    expect((await buildHealthReport(items, { ...deps, settings: two }, NOW)).recoveryBreached.map((e) => e.breaches)).toEqual([['Alpha', 'Beta']]);
  });

  it('hides at once when dismissed', async () => {
    const { items } = vaultOf([]);
    const report = await buildHealthReport(items, { ...deps, settings: alerts([{ address: 'me@gmail.com', breaches: [breach('Alpha')] }]) }, NOW);
    expect(withoutWarnings(report, new Set([report.recoveryBreached[0]!.warning!])).recoveryBreached).toEqual([]);
  });
});

describe('the second opt-in', () => {
  it('sends the account email and aliases only, until recovery emails are turned on', async () => {
    const { items } = vaultOf([]);
    const off = await buildHealthReport(items, { ...deps, settings: alerts([]) }, NOW);
    expect(off.emailBreaches.recoveryEmails).toBe(false);
    expect(emailBreachAddresses('account@open.example', off)).toEqual(['account@open.example', 'alias@relay.example']);

    const on = await buildHealthReport(items, { ...deps, settings: alerts([], { recoveryEmails: true }) }, NOW);
    expect(on.emailBreaches.recoveryEmails).toBe(true);
    expect(emailBreachAddresses('account@open.example', on)).toEqual(['account@open.example', 'alias@relay.example', 'me@gmail.com', 'old@isp.example']);
    // The account email isn't sent twice when it's also a recovery email.
    expect(emailBreachAddresses('ME@gmail.com', on)).toEqual(['ME@gmail.com', 'alias@relay.example', 'old@isp.example']);
  });

  it('is off whenever alerts are off', async () => {
    const report = await buildHealthReport([], { ...deps, settings: alerts([], { enabled: false, recoveryEmails: true }) }, NOW);
    expect(report.emailBreaches.recoveryEmails).toBe(false);
  });
});

describe('HealthSettings with the second opt-in', () => {
  function fakeVault() {
    const stored: Item[] = [];
    const looked: string[] = [];
    const vault = {
      listItems: async () => stored.map((item) => ({ id: item.id })),
      getItem: async (id: string) => stored.find((item) => item.id === id)!,
      saveItem: async (input: Partial<Item>) => {
        const existing = stored.find((item) => item.id === input.id);
        const item = { ...existing, ...input, id: input.id ?? 'settings', createdAt: '2026-01-01', updatedAt: new Date().toISOString(), revision: (existing?.revision ?? 0) + 1 } as Item;
        stored.splice(0, stored.length, ...stored.filter((i) => i.id !== item.id), item);
        return item;
      },
      deleteItem: async () => undefined,
      listVaults: async () => [{ id: 'v1', type: 'personal' }],
      lookupEmailBreaches: async (address: string) => {
        looked.push(address);
        return address === 'me@gmail.com' ? [breach('Alpha')] : [];
      },
    } as unknown as VaultService;
    return { vault, stored, looked };
  }

  it('is off until turned on, forgets results either way, and follows the stored choice', async () => {
    const { vault, looked } = fakeVault();
    const settings = createHealthSettings(vault);
    const { recovery } = await buildHealthReport(vaultOf([]).items, deps, NOW);
    const addresses = (stored: { recoveryEmails?: boolean }) => emailBreachAddresses('account@open.example', { recovery, emailBreaches: { recoveryEmails: stored.recoveryEmails === true } });

    // Can't be turned on while alerts are off.
    await settings.setRecoveryEmailChecks(true);
    expect((await settings.read()).emailBreachAlerts).toBeUndefined();

    await settings.setEmailBreachAlerts(true);
    expect(await settings.checkEmailBreaches(addresses, { now: NOW })).toBe('checked');
    expect(looked).toEqual(['account@open.example', 'alias@relay.example']);

    await settings.setRecoveryEmailChecks(true);
    expect((await settings.read()).emailBreachAlerts).toEqual({ enabled: true, recoveryEmails: true });
    looked.length = 0;
    expect(await settings.checkEmailBreaches(addresses, { now: NOW })).toBe('checked');
    expect(looked).toEqual(['account@open.example', 'alias@relay.example', 'me@gmail.com', 'old@isp.example']);
    expect((await settings.read()).emailBreachAlerts).toMatchObject({ enabled: true, recoveryEmails: true, found: [{ address: 'me@gmail.com' }] });

    // Off again: what those addresses found is gone at once.
    await settings.setRecoveryEmailChecks(false);
    expect((await settings.read()).emailBreachAlerts).toEqual({ enabled: true });
    // Turning alerts off drops the second opt-in with them.
    await settings.setRecoveryEmailChecks(true);
    await settings.setEmailBreachAlerts(false);
    await settings.setEmailBreachAlerts(true);
    expect((await settings.read()).emailBreachAlerts).toEqual({ enabled: true });
  });
});
