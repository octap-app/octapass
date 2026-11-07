import { describe, expect, it } from 'vitest';
import { emptyDraft, withPasswordHistory } from './items';
import { DEFAULT_SERVER_URL, MockVaultService } from './mock/MockVaultService';
import type { Item, ItemSummary, WifiDetails } from './types';
import { inRangeFirst, parseWifiQr, parseWifiSecurity, sightingsByName, signalBars, upgradeLegacyWifi, upgradeLegacyWifiItems, wifiDraft, wifiQrText } from './wifi';

function item(type: Item['overview']['type'], details: Record<string, unknown>, overview: Partial<Item['overview']> = {}): Item {
  return {
    id: 'i',
    vaultId: 'v',
    revision: 4,
    createdAt: '',
    updatedAt: '',
    overview: { schemaVersion: 1, type, title: 'Home', ...overview },
    details: { schemaVersion: 1, ...details } as Item['details'],
  };
}

describe('Wi-Fi QR codes', () => {
  it('escape what WIFI: needs escaped, and read back', () => {
    const network = { ssid: 'My;Net', password: 'p:a,s"s\\', security: 'wpa2' as const, hidden: true };
    const text = wifiQrText(network)!;
    expect(text).toBe(String.raw`WIFI:T:WPA;S:My\;Net;P:p\:a\,s\"s\\;H:true;;`);
    expect(parseWifiQr(text)).toEqual(network);
  });

  it('use T:WPA for every WPA kind, WEP for WEP and nopass for open networks', () => {
    for (const security of ['wpa', 'wpaWpa2', 'wpa2', 'wpa2Wpa3', 'wpa3'] as const) expect(wifiQrText({ ssid: 'A', password: 'p', security })).toBe('WIFI:T:WPA;S:A;P:p;;');
    expect(wifiQrText({ ssid: 'Old', password: 'p', security: 'wep' })).toBe('WIFI:T:WEP;S:Old;P:p;;');
    expect(wifiQrText({ ssid: 'Cafe', password: 'ignored', security: 'open', hidden: false })).toBe('WIFI:T:nopass;S:Cafe;;');
    // Enterprise networks sign each person in: there's nothing to share.
    expect(wifiQrText({ ssid: 'Corp', password: 'p', security: 'wpa2Enterprise' })).toBeUndefined();
    expect(wifiQrText({ ssid: '', security: 'open' })).toBeUndefined();
  });

  it('scanned codes become networks, with Enterprise fields where Android writes them', () => {
    expect(parseWifiQr('WIFI:S:Cafe;;')).toEqual({ ssid: 'Cafe', security: 'open' });
    expect(parseWifiQr('WIFI:T:SAE;S:New;P:pw;;')).toEqual({ ssid: 'New', security: 'wpa3', password: 'pw' });
    expect(parseWifiQr('WIFI:T:nopass;S:Free;P:junk;;')).toEqual({ ssid: 'Free', security: 'open' });
    expect(parseWifiQr('WIFI:T:WPA2-EAP;S:Corp;E:PEAP;PH2:MSCHAPV2;I:maya;A:anon;P:pw;;')).toEqual({
      ssid: 'Corp',
      security: 'wpa2Enterprise',
      password: 'pw',
      eapMethod: 'peap',
      phase2: 'mschapv2',
      username: 'maya',
      identity: 'anon',
    });
    expect(parseWifiQr('WIFI:T:WPA;;')).toBeUndefined();
    expect(parseWifiQr('https://example.com')).toBeUndefined();
  });

  it('scans become Wi-Fi items named after the network', () => {
    expect(wifiDraft({ ssid: 'Office', security: 'wep', password: 'secret' }, 'v')).toEqual({
      vaultId: 'v',
      overview: { schemaVersion: 1, type: 'wifi', title: 'Office', subtitle: 'Office' },
      details: { schemaVersion: 1, ssid: 'Office', security: 'wep', password: 'secret' },
    });
    expect(wifiDraft({ ssid: 'Cafe', security: 'open', password: 'x' }, 'v').details).toEqual({ schemaVersion: 1, ssid: 'Cafe', security: 'open' });
  });
});

describe('security types', () => {
  it('are read as people and other apps write them', () => {
    const cases: [string | undefined, string | undefined][] = [
      ['None', 'open'],
      ['unsecured', 'open'],
      ['WEP', 'wep'],
      ['WPA', 'wpa'],
      ['WPA/WPA2 Personal', 'wpaWpa2'],
      ['wpa2-personal', 'wpa2'],
      ['WPA2/WPA3', 'wpa2Wpa3'],
      ['WPA3', 'wpa3'],
      ['SAE', 'wpa3'],
      ['WPA2 Enterprise', 'wpa2Enterprise'],
      ['WPA3-Enterprise', 'wpa3Enterprise'],
      ['802.1X', 'wpa2Enterprise'],
      ['carrier pigeon', undefined],
    ];
    for (const [text, security] of cases) expect(parseWifiSecurity(text), text).toBe(security);
    expect(parseWifiSecurity('', 'pw')).toBe('wpa2');
    expect(parseWifiSecurity(undefined)).toBe('open');
  });
});

describe('older Wi-Fi items', () => {
  it('password items with an SSID field become Wi-Fi items, losing nothing', () => {
    const legacy = item(
      'password',
      {
        password: 'pw',
        notes: 'router in the hall',
        passwordHistory: [{ password: 'old', changedAt: '2026-01-01T00:00:00Z' }],
        customFields: [
          { label: ' SSID ', value: ' Home-5G ', hidden: false },
          { label: 'Security', value: 'WPA2/WPA3', hidden: false },
          { label: 'Hidden', value: 'Yes', hidden: false },
          { label: 'Router admin', value: 'admin', hidden: true },
        ],
        future: { kept: true },
      },
      { tags: ['home'], favorite: true },
    );
    expect(upgradeLegacyWifi(legacy)).toEqual({
      id: 'i',
      vaultId: 'v',
      revision: 4,
      overview: { schemaVersion: 1, type: 'wifi', title: 'Home', subtitle: 'Home-5G', tags: ['home'], favorite: true },
      details: {
        schemaVersion: 1,
        ssid: 'Home-5G',
        security: 'wpa2Wpa3',
        password: 'pw',
        hidden: true,
        notes: 'router in the hall',
        passwordHistory: [{ password: 'old', changedAt: '2026-01-01T00:00:00Z' }],
        customFields: [{ label: 'Router admin', value: 'admin', hidden: true }],
        future: { kept: true },
      },
    });
  });

  it('keep a security type they can’t read as a field, and guess from the password', () => {
    const odd = upgradeLegacyWifi(item('password', { password: 'pw', customFields: [{ label: 'SSID', value: 'A', hidden: false }, { label: 'Security', value: 'carrier pigeon', hidden: false }] }));
    expect(odd?.details).toMatchObject({ security: 'wpa2', customFields: [{ label: 'Security', value: 'carrier pigeon', hidden: false }] });
    const open = upgradeLegacyWifi(item('login', { customFields: [{ label: 'Network name', value: 'Cafe', hidden: false }] }));
    expect(open?.details).toEqual({ schemaVersion: 1, ssid: 'Cafe', security: 'open' });
    const named = upgradeLegacyWifi(item('password', { username: 'guest', password: 'pw', customFields: [{ label: 'SSID', value: 'A', hidden: false }] }));
    expect((named?.details as WifiDetails).customFields).toEqual([{ label: 'Username', value: 'guest', hidden: false }]);
  });

  it('stay as they are when they hold what only a login has, or no network name', () => {
    const ssid = [{ label: 'SSID', value: 'Home', hidden: false }];
    expect(upgradeLegacyWifi(item('password', { password: 'pw' }))).toBeUndefined();
    expect(upgradeLegacyWifi(item('password', { customFields: [{ label: 'SSID', value: '  ', hidden: false }] }))).toBeUndefined();
    expect(upgradeLegacyWifi(item('login', { username: 'admin', customFields: ssid }))).toBeUndefined();
    expect(upgradeLegacyWifi(item('login', { customFields: ssid }, { urls: ['http://192.168.1.1'] }))).toBeUndefined();
    expect(upgradeLegacyWifi(item('password', { totp: 'JBSWY3DPEHPK3PXP', customFields: ssid }))).toBeUndefined();
    expect(upgradeLegacyWifi(item('secureNote', { notes: '', customFields: ssid }))).toBeUndefined();
    expect(upgradeLegacyWifi(item('wifi', { ssid: 'Home', security: 'wpa2' }))).toBeUndefined();
  });

  it('are moved in writable vaults once, and only rows that changed are opened again', async () => {
    const service = await MockVaultService.create({ dbName: 'wifi-upgrade', latency: [0, 0], fetch: async () => new Response(''), seed: true });
    const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: 'maya@example.com', password: 'Lantern ruby quiet anchor' });
    await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
    const before = await service.listItems({ type: 'password' });
    const studio = before.find((s) => s.title === 'Studio Wi-Fi')!;
    const checked = new Map<string, string>();
    let opened = 0;
    const counting = {
      listVaults: () => service.listVaults(),
      listItems: service.listItems.bind(service),
      saveItem: service.saveItem.bind(service),
      getItem: (id: string) => (opened++, service.getItem(id)),
    };

    expect(await upgradeLegacyWifiItems(counting, checked)).toBe(1);
    const moved = await service.getItem(studio.id);
    expect(moved.overview).toMatchObject({ type: 'wifi', title: 'Studio Wi-Fi', subtitle: 'Studio-Guest' });
    expect(moved.details).toMatchObject({ ssid: 'Studio-Guest', security: 'wpa2' });

    const firstRun = opened;
    expect(await upgradeLegacyWifiItems(counting, checked)).toBe(0);
    expect(opened).toBe(firstRun);
  });
});

describe('password history', () => {
  it('keeps a Wi-Fi network’s old password', () => {
    const before = item('wifi', { ssid: 'Home', security: 'wpa2', password: 'old' });
    const next = withPasswordHistory(before, { ...before, details: { ...(before.details as WifiDetails), password: 'new' } }, new Date('2026-10-24T00:00:00Z'));
    expect((next.details as WifiDetails).passwordHistory).toEqual([{ password: 'old', changedAt: '2026-10-24T00:00:00.000Z' }]);
  });

  it('new Wi-Fi items start as WPA2 networks with no name', () => {
    expect(emptyDraft('wifi', 'v').details).toEqual({ schemaVersion: 1, ssid: '', security: 'wpa2' });
  });
});

describe('networks in range', () => {
  const row = (title: string, ssid?: string): ItemSummary => ({
    id: title,
    vaultId: 'v',
    type: ssid ? 'wifi' : 'login',
    title,
    subtitle: ssid,
    favorite: false,
    hasTotp: false,
    hasPasskey: false,
    createdAt: '',
    updatedAt: '',
  });

  it('come first: the connected one, then by signal, the rest in their order', () => {
    const sightings = sightingsByName([
      { ssid: 'Cafe', signal: 30 },
      { ssid: 'Office', signal: 80 },
      { ssid: 'Cafe', signal: 55 },
    ]);
    expect(sightings.get('Cafe')?.signal).toBe(55);
    const rows = [row('A home', 'Home'), row('B login'), row('C cafe', 'Cafe'), row('D office', 'Office'), row('E far', 'Far')];
    expect(inRangeFirst(rows, sightings, 'Home').map((r) => r.title)).toEqual(['A home', 'D office', 'C cafe', 'B login', 'E far']);
    expect(inRangeFirst(rows, new Map()).map((r) => r.title)).toEqual(rows.map((r) => r.title));
  });

  it('signal shows as one to four bars', () => {
    expect([0, 24, 25, 50, 74, 75, 100].map(signalBars)).toEqual([1, 1, 2, 3, 3, 4, 4]);
  });
});
