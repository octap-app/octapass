import { DEFAULT_SERVER_URL, MockVaultService } from '../mock/MockVaultService';
import type { EmailBreach, Item, ItemSummary, Vault } from '../types';
import { createHealthSettings, readHealthSettings, warningKey, type HealthSettingsVault } from './healthSettings';

const breach: EmailBreach = { name: 'Adobe', title: 'Adobe', dataClasses: ['Passwords'] };
const NOW = new Date('2026-11-02T12:00:00.000Z');

/** Just enough vault: a list of items with revisions; a stale save leaves a conflict copy, as the real ones do. */
function fakeVault(lookup: (address: string) => Promise<EmailBreach[]> = async () => []) {
  const items = new Map<string, Item>();
  let next = 0;
  const saves: string[] = [];
  const vault: HealthSettingsVault = {
    listItems: async (filter) => [...items.values()].filter((item) => item.overview.type === filter?.type && !item.deletedAt).map((item) => ({ id: item.id }) as ItemSummary),
    getItem: async (id) => structuredClone(items.get(id)!),
    saveItem: async (draft) => {
      const stored = draft.id ? items.get(draft.id) : undefined;
      saves.push(draft.id ?? 'new');
      const stale = stored && draft.revision !== stored.revision;
      const id = stored && !stale ? stored.id : `item-${++next}`;
      const item: Item = { id, vaultId: draft.vaultId, revision: (stored?.revision ?? 0) + 1, createdAt: stored?.createdAt ?? `2026-01-0${next}`, updatedAt: `2026-02-${String(items.size + saves.length).padStart(2, '0')}`, overview: draft.overview, details: draft.details };
      items.set(id, item);
      return item;
    },
    deleteItem: async (id) => void (items.get(id)!.deletedAt = 'now'),
    listVaults: async () => [{ id: 'personal-1', type: 'personal' } as Vault],
    lookupEmailBreaches: vi.fn(lookup),
  };
  return { vault, items };
}

describe('health settings', () => {
  it('starts empty and keeps one hidden item in the personal vault', async () => {
    const { vault, items } = fakeVault();
    const settings = createHealthSettings(vault);
    expect(await settings.read()).toEqual({ schemaVersion: 1 });
    await settings.dismiss(['weak:a:']);
    await settings.dismiss(['old:b:']);
    expect(items.size).toBe(1);
    const [item] = [...items.values()];
    expect(item!.vaultId).toBe('personal-1');
    expect(item!.overview.type).toBe('healthSettings');
    expect((await settings.read()).dismissed).toEqual(['weak:a:', 'old:b:']);
  });

  it('runs quick dismissals one after another, without a conflict copy', async () => {
    const { vault, items } = fakeVault();
    const settings = createHealthSettings(vault);
    await Promise.all([settings.dismiss(['a']), settings.dismiss(['b']), settings.dismiss(['c'])]);
    expect(items.size).toBe(1);
    expect((await settings.read()).dismissed?.sort()).toEqual(['a', 'b', 'c']);
  });

  it('restores a warning', async () => {
    const { vault } = fakeVault();
    const settings = createHealthSettings(vault);
    await settings.dismiss(['a', 'b']);
    await settings.restore(['a']);
    expect((await settings.read()).dismissed).toEqual(['b']);
  });

  it('merges a conflict copy and folds it away on the next save', async () => {
    const { vault, items } = fakeVault();
    const settings = createHealthSettings(vault);
    await settings.dismiss(['first']);
    const [original] = [...items.values()];
    await vault.saveItem({ id: original!.id, revision: 99, vaultId: original!.vaultId, overview: original!.overview, details: { schemaVersion: 1, dismissed: ['other-device'] } as never });
    expect(items.size).toBe(2);
    expect((await settings.read()).dismissed?.sort()).toEqual(['first', 'other-device']);
    await settings.restore(['other-device']);
    expect([...items.values()].filter((item) => !item.deletedAt)).toHaveLength(1);
    expect((await settings.read()).dismissed).toEqual(['first']);
  });

  it('ignores a settings item in the trash', () => {
    const item = { overview: { type: 'healthSettings' }, details: { dismissed: ['x'] }, deletedAt: 'now', updatedAt: '' } as unknown as Item;
    expect(readHealthSettings([item])).toEqual({ schemaVersion: 1 });
  });
});

describe('email breach alerts', () => {
  it('sends nothing until the user opts in', async () => {
    const { vault } = fakeVault();
    const settings = createHealthSettings(vault);
    expect(await settings.checkEmailBreaches(['me@x.example'], { now: NOW })).toBe('off');
    expect(vault.lookupEmailBreaches).not.toHaveBeenCalled();
  });

  it('checks once a day unless forced, and stores the results in the encrypted item', async () => {
    const { vault } = fakeVault(async (address) => (address === 'me@x.example' ? [breach] : []));
    const settings = createHealthSettings(vault);
    await settings.setEmailBreachAlerts(true);
    expect(await settings.checkEmailBreaches(['me@x.example', 'alias@y.example'], { now: NOW })).toBe('checked');
    expect(vault.lookupEmailBreaches).toHaveBeenCalledTimes(2);
    expect((await settings.read()).emailBreachAlerts).toEqual({ enabled: true, checkedAt: NOW.toISOString(), found: [{ address: 'me@x.example', breaches: [breach] }] });

    const later = new Date(NOW.getTime() + 23 * 3_600_000);
    expect(await settings.checkEmailBreaches(['me@x.example'], { now: later })).toBe('notDue');
    expect(await settings.checkEmailBreaches(['me@x.example'], { now: later, force: true })).toBe('checked');
    expect((await settings.read()).emailBreachAlerts?.previous).toEqual([warningKey('emailBreach', 'me@x.example', 'Adobe')]);
  });

  it('keeps the last results when a lookup fails', async () => {
    let fail = false;
    const { vault } = fakeVault(async () => {
      if (fail) throw new Error('rate limited');
      return [breach];
    });
    const settings = createHealthSettings(vault);
    await settings.setEmailBreachAlerts(true);
    await settings.checkEmailBreaches(['me@x.example'], { now: NOW });
    fail = true;
    expect(await settings.checkEmailBreaches(['me@x.example'], { now: NOW, force: true })).toBe('failed');
    expect((await settings.read()).emailBreachAlerts?.found).toHaveLength(1);
  });

  it('forgets the results when turned off, and an off during a check wins', async () => {
    const { vault } = fakeVault(async () => [breach]);
    const settings = createHealthSettings(vault);
    await settings.setEmailBreachAlerts(true);
    await settings.checkEmailBreaches(['me@x.example'], { now: NOW });
    await settings.setEmailBreachAlerts(false);
    expect((await settings.read()).emailBreachAlerts).toEqual({ enabled: false });

    await settings.setEmailBreachAlerts(true);
    (vault.lookupEmailBreaches as ReturnType<typeof vi.fn>).mockImplementationOnce(async () => {
      await settings.setEmailBreachAlerts(false);
      return [breach];
    });
    await settings.checkEmailBreaches(['me@x.example'], { now: NOW });
    expect((await settings.read()).emailBreachAlerts).toEqual({ enabled: false });
  });

  it('sends at most 50 addresses in one check', async () => {
    const { vault } = fakeVault();
    const settings = createHealthSettings(vault);
    await settings.setEmailBreachAlerts(true);
    await settings.checkEmailBreaches(Array.from({ length: 80 }, (_, i) => `a${i}@x.example`), { now: NOW });
    expect(vault.lookupEmailBreaches).toHaveBeenCalledTimes(50);
  });
});

describe('with the demo vault', () => {
  it('keeps the settings item out of lists, counts and CSV, and the report reads it', async () => {
    const service = await MockVaultService.create({ dbName: 'health-settings', latency: [0, 0], fetch: async () => new Response('') });
    const { signupId, devVerificationCode } = await service.startSignup({ serverUrl: DEFAULT_SERVER_URL, email: 'maya@example.com', password: 'Lantern ruby quiet anchor' });
    await service.finishSignup({ signupId, verificationCode: devVerificationCode! });
    const before = (await service.listItems()).length;

    const report = await service.getHealthReport();
    const warning = report.weak[0]?.warning ?? report.missing2fa[0]!.warning!;
    await createHealthSettings(service).dismiss([warning]);

    expect(await service.listItems()).toHaveLength(before);
    expect(await service.listItems({ type: 'healthSettings' })).toHaveLength(1);
    const after = await service.getHealthReport();
    expect(after.dismissed.map((entry) => entry.warning)).toEqual([warning]);
    for (const format of ['csv', 'json'] as const) {
      const file = await (await service.exportVault(format)).text();
      expect(file).not.toContain('healthSettings');
    }
  });
});
