import { createRequire } from 'node:module';
import { it } from 'vitest';
import { seedVault } from '../../mock/seed';
import { exportVaultFile, importVaultFile, type TransferCore } from '../transfer';
const core = createRequire(import.meta.url)('@octapass/core/node') as TransferCore;
it('diffs', async () => {
  const { vaults, items } = seedVault('maya@example.com');
  for (const format of ['cxf', 'csv'] as const) {
    const blob = await exportVaultFile(core, format, { vaults, items, account: { id: 'a', email: 'a@b.c' }, exporterRpId: 'o.example', now: new Date() });
    const updates: any[] = []; const saved: any[] = [];
    await importVaultFile(core, format === 'cxf' ? 'cxf' : 'generic-csv', blob, {}, {
      existingLogins: [], existingItems: items, vaultId: vaults[0]!.id,
      saveItems: async (e) => { saved.push(...e.map((x) => x.item)); return { ids: e.map((_, i) => `n${i}`), warnings: [] }; },
      updateItem: async (id, item) => void updates.push({ id, item }), setTotp: async () => {},
    });
    console.log(format, 'NEW', saved.map((s) => `${s.overview.type}:${s.overview.title}`).join(' | '));
    for (const u of updates.slice(0, 4)) {
      const old = items.find((i) => i.id === u.id)!;
      const keys = new Set([...Object.keys(old.details), ...Object.keys(u.item.details)]);
      const changed = [...keys].filter((k) => JSON.stringify((old.details as any)[k]) !== JSON.stringify(u.item.details[k]));
      console.log(format, 'UPD', old.overview.type, old.overview.title, '->', u.item.overview.type, 'changed:', changed.join(','), 'tags', JSON.stringify(old.overview.tags), JSON.stringify(u.item.overview.tags));
    }
    console.log(format, 'vaults of new:', [...new Set(saved.map(() => ''))].length, 'vaults in seed', vaults.length, 'items per vault', JSON.stringify(vaults.map((v) => items.filter((i) => i.vaultId === v.id).length)));
  }
});
