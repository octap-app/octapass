import { createRequire } from 'node:module';
import { it } from 'vitest';
import * as seed from '../../mock/seed';
import { exportVaultFile, importVaultFile, type TransferCore } from '../transfer';

const core = createRequire(import.meta.url)('@octapass/core/node') as TransferCore;

it('round trips', async () => {
  const s: any = seed;
  console.log(Object.keys(s));
  const data = (s.seedVault ?? s.createSeed ?? s.seed ?? Object.values(s).find((v) => typeof v === 'function')) as any;
  const made = typeof data === 'function' ? data('maya@example.com') : data;
  console.log(Object.keys(made ?? {}));
  const vaults = made.vaults; const items = made.items.filter((i: any) => !i.deletedAt);
  console.log('types', [...new Set(items.map((i: any) => i.overview.type))].join(','));
  for (const [format, src] of [['json', 'octapass'], ['cxf', 'cxf'], ['encrypted', 'octapass'], ['csv', 'generic-csv']] as const) {
    const blob = await exportVaultFile(core, format, { vaults, items, account: { id: 'a', email: 'a@b.c' }, exporterRpId: 'openpass.example', now: new Date(), kdf: undefined }, { password: 'correct horse battery staple' });
    const saved: any[] = [];
    try {
      const r = await importVaultFile(core, src, blob, { password: 'correct horse battery staple' }, {
        existingLogins: [], existingItems: items, vaultId: vaults[0].id,
        saveItems: async (e) => { saved.push(...e.map((x) => x.item)); return { ids: e.map((_, i) => `n${saved.length}-${i}`), warnings: [] }; },
        updateItem: async () => {}, setTotp: async () => {}, attach: async () => {},
      });
      console.log(format, JSON.stringify(r).slice(0, 600), 'types', [...new Set(saved.map((i) => i.overview.type))].join(','));
    } catch (e: any) { console.log(format, 'ERROR', e.code, e.message); }
    // and into an empty vault
    try {
      const r = await importVaultFile(core, src, blob, { password: 'correct horse battery staple' }, {
        existingLogins: [], saveItems: async (e) => ({ ids: e.map((_, i) => `m${i}`), warnings: [] }), setTotp: async () => {},
      });
      console.log(format, 'empty', JSON.stringify(r).slice(0, 400));
    } catch (e: any) { console.log(format, 'empty ERROR', e.code, e.message); }
  }
});
