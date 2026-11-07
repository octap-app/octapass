import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { isVaultError } from '../errors';
import type { Item } from '../types';
import { existingLogins, importVaultFile, PendingImports, readQrCodes, type ImportTarget, type TransferCore } from './transfer';

const core = createRequire(import.meta.url)('@octapass/core/node') as TransferCore;
// Tests run from the package's folder.
const qr = (name: string) => new Blob([readFileSync(join(process.cwd(), '../../crates/octapass-core/tests/qr-fixtures', name))]);

const GITHUB = 'otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub';
const DUO = 'otpauth://totp/Duo:maya?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Duo';

function target(): ImportTarget & { saved: unknown[]; totp: [string, string][] } {
  const saved: unknown[] = [];
  const totp: [string, string][] = [];
  return {
    saved,
    totp,
    existingLogins: [{ id: 'gh', title: 'GitHub', urls: ['https://github.com'] }],
    saveItems: async (entries) => {
      saved.push(...entries.map((e) => e.item));
      return { ids: entries.map((_, i) => `new-${i}`), warnings: [] };
    },
    setTotp: async (itemId, value) => void totp.push([itemId, value]),
  };
}

describe('the import review', () => {
  it('keeps the parsed file until finished, and only names reach the review', async () => {
    const pending = new PendingImports();
    const file = new Blob([`${GITHUB}\n${DUO}\n`]);
    const review = await pending.review(core, 'otpauth', file, {}, [{ id: 'gh', title: 'GitHub', urls: ['https://github.com'] }]);
    expect(review.codes).toEqual([
      { index: 0, title: 'GitHub', issuer: 'GitHub', account: 'octo', loginId: 'gh' },
      { index: 1, title: 'Duo', issuer: 'Duo', account: 'maya' },
    ]);
    expect(JSON.stringify(review)).not.toContain('JBSWY3DPEHPK3PXP');
    expect(review.otherItems).toBe(0);

    // GitHub's code becomes its own login; Duo's joins the login "duo".
    const to = target();
    const result = await pending.finish(core, review.id, [{ code: 0 }, { code: 1, loginId: 'duo' }], to);
    expect(result.imported).toBe(2);
    expect(to.totp).toEqual([['duo', expect.stringContaining('otpauth://totp/Duo:maya?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')]]);
    expect(to.saved).toHaveLength(1);

    await expect(pending.finish(core, review.id, [], target())).rejects.toSatisfy((e) => isVaultError(e, 'importReviewExpired'));
  });

  it('forgets reviews when cancelled or cleared', async () => {
    const pending = new PendingImports();
    const first = await pending.review(core, 'otpauth', new Blob([GITHUB]), {}, []);
    // A JSON port delivers missing options as `null`.
    const second = await pending.review(core, 'otpauth', new Blob([DUO]), null as never, []);
    pending.cancel(first.id);
    pending.clear();
    for (const id of [first.id, second.id]) await expect(pending.finish(core, id, [], target())).rejects.toSatisfy((e) => isVaultError(e, 'importReviewExpired'));
  });
});

describe('files the web build cannot read', () => {
  it('asks for the full core when the small one has no OpenPGP', async () => {
    const small = {
      importFile: () => {
        throw { code: 'pgp_unavailable' };
      },
    } as unknown as TransferCore;
    const importFile = vi.fn(() => ({ items: [], totpUpdates: [], warnings: [], skipped: 0 }));
    const full = { importFile } as unknown as Pick<TransferCore, 'importFile'>;
    const loadFullCore = vi.fn(async () => full);
    const result = await importVaultFile(small, 'protonpass', new Blob(['pgp']), {}, target(), loadFullCore);
    expect(loadFullCore).toHaveBeenCalledOnce();
    expect(importFile).toHaveBeenCalledOnce();
    expect(result.imported).toBe(0);
  });
});

describe('logins an import may add codes to', () => {
  it('reach the core without empty fields, so a login without a website or username still matches', async () => {
    const login = {
      id: 'gh',
      vaultId: 'v',
      revision: 1,
      createdAt: '2026-10-24T00:00:00Z',
      updatedAt: '2026-10-24T00:00:00Z',
      overview: { schemaVersion: 1, type: 'login', title: 'GitHub' },
      details: { schemaVersion: 1, password: 'pw' },
    } as Item;
    expect(existingLogins([login])).toEqual([{ id: 'gh', title: 'GitHub', urls: [], hasTotp: false }]);
    const review = await new PendingImports().review(core, 'otpauth', new Blob([GITHUB]), {}, existingLogins([login]));
    expect(review.codes[0]!.loginId).toBe('gh');
  });

  it('carry their one-time code, so importing an authenticator backup again recognises it', () => {
    const login = {
      id: 'gh',
      vaultId: 'v',
      revision: 1,
      createdAt: '2026-10-24T00:00:00Z',
      updatedAt: '2026-10-24T00:00:00Z',
      overview: { schemaVersion: 1, type: 'login', title: 'GitHub' },
      details: { schemaVersion: 1, totp: GITHUB },
    } as Item;
    expect(existingLogins([login])).toEqual([{ id: 'gh', title: 'GitHub', urls: [], hasTotp: true, totp: GITHUB }]);
  });
});

describe('reading QR codes', () => {
  it('uses the core’s decoders when it has them', async () => {
    expect(await readQrCodes(core, qr('github.png'))).toEqual([GITHUB]);
    await expect(readQrCodes(core, new Blob(['not an image']))).rejects.toSatisfy((e) => isVaultError(e, 'invalidImage'));
  });

  it('otherwise has the browser decode the image and the core read the pixels', async () => {
    const readQrPixels = vi.fn(() => [GITHUB]);
    // jsdom has neither createImageBitmap nor OffscreenCanvas: a picture the browser can't open.
    await expect(readQrCodes({ readQrPixels }, new Blob(['x']))).rejects.toSatisfy((e) => isVaultError(e, 'invalidImage'));
    expect(readQrPixels).not.toHaveBeenCalled();
  });
});
