import type { BatchOperation, BatchResult } from './api';
import { chunkOperations, runBatch } from './batch';

const put = (itemId: string, vaultId = 'v1', size = 10): BatchOperation => ({
  op: 'put',
  vaultId,
  itemId,
  item: { encryptedItemKey: 'k', overview: 'o'.repeat(size), details: 'd' },
});

describe('chunkOperations', () => {
  it('splits by count', () => {
    const ops = Array.from({ length: 2500 }, (_, i) => put(`i${i}`));
    expect(chunkOperations(ops).map((c) => c.length)).toEqual([1000, 1000, 500]);
  });

  it('splits by size, and never leaves an operation out', () => {
    const ops = [put('a', 'v1', 400), put('b', 'v1', 400), put('c', 'v1', 2000)];
    const chunks = chunkOperations(ops, 1000, 1000);
    expect(chunks.map((c) => c.map((op) => op.itemId))).toEqual([['a', 'b'], ['c']]);
  });
});

describe('runBatch', () => {
  it('sends each chunk and collects the new revisions', async () => {
    const batch = vi.fn(async (ops: BatchOperation[]) => ({ results: ops.map((op, i) => ({ itemId: op.itemId, status: 200, revision: i + 1 })) }));
    const ops = Array.from({ length: 1001 }, (_, i) => put(`i${i}`));
    const outcome = await runBatch({ batch }, ops);
    expect(batch).toHaveBeenCalledTimes(2);
    expect(outcome.applied.size).toBe(1001);
    expect(outcome.failed).toEqual([]);
  });

  it('resends the writes a failure aborted, without the one that failed', async () => {
    const quota: BatchResult = { itemId: 'b', status: 403, problem: { type: 'https://octap.app/problems/quota-exceeded', status: 403 } };
    const batch = vi.fn(async (ops: BatchOperation[]) => ({
      results: ops.map((op): BatchResult => {
        if (op.itemId === 'b') return quota;
        // Atomic per vault: while `b` is in the request, the rest of v1 is aborted.
        if (op.vaultId === 'v1' && ops.some((o) => o.itemId === 'b')) return { itemId: op.itemId, status: 424 };
        return { itemId: op.itemId, status: 200, revision: 9 };
      }),
    }));
    const outcome = await runBatch({ batch }, [put('a'), put('b'), put('c'), put('x', 'v2')]);
    expect(batch).toHaveBeenCalledTimes(2);
    expect(batch.mock.calls[1]![0].map((op) => op.itemId)).toEqual(['a', 'c']);
    expect([...outcome.applied.keys()].sort()).toEqual(['a', 'c', 'x']);
    expect(outcome.failed).toEqual([{ itemId: 'b', result: quota }]);
  });

  it('doesn’t loop on aborts with nothing to blame', async () => {
    const batch = vi.fn(async (ops: BatchOperation[]) => ({ results: ops.map((op) => ({ itemId: op.itemId, status: 424 })) }));
    const outcome = await runBatch({ batch }, [put('a'), put('b')]);
    expect(batch).toHaveBeenCalledTimes(1);
    expect(outcome.failed.map((f) => f.itemId)).toEqual(['a', 'b']);
  });
});
