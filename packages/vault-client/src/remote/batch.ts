// Many item writes in few requests through `POST /v1/batch` (docs/developers/sync-api.md,
// "Batch writes"). A batch is atomic per vault: one failing write aborts the others in its vault
// with 424, so those are sent again without it.

import type { Api, BatchOperation, BatchResult } from './api';

export const BATCH_MAX_OPERATIONS = 1000;
/** Under the server's 16 MiB request limit, with room for the JSON around the ciphertext. */
export const BATCH_MAX_BYTES = 12 * 1024 * 1024;
const ABORTED = 424;

export interface BatchOutcome {
  /** New revisions of the operations that were applied, by item id. */
  applied: Map<string, number>;
  failed: { itemId: string; result: BatchResult }[];
}

/** Splits operations into requests the server accepts: at most 1,000 operations and about 12 MiB each. */
export function chunkOperations(operations: BatchOperation[], maxOperations = BATCH_MAX_OPERATIONS, maxBytes = BATCH_MAX_BYTES): BatchOperation[][] {
  const chunks: BatchOperation[][] = [];
  let chunk: BatchOperation[] = [];
  let bytes = 0;
  for (const operation of operations) {
    const size = JSON.stringify(operation).length;
    if (chunk.length > 0 && (chunk.length >= maxOperations || bytes + size > maxBytes)) {
      chunks.push(chunk);
      chunk = [];
      bytes = 0;
    }
    chunk.push(operation);
    bytes += size;
  }
  if (chunk.length > 0) chunks.push(chunk);
  return chunks;
}

export async function runBatch(api: Pick<Api, 'batch'>, operations: BatchOperation[]): Promise<BatchOutcome> {
  const outcome: BatchOutcome = { applied: new Map(), failed: [] };
  for (const chunk of chunkOperations(operations)) {
    let pending = chunk;
    while (pending.length > 0) {
      const { results } = await api.batch(pending);
      const aborted: BatchOperation[] = [];
      let failures = 0;
      results.forEach((result, i) => {
        if (result.status === 200) outcome.applied.set(result.itemId, result.revision!);
        else if (result.status === ABORTED) aborted.push(pending[i]!);
        else {
          outcome.failed.push({ itemId: result.itemId, result });
          failures++;
        }
      });
      if (failures === 0) {
        // Aborted without a failure to blame: the server isn't following the contract. Don't loop.
        for (const op of aborted) outcome.failed.push({ itemId: op.itemId, result: { itemId: op.itemId, status: ABORTED } });
        break;
      }
      pending = aborted;
    }
  }
  return outcome;
}
