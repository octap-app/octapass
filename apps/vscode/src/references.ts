// `octapass://<vault>/<item>/<field>` references for what GET /v1/items lists. No `vscode` import.

import type { ItemRef } from './connect';

export interface FieldRow {
  vault: string;
  item: string;
  itemId: string;
  field: string;
  secret: boolean;
  reference: string;
}

/** `%` as `%25` and `/` as `%2F`, in that order so the second isn't encoded twice. */
export function encodePart(part: string): string {
  return part.replace(/%/g, '%25').replace(/\//g, '%2F');
}

export function reference(vault: string, item: string, field: string): string {
  return `octapass://${encodePart(vault)}/${encodePart(item)}/${encodePart(field)}`;
}

function nameKey(vault: string, item: string): string {
  return JSON.stringify([vault.trim().toLowerCase(), item.trim().toLowerCase()]);
}

/**
 * One row per field that a reference can name. Item names are matched without regard to case and
 * two items with the same name would make a reference ambiguous, so those are named by id. So is
 * an item with no name. A blank field name can't be written in a reference, so it's left out.
 */
export function fieldRows(items: readonly ItemRef[]): FieldRow[] {
  const seen = new Map<string, number>();
  for (const { vault, item } of items) {
    const key = nameKey(vault, item);
    seen.set(key, (seen.get(key) ?? 0) + 1);
  }
  return items.flatMap(({ vault, item, itemId, fields }) => {
    const unique = item.trim() !== '' && seen.get(nameKey(vault, item)) === 1;
    return fields
      .filter(({ name }) => name.trim() !== '')
      .map(({ name, secret }) => ({
        vault,
        item: item.trim() === '' ? itemId : item,
        itemId,
        field: name,
        secret,
        reference: reference(vault, unique ? item : itemId, name),
      }));
  });
}
