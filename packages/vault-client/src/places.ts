// Nearby (plan 01): places saved as `place` items, and the items at each. Which place the device is
// at is worked out by the core (`nearbyList`, `suggestedPlace` in octapass-core's `places`), on the
// device: nothing here sends a location or a network name anywhere.

import { compareSummaries, HIDDEN_ITEM_TYPES } from './items';
import type { Here, ItemSummary, NearbyPlace, PlaceData, Vault } from './types';

export const PLACE_TYPE = 'place' as const;

/** The part of the core Nearby needs (the WASM build has it). */
export interface PlacesCore {
  nearbyList(places: unknown[], items: unknown[], here: Here | undefined): NearbyPlace[];
  suggestedPlace(places: unknown[], items: unknown[], here: Here | undefined, item: unknown, itemVault: string, personal: boolean): string | undefined;
}

/** The places and the items that can be at them, each sorted by name, out of every summary. */
export function nearbyInputs(summaries: readonly ItemSummary[]): { places: ItemSummary[]; items: ItemSummary[] } {
  const live = summaries.filter((summary) => !summary.deletedAt).sort(compareSummaries);
  return {
    places: live.filter((summary) => summary.type === PLACE_TYPE),
    items: live.filter((summary) => !HIDDEN_ITEM_TYPES.has(summary.type)),
  };
}

/** `VaultService.nearby` over the summaries a host already has. */
export function nearbyFrom(core: PlacesCore, summaries: readonly ItemSummary[], here: Here): NearbyPlace[] {
  const { places, items } = nearbyInputs(summaries);
  return core.nearbyList(places, items, here);
}

/** `VaultService.suggestPlace` over the summaries a host already has. */
export function suggestFrom(core: PlacesCore, summaries: readonly ItemSummary[], vaults: readonly Pick<Vault, 'id' | 'type'>[], itemId: string, here: Here): string | undefined {
  const { places, items } = nearbyInputs(summaries);
  const item = summaries.find((summary) => summary.id === itemId);
  if (!item || item.deletedAt || HIDDEN_ITEM_TYPES.has(item.type)) return undefined;
  const personal = vaults.find((vault) => vault.id === item.vaultId)?.type === 'personal';
  return core.suggestedPlace(places, items, here, item, item.vaultId, personal) ?? undefined;
}

/** Whether a place has a point. */
export function hasPoint(place: PlaceData | undefined): place is PlaceData & { latitude: number; longitude: number } {
  return typeof place?.latitude === 'number' && typeof place.longitude === 'number';
}

/**
 * A rough distance for a list: metres to the nearest 10 under a kilometre, then kilometres with one
 * decimal under 10 km, whole kilometres beyond ("40 m", "1.2 km", "37 km").
 */
export function formatDistance(metres: number, locale?: string): string {
  const rounded = Math.max(10, Math.round(metres / 10) * 10);
  if (rounded < 1000) {
    return new Intl.NumberFormat(locale, { style: 'unit', unit: 'meter', unitDisplay: 'short' }).format(rounded);
  }
  const km = metres / 1000;
  return new Intl.NumberFormat(locale, { style: 'unit', unit: 'kilometer', unitDisplay: 'short', maximumFractionDigits: km < 10 ? 1 : 0 }).format(km);
}

/** An item's places with `placeId` added (once) or removed. */
export function withPlace(places: readonly string[] | undefined, placeId: string, linked: boolean): string[] | undefined {
  const rest = (places ?? []).filter((id) => id !== placeId);
  const next = linked ? [...rest, placeId] : rest;
  return next.length ? next : undefined;
}
