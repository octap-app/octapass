// Passkey private keys stay in the service worker. The extension's pages get items without them,
// and when a page saves an item back, the keys of the passkeys it kept are put back in.

import type { Item, ItemDraft, LoginDetails } from '@octapass/vault-client';

interface StoredPasskey {
  rpId?: string;
  credentialId?: string;
  privateKey?: string;
}

const passkeysOf = (details: unknown) => (details as LoginDetails | undefined)?.passkeys as (StoredPasskey & Record<string, unknown>)[] | undefined;

export function withoutPasskeyKeys(item: Item): Item {
  const passkeys = passkeysOf(item.details);
  if (!passkeys?.length) return item;
  return { ...item, details: { ...item.details, passkeys: passkeys.map(({ privateKey: _privateKey, ...rest }) => rest) } as unknown as Item['details'] };
}

export function withPasskeyKeys(draft: ItemDraft, existing: Item | undefined): ItemDraft {
  const passkeys = passkeysOf(draft.details);
  // The same credential for the same site, so an edit can't move a key to another site.
  const id = (p: StoredPasskey) => `${p.rpId}\u0000${p.credentialId}`;
  const keys = new Map(passkeysOf(existing?.details)?.filter((p) => p.credentialId && p.privateKey).map((p) => [id(p), p.privateKey]));
  if (!passkeys?.length || !keys.size) return draft;
  const restored = passkeys.map((p) => (p.privateKey || !keys.has(id(p)) ? p : { ...p, privateKey: keys.get(id(p)) }));
  return { ...draft, details: { ...draft.details, passkeys: restored } as unknown as ItemDraft['details'] };
}
