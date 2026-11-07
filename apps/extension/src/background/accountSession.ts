// A core `Session` of its own for the work the engine has no call for (passkeys, batch imports).
// It's opened from the session wrap, the same unwrap the keeper uses after a restart, with the
// encrypted records from the engine's local copy. That couples this file to two of the engine's
// storage records, `session` and `vault-cache:<accountId>` (`@octapass/vault-client`
// `remote/store.ts`); see plan 13, History. Vault keys open as the engine opens them
// (`openVaultKey`): shared and family vaults only once their grant verifies.

import type { AccountBundle, EncryptedItem, Session } from '@octapass/core';
import { base64UrlDecode, VaultError } from '@octapass/vault-client';
import { openVaultKey, type Core, type VaultRecord } from '@octapass/vault-client/remote';
import type { SessionKeeper } from './sessionKeeper';
import type { KeyValueStore } from './storage';

export interface CachedRecord extends EncryptedItem {
  id: string;
  vaultId: string;
  revision: number;
  deletedAt?: string;
}

export interface AccountCache {
  vaults: VaultRecord[];
  items: CachedRecord[];
}

export interface AccountSession {
  core: Core;
  session: Session;
  cache: AccountCache;
  serverUrl: string;
  /** Shared and family vaults whose grant didn't verify: their keys aren't open. */
  untrusted: Set<string>;
}

export interface AccountSessionOptions {
  keeper: SessionKeeper;
  loadCore: () => Promise<Core>;
  disk: KeyValueStore;
}

/** Runs `fn` with a session over every vault, freed afterwards. Throws `locked` without an unlocked account. */
export async function withAccountSession<T>({ keeper, loadCore, disk }: AccountSessionOptions, fn: (context: AccountSession) => Promise<T>): Promise<T> {
  const [core, wrap, stored] = await Promise.all([loadCore(), keeper.read(), disk.get<{ accountId: string; account: AccountBundle; serverUrl: string }>('session')]);
  const cache = stored && (await disk.get<AccountCache>(`vault-cache:${stored.accountId}`));
  if (!wrap || !stored || !cache || wrap.record.accountId !== stored.accountId) throw new VaultError('locked');
  const session = core.Session.unlockWithDeviceKey(base64UrlDecode(wrap.key), wrap.record.deviceSalt, wrap.record.wrappedAsk, stored.account);
  try {
    const untrusted = new Set<string>();
    for (const vault of cache.vaults) if (!openVaultKey(session, vault, stored.accountId)) untrusted.add(vault.id);
    return await fn({ core, session, cache, serverUrl: stored.serverUrl, untrusted });
  } finally {
    session.free();
  }
}
