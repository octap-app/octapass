// What the web vault keeps in this browser's IndexedDB. Never plaintext: the Secret Key, the
// trusted-device token that skips two-step sign-in, the refresh token, the sealed account bundle, ciphertext records for offline viewing, the device
// unlock record (plan 11), and for sharing (plan 15) the fingerprints the user verified, what this
// device pinned about the key log (plan 03) and which item each of their share links came from (ids only).

import type { AccountBundle } from '@octapass/core';
import type { KeyValueStore } from '../idb';
import type { RememberedAccount } from '../types';
import type { ItemRecord, VaultRecord } from './api';

/** An account this browser has signed in to, so the next sign-in here needs only the password. */
export interface DeviceAccount extends RememberedAccount {
  secretKey: string;
  /**
   * From the server at sign-in, sent with the next one so this device skips two-step sign-in. It
   * outlives an expired session, not a sign-out.
   */
  trustedDeviceToken?: string;
}

/** The signed-in account. Survives reloads, which come back locked. */
export interface StoredSession extends RememberedAccount {
  accountId: string;
  account: AccountBundle;
  refreshToken: string;
}

export interface DeviceUnlockRecord {
  accountId: string;
  credentialId: string;
  deviceSalt: string;
  /** The ASK, sealed with the key derived from the passkey's PRF output. */
  wrappedAsk: string;
  enabledAt: string;
  lastPasswordUnlockAt: string;
}

export interface CachedVaults {
  vaults: VaultRecord[];
  items: ItemRecord[];
}

const KEYS = {
  accounts: 'device-accounts',
  session: 'session',
  cache: (accountId: string) => `vault-cache:${accountId}`,
  deviceUnlock: (accountId: string) => `device-unlock:${accountId}`,
  verified: (accountId: string) => `verified-fingerprints:${accountId}`,
  keyLog: (accountId: string) => `key-log:${accountId}`,
  shareLinks: (accountId: string) => `share-links:${accountId}`,
};

/** Other accounts' fingerprint digits, as the user verified them, by account id. */
export type VerifiedFingerprints = Record<string, string>;
/** Share link id → the id of the item it was made from. */
export type ShareLinkSources = Record<string, string>;

export const accountKey = (a: RememberedAccount) => `${a.serverUrl}|${a.email}`;

export class LocalStore {
  constructor(private readonly kv: KeyValueStore) {}

  async accounts(): Promise<DeviceAccount[]> {
    return (await this.kv.get<DeviceAccount[]>(KEYS.accounts)) ?? [];
  }

  async rememberAccount(account: DeviceAccount): Promise<DeviceAccount[]> {
    const accounts = [...(await this.accounts()).filter((a) => accountKey(a) !== accountKey(account)), account];
    await this.kv.set(KEYS.accounts, accounts);
    return accounts;
  }

  /** Keeps the account's place in the list, which decides the email the sign-in screen suggests. */
  async setTrustedDeviceToken(account: RememberedAccount, trustedDeviceToken: string): Promise<DeviceAccount[]> {
    const accounts = (await this.accounts()).map((a) => (accountKey(a) === accountKey(account) ? { ...a, trustedDeviceToken } : a));
    await this.kv.set(KEYS.accounts, accounts);
    return accounts;
  }

  async forgetAccount(account: RememberedAccount): Promise<DeviceAccount[]> {
    const accounts = (await this.accounts()).filter((a) => accountKey(a) !== accountKey(account));
    await this.kv.set(KEYS.accounts, accounts);
    return accounts;
  }

  session(): Promise<StoredSession | undefined> {
    return this.kv.get<StoredSession>(KEYS.session);
  }

  setSession(session: StoredSession): Promise<void> {
    return this.kv.set(KEYS.session, session);
  }

  cache(accountId: string): Promise<CachedVaults | undefined> {
    return this.kv.get<CachedVaults>(KEYS.cache(accountId));
  }

  setCache(accountId: string, cache: CachedVaults): Promise<void> {
    return this.kv.set(KEYS.cache(accountId), cache);
  }

  deviceUnlock(accountId: string): Promise<DeviceUnlockRecord | undefined> {
    return this.kv.get<DeviceUnlockRecord>(KEYS.deviceUnlock(accountId));
  }

  setDeviceUnlock(record: DeviceUnlockRecord): Promise<void> {
    return this.kv.set(KEYS.deviceUnlock(record.accountId), record);
  }

  removeDeviceUnlock(accountId: string): Promise<void> {
    return this.kv.delete(KEYS.deviceUnlock(accountId));
  }

  async verified(accountId: string): Promise<VerifiedFingerprints> {
    return (await this.kv.get<VerifiedFingerprints>(KEYS.verified(accountId))) ?? {};
  }

  setVerified(accountId: string, verified: VerifiedFingerprints): Promise<void> {
    return this.kv.set(KEYS.verified(accountId), verified);
  }

  /** What this device pinned about the key log, as the core saved it. */
  keyLog(accountId: string): Promise<string | undefined> {
    return this.kv.get<string>(KEYS.keyLog(accountId));
  }

  setKeyLog(accountId: string, state: string): Promise<void> {
    return this.kv.set(KEYS.keyLog(accountId), state);
  }

  async shareLinks(accountId: string): Promise<ShareLinkSources> {
    return (await this.kv.get<ShareLinkSources>(KEYS.shareLinks(accountId))) ?? {};
  }

  setShareLinks(accountId: string, links: ShareLinkSources): Promise<void> {
    return this.kv.set(KEYS.shareLinks(accountId), links);
  }

  /** Removes everything this browser holds for the account except the remembered Secret Key. */
  async wipeAccount(accountId: string): Promise<void> {
    await this.kv.delete(KEYS.cache(accountId));
    await this.kv.delete(KEYS.deviceUnlock(accountId));
    await this.kv.delete(KEYS.verified(accountId));
    await this.kv.delete(KEYS.keyLog(accountId));
    await this.kv.delete(KEYS.shareLinks(accountId));
    if ((await this.session())?.accountId === accountId) await this.kv.delete(KEYS.session);
  }
}
