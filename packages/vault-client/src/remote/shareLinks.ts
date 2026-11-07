// One-time share links (plan 06; docs/developers/sync-api.md, "Share links"). The item snapshot is
// encrypted here under a random key that only ever travels in the link's `#` fragment.

import type * as CoreModule from '@octapass/core';
import type { ItemPlaintext } from '@octapass/core';
import { isVaultError, VaultError } from '../errors';
import { shareableSnapshot } from '../items';
import { serverOrigin } from '../serverUrl';
import type { CreatedShareLink, ItemDetails, ItemOverview, ShareLinkEnvelope, ShareLinkInfo, ShareLinkOptions, SharedItem } from '../types';
import type { Api } from './api';
import { ApiProblem } from './http';
import type { LocalStore } from './store';
import type { VaultIndex } from './vaultIndex';

export type ShareLinkCore = Pick<typeof CoreModule, 'createShareLink' | 'openShareLink'>;

export interface ShareLinkHost {
  core(): Promise<ShareLinkCore>;
  index(): VaultIndex;
  /** The signed-in account's API. */
  api(): Api;
  /** Any server's API, without a session: the viewer may not have an account. */
  publicApi(serverUrl: string): Api;
  accountId(): string;
  store: LocalStore;
  now(): number;
  changed(): void;
}

export const SHARE_LINK_LIMITS = { minHours: 1, maxHours: 30 * 24, minViews: 1, maxViews: 100 } as const;

export function validateShareLinkOptions({ expiresInHours, maxViews }: ShareLinkOptions): void {
  const { minHours, maxHours, minViews, maxViews: most } = SHARE_LINK_LIMITS;
  if (!(expiresInHours >= minHours && expiresInHours <= maxHours) || !Number.isInteger(maxViews) || maxViews < minViews || maxViews > most) {
    throw new VaultError('serverError', 'Share links last 1 hour to 30 days and allow 1 to 100 views.');
  }
}

export class ShareLinks {
  constructor(private readonly host: ShareLinkHost) {}

  async create(itemId: string, options: ShareLinkOptions): Promise<CreatedShareLink> {
    validateShareLinkOptions(options);
    const entry = this.host.index().get(itemId);
    if (!entry || entry.item.deletedAt) throw new VaultError('notFound');
    const core = await this.host.core();
    // A snapshot: later edits to the item don't reach the link.
    const link = core.createShareLink(shareableSnapshot(entry.item) as unknown as ItemPlaintext, options.passphrase || undefined);
    const expiresAt = new Date(this.host.now() + options.expiresInHours * 3_600_000).toISOString();
    const created = await this.host.api().createShareLink({ ciphertext: link.ciphertext, expiresAt, maxViews: options.maxViews, passphraseRequired: link.passphraseRequired });
    const me = this.host.accountId();
    await this.host.store.setShareLinks(me, { ...(await this.host.store.shareLinks(me)), [created.id]: itemId });
    this.host.changed();
    return { id: created.id, key: link.key, expiresAt: created.expiresAt };
  }

  async list(): Promise<ShareLinkInfo[]> {
    const me = this.host.accountId();
    const [{ links }, sources] = await Promise.all([this.host.api().shareLinks(), this.host.store.shareLinks(me)]);
    // Links the server no longer has were used up, expired or revoked elsewhere.
    const open = Object.fromEntries(Object.entries(sources).filter(([id]) => links.some((l) => l.id === id)));
    if (Object.keys(open).length !== Object.keys(sources).length) await this.host.store.setShareLinks(me, open);
    const index = this.host.index();
    return links.map((link) => {
      const itemId = open[link.id];
      const item = itemId ? index.get(itemId)?.item : undefined;
      return { ...link, ...(item ? { itemId: item.id, itemTitle: item.overview.title } : {}) };
    });
  }

  async revoke(id: string): Promise<void> {
    try {
      await this.host.api().deleteShareLink(id);
    } catch (error) {
      // Already gone: used up or expired in the meantime, which is what revoking wanted.
      if (!isVaultError(error, 'notFound') && !(error instanceof ApiProblem && error.status === 404)) throw error;
    }
    const me = this.host.accountId();
    const { [id]: _gone, ...rest } = await this.host.store.shareLinks(me);
    await this.host.store.setShareLinks(me, rest);
    this.host.changed();
  }

  fetch(serverUrl: string, id: string): Promise<ShareLinkEnvelope> {
    return this.host.publicApi(serverOrigin(serverUrl)).viewShareLink(id);
  }

  async open(ciphertext: string, key: string, passphrase?: string): Promise<SharedItem> {
    const core = await this.host.core();
    const plain = core.openShareLink(ciphertext, key, passphrase || undefined);
    return { overview: plain.overview as unknown as ItemOverview, details: plain.details as unknown as ItemDetails };
  }
}
