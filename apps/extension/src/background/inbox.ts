// Saving while locked (plan 03, Saving while locked; plan 05, Save/update). Encrypting into the
// vault needs the vault key, which only exists after an unlock, so what the user saves while Open
// Pass is locked goes into an inbox instead: sealed by the core to the account's own public keys,
// which this browser pinned at its last unlock. The worker can add to the inbox while locked but
// can't read it back. At the next unlock the engine opens it and it's merged into the vault:
//
// - logins by the core's rules (`planInboxMerge`): a new login is tagged "Unconfirmed" for review;
//   one that has the site and username already gets the new password, the old one going into its
//   history, and keeps its review mark as it was; exact duplicates are dropped;
// - addresses, cards and API keys by the rules their own save prompts use (`DetailsSaver`,
//   `ApiKeySaver`), new ones tagged "Unconfirmed" too.
//
// Merged and duplicate entries leave the inbox; an entry whose merge fails stays for the next
// unlock. The inbox lives in this browser only (its own IndexedDB), one per vault, and never syncs.

import type * as Full from '@octapass/core/full';
import type { Item, ItemDraft, LoginDetails } from '@octapass/vault-client';
import { loginDetails } from '@octapass/vault-client';
import type { Matcher } from './matching';
import { UNCONFIRMED_TAG } from './saves';
import type { KeyValueStore } from './storage';
import type { VaultHost } from './vault';

export type InboxEntry = Full.InboxEntry;
export type OpenedInboxEntry = Full.OpenedInboxEntry;

/** The core's inbox functions (`@octapass/core/full`). */
export type InboxCore = Pick<typeof Full, 'inboxAccepts' | 'inboxAdd' | 'inboxRemove' | 'planInboxMerge'>;

/** Merges one address, card or API key entry. True once it's in the vault (or already was). */
export type DetailsMerger = (entry: OpenedInboxEntry) => Promise<boolean>;

export interface MergeResult {
  /** New logins. */
  added: number;
  /** Logins that got a new password, and addresses, cards and API keys merged by their savers. */
  updated: number;
  duplicates: number;
  /** Entries that couldn't be merged this time; they stay in the inbox. */
  failed: number;
}

const site = (url: string) => {
  try {
    return new URL(url);
  } catch {
    return undefined;
  }
};

export class SaveInbox {
  private merging: Promise<MergeResult | undefined> | undefined;
  /** Merges addresses, cards and API keys, set by the savers that know their rules. */
  readonly mergers: Partial<Record<'identity' | 'card' | 'apiKey', DetailsMerger>> = {};

  constructor(
    private readonly host: VaultHost,
    private readonly store: KeyValueStore,
    private readonly core: () => Promise<InboxCore>,
    private readonly matcher: Pick<Matcher, 'logins' | 'otherLogins'>,
    private readonly now: () => number = Date.now,
  ) {}

  /** Where this vault's inbox is kept: one per account (or local vault); none when signed out. */
  private key(): string | undefined {
    if (this.host.local) return 'inbox:local';
    const { status, email, serverUrl } = this.host.snapshot.session;
    return status === 'signedOut' ? undefined : `inbox:${serverUrl}|${email}`;
  }

  private async read(key: string): Promise<string> {
    return (await this.store.get<string>(key)) ?? '';
  }

  /** Whether a save made now (locked) can go into the inbox: a key is pinned and there's room. */
  async accepts(): Promise<boolean> {
    const key = this.key();
    if (!key || this.host.unlocked) return false;
    return (await this.core()).inboxAccepts(await this.read(key));
  }

  /** Seals an entry into the inbox. False when there's no inbox to save to, or it's full. */
  async add(entry: Omit<InboxEntry, 'savedAt'>): Promise<boolean> {
    const key = this.key();
    if (!key) return false;
    const core = await this.core();
    const inbox = await this.read(key);
    const owner = (JSON.parse(inbox || '{}') as { key?: { owner?: string } }).key?.owner;
    if (!owner || !core.inboxAccepts(inbox)) return false;
    try {
      await this.store.set(key, core.inboxAdd(inbox, owner, { ...entry, savedAt: this.now() }));
      return true;
    } catch {
      return false;
    }
  }

  /** At every unlock: pins the vault's own public keys, then merges what's waiting. */
  unlocked(): Promise<MergeResult | undefined> {
    this.merging ??= this.pinAndMerge().finally(() => (this.merging = undefined));
    return this.merging;
  }

  private async pinAndMerge(): Promise<MergeResult | undefined> {
    const key = this.key();
    if (!key || !this.host.unlocked) return undefined;
    const pinned = await this.host.engine.call('pinInbox', [await this.read(key)]);
    await this.store.set(key, pinned);
    const opened = await this.host.engine.call('openInbox', [pinned]);
    if (!opened.entries.length && !opened.unreadable.length) return undefined;
    const result: MergeResult = { added: 0, updated: 0, duplicates: 0, failed: 0 };
    // Sealed to a key that isn't this vault's (or damaged): they'll never open, so they go.
    const done = [...opened.unreadable];
    const logins = opened.entries.filter((e) => e.kind === 'login');
    done.push(...(await this.mergeLogins(logins, result)));
    for (const entry of opened.entries.filter((e) => e.kind !== 'login')) {
      const merge = this.mergers[entry.kind as 'identity' | 'card' | 'apiKey'];
      const ok = merge ? await merge(entry).catch(() => false) : false;
      if (ok) {
        done.push(entry.id);
        result.updated++;
      } else result.failed++;
    }
    const core = await this.core();
    // Read again: a save while this ran (it can't happen unlocked, but a lock can race it) is kept.
    await this.store.set(key, core.inboxRemove(await this.read(key), done));
    return result;
  }

  /** Applies the core's plan for the login entries. Returns the ids that are done with. */
  private async mergeLogins(entries: OpenedInboxEntry[], result: MergeResult): Promise<string[]> {
    if (!entries.length) return [];
    const core = await this.core();
    const summaries = await this.host.listItems();
    const ids = new Set<string>();
    for (const entry of entries) {
      for (const summary of this.matcher.logins(summaries, entry.url)) ids.add(summary.id);
      for (const { item } of this.matcher.otherLogins(summaries, entry.url)) ids.add(item.id);
    }
    const logins: Full.InboxVaultLogin[] = [];
    for (const id of ids) {
      const item = await this.host.getItem(id).catch(() => undefined);
      const details = item && loginDetails(item);
      if (!item || !details) continue;
      logins.push({
        id,
        urls: item.overview.urls ?? [],
        ...(item.overview.urlMatch ? { urlMatch: item.overview.urlMatch as Full.InboxVaultLogin['urlMatch'] } : {}),
        ...(details.username ? { username: details.username } : {}),
        ...(details.password ? { password: details.password } : {}),
      });
    }
    const options = await this.matchOptions();
    const plan = core.planInboxMerge(entries, logins, options);
    const done = [...plan.duplicates];
    result.duplicates += plan.duplicates.length;
    for (const merge of plan.logins) {
      try {
        await this.applyLogin(merge);
        done.push(...merge.entryIds);
        if (merge.itemId) result.updated++;
        else result.added++;
      } catch {
        result.failed += merge.entryIds.length;
      }
    }
    return done;
  }

  private async matchOptions(): Promise<Full.MatchOptions | undefined> {
    const list = await this.host.engine.call('equivalentDomains', []).catch(() => undefined);
    return list ? { equivalentDomains: list.groups, excludedDefaults: list.excludedDefaults } : undefined;
  }

  /** One save per password, oldest first, so all but the newest land in the password history. */
  private async applyLogin(merge: Full.InboxLoginMerge): Promise<void> {
    let item: Item | undefined = merge.itemId ? await this.host.getItem(merge.itemId) : undefined;
    for (const password of merge.passwords) {
      item = (await this.host.engine.call('saveItem', [item ? withPassword(item, password) : await this.newLogin(merge, password)])) as Item;
    }
  }

  private async newLogin(merge: Full.InboxLoginMerge, password: string): Promise<ItemDraft> {
    const vaults = await this.host.engine.call('listVaults', []);
    const personal = vaults.find((v) => v.type === 'personal') ?? vaults[0]!;
    const page = site(merge.url);
    const title = merge.title ?? page?.hostname.replace(/^www\./, '') ?? merge.url;
    return {
      vaultId: personal.id,
      overview: {
        schemaVersion: 1,
        title,
        type: 'login',
        urls: [page && page.origin !== 'null' ? page.origin : merge.url],
        ...(merge.username ? { subtitle: merge.username } : {}),
        tags: [UNCONFIRMED_TAG],
      },
      details: { schemaVersion: 1, ...(merge.username ? { username: merge.username } : {}), password },
    };
  }
}

/** The login with a new password. Its tags stay as they are: an inbox entry never adds or removes the review mark. */
function withPassword(item: Item, password: string): ItemDraft {
  return {
    id: item.id,
    vaultId: item.vaultId,
    revision: item.revision,
    overview: item.overview,
    details: { ...(item.details as LoginDetails), password },
  };
}

/** A new item merged from the inbox: tagged for review, like a new login. */
export function forReview<T extends ItemDraft>(draft: T): T {
  const tags = (draft.overview.tags ?? []).filter((t) => t !== UNCONFIRMED_TAG);
  return { ...draft, overview: { ...draft.overview, tags: [...tags, UNCONFIRMED_TAG] } };
}
