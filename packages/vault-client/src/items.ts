import type { Attachment, EnvironmentDetails, Item, ItemDetails, ItemDetailsByType, ItemDraft, ItemFilter, ItemOverview, ItemSummary, ItemType, ItemVersion, LoginDetails } from './types';
import { SCHEMA_VERSION } from './types';
import { emptySshKey } from './sshKeys';
import { hotpCounter, isHotp, withHotpCounter } from './tools/totp';
import { emptyWifi } from './wifi';

export function isLoginLike(type: ItemType): type is 'login' | 'password' {
  return type === 'login' || type === 'password';
}

export function loginDetails(item: Pick<Item, 'overview' | 'details'>): LoginDetails | undefined {
  return isLoginLike(item.overview.type) ? (item.details as LoginDetails) : undefined;
}

export function emptyEnvironment(): EnvironmentDetails {
  return { schemaVersion: SCHEMA_VERSION, variables: [] };
}

export function emptyDetails<T extends ItemType>(type: T): ItemDetailsByType[T] {
  const details: ItemDetails =
    type === 'secureNote'
      ? { schemaVersion: SCHEMA_VERSION, notes: '' }
      : type === 'wifi'
        ? emptyWifi()
        : type === 'sshKey'
          ? emptySshKey()
          : type === 'environment'
            ? emptyEnvironment()
            : type === 'equivalentDomains'
              ? { schemaVersion: SCHEMA_VERSION, groups: [] }
              : type === 'custom' || type === 'customTemplate'
                ? ({ schemaVersion: SCHEMA_VERSION, fields: [] } as ItemDetails)
              : ({ schemaVersion: SCHEMA_VERSION } as ItemDetails);
  return details as ItemDetailsByType[T];
}

export function emptyDraft(type: ItemType, vaultId: string): ItemDraft {
  return { vaultId, overview: { schemaVersion: SCHEMA_VERSION, type, title: '' }, details: emptyDetails(type) };
}

export function summarizeItem(item: Item): ItemSummary {
  const login = loginDetails(item);
  const environment = item.overview.type === 'environment' ? (item.details as EnvironmentDetails) : undefined;
  return {
    id: item.id,
    vaultId: item.vaultId,
    type: item.overview.type,
    title: item.overview.title,
    subtitle: item.overview.subtitle,
    urls: item.overview.urls,
    ...(item.overview.urlMatch && { urlMatch: item.overview.urlMatch }),
    tags: item.overview.tags,
    favorite: item.overview.favorite === true,
    pinned: item.overview.pinned === true,
    ...(item.overview.places?.length && { places: item.overview.places }),
    ...(item.overview.place && { place: item.overview.place }),
    hasTotp: Boolean(login?.totp),
    hasPasskey: (login?.passkeys?.length ?? 0) > 0,
    project: environment?.project,
    stage: environment?.stage,
    variableKeys: environment?.variables.map((variable) => variable.key),
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    deletedAt: item.deletedAt,
  };
}

/** Case- and accent-insensitive search over what a list row shows. Secrets are never searched. */
export function matchesQuery(summary: ItemSummary, query: string): boolean {
  const fold = (text: string) => text.normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase();
  const terms = fold(query).split(/\s+/).filter(Boolean);
  // Environment variable names are searchable; their values never are.
  const haystack = fold([summary.title, summary.subtitle, ...(summary.urls ?? []), ...(summary.tags ?? []), ...(summary.variableKeys ?? [])].filter(Boolean).join(' '));
  return terms.every((term) => haystack.includes(term));
}

/** Item types that hold settings rather than things to list: shown only when asked for by type. */
export const HIDDEN_ITEM_TYPES: ReadonlySet<string> = new Set<string>(['maskedEmailProvider', 'healthSettings', 'equivalentDomains', 'usageStats', 'customTemplate', 'fileSafe', 'place']);

export function matchesFilter(summary: ItemSummary, filter: ItemFilter = {}): boolean {
  if (Boolean(filter.trash) !== Boolean(summary.deletedAt)) return false;
  if (filter.vaultId && summary.vaultId !== filter.vaultId) return false;
  if (filter.type ? summary.type !== filter.type : HIDDEN_ITEM_TYPES.has(summary.type)) return false;
  if (filter.favorites && !summary.favorite) return false;
  if (filter.pinned && !summary.pinned) return false;
  if (filter.passkeys && !summary.hasPasskey) return false;
  if (filter.totp && !summary.hasTotp) return false;
  return !filter.query || matchesQuery(summary, filter.query);
}

export function compareSummaries(a: ItemSummary, b: ItemSummary): number {
  if (a.deletedAt && b.deletedAt) return b.deletedAt.localeCompare(a.deletedAt);
  return a.title.localeCompare(b.title, undefined, { sensitivity: 'base', numeric: true }) || a.id.localeCompare(b.id);
}

/** Item types whose password changes are kept in `passwordHistory`. */
export function keepsPasswordHistory(type: ItemType): boolean {
  return isLoginLike(type) || type === 'wifi' || type === 'database';
}

/**
 * An edit of `previous`. Keeps the previous password in the item's history when a login's or
 * network's password changes (unless the draft has already added it, as an import does), and drops
 * the date the item last changed in the app it was imported from unless the draft sets a new one:
 * it changed here now.
 */
export function withPasswordHistory(previous: Item | undefined, next: ItemDraft, now: Date): ItemDraft {
  if (previous?.overview.updatedAt && next.overview.updatedAt === previous.overview.updatedAt) {
    const { updatedAt: _imported, ...overview } = next.overview;
    next = { ...next, overview };
  }
  if (!previous || !keepsPasswordHistory(next.overview.type) || !keepsPasswordHistory(previous.overview.type)) return next;
  const before = (previous.details as LoginDetails).password;
  const after = (next.details as LoginDetails).password;
  if (!before || before === after) return next;
  const history = (next.details as LoginDetails).passwordHistory ?? [];
  const lists = (entries: LoginDetails['passwordHistory']) => (entries ?? []).some((entry) => entry.password === before);
  if (lists(history) && !lists((previous.details as LoginDetails).passwordHistory)) return next;
  return {
    ...next,
    details: { ...(next.details as LoginDetails), passwordHistory: [{ password: before, changedAt: now.toISOString() }, ...history].slice(0, 20) },
  };
}

/**
 * The edit that makes a past version current. Only what the item said comes back: files and
 * passkeys stay as they are now (they live outside the version, and an old list could drop a
 * passkey the site still expects), the favourite and pinned flags stay, the password history keeps growing,
 * and a counter-based code never moves backwards, because the site won't take its old codes again.
 */
export function restoredVersion(current: Item, version: Pick<ItemVersion, 'overview' | 'details'>): ItemDraft {
  const { favorite, pinned } = current.overview;
  const { favorite: _old, pinned: _oldPin, ...overview } = version.overview;
  let details = version.details;
  if (isLoginLike(version.overview.type) && isLoginLike(current.overview.type)) {
    const now = current.details as LoginDetails;
    const { passkeys: _passkeys, passwordHistory: _history, ...old } = version.details as LoginDetails;
    const login: LoginDetails = { ...old, ...(now.passkeys && { passkeys: now.passkeys }), ...(now.passwordHistory && { passwordHistory: now.passwordHistory }) };
    if (old.totp && isHotp(old.totp) && isHotp(now.totp) && hotpCounter(now.totp!) > hotpCounter(old.totp)) login.totp = withHotpCounter(old.totp, hotpCounter(now.totp!));
    details = login;
  }
  return { id: current.id, vaultId: current.vaultId, revision: current.revision, overview: { ...overview, ...(favorite !== undefined && { favorite }), ...(pinned !== undefined && { pinned }) }, details };
}

/**
 * The dates an item shows: those from the app it was imported from where it has them, else the
 * sync record's. A login's or network's password changed at the later of its imported date and
 * its newest password history entry.
 */
export function itemDates(item: Item): { createdAt: string; updatedAt: string; lastUsedAt?: string; passwordChangedAt?: string } {
  // Wi-Fi networks keep a password and its history the way logins do.
  const login = keepsPasswordHistory(item.overview.type) ? (item.details as LoginDetails) : undefined;
  const changes = [login?.passwordChangedAt, ...(login?.passwordHistory ?? []).map((entry) => entry.changedAt)].filter(
    (date): date is string => Boolean(date) && !Number.isNaN(Date.parse(date!)),
  );
  const passwordChangedAt = changes.length ? changes.reduce((a, b) => (Date.parse(b) > Date.parse(a) ? b : a)) : undefined;
  return {
    createdAt: item.overview.createdAt ?? item.createdAt,
    updatedAt: item.overview.updatedAt ?? item.updatedAt,
    lastUsedAt: item.overview.lastUsedAt,
    passwordChangedAt: login?.password ? passwordChangedAt : undefined,
  };
}

export function attachmentsOf(item: Pick<Item, 'details'>): Attachment[] {
  // Environments and the other new types have no attachments; they keep whatever they were given.
  return (item.details as { attachments?: Attachment[] }).attachments ?? [];
}

/** The details with `attachments` set to `list`, or without the field when it's empty. */
export function withAttachments<T extends ItemDetails>(details: T, list: Attachment[]): T {
  const { attachments: _old, ...rest } = details as T & { attachments?: Attachment[] };
  return (list.length ? { ...rest, attachments: list } : rest) as T;
}

/**
 * Attachments change only through the attachment calls, never through an edit: a draft keeps the
 * stored item's list (`from`), or none for a new item, whatever list the editor had.
 */
export function keepAttachments<T extends Pick<ItemDraft, 'details'>>(draft: T, from: Pick<Item, 'details'> | undefined): T {
  return { ...draft, details: withAttachments(draft.details, from ? attachmentsOf(from) : []) };
}

/**
 * What a share link carries: the item as it is now, without its old passwords, with no favourite
 * or pinned flag and no attachments (their files can't be opened from a link). The recipient gets a copy of
 * the current secret, not its history.
 */
export function shareableSnapshot(item: Pick<Item, 'overview' | 'details'>): Pick<Item, 'overview' | 'details'> {
  const { favorite: _favorite, pinned: _pinned, ...overview } = item.overview;
  const { passwordHistory: _history, attachments: _files, ...details } = item.details as LoginDetails;
  return structuredClone({ overview, details: details as Item['details'] });
}

/** The overview without the pinned flag: a copy in another vault starts unpinned, as it starts as no favourite. */
export function withoutPin(overview: ItemOverview): ItemOverview {
  const { pinned: _pinned, ...rest } = overview;
  return rest;
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function normalizePassword(password: string): string {
  return password.normalize('NFKD');
}

export function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
