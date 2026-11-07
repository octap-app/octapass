// Saving addresses and cards the user types into websites, like logins (`saves.ts`): the engine reports
// a submitted address or card form, and the page asks "Save this address?" or "Save this card?", or
// offers to update the Identity or Card that clearly matches. Only from secure pages (https, or the
// user's own machine); frames from other sites need the user's approval first, like everything else.
//
// A card number never leaves the service worker again: prompts name the card by brand and last four
// digits. A security code is kept only if the user ticks "Also save the security code" (plan 05 fills
// it only after re-authentication, so storing it is the user's choice), and is forgotten with the prompt.
//
// While Octa Pass is locked the prompt is always "Save", and a Save goes into the inbox (`inbox.ts`):
// at the next unlock it's merged by the same rules, a new address or card tagged "Unconfirmed".

import type { AddressValues, CardValues } from '@octapass/autofill';
import { detectCardBrand } from '@octapass/web/src/screens/vault/editorModel';
import { normalizeEmail, type Address, type CardDetails, type IdentityDetails, type Item, type ItemDraft } from '@octapass/vault-client';
import type { ContentRequest, SaveAnswer, SavePrompt, SaveResponse } from '../shared/messages';
import { webPage, type Matcher } from './matching';
import { forReview, type OpenedInboxEntry, type SaveInbox } from './inbox';
import type { NeverSave } from './neverSave';
import { PROMPT_TTL_MS } from './saves';
import type { PageSender } from './senders';
import type { VaultHost } from './vault';

type Report = Extract<ContentRequest, { type: 'saveDetails' }>['report'];

interface Pending {
  prompt: SavePrompt;
  url: string;
  at: number;
  itemId?: string;
  identity?: IdentityDetails;
  card?: CardDetails;
  /** The security code typed with the card, saved only if the user ticks the box. */
  code?: string;
  /** Asked while locked: compared with the vault only when it's saved. */
  locked?: boolean;
}

const isLocal = (hostname: string) => hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '127.0.0.1' || hostname === '[::1]';

/** https, or the user's own machine (what browsers treat as a secure context). */
export function securePage(url: string): URL | undefined {
  const page = webPage(url);
  return page && (page.protocol === 'https:' || isLocal(page.hostname)) ? page : undefined;
}

const fold = (text: string | undefined) => (text ?? '').toLowerCase().normalize('NFKD').replace(/[\s.,#-]/g, '');

/** The identity details in an address form. A single name is split on its last space. */
export function identityFrom(values: AddressValues): IdentityDetails {
  const words = values.name?.trim().split(/\s+/) ?? [];
  const firstName = values['given-name'] ?? (words.length > 1 ? words.slice(0, -1).join(' ') : words[0]);
  const lastName = values['family-name'] ?? (words.length > 1 ? words[words.length - 1] : undefined);
  const address: Address = {
    ...(values['address-line1'] ? { line1: values['address-line1'] } : {}),
    ...(values['address-line2'] ? { line2: values['address-line2'] } : {}),
    ...(values['address-level2'] ? { city: values['address-level2'] } : {}),
    ...(values['address-level1'] ? { region: values['address-level1'] } : {}),
    ...(values['postal-code'] ? { postalCode: values['postal-code'] } : {}),
    ...(values.country ? { country: values.country } : {}),
  };
  return {
    schemaVersion: 1,
    ...(firstName ? { firstName } : {}),
    ...(lastName ? { lastName } : {}),
    ...(values.email ? { email: values.email } : {}),
    ...(values.tel ? { phone: values.tel } : {}),
    ...(Object.keys(address).length ? { address } : {}),
  };
}

/** The card details in a card form, without the security code. */
export function cardFrom(values: CardValues): CardDetails {
  const brand = values['cc-number'] && detectCardBrand(values['cc-number']);
  return {
    schemaVersion: 1,
    ...(values['cc-name'] ? { cardholder: values['cc-name'] } : {}),
    ...(values['cc-number'] ? { number: values['cc-number'] } : {}),
    ...(values['cc-exp'] ? { expiry: values['cc-exp'] } : {}),
    ...(brand ? { brand } : {}),
  };
}

const digits = (number: string | undefined) => number?.replace(/\D/g, '') ?? '';

/** Same email, or the same street line in the same postcode (or city). */
function sameIdentity(saved: IdentityDetails, typed: IdentityDetails): boolean {
  if (saved.email && typed.email && normalizeEmail(saved.email) === normalizeEmail(typed.email)) return true;
  const a = saved.address;
  const b = typed.address;
  if (!a?.line1 || !b?.line1 || fold(a.line1) !== fold(b.line1)) return false;
  return (!!a.postalCode && fold(a.postalCode) === fold(b.postalCode)) || (!!a.city && fold(a.city) === fold(b.city));
}

/** Equal apart from case, spaces and punctuation: `N1 9GU` is `n1 9gu`, `4242 4242…` is `42424242…`. */
const same = (a: unknown, b: unknown) => (typeof a === 'string' && typeof b === 'string' ? fold(a) === fold(b) : a === b);

/**
 * What the saved item would gain or change: only fields the form had are compared, nothing is removed,
 * and a value that's only written differently keeps the saved spelling.
 */
function merge<T extends object>(saved: T, typed: Partial<T>): { merged: T; changed: boolean } {
  const merged = { ...saved } as Record<string, unknown>;
  let changed = false;
  for (const [key, value] of Object.entries(typed)) {
    if (key === 'schemaVersion' || value === undefined) continue;
    if (value && typeof value === 'object') {
      const inner = merge((merged[key] ?? {}) as object, value as object);
      merged[key] = inner.merged;
      changed ||= inner.changed;
    } else if (!same(merged[key], value)) {
      merged[key] = value;
      changed = true;
    }
  }
  return { merged: merged as T, changed };
}

function oneLine(details: IdentityDetails): string {
  const name = [details.firstName, details.lastName].filter(Boolean).join(' ');
  return [name, details.address?.line1, details.address?.city ?? details.address?.postalCode].filter(Boolean).join(', ');
}

export class DetailsSaver {
  private readonly pending = new Map<number, Pending>();

  constructor(
    private readonly host: VaultHost,
    private readonly matcher: Pick<Matcher, 'site'>,
    private readonly never: NeverSave,
    private readonly now: () => number = Date.now,
    /** Where a Save goes while the vault is locked. */
    private readonly inbox?: Pick<SaveInbox, 'accepts' | 'add' | 'mergers'>,
  ) {
    if (inbox) inbox.mergers.card = inbox.mergers.identity = (entry) => this.mergeSaved(entry);
  }

  async report(report: Report, sender: PageSender): Promise<SaveResponse> {
    const page = securePage(sender.url);
    if (!page || (await this.never.has(report.kind, sender.url))) return null;
    if (!this.host.unlocked && !(this.inbox && (await this.inbox.accepts()))) return null;
    const pending = !this.host.unlocked
      ? lockedPrompt(report)
      : report.kind === 'card'
        ? await this.card(report.values)
        : await this.identity(report.values);
    if (!pending) return null;
    const prompt: SavePrompt = { ...pending.prompt, id: crypto.randomUUID(), host: page.hostname };
    this.pending.set(sender.tabId, { ...pending, prompt, url: sender.url, at: this.now() });
    return { prompt };
  }

  private async card(values: CardValues): Promise<Omit<Pending, 'url' | 'at'> | undefined> {
    const typed = cardFrom(values);
    const number = digits(typed.number);
    if (!number) return undefined;
    const existing = await this.find('card', (details: CardDetails) => digits(details.number) === number);
    // The brand comes from the number, so it alone is no reason to ask.
    const { brand, ...rest } = typed;
    const { merged, changed } = existing ? merge(existing.details as CardDetails, rest) : { merged: typed, changed: true };
    if (!changed) return undefined;
    if (brand && !merged.brand) merged.brand = brand;
    const code = values['cc-csc'];
    return {
      prompt: {
        id: '',
        host: '',
        kind: existing ? 'update' : 'save',
        item: 'card',
        card: { last4: number.slice(-4), ...(typed.brand ? { brand: typed.brand } : {}), ...(typed.expiry ? { expiry: typed.expiry } : {}) },
        ...(code ? { offerCode: true } : {}),
      },
      card: merged,
      ...(code ? { code } : {}),
      ...(existing ? { itemId: existing.id } : {}),
    };
  }

  private async identity(values: AddressValues): Promise<Omit<Pending, 'url' | 'at'> | undefined> {
    const typed = identityFrom(values);
    const existing = await this.find('identity', (details: IdentityDetails) => sameIdentity(details, typed));
    const { merged, changed } = existing ? merge(existing.details as IdentityDetails, typed) : { merged: typed, changed: true };
    if (!changed) return undefined;
    return {
      prompt: { id: '', host: '', kind: existing ? 'update' : 'save', item: 'identity', address: oneLine(typed) },
      identity: merged,
      ...(existing ? { itemId: existing.id } : {}),
    };
  }

  private async find<T>(type: 'card' | 'identity', matches: (details: T) => boolean): Promise<Item | undefined> {
    for (const summary of await this.host.listItems()) {
      if (summary.type !== type || summary.deletedAt) continue;
      const item = await this.host.getItem(summary.id).catch(() => undefined);
      if (item && !item.deletedAt && matches(item.details as T)) return item;
    }
    return undefined;
  }

  /** The prompt waiting for this tab, if it's recent and the page is still on the same site. */
  waiting(sender: PageSender): SavePrompt | null {
    const pending = this.pending.get(sender.tabId);
    if (!pending) return null;
    const fresh = this.now() - pending.at < PROMPT_TTL_MS && this.matcher.site(pending.url) === this.matcher.site(sender.url);
    if (!fresh) this.pending.delete(sender.tabId);
    return fresh ? pending.prompt : null;
  }

  async answer(id: string, answer: SaveAnswer, saveCode: boolean, sender: PageSender): Promise<void> {
    const pending = this.pending.get(sender.tabId);
    if (pending?.prompt.id !== id) return;
    this.pending.delete(sender.tabId);
    if (answer === 'never') await this.never.add(pending.prompt.item, pending.url);
    if (answer !== 'save') return;
    const details = pending.card ? { ...pending.card, ...(saveCode && pending.code ? { cvv: pending.code } : {}) } : pending.identity!;
    const kind = pending.card ? 'card' : 'identity';
    if (!this.host.unlocked) {
      await this.inbox?.add({ kind, url: pending.url, details });
      return;
    }
    // Asked while locked and unlocked since: compared with the vault now.
    if (pending.locked) return void (await this.mergeTyped(kind, details, false));
    const existing = pending.itemId ? await this.host.getItem(pending.itemId).catch(() => undefined) : undefined;
    await this.host.engine.call('saveItem', [existing ? updated(existing, details) : await this.created(kind, details)]);
  }

  /** An address or card from the inbox, at unlock. True once it's in the vault (or already was). */
  async mergeSaved(entry: OpenedInboxEntry): Promise<boolean> {
    if ((entry.kind !== 'card' && entry.kind !== 'identity') || !entry.details || typeof entry.details !== 'object') return true;
    await this.mergeTyped(entry.kind, entry.details as CardDetails | IdentityDetails, true);
    return true;
  }

  /**
   * Saves what was typed by the prompt's rules: the card with that number, or the address that clearly
   * matches, gains or changes only the fields typed (nothing changes: nothing is saved); otherwise a
   * new item, tagged for review when it comes from the inbox.
   */
  private async mergeTyped(kind: 'card' | 'identity', typed: CardDetails | IdentityDetails, review: boolean): Promise<void> {
    let existing: Item | undefined;
    if (kind === 'card') {
      const number = digits((typed as CardDetails).number);
      if (!number) return;
      existing = await this.find('card', (details: CardDetails) => digits(details.number) === number);
    } else {
      existing = await this.find('identity', (details: IdentityDetails) => sameIdentity(details, typed as IdentityDetails));
    }
    if (existing) {
      // The brand comes from the number, so it alone is no change.
      const { brand: _brand, ...rest } = typed as CardDetails;
      const { merged, changed } = merge(existing.details as CardDetails | IdentityDetails, kind === 'card' ? rest : typed);
      if (changed) await this.host.engine.call('saveItem', [updated(existing, merged)]);
      return;
    }
    const draft = await this.created(kind, typed);
    await this.host.engine.call('saveItem', [review ? forReview(draft) : draft]);
  }

  private async created(kind: 'card' | 'identity', details: CardDetails | IdentityDetails): Promise<ItemDraft> {
    const vaults = await this.host.engine.call('listVaults', []);
    const personal = vaults.find((v) => v.type === 'personal') ?? vaults[0]!;
    if (kind === 'card') {
      const card = details as CardDetails;
      const ending = `${card.brand ?? 'Card'} ending ${digits(card.number).slice(-4)}`;
      return {
        vaultId: personal.id,
        overview: { schemaVersion: 1, title: ending, type: 'card', subtitle: card.cardholder ?? ending },
        details: card,
      };
    }
    const identity = details as IdentityDetails;
    const name = [identity.firstName, identity.lastName].filter(Boolean).join(' ');
    const title = [identity.address?.line1, identity.address?.city].filter(Boolean).join(', ') || name || 'Address';
    return {
      vaultId: personal.id,
      overview: { schemaVersion: 1, title, type: 'identity', ...(name || identity.email ? { subtitle: name || identity.email } : {}) },
      details: identity,
    };
  }
}

/** The prompt while locked: always "Save", since nothing can be compared with the vault. */
function lockedPrompt(report: Report): Omit<Pending, 'url' | 'at'> | undefined {
  if (report.kind === 'card') {
    const card = cardFrom(report.values);
    const number = digits(card.number);
    if (!number) return undefined;
    const code = report.values['cc-csc'];
    return {
      prompt: {
        id: '',
        host: '',
        kind: 'save',
        item: 'card',
        locked: true,
        card: { last4: number.slice(-4), ...(card.brand ? { brand: card.brand } : {}), ...(card.expiry ? { expiry: card.expiry } : {}) },
        ...(code ? { offerCode: true } : {}),
      },
      card,
      locked: true,
      ...(code ? { code } : {}),
    };
  }
  const identity = identityFrom(report.values);
  return { prompt: { id: '', host: '', kind: 'save', item: 'identity', locked: true, address: oneLine(identity) }, identity, locked: true };
}

function updated(existing: Item, details: CardDetails | IdentityDetails): ItemDraft {
  return { id: existing.id, vaultId: existing.vaultId, revision: existing.revision, overview: existing.overview, details };
}
