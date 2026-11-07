// API keys pasted into websites, and the keys the in-page menu fills (plan 16, Browser extension).
//
// Saving: the content script recognises a key on the device and asks here, naming only what kind it is,
// whether to offer. The value stays in the content script until the user chooses Save; if they don't,
// it never reaches this worker. So unlike a login, nothing can be compared with the vault before asking:
// a key that's already saved is only noticed when Save is clicked, and then nothing is added. While
// Octa Pass is locked a Save goes into the inbox (`inbox.ts`) and is added, tagged "Unconfirmed", at
// the next unlock, unless the vault has the key by then.
//
// Filling: an `apiCredential` item follows the login rules exactly, through the same matcher, with the
// same gesture, frame and device-auth checks in `content.ts`.

import { API_KEY_SERVICES, type ApiKeyKind, type FillValues } from '@octapass/autofill';
import { HOSTED_WEB_VAULT_URL, type ApiCredentialDetails, type Item, type ItemDraft } from '@octapass/vault-client';
import type { SaveAnswer, SavePrompt, SaveResponse } from '../shared/messages';
import { securePage } from './detailsSaves';
import { forReview, type OpenedInboxEntry, type SaveInbox } from './inbox';
import type { Matcher } from './matching';
import type { NeverSave } from './neverSave';
import { PROMPT_TTL_MS } from './saves';
import type { PageSender } from './senders';
import type { VaultHost } from './vault';

/** "Offer to save API keys", kept by the popup in `chrome.storage.local`, per device. On unless set to false. */
export const API_KEY_OFFERS_KEY = 'octapass:apiKeyOffers';

export async function apiKeyOffersEnabled(): Promise<boolean> {
  try {
    return (await chrome.storage.local.get(API_KEY_OFFERS_KEY))[API_KEY_OFFERS_KEY] !== false;
  } catch {
    return false;
  }
}

const MAX_CREDENTIAL_LENGTH = 8192;

const originOf = (url: string | undefined) => {
  try {
    return url ? new URL(url).origin : undefined;
  } catch {
    return undefined;
  }
};

/** The value an item fills, or undefined when it has none to give. `nowSeconds`: Unix time, as `expiresAt`. */
export function credentialValue(details: ApiCredentialDetails, nowSeconds: number): string | undefined {
  const { accessToken, expiresAt } = details.oauth2 ?? {};
  // A token with no recorded expiry can't be said to have expired; a garbled expiry can't be trusted.
  if (accessToken && (expiresAt === undefined || (typeof expiresAt === 'number' && expiresAt > nowSeconds))) return accessToken;
  // `key` first: it's the field people edit, so `credential` may be an older copy of it.
  return details.key || details.credential || details.secret || undefined;
}

/** The value to fill, only when the item is saved for `pageUrl`, by the rule logins use. */
export function apiCredentialFillValues(matcher: Pick<Matcher, 'belongs'>, item: Item, pageUrl: string, nowMs = Date.now()): FillValues | null {
  if (item.deletedAt || item.overview.type !== 'apiCredential' || !matcher.belongs(item.overview, pageUrl)) return null;
  const value = credentialValue(item.details as ApiCredentialDetails, Math.floor(nowMs / 1000));
  return value ? { 'api-credential': value } : null;
}

interface Pending {
  prompt: SavePrompt;
  url: string;
  kind: ApiKeyKind;
  at: number;
}

export class ApiKeySaver {
  private readonly pending = new Map<number, Pending>();

  constructor(
    private readonly host: VaultHost,
    private readonly matcher: Pick<Matcher, 'apiCredentials'>,
    private readonly never: Pick<NeverSave, 'has' | 'add'>,
    private readonly enabled: () => Promise<boolean> = apiKeyOffersEnabled,
    private readonly now: () => number = Date.now,
    /** Where a Save goes while the vault is locked. */
    private readonly inbox?: Pick<SaveInbox, 'accepts' | 'add' | 'mergers'>,
  ) {
    if (inbox) inbox.mergers.apiKey = (entry) => this.mergeSaved(entry);
  }

  /** Octa Pass's own web vault: the hosted one, and the one a self-hosted server serves itself. */
  private isWebVault(origin: string): boolean {
    return origin === originOf(HOSTED_WEB_VAULT_URL) || origin === originOf(this.host.snapshot.session.serverUrl);
  }

  /** Whether to ask. Only top frames, like the popup's fill, and only pages that are safe to name as the key's site. */
  async offer(kind: ApiKeyKind, sender: PageSender): Promise<SaveResponse> {
    const page = securePage(sender.url);
    const known = kind === 'generic' || Object.hasOwn(API_KEY_SERVICES, kind);
    if (!known || !page || sender.frameId !== 0 || this.isWebVault(page.origin)) return null;
    if (!(await this.enabled()) || (await this.never.has('apiKey', sender.url))) return null;
    if (!this.host.unlocked && !(this.inbox && (await this.inbox.accepts()))) return null;
    const prompt: SavePrompt = {
      id: crypto.randomUUID(),
      kind: 'save',
      item: 'apiKey',
      host: page.hostname,
      ...(this.host.unlocked ? {} : { locked: true }),
      ...(kind === 'generic' ? {} : { service: API_KEY_SERVICES[kind] }),
    };
    this.pending.set(sender.tabId, { prompt, url: sender.url, kind, at: this.now() });
    return { prompt };
  }

  /** The user's answer, with the key only if it was Save. True once the key is in the vault. */
  async answer(id: string, answer: SaveAnswer, credential: string | undefined, sender: PageSender): Promise<boolean> {
    const pending = this.pending.get(sender.tabId);
    if (pending?.prompt.id !== id) return false;
    this.pending.delete(sender.tabId);
    // The key belongs to the page it was pasted into, not to wherever the tab is now.
    if (new URL(pending.url).origin !== sender.origin) return false;
    if (answer === 'never') await this.never.add('apiKey', pending.url);
    if (answer !== 'save' || this.now() - pending.at >= PROMPT_TTL_MS) return false;
    if (typeof credential !== 'string' || !credential || credential.length > MAX_CREDENTIAL_LENGTH) return false;
    if (!this.host.unlocked) return (await this.inbox?.add({ kind: 'apiKey', url: pending.url, details: { kind: pending.kind, credential } })) ?? false;
    if (!(await this.alreadySaved(credential, pending.url))) await this.host.engine.call('saveItem', [await this.draft(pending, credential)]);
    return true;
  }

  /** An API key from the inbox, at unlock. True once it's in the vault (or already was). */
  async mergeSaved(entry: OpenedInboxEntry): Promise<boolean> {
    const { kind, credential } = (entry.details ?? {}) as { kind?: ApiKeyKind; credential?: unknown };
    const known = kind === 'generic' || (!!kind && Object.hasOwn(API_KEY_SERVICES, kind));
    if (!known || typeof credential !== 'string' || !credential || credential.length > MAX_CREDENTIAL_LENGTH || !securePage(entry.url)) return true;
    if (await this.alreadySaved(credential, entry.url)) return true;
    await this.host.engine.call('saveItem', [forReview(await this.draft({ url: entry.url, kind } as Pending, credential))]);
    return true;
  }

  private async alreadySaved(credential: string, url: string): Promise<boolean> {
    for (const summary of this.matcher.apiCredentials(await this.host.listItems(), url)) {
      const item = await this.host.getItem(summary.id).catch(() => undefined);
      const details = item?.details as ApiCredentialDetails | undefined;
      if (details && (details.key === credential || details.credential === credential)) return true;
    }
    return false;
  }

  private async draft({ url, kind }: Pending, credential: string): Promise<ItemDraft> {
    const page = new URL(url);
    const site = page.hostname.replace(/^www\./, '');
    const vaults = await this.host.engine.call('listVaults', []);
    const personal = vaults.find((v) => v.type === 'personal') ?? vaults[0]!;
    const details: ApiCredentialDetails = {
      schemaVersion: 1,
      credential,
      hostname: page.hostname,
      // The names the item editor reads and writes. See `credentialValue` for which one fills.
      key: credential,
      host: page.hostname,
      credentialType: kind === 'jwt' ? 'jwt' : 'apiKey',
    };
    return {
      vaultId: personal.id,
      overview: {
        schemaVersion: 1,
        title: `${kind === 'generic' ? 'API key' : API_KEY_SERVICES[kind]} (${site})`,
        type: 'apiCredential',
        urls: [page.origin],
        subtitle: page.hostname,
      },
      details,
    };
  }
}
