// "Use a masked email" in sign-up forms (plan 06, Phase A). The service worker asks the user's own
// provider for an alias, straight from here (extension pages and the worker aren't held to CORS);
// the page fills it, and the login saved for that site next gets it as its recovery email.

import { createMaskedEmailService, type MaskedAlias, type MaskedEmailHttp, type MaskedEmailService, type RecoveryInfo, type VaultService } from '@octapass/vault-client';
import type { Matcher } from './matching';
import type { PageSender } from './senders';
import type { VaultHost } from './vault';

/** A sign-up takes a while: an alias still links to the login saved this long after it was made. */
const LINK_TTL_MS = 30 * 60_000;

export class MaskedEmailFiller {
  private readonly service: MaskedEmailService;
  private readonly recent = new Map<number, { alias: MaskedAlias; site: string | undefined; at: number }>();

  constructor(
    private readonly host: VaultHost,
    private readonly matcher: Matcher,
    http?: MaskedEmailHttp,
    private readonly now: () => number = Date.now,
  ) {
    const vault: Pick<VaultService, 'listItems' | 'getItem' | 'saveItem' | 'deleteItem' | 'listVaults'> = {
      listItems: (filter) => host.engine.call('listItems', [filter ?? {}]),
      getItem: (id) => host.getItem(id),
      saveItem: (draft) => host.engine.call('saveItem', [draft]),
      deleteItem: (id) => host.engine.call('deleteItem', [id]),
      listVaults: () => host.engine.call('listVaults', []),
    };
    this.service = createMaskedEmailService(vault, { context: 'extension', ...(http ? { http } : {}) });
  }

  /** A provider is connected. Not in a vault on this device only: masked email needs an account. */
  async available(): Promise<boolean> {
    if (!this.host.unlocked || this.host.local) return false;
    return (await this.service.listConnections()).length > 0;
  }

  /** Makes an alias for the page and remembers it for this tab, to link the login saved next. */
  async create(sender: PageSender): Promise<MaskedAlias> {
    const alias = await this.service.createAlias({ site: sender.url });
    this.recent.set(sender.tabId, { alias, site: this.matcher.site(sender.url), at: this.now() });
    return alias;
  }

  /** The recovery info linking a login saved on this tab and site, when its username is the alias made there. */
  linkFor(tabId: number, url: string, username: string | undefined): Pick<RecoveryInfo, 'email' | 'emailSource'> | undefined {
    const made = this.recent.get(tabId);
    if (!made || this.now() - made.at > LINK_TTL_MS || made.site !== this.matcher.site(url)) return undefined;
    if (username?.trim().toLowerCase() !== made.alias.email.toLowerCase()) return undefined;
    const { email, provider, aliasId } = made.alias;
    return { email, emailSource: { kind: 'alias', provider, aliasId } };
  }
}
