import { VaultError } from '../errors';
import { hostnameOf, registrableDomain } from '../tools/url';
import type {
  AliasRef,
  Item,
  LoginDetails,
  MaskedAlias,
  MaskedEmailConnection,
  MaskedEmailContext,
  MaskedEmailProviderDetails,
  MaskedEmailProviderId,
  MaskedEmailService,
  VaultService,
} from '../types';
import { canManageAlias, changeProviderAlias, checkBaseUrl, createProviderAlias, fetchHttp, MaskedEmailError, providerInfo, type AliasAction, type AliasFor, type MaskedEmailHttp } from './providers';

export interface MaskedEmailOptions {
  context: MaskedEmailContext;
  /** Defaults to `fetch`. The apps pass their native HTTP client. */
  http?: MaskedEmailHttp;
}

type Vault = Pick<VaultService, 'listItems' | 'getItem' | 'saveItem' | 'deleteItem' | 'listVaults'>;

/** The site an alias is for, from a URL or a bare host. */
export function aliasSite(site: string): AliasFor {
  const host = hostnameOf(site);
  if (!host) throw new VaultError('maskedEmailFailed', 'Enter a website for the alias.');
  return { domain: registrableDomain(host), origin: `https://${host}` };
}

/** Whether a provider's API can be called from here: web pages only reach providers that answer CORS. */
export function usableIn(context: MaskedEmailContext, provider: MaskedEmailProviderId, baseUrl?: string): boolean {
  // A self-hosted server may allow this page; the call will tell.
  return context !== 'browser' || providerInfo(provider).cors || Boolean(baseUrl);
}

class Service implements MaskedEmailService {
  private readonly http: MaskedEmailHttp;

  constructor(
    private readonly vault: Vault,
    readonly context: MaskedEmailContext,
    http: MaskedEmailHttp | undefined,
  ) {
    this.http = http ?? fetchHttp();
  }

  private connection(item: Item): MaskedEmailConnection {
    const { provider, baseUrl, domain } = item.details as MaskedEmailProviderDetails;
    return { itemId: item.id, provider, ...(baseUrl ? { baseUrl } : {}), ...(domain ? { domain } : {}), usableHere: usableIn(this.context, provider, baseUrl) };
  }

  private async items(): Promise<Item[]> {
    const summaries = await this.vault.listItems({ type: 'maskedEmailProvider' });
    const items = await Promise.all(summaries.map((s) => this.vault.getItem(s.id)));
    // Oldest first, so the first connected provider stays the default.
    return items.sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));
  }

  async listConnections(): Promise<MaskedEmailConnection[]> {
    return (await this.items()).map((item) => this.connection(item));
  }

  async connect(input: { provider: MaskedEmailProviderId; token: string; baseUrl?: string; domain?: string }): Promise<MaskedEmailConnection> {
    const info = providerInfo(input.provider);
    const token = input.token.trim();
    const domain = input.domain?.trim().toLowerCase().replace(/^@/, '');
    const baseUrl = input.baseUrl?.trim() ? checkBaseUrl(input.baseUrl) : undefined;
    if (!token) throw new MaskedEmailError('maskedEmailToken');
    if (info.needsDomain && !domain) throw new MaskedEmailError('maskedEmailFailed', `${info.name} needs a domain for new aliases.`);
    const vaults = await this.vault.listVaults();
    const personal = vaults.find((v) => v.type === 'personal') ?? vaults[0];
    if (!personal) throw new VaultError('notFound');
    const details: MaskedEmailProviderDetails = {
      schemaVersion: 1,
      provider: info.id,
      token,
      ...(baseUrl && baseUrl !== info.defaultBaseUrl ? { baseUrl } : {}),
      ...(domain ? { domain } : {}),
    };
    const subtitle = domain ?? (details.baseUrl ? new URL(details.baseUrl).host : undefined);
    const item = await this.vault.saveItem({
      vaultId: personal.id,
      overview: { schemaVersion: 1, type: 'maskedEmailProvider', title: info.name, ...(subtitle ? { subtitle } : {}) },
      details,
    });
    return this.connection(item);
  }

  async disconnect(itemId: string): Promise<void> {
    const item = await this.vault.getItem(itemId);
    if (item.overview.type !== 'maskedEmailProvider') throw new VaultError('notFound');
    await this.vault.deleteItem(itemId);
  }

  async createAlias(input: { site: string; connectionId?: string }): Promise<MaskedAlias> {
    const site = aliasSite(input.site);
    const items = await this.items();
    let item: Item | undefined;
    if (input.connectionId) {
      item = items.find((i) => i.id === input.connectionId);
      if (!item) throw new MaskedEmailError('maskedEmailNotSetUp');
    } else {
      item = items.find((i) => this.connection(i).usableHere) ?? items[0];
      if (!item) throw new MaskedEmailError('maskedEmailNotSetUp');
    }
    const details = item.details as MaskedEmailProviderDetails;
    if (!usableIn(this.context, details.provider, details.baseUrl)) throw new MaskedEmailError('maskedEmailBlocked', providerInfo(details.provider).name);
    return createProviderAlias(this.http, details, site);
  }

  private async change(alias: AliasRef, action: AliasAction): Promise<void> {
    if (!canManageAlias(alias.provider, alias.aliasId, alias.email)) throw new MaskedEmailError('maskedEmailFailed', `${providerInfo(alias.provider).name} can only do this on its own site.`);
    const items = await this.items();
    const matches = items.filter((item) => (item.details as MaskedEmailProviderDetails).provider === alias.provider);
    const item = matches.find((i) => this.connection(i).usableHere) ?? matches[0];
    if (!item) throw new MaskedEmailError('maskedEmailNotSetUp');
    const details = item.details as MaskedEmailProviderDetails;
    if (!usableIn(this.context, details.provider, details.baseUrl)) throw new MaskedEmailError('maskedEmailBlocked', providerInfo(details.provider).name);
    await changeProviderAlias(this.http, details, alias.aliasId, action);
  }

  setAliasEnabled(alias: AliasRef, enabled: boolean): Promise<void> {
    return this.change(alias, enabled ? 'enable' : 'disable');
  }

  async deleteAlias(alias: AliasRef, loginIds: readonly string[]): Promise<void> {
    await this.change(alias, 'delete');
    // The address stays on the logins as plain text: it's still what the site has. Only the link
    // to an alias that no longer exists goes.
    await Promise.all(
      loginIds.map(async (id) => {
        const item = await this.vault.getItem(id);
        const details = item.details as LoginDetails;
        const source = details.recovery?.emailSource;
        if (source?.kind !== 'alias' || source.provider !== alias.provider || source.aliasId !== alias.aliasId) return;
        const { emailSource: _unlinked, ...recovery } = details.recovery!;
        await this.vault.saveItem({ id: item.id, vaultId: item.vaultId, revision: item.revision, overview: item.overview, details: { ...details, recovery } });
      }),
    );
  }
}

export function createMaskedEmailService(vault: Vault, options: MaskedEmailOptions): MaskedEmailService {
  return new Service(vault, options.context, options.http);
}
