// "Add login.example.com to this login?" (plan 05, Filling rules). A login saved for another part of
// the page's site is filled only when the user picks it from "Logins for other parts of example.com";
// then Octa Pass offers to add the page's website to it, so next time it's the page's own login.
// Offered only for a vault the user can change and a login without that website yet, and added
// through the usual item save with each website kept once.

import { hasWebsite, withUniqueWebsites, type Item } from '@octapass/vault-client';
import type { WebsiteAnswer, WebsitePrompt } from '../shared/messages';
import type { Matcher } from './matching';
import type { VaultHost } from './vault';

/** An offer still shows for this long after the fill. */
export const WEBSITE_PROMPT_TTL_MS = 2 * 60_000;

interface Pending {
  prompt: WebsitePrompt;
  itemId: string;
  website: string;
  at: number;
}

export class WebsiteAdder {
  /** One offer per tab: the last fill's. */
  private readonly pending = new Map<number, Pending>();

  constructor(
    private readonly host: VaultHost,
    private readonly matcher: Matcher,
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * After `item`, a login for another part of the site, was filled into `pageUrl` on `tabId`: the
   * offer to add the page's website, or null when there's nothing to offer.
   */
  async offer(item: Item, pageUrl: string, tabId: number): Promise<WebsitePrompt | null> {
    this.pending.delete(tabId);
    const website = this.matcher.website(pageUrl);
    if (!website || item.deletedAt || hasWebsite(item.overview.urls ?? [], item.overview.urlMatch, website)) return null;
    if (!(await this.writable(item.vaultId))) return null;
    const prompt: WebsitePrompt = { id: crypto.randomUUID(), host: new URL(website).hostname.replace(/^www\./, ''), title: item.overview.title };
    this.pending.set(tabId, { prompt, itemId: item.id, website, at: this.now() });
    return prompt;
  }

  /** The offer waiting after `itemId` was filled in this tab, while the page is still on that website. */
  waiting(tabId: number, itemId: string, pageUrl: string): WebsitePrompt | null {
    const pending = this.pending.get(tabId);
    if (!pending || pending.itemId !== itemId) return null;
    if (this.now() - pending.at >= WEBSITE_PROMPT_TTL_MS) {
      this.pending.delete(tabId);
      return null;
    }
    return this.matcher.website(pageUrl) === pending.website ? pending.prompt : null;
  }

  /** The user's answer. True once the login has the website (added now, or already there). */
  async answer(id: string, answer: WebsiteAnswer, tabId: number): Promise<boolean> {
    const pending = this.pending.get(tabId);
    if (pending?.prompt.id !== id) return false;
    this.pending.delete(tabId);
    if (answer !== 'add' || !this.host.unlocked) return false;
    try {
      const item = await this.host.getItem(pending.itemId);
      if (item.deletedAt) return false;
      const urls = item.overview.urls ?? [];
      if (hasWebsite(urls, item.overview.urlMatch, pending.website)) return true;
      if (!(await this.writable(item.vaultId))) return false;
      const overview = withUniqueWebsites({ ...item.overview, urls: [...urls, pending.website] });
      await this.host.engine.call('saveItem', [{ id: item.id, vaultId: item.vaultId, revision: item.revision, overview, details: item.details }]);
      return true;
    } catch {
      return false;
    }
  }

  private async writable(vaultId: string): Promise<boolean> {
    const vaults = await this.host.engine.call('listVaults', []).catch(() => []);
    const vault = vaults.find((v) => v.id === vaultId);
    return !!vault && vault.role !== 'read' && !vault.untrusted;
  }
}
