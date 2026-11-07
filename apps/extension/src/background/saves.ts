// Saving what the user types into websites (plan 05, Save/update and Suggested strong passwords).
// A suggested password is saved at once as an "Unconfirmed" draft, so it can't be lost; a later
// submit with the same password confirms it. Anything else becomes a prompt the user answers, which
// waits here so it can still be shown after the page navigates away.
//
// While Octa Pass is locked nothing can be compared with the vault, so the prompt is always "Save",
// and a Save goes into the inbox (`inbox.ts`, plan 03 Saving while locked), merged at the next unlock.

import type { SaveReport } from '@octapass/autofill';
import { loginDetails, normalizeEmail, type Item, type ItemDraft, type LoginDetails, type RecoveryInfo } from '@octapass/vault-client';
import type { SaveAnswer, SavePrompt, SaveResponse } from '../shared/messages';
import type { MaskedEmailFiller } from './maskedEmail';
import { webPage, type Matcher } from './matching';
import type { SaveInbox } from './inbox';
import type { NeverSave } from './neverSave';
import type { PageSender } from './senders';
import type { VaultHost } from './vault';

export const UNCONFIRMED_TAG = 'Unconfirmed';
/** A prompt still shows on the next page for this long. */
export const PROMPT_TTL_MS = 2 * 60_000;

interface Pending {
  prompt: SavePrompt;
  tabId: number;
  url: string;
  username?: string;
  password: string;
  itemId?: string;
  at: number;
  /** Asked while locked: compared with the vault only when it's saved. */
  locked?: boolean;
}

/** The alias as the login's recovery email, unless the login already names one. */
function withLink(details: LoginDetails, link: Pick<RecoveryInfo, 'email' | 'emailSource'> | undefined): Partial<LoginDetails> {
  return link && !details.recovery?.email ? { recovery: { ...details.recovery, ...link } } : {};
}

const sameUser = (a: string | undefined, b: string | undefined) => (a ? normalizeEmail(a) : '') === (b ? normalizeEmail(b) : '');

export class LoginSaver {
  private readonly pending = new Map<number, Pending>();

  constructor(
    private readonly host: VaultHost,
    private readonly matcher: Matcher,
    private readonly now: () => number = Date.now,
    /** Links a login saved with a masked email made on the same tab to that alias. */
    private readonly aliases?: Pick<MaskedEmailFiller, 'linkFor'>,
    private readonly never?: NeverSave,
    /** Where a Save goes while the vault is locked. */
    private readonly inbox?: Pick<SaveInbox, 'accepts' | 'add'>,
  ) {}

  async report(report: Omit<SaveReport, 'url'>, sender: PageSender): Promise<SaveResponse> {
    const page = webPage(sender.url);
    if (!page || !report.password) return null;
    if (!this.host.unlocked) return this.reportLocked(report, page, sender);
    const existing = await this.loginFor(sender.url, report.username);

    if (report.draft) {
      await this.save(existing, sender.url, report.username, report.password, true, sender.tabId);
      return { saved: 'draft' };
    }
    const details = existing && loginDetails(existing);
    if (existing && details?.password === report.password) {
      if (!existing.overview.tags?.includes(UNCONFIRMED_TAG)) return null;
      await this.save(existing, sender.url, report.username, report.password, false, sender.tabId);
      return { saved: 'confirmed' };
    }
    // Signing in with a login for another part of the site (filled from "Logins for other parts of …"):
    // it's saved already, and the offer to add this page to it is the question to ask, not a new login.
    if (!existing && (await this.otherPartHas(sender.url, report.username, report.password))) return null;
    if (await this.never?.has('login', sender.url)) return null;
    const prompt: SavePrompt = {
      id: crypto.randomUUID(),
      kind: existing ? 'update' : 'save',
      item: 'login',
      host: page.hostname,
      ...(report.username ? { username: report.username } : {}),
    };
    this.pending.set(sender.tabId, {
      prompt,
      tabId: sender.tabId,
      url: sender.url,
      password: report.password,
      at: this.now(),
      ...(report.username ? { username: report.username } : {}),
      ...(existing ? { itemId: existing.id } : {}),
    });
    return { prompt };
  }

  /**
   * Locked: no lookup is possible, so it's always "Save" (the merge at unlock sorts out updates and
   * duplicates). A suggested-password draft waits for the submit, which asks like any other.
   */
  private async reportLocked(report: Omit<SaveReport, 'url'>, page: URL, sender: PageSender): Promise<SaveResponse> {
    if (report.draft || !this.inbox || (await this.never?.has('login', sender.url)) || !(await this.inbox.accepts())) return null;
    const prompt: SavePrompt = {
      id: crypto.randomUUID(),
      kind: 'save',
      item: 'login',
      host: page.hostname,
      locked: true,
      ...(report.username ? { username: report.username } : {}),
    };
    this.pending.set(sender.tabId, {
      prompt,
      tabId: sender.tabId,
      url: sender.url,
      password: report.password!,
      at: this.now(),
      locked: true,
      ...(report.username ? { username: report.username } : {}),
    });
    return { prompt };
  }

  /** The prompt waiting for this tab, if the page is still on the same site. */
  waiting(sender: PageSender): SavePrompt | null {
    const pending = this.pending.get(sender.tabId);
    if (!pending) return null;
    const fresh = this.now() - pending.at < PROMPT_TTL_MS && this.matcher.site(pending.url) === this.matcher.site(sender.url);
    if (!fresh) this.pending.delete(sender.tabId);
    return fresh ? pending.prompt : null;
  }

  async answer(id: string, answer: SaveAnswer, sender: PageSender): Promise<void> {
    const pending = this.pending.get(sender.tabId);
    if (pending?.prompt.id !== id) return;
    this.pending.delete(sender.tabId);
    if (answer === 'never') await this.never?.add('login', pending.url);
    if (answer !== 'save') return;
    if (!this.host.unlocked) {
      await this.inbox?.add({ kind: 'login', url: pending.url, password: pending.password, ...(pending.username ? { username: pending.username } : {}) });
      return;
    }
    // Asked while locked and unlocked since: compared with the vault now.
    const existing = pending.locked
      ? await this.loginFor(pending.url, pending.username)
      : pending.itemId
        ? await this.host.getItem(pending.itemId).catch(() => undefined)
        : undefined;
    if (pending.locked && existing && loginDetails(existing)?.password === pending.password) return;
    await this.save(existing, pending.url, pending.username, pending.password, false, pending.tabId);
  }

  /** The login for this site and username (a draft without a username matches a login without one). */
  private async loginFor(url: string, username: string | undefined): Promise<Item | undefined> {
    for (const summary of this.matcher.logins(await this.host.listItems(), url)) {
      const item = await this.host.getItem(summary.id);
      if (item.overview.type === 'login' && sameUser((item.details as LoginDetails).username, username)) return item;
    }
    return undefined;
  }

  /** Whether a login for another part of the page's site has this username and password. */
  private async otherPartHas(url: string, username: string | undefined, password: string): Promise<boolean> {
    for (const { item: summary } of this.matcher.otherLogins(await this.host.listItems(), url)) {
      const details = loginDetails(await this.host.getItem(summary.id));
      if (details?.password === password && sameUser(details.username, username)) return true;
    }
    return false;
  }

  private async save(existing: Item | undefined, url: string, username: string | undefined, password: string, draft: boolean, tabId: number): Promise<void> {
    const link = this.aliases?.linkFor(tabId, url, username);
    const tags = (tags: string[] = []) => {
      const rest = tags.filter((t) => t !== UNCONFIRMED_TAG);
      return draft ? [...rest, UNCONFIRMED_TAG] : rest;
    };
    let item: ItemDraft;
    if (existing) {
      // A draft never demotes a confirmed login: only its password changes (into the history).
      const keepConfirmed = draft && !existing.overview.tags?.includes(UNCONFIRMED_TAG);
      const nextTags = keepConfirmed ? existing.overview.tags : tags(existing.overview.tags);
      item = {
        id: existing.id,
        vaultId: existing.vaultId,
        revision: existing.revision,
        overview: { ...existing.overview, ...(nextTags?.length ? { tags: nextTags } : { tags: undefined }) },
        details: { ...(existing.details as LoginDetails), password, ...withLink(existing.details as LoginDetails, link) },
      };
    } else {
      const page = new URL(url);
      const vaults = await this.host.engine.call('listVaults', []);
      const personal = vaults.find((v) => v.type === 'personal') ?? vaults[0]!;
      const nextTags = tags();
      item = {
        vaultId: personal.id,
        overview: {
          schemaVersion: 1,
          title: page.hostname.replace(/^www\./, ''),
          type: 'login',
          urls: [page.origin],
          ...(username ? { subtitle: username } : {}),
          ...(nextTags.length ? { tags: nextTags } : {}),
        },
        details: { schemaVersion: 1, ...(username ? { username } : {}), password, ...withLink({ schemaVersion: 1 }, link) },
      };
    }
    await this.host.engine.call('saveItem', [item]);
  }
}
